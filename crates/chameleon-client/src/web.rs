use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use chameleon_core::config::{self, AppConfig};
use chameleon_core::crypto;
use chameleon_core::protocol::{
    error_code_name, AuthRequest, AuthResponse, STATUS_OK,
};
use chameleon_core::transport;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::{watch, RwLock};
use tokio::time::timeout;

pub struct RuntimeState {
    started: Instant,
    active_connections: AtomicUsize,
    total_connections: AtomicU64,
    total_bytes_up: AtomicU64,
    total_bytes_down: AtomicU64,
    last_error: Mutex<Option<String>>,
    last_bridge_latency_ms: AtomicU64,
    restart_requested: AtomicBool,
}

impl RuntimeState {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            active_connections: AtomicUsize::new(0),
            total_connections: AtomicU64::new(0),
            total_bytes_up: AtomicU64::new(0),
            total_bytes_down: AtomicU64::new(0),
            last_error: Mutex::new(None),
            last_bridge_latency_ms: AtomicU64::new(0),
            restart_requested: AtomicBool::new(false),
        }
    }

    pub fn inc_active(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        self.total_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_active(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn active_connections(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
    }

    pub fn add_bytes(&self, up: u64, down: u64) {
        self.total_bytes_up.fetch_add(up, Ordering::Relaxed);
        self.total_bytes_down.fetch_add(down, Ordering::Relaxed);
    }

    pub fn set_error(&self, err: String) {
        if let Ok(mut guard) = self.last_error.lock() {
            *guard = Some(err);
        }
    }

    pub fn clear_error(&self) {
        if let Ok(mut guard) = self.last_error.lock() {
            *guard = None;
        }
    }

    pub fn set_bridge_latency(&self, ms: u64) {
        self.last_bridge_latency_ms.store(ms, Ordering::Relaxed);
    }

    pub fn status(&self) -> StatusResponse {
        StatusResponse {
            uptime_ms: self.started.elapsed().as_millis() as u64,
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_connections: self.total_connections.load(Ordering::Relaxed),
            bytes_up: self.total_bytes_up.load(Ordering::Relaxed),
            bytes_down: self.total_bytes_down.load(Ordering::Relaxed),
            last_error: self
                .last_error
                .lock()
                .ok()
                .and_then(|guard| guard.clone()),
            last_bridge_latency_ms: optional_nonzero(
                self.last_bridge_latency_ms.load(Ordering::Relaxed),
            ),
        }
    }

    pub fn request_restart(&self) {
        self.restart_requested.store(true, Ordering::Relaxed);
    }

    pub fn restart_requested(&self) -> bool {
        self.restart_requested.load(Ordering::Relaxed)
    }
}

pub struct WebState {
    pub config_path: PathBuf,
    pub config: RwLock<AppConfig>,
    pub runtime: Arc<RuntimeState>,
    pub auth_token: RwLock<String>,
    pub log_file: PathBuf,
    pub shutdown_tx: watch::Sender<bool>,
}

pub fn router(state: Arc<WebState>) -> Router {
    Router::new()
        .route("/", get(ui_index))
        .route("/app.js", get(ui_js))
        .route("/style.css", get(ui_css))
        .route("/api/status", get(api_status))
        .route("/api/config", get(api_get_config).post(api_set_config))
        .route("/api/bridge-test", post(api_bridge_test))
        .route("/api/logs", get(api_logs))
        .with_state(state)
}

async fn ui_index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn ui_js() -> impl IntoResponse {
    (
        [("content-type", "application/javascript; charset=utf-8")],
        APP_JS,
    )
}

async fn ui_css() -> impl IntoResponse {
    (
        [("content-type", "text/css; charset=utf-8")],
        STYLE_CSS,
    )
}

async fn api_status(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Result<Json<StatusResponse>, StatusCode> {
    authorize(&state, &headers).await?;
    Ok(Json(state.runtime.status()))
}

async fn api_get_config(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Result<Json<ConfigResponse>, StatusCode> {
    authorize(&state, &headers).await?;
    let cfg = state.config.read().await.clone();
    Ok(Json(ConfigResponse { config: cfg }))
}

async fn api_set_config(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Json(payload): Json<ConfigUpdate>,
) -> Result<Json<ConfigUpdateResponse>, StatusCode> {
    authorize(&state, &headers).await?;
    payload.config.validate().map_err(|_| StatusCode::BAD_REQUEST)?;

    let toml = payload
        .config
        .to_toml()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    tokio::fs::write(&state.config_path, toml)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Some(client) = &payload.config.client {
        let mut token_guard = state.auth_token.write().await;
        *token_guard = client.web_ui_auth_token.clone();
    }
    *state.config.write().await = payload.config;
    state.runtime.clear_error();

    if payload.restart.unwrap_or(false) {
        state.runtime.request_restart();
        let _ = state.shutdown_tx.send(true);
    }

    Ok(Json(ConfigUpdateResponse {
        ok: true,
        restart_triggered: payload.restart.unwrap_or(false),
    }))
}

async fn api_bridge_test(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Result<Json<BridgeTestResponse>, StatusCode> {
    authorize(&state, &headers).await?;
    let cfg = state.config.read().await.clone();
    let client = cfg.client.ok_or(StatusCode::BAD_REQUEST)?;

    match bridge_test(&client).await {
        Ok(ms) => {
            state.runtime.set_bridge_latency(ms);
            Ok(Json(BridgeTestResponse {
                ok: true,
                latency_ms: Some(ms),
                error: None,
            }))
        }
        Err(err) => {
            state.runtime.set_error(err.clone());
            Ok(Json(BridgeTestResponse {
                ok: false,
                latency_ms: None,
                error: Some(err),
            }))
        }
    }
}

async fn api_logs(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Json<LogsResponse>, StatusCode> {
    authorize(&state, &headers).await?;
    let limit = query
        .get("n")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(200);

    let lines = tail_lines(&state.log_file, limit)
        .await
        .unwrap_or_else(|_| vec!["(log read error)".to_string()]);

    Ok(Json(LogsResponse { lines }))
}

async fn authorize(state: &WebState, headers: &HeaderMap) -> Result<(), StatusCode> {
    let expected_token = state.auth_token.read().await.clone();
    if expected_token.is_empty() {
        return Ok(());
    }
    if let Some(value) = headers.get("authorization") {
        if let Ok(val) = value.to_str() {
            if let Some(token) = val.strip_prefix("Bearer ") {
                if token == expected_token {
                    return Ok(());
                }
            }
        }
    }
    if let Some(value) = headers.get("x-auth-token") {
        if let Ok(val) = value.to_str() {
            if val == expected_token {
                return Ok(());
            }
        }
    }
    Err(StatusCode::UNAUTHORIZED)
}

async fn bridge_test(cfg: &config::ClientConfig) -> Result<u64, String> {
    let start = Instant::now();
    let mut bridge = timeout(cfg.connect_timeout(), transport::connect(cfg.transport, &cfg.bridge_addr))
        .await
        .map_err(|_| "bridge connect timeout".to_string())?
        .map_err(|e| format!("bridge connect error: {e}"))?;

    let server_pub = crypto::decode_key_b64(&cfg.server_pubkey_b64)
        .map_err(|e| format!("pubkey error: {e}"))?;
    let noise = timeout(
        cfg.handshake_timeout(),
        crypto::client_handshake(&mut bridge, &server_pub, cfg.max_frame),
    )
    .await
    .map_err(|_| "handshake timeout".to_string())?
    .map_err(|e| format!("handshake error: {e}"))?;

    let auth_psk = crypto::decode_optional_b64(&cfg.auth_psk_b64)
        .map_err(|e| format!("auth token error: {e}"))?;
    let auth_req = AuthRequest { token: auth_psk };
    let payload = auth_req.encode().map_err(|e| format!("auth encode: {e}"))?;
    timeout(cfg.handshake_timeout(), noise.write_frame(&mut bridge, &payload))
        .await
        .map_err(|_| "auth write timeout".to_string())?
        .map_err(|e| format!("auth write error: {e}"))?;

    let auth_resp_bytes = timeout(cfg.handshake_timeout(), noise.read_frame(&mut bridge))
        .await
        .map_err(|_| "auth read timeout".to_string())?
        .map_err(|e| format!("auth read error: {e}"))?;
    let auth_resp = AuthResponse::decode(&auth_resp_bytes)
        .map_err(|e| format!("auth response decode: {e}"))?;
    if auth_resp.status != STATUS_OK {
        return Err(format!("auth failed: {}", error_code_name(auth_resp.error_code)));
    }

    Ok(start.elapsed().as_millis() as u64)
}

async fn tail_lines(path: &PathBuf, limit: usize) -> Result<Vec<String>, std::io::Error> {
    let content = tokio::fs::read_to_string(path).await?;
    let mut lines: Vec<String> = content.lines().rev().take(limit).map(|s| s.to_string()).collect();
    lines.reverse();
    Ok(lines)
}

fn optional_nonzero(value: u64) -> Option<u64> {
    if value == 0 { None } else { Some(value) }
}

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub uptime_ms: u64,
    pub active_connections: usize,
    pub total_connections: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub last_error: Option<String>,
    pub last_bridge_latency_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct ConfigResponse {
    pub config: AppConfig,
}

#[derive(Debug, Deserialize)]
pub struct ConfigUpdate {
    pub config: AppConfig,
    pub restart: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ConfigUpdateResponse {
    pub ok: bool,
    pub restart_triggered: bool,
}

#[derive(Debug, Serialize)]
pub struct BridgeTestResponse {
    pub ok: bool,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LogsResponse {
    pub lines: Vec<String>,
}

const INDEX_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Chameleon Client</title>
  <link rel="stylesheet" href="/style.css" />
</head>
<body>
  <div class="shell">
    <header>
      <h1>Chameleon Client</h1>
      <p class="subtitle">Local control panel</p>
    </header>

    <nav class="tabs">
      <button data-tab="dashboard" class="active">Dashboard</button>
      <button data-tab="config">Configuration</button>
      <button data-tab="diagnostics">Diagnostics</button>
    </nav>

    <section id="dashboard" class="panel active">
      <div class="grid">
        <div class="card">
          <h3>Status</h3>
          <div id="status-summary">Loading...</div>
        </div>
        <div class="card">
          <h3>Connections</h3>
          <div id="status-connections">Loading...</div>
        </div>
        <div class="card">
          <h3>Traffic</h3>
          <div id="status-traffic">Loading...</div>
        </div>
      </div>
    </section>

    <section id="config" class="panel">
      <div class="card">
        <h3>Config</h3>
        <textarea id="config-json" spellcheck="false"></textarea>
        <div class="actions">
          <label><input type="checkbox" id="restart-on-save" /> Restart service after save</label>
          <button id="save-config">Save</button>
        </div>
        <p class="hint">Use JSON format. Fields are validated on save.</p>
      </div>
    </section>

    <section id="diagnostics" class="panel">
      <div class="grid">
        <div class="card">
          <h3>Bridge test</h3>
          <button id="bridge-test">Run test</button>
          <div id="bridge-result" class="result"></div>
        </div>
        <div class="card">
          <h3>Recent logs</h3>
          <button id="refresh-logs">Refresh</button>
          <pre id="logs"></pre>
        </div>
      </div>
    </section>

    <section class="card">
      <h3>Auth token</h3>
      <input id="auth-token" placeholder="optional" />
      <p class="hint">If token is set in config, enter it here to enable API calls.</p>
    </section>
  </div>

  <script src="/app.js"></script>
</body>
</html>
"#;

const STYLE_CSS: &str = r#"
:root {
  --bg: #f4f1ed;
  --panel: #ffffff;
  --accent: #1f7a8c;
  --text: #1b1b1b;
  --muted: #606060;
  --border: #e0dbd5;
}

* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
  color: var(--text);
  background: linear-gradient(120deg, #efe7df, #f9f6f3);
}

.shell {
  max-width: 960px;
  margin: 40px auto;
  padding: 24px;
}

header {
  margin-bottom: 20px;
}

.subtitle {
  color: var(--muted);
  margin-top: 4px;
}

.tabs {
  display: flex;
  gap: 12px;
  margin-bottom: 16px;
}

.tabs button {
  border: 1px solid var(--border);
  background: var(--panel);
  padding: 8px 14px;
  cursor: pointer;
}

.tabs button.active {
  border-color: var(--accent);
  color: var(--accent);
}

.panel {
  display: none;
}

.panel.active {
  display: block;
}

.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 16px;
}

.card {
  background: var(--panel);
  padding: 16px;
  border: 1px solid var(--border);
  border-radius: 8px;
}

textarea {
  width: 100%;
  height: 240px;
  font-family: "IBM Plex Mono", ui-monospace, monospace;
}

.actions {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-top: 8px;
}

button {
  border: none;
  background: var(--accent);
  color: white;
  padding: 8px 12px;
  cursor: pointer;
}

button.secondary {
  background: #888;
}

pre {
  background: #101010;
  color: #f1f1f1;
  padding: 12px;
  height: 220px;
  overflow: auto;
}

.result {
  margin-top: 8px;
  color: var(--muted);
}

.hint {
  color: var(--muted);
  font-size: 0.9rem;
}
"#;

const APP_JS: &str = r#"
const tokenInput = document.getElementById('auth-token');
const statusSummary = document.getElementById('status-summary');
const statusConnections = document.getElementById('status-connections');
const statusTraffic = document.getElementById('status-traffic');
const configArea = document.getElementById('config-json');
const logsArea = document.getElementById('logs');
const bridgeResult = document.getElementById('bridge-result');

function authHeaders() {
  const token = tokenInput.value.trim();
  return token ? { 'x-auth-token': token } : {};
}

async function apiGet(path) {
  const res = await fetch(path, { headers: authHeaders() });
  if (!res.ok) throw new Error(`${path} ${res.status}`);
  return res.json();
}

async function apiPost(path, body) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...authHeaders() },
    body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error(`${path} ${res.status}`);
  return res.json();
}

async function refreshStatus() {
  try {
    const data = await apiGet('/api/status');
    statusSummary.textContent = `Uptime: ${Math.round(data.uptime_ms/1000)}s`;    
    statusConnections.textContent = `Active: ${data.active_connections}, Total: ${data.total_connections}`;
    statusTraffic.textContent = `Up: ${data.bytes_up} bytes, Down: ${data.bytes_down} bytes`;
  } catch (e) {
    statusSummary.textContent = 'Status unavailable';
  }
}

async function loadConfig() {
  try {
    const data = await apiGet('/api/config');
    configArea.value = JSON.stringify(data.config, null, 2);
  } catch (e) {
    configArea.value = '// Unable to load config. Check auth token.';
  }
}

async function saveConfig() {
  const restart = document.getElementById('restart-on-save').checked;
  try {
    const config = JSON.parse(configArea.value);
    await apiPost('/api/config', { config, restart });
    alert('Saved.');
  } catch (e) {
    alert('Save failed: ' + e.message);
  }
}

async function bridgeTest() {
  bridgeResult.textContent = 'Running...';
  try {
    const data = await apiPost('/api/bridge-test', {});
    if (data.ok) {
      bridgeResult.textContent = `OK, latency ${data.latency_ms} ms`;
    } else {
      bridgeResult.textContent = `Failed: ${data.error}`;
    }
  } catch (e) {
    bridgeResult.textContent = `Error: ${e.message}`;
  }
}

async function refreshLogs() {
  try {
    const data = await apiGet('/api/logs?n=200');
    logsArea.textContent = data.lines.join('\n');
  } catch (e) {
    logsArea.textContent = 'Logs unavailable';
  }
}

function setupTabs() {
  const buttons = document.querySelectorAll('.tabs button');
  buttons.forEach(btn => {
    btn.addEventListener('click', () => {
      buttons.forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(btn.dataset.tab).classList.add('active');
    });
  });
}

window.addEventListener('load', () => {
  setupTabs();
  refreshStatus();
  loadConfig();
  refreshLogs();
  setInterval(refreshStatus, 5000);
});

document.getElementById('save-config').addEventListener('click', saveConfig);
document.getElementById('bridge-test').addEventListener('click', bridgeTest);
document.getElementById('refresh-logs').addEventListener('click', refreshLogs);
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use serde_json::json;
    use tower::ServiceExt;

    fn sample_config() -> AppConfig {
        AppConfig {
            client: Some(config::ClientConfig {
                listen: "127.0.0.1:1080".to_string(),
                bridge_addr: "127.0.0.1:443".to_string(),
                server_pubkey_b64: "AAAA".to_string(),
                transport: chameleon_core::transport::TransportKind::Raw,
                max_frame: 65535,
                auth_psk_b64: "".to_string(),
                handshake_timeout_ms: 5000,
                connect_timeout_ms: 8000,
                relay_idle_timeout_ms: 60000,
                shutdown_grace_ms: 5000,
                web_ui_addr: "127.0.0.1:7777".to_string(),
                web_ui_enabled: true,
                web_ui_auth_token: "".to_string(),
            }),
            bridge: None,
        }
    }

    fn sample_state(token: &str, config_path: PathBuf) -> Arc<WebState> {
        let runtime = Arc::new(RuntimeState::new());
        let (tx, _) = watch::channel(false);
        Arc::new(WebState {
            config_path,
            config: RwLock::new(sample_config()),
            runtime,
            auth_token: RwLock::new(token.to_string()),
            log_file: std::env::temp_dir().join("chameleon-test.log"),
            shutdown_tx: tx,
        })
    }

    #[tokio::test]
    async fn status_requires_auth_token() {
        let state = sample_state("secret", std::env::temp_dir().join("cfg.toml"));
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn status_ok_without_token() {
        let state = sample_state("", std::env::temp_dir().join("cfg.toml"));
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn config_update_writes_file() {
        let path = std::env::temp_dir().join("chameleon-web-config.json");
        let state = sample_state("", path.clone());
        let app = router(state);

        let payload = json!({
            "config": sample_config(),
            "restart": false
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/config")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(tokio::fs::read_to_string(path).await.unwrap().contains("[client]"));
    }
}
