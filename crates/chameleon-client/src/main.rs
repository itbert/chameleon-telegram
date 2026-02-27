mod logging;
mod web;

use axum::Router;
use base64::Engine;
use clap::{Parser, Subcommand};
use chameleon_core::config::{self, AppConfig};
use chameleon_core::crypto;
use chameleon_core::protocol::{
    error_code_name, AuthRequest, AuthResponse, ConnectRequest, ConnectResponse, STATUS_OK,
};
use chameleon_core::relay;
use chameleon_core::transport;
use chameleon_core::{Error, Result};
use rand::RngCore;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, RwLock};
use tokio::time::{sleep, timeout, Instant};
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "chameleon-client")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Run {
        #[arg(long)]
        config: PathBuf,
    },
    Install {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Status {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    OpenUi {
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run { config } => run(config).await,
        Commands::Install { config } => install(config).await,
        Commands::Status { config } => status(config).await,
        Commands::OpenUi { config } => open_ui(config).await,
    }
}

async fn run(path: PathBuf) -> Result<()> {
    let log_output = logging::init_logging().map_err(|e| Error::Io(e))?;
    let _log_guard = log_output.guard;

    let mut app_cfg = config::AppConfig::from_file(&path)?;
    app_cfg.validate()?;

    let token = ensure_web_token(&mut app_cfg, &path)?;
    let client_cfg = app_cfg
        .client
        .clone()
        .ok_or_else(|| Error::Config("missing [client] section".into()))?;

    let listen: SocketAddr = client_cfg
        .listen
        .parse()
        .map_err(|e| Error::Config(format!("invalid listen address: {e}")))?;
    let auth_psk = Arc::new(crypto::decode_optional_b64(&client_cfg.auth_psk_b64)?);

    let runtime = Arc::new(web::RuntimeState::new());
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let config_state = Arc::new(RwLock::new(app_cfg.clone()));

    if client_cfg.web_ui_enabled {
        let addr = client_cfg.web_ui_socket_addr()?;
        let state = Arc::new(web::WebState {
            config_path: path.clone(),
            config: config_state.clone(),
            runtime: runtime.clone(),
            auth_token: RwLock::new(token.clone()),
            log_file: log_output.log_file.clone(),
            shutdown_tx: shutdown_tx.clone(),
        });
        let router = web::router(state);
        tokio::spawn(async move {
            if let Err(err) = serve_web(addr, router).await {
                warn!("web ui server error: {}", err);
            }
        });
        info!(web_ui_addr = %addr, "web ui enabled");
    } else {
        info!("web ui disabled");
    }

    let listener = TcpListener::bind(listen).await.map_err(Error::Io)?;
    info!(listen = %listen, "client listening");

    let conn_seq = Arc::new(AtomicU64::new(1));
    let shutdown = wait_shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutdown signal received; stop accepting new connections");
                break;
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("shutdown requested by web ui");
                    break;
                }
            }
            accept_res = listener.accept() => {
                let (socket, peer) = match accept_res {
                    Ok(v) => v,
                    Err(err) => {
                        warn!("accept error: {}", err);
                        continue;
                    }
                };

                let cfg = client_cfg.clone();
                let auth_psk = auth_psk.clone();
                let runtime = runtime.clone();
                let conn_id = conn_seq.fetch_add(1, Ordering::Relaxed);
                runtime.inc_active();

                tokio::spawn(async move {
                    let started = Instant::now();
                    let result = handle_client(conn_id, peer, socket, cfg, auth_psk, runtime.clone()).await;
                    let duration_ms = started.elapsed().as_millis() as u64;
                    match result {
                        Ok(()) => info!(conn_id, peer = %peer, duration_ms, "connection closed"),
                        Err(err) => {
                            runtime.set_error(err.to_string());
                            warn!(conn_id, peer = %peer, duration_ms, error = %err, "connection failed");
                        }
                    }
                    runtime.dec_active();
                });
            }
        }
    }

    wait_for_active_connections(runtime, client_cfg.shutdown_grace()).await;
    Ok(())
}

async fn serve_web(addr: SocketAddr, router: Router) -> Result<()> {
    let listener = TcpListener::bind(addr).await.map_err(Error::Io)?;
    axum::serve(listener, router)
        .await
        .map_err(|e| Error::Transport(format!("web server error: {e}")))?;
    Ok(())
}

async fn handle_client(
    conn_id: u64,
    peer: SocketAddr,
    mut local: TcpStream,
    cfg: config::ClientConfig,
    auth_psk: Arc<Vec<u8>>,
    runtime: Arc<web::RuntimeState>,
) -> Result<()> {
    let target = socks5::handshake(&mut local).await?;
    info!(conn_id, peer = %peer, target_host = %target.host, target_port = target.port, "socks5 connect request");

    let mut bridge = timeout(cfg.connect_timeout(), transport::connect(cfg.transport, &cfg.bridge_addr))
        .await
        .map_err(|_| Error::Transport("bridge connect timeout".into()))??;

    let server_pub = crypto::decode_key_b64(&cfg.server_pubkey_b64)?;
    let noise = timeout(
        cfg.handshake_timeout(),
        crypto::client_handshake(&mut bridge, &server_pub, cfg.max_frame),
    )
    .await
    .map_err(|_| Error::Protocol("handshake timeout".into()))??;
    info!(conn_id, peer = %peer, "noise handshake ok");

    let auth_req = AuthRequest {
        token: auth_psk.as_ref().clone(),
    };
    let auth_payload = auth_req.encode()?;
    timeout(cfg.handshake_timeout(), noise.write_frame(&mut bridge, &auth_payload))
        .await
        .map_err(|_| Error::Protocol("auth write timeout".into()))??;

    let auth_resp_bytes = timeout(cfg.handshake_timeout(), noise.read_frame(&mut bridge))
        .await
        .map_err(|_| Error::Protocol("auth read timeout".into()))??;
    let auth_resp = AuthResponse::decode(&auth_resp_bytes)?;
    if auth_resp.status != STATUS_OK {
        socks5::reply(&mut local, false).await?;
        return Err(Error::Protocol(format!(
            "auth failed: {}",
            error_code_name(auth_resp.error_code)
        )));
    }

    let req = ConnectRequest {
        host: target.host.clone(),
        port: target.port,
    };
    let payload = req.encode()?;
    timeout(cfg.connect_timeout(), noise.write_frame(&mut bridge, &payload))
        .await
        .map_err(|_| Error::Protocol("connect request write timeout".into()))??;

    let resp_bytes = timeout(cfg.connect_timeout(), noise.read_frame(&mut bridge))
        .await
        .map_err(|_| Error::Protocol("connect response read timeout".into()))??;
    let resp = ConnectResponse::decode(&resp_bytes)?;
    if resp.status != STATUS_OK {
        socks5::reply(&mut local, false).await?;
        return Err(Error::Protocol(format!(
            "bridge rejected target: {}",
            error_code_name(resp.error_code)
        )));
    }

    socks5::reply(&mut local, true).await?;
    info!(conn_id, peer = %peer, target_host = %target.host, target_port = target.port, "relay started");

    let stats = relay::relay_plain_and_noise(local, bridge, noise, cfg.relay_idle_timeout()).await?;
    runtime.add_bytes(stats.bytes_up, stats.bytes_down);
    info!(
        conn_id,
        peer = %peer,
        bytes_up = stats.bytes_up,
        bytes_down = stats.bytes_down,
        close_reason = ?stats.close_reason,
        "relay finished"
    );
    Ok(())
}

async fn wait_for_active_connections(runtime: Arc<web::RuntimeState>, grace: std::time::Duration) {
    let started = Instant::now();
    loop {
        if runtime.active_connections() == 0 {
            info!("all active connections drained");
            return;
        }
        if started.elapsed() >= grace {
            warn!(active_connections = runtime.active_connections(), "shutdown grace timeout reached");
            return;
        }
        sleep(std::time::Duration::from_millis(100)).await;
    }
}

async fn wait_shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = sigterm.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn status(config: Option<PathBuf>) -> Result<()> {
    let path = resolve_config_path(config)?;
    let app_cfg = config::AppConfig::from_file(&path)?;
    let client = app_cfg
        .client
        .ok_or_else(|| Error::Config("missing [client] section".into()))?;
    if !client.web_ui_enabled {
        return Err(Error::Config("web ui is disabled".into()));
    }
    let addr = client.web_ui_socket_addr()?;
    let token = client.web_ui_auth_token;

    let body = http_get(addr, "/api/status", &token).await?;
    println!("{}", body);
    Ok(())
}

async fn open_ui(config: Option<PathBuf>) -> Result<()> {
    let path = resolve_config_path(config)?;
    let app_cfg = config::AppConfig::from_file(&path)?;
    let client = app_cfg
        .client
        .ok_or_else(|| Error::Config("missing [client] section".into()))?;
    if !client.web_ui_enabled {
        return Err(Error::Config("web ui is disabled".into()));
    }
    let addr = client.web_ui_socket_addr()?;
    let url = format!("http://{}", addr);

    if open_browser(&url).is_err() {
        println!("{}", url);
    }
    Ok(())
}

async fn install(config: Option<PathBuf>) -> Result<()> {
    let path = resolve_config_path(config)?;

    #[cfg(unix)]
    {
        install_linux(&path)?;
        return Ok(());
    }

    #[cfg(windows)]
    {
        install_windows(&path)?;
        return Ok(());
    }

    Err(Error::Config("install not supported on this platform".into()))
}

fn install_linux(config_path: &Path) -> Result<()> {
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    let exe = std::env::current_exe().map_err(Error::Io)?;
    let bin_dir = PathBuf::from("/usr/local/bin");
    let target_exe = bin_dir.join("chameleon-client");

    fs::create_dir_all(&bin_dir).map_err(Error::Io)?;
    fs::copy(&exe, &target_exe).map_err(Error::Io)?;
    let mut perm = fs::metadata(&target_exe).map_err(Error::Io)?.permissions();
    perm.set_mode(0o755);
    fs::set_permissions(&target_exe, perm).map_err(Error::Io)?;

    let config_dir = PathBuf::from("/etc/chameleon");
    fs::create_dir_all(&config_dir).map_err(Error::Io)?;
    let default_config = if config_path.exists() {
        fs::read_to_string(config_path).map_err(Error::Io)?
    } else {
        default_client_config()
    };
    let dest_config = config_dir.join("config.toml");
    if !dest_config.exists() {
        let mut file = fs::File::create(&dest_config).map_err(Error::Io)?;
        file.write_all(default_config.as_bytes()).map_err(Error::Io)?;
    }

    let unit = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/systemd/chameleon-client.service"
    ));
    let unit_path = PathBuf::from("/etc/systemd/system/chameleon-client.service");
    fs::write(&unit_path, unit).map_err(Error::Io)?;

    let _ = Command::new("systemctl").arg("daemon-reload").status();
    let _ = Command::new("systemctl")
        .args(["enable", "--now", "chameleon-client"])
        .status();

    println!("installed to {}", target_exe.display());
    Ok(())
}

fn install_windows(config_path: &Path) -> Result<()> {
    use std::fs;
    use std::io::Write;
    use std::process::Command;

    let exe = std::env::current_exe().map_err(Error::Io)?;
    let program_files = std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".to_string());
    let install_dir = PathBuf::from(program_files).join("Chameleon");
    fs::create_dir_all(&install_dir).map_err(Error::Io)?;
    let target_exe = install_dir.join("chameleon-client.exe");
    fs::copy(&exe, &target_exe).map_err(Error::Io)?;

    let program_data = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
    let config_dir = PathBuf::from(program_data).join("Chameleon");
    fs::create_dir_all(&config_dir).map_err(Error::Io)?;
    let default_config = if config_path.exists() {
        fs::read_to_string(config_path).map_err(Error::Io)?
    } else {
        default_client_config()
    };
    let dest_config = config_dir.join("config.toml");
    if !dest_config.exists() {
        let mut file = fs::File::create(&dest_config).map_err(Error::Io)?;
        file.write_all(default_config.as_bytes()).map_err(Error::Io)?;
    }

    let winsw_path = install_dir.join("winsw.exe");
    if !winsw_path.exists() {
        return Err(Error::Config(
            "winsw.exe not found in install directory. Place winsw.exe and retry.".into(),
        ));
    }

    let service_xml = install_dir.join("ChameleonClientService.xml");
    let xml_content = format!(
        r#"<service>
  <id>ChameleonClient</id>
  <name>Chameleon Client</name>
  <description>Chameleon local SOCKS5 client</description>
  <executable>{}</executable>
  <arguments>run --config {}</arguments>
  <logpath>{}</logpath>
  <log mode="roll-by-size">
    <sizeThreshold>10485760</sizeThreshold>
    <keepFiles>5</keepFiles>
  </log>
</service>"#,
        target_exe.display(),
        dest_config.display(),
        install_dir.display()
    );
    fs::write(&service_xml, xml_content).map_err(Error::Io)?;

    let _ = Command::new(&winsw_path).arg("install").status();
    let _ = Command::new(&winsw_path).arg("start").status();

    println!("installed to {}", target_exe.display());
    Ok(())
}

fn resolve_config_path(path: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = path {
        return Ok(path);
    }
    Ok(default_config_path())
}

fn default_config_path() -> PathBuf {
    #[cfg(windows)]
    {
        let program_data = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
        return PathBuf::from(program_data).join("Chameleon").join("config.toml");
    }

    #[cfg(unix)]
    {
        return PathBuf::from("/etc/chameleon/config.toml");
    }

    #[cfg(not(any(unix, windows)))]
    {
        return PathBuf::from("./config.toml");
    }
}

fn ensure_web_token(app_cfg: &mut AppConfig, path: &Path) -> Result<String> {
    let client = app_cfg
        .client
        .as_mut()
        .ok_or_else(|| Error::Config("missing [client] section".into()))?;
    if !client.web_ui_enabled {
        return Ok(client.web_ui_auth_token.clone());
    }
    if client.web_ui_auth_token.trim().is_empty() {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let token = base64::engine::general_purpose::STANDARD.encode(bytes);
        client.web_ui_auth_token = token.clone();
        let toml = app_cfg.to_toml()?;
        std::fs::write(path, toml).map_err(Error::Io)?;
        info!(config_path = %path.display(), "web ui auth token generated");
        return Ok(token);
    }
    Ok(client.web_ui_auth_token.clone())
}

fn open_browser(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .status()
            .map(|_| ())
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(url).status().map(|_| ())
    }

    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open").arg(url).status().map(|_| ())
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "open browser not supported",
        ))
    }
}

async fn http_get(addr: SocketAddr, path: &str, token: &str) -> Result<String> {
    let mut stream = TcpStream::connect(addr).await.map_err(Error::Io)?;
    let host_header = match addr.ip() {
        IpAddr::V4(_) => format!("127.0.0.1:{}", addr.port()),
        IpAddr::V6(_) => format!("[::1]:{}", addr.port()),
    };
    let auth_header = if token.is_empty() {
        String::new()
    } else {
        format!("X-Auth-Token: {}\r\n", token)
    };
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\n{}Connection: close\r\n\r\n",
        path, host_header, auth_header
    );
    tokio::io::AsyncWriteExt::write_all(&mut stream, request.as_bytes())
        .await
        .map_err(Error::Io)?;
    let mut buf = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut buf)
        .await
        .map_err(Error::Io)?;
    let resp = String::from_utf8_lossy(&buf).to_string();
    let parts: Vec<&str> = resp.split("\r\n\r\n").collect();
    if parts.len() < 2 {
        return Err(Error::Protocol("invalid http response".into()));
    }
    Ok(parts[1].to_string())
}

fn default_client_config() -> String {
    let toml = r#"[client]
listen = "127.0.0.1:1080"
bridge_addr = "127.0.0.1:443"
server_pubkey_b64 = ""
transport = "raw"
max_frame = 65535
web_ui_addr = "127.0.0.1:7777"
web_ui_enabled = true
web_ui_auth_token = ""
"#;
    toml.to_string()
}

mod socks5 {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Debug, Clone)]
    pub struct Target {
        pub host: String,
        pub port: u16,
    }

    pub async fn handshake(stream: &mut TcpStream) -> Result<Target> {
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).await.map_err(Error::Io)?;
        if header[0] != 0x05 {
            return Err(Error::Protocol("invalid socks version".into()));
        }
        let nmethods = header[1] as usize;
        if nmethods == 0 {
            return Err(Error::Protocol("invalid socks methods length".into()));
        }
        let mut methods = vec![0u8; nmethods];
        stream.read_exact(&mut methods).await.map_err(Error::Io)?;
        if !methods.contains(&0x00) {
            stream.write_all(&[0x05, 0xFF]).await.map_err(Error::Io)?;
            return Err(Error::Protocol("no acceptable auth methods".into()));
        }
        stream.write_all(&[0x05, 0x00]).await.map_err(Error::Io)?;

        let mut req = [0u8; 4];
        stream.read_exact(&mut req).await.map_err(Error::Io)?;
        if req[0] != 0x05 || req[1] != 0x01 {
            return Err(Error::Protocol("only CONNECT is supported".into()));
        }
        let atyp = req[3];
        let host = match atyp {
            0x01 => {
                let mut ip = [0u8; 4];
                stream.read_exact(&mut ip).await.map_err(Error::Io)?;
                std::net::Ipv4Addr::from(ip).to_string()
            }
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await.map_err(Error::Io)?;
                let host_len = len[0] as usize;
                if host_len == 0 {
                    return Err(Error::Protocol("domain host is empty".into()));
                }
                let mut name = vec![0u8; host_len];
                stream.read_exact(&mut name).await.map_err(Error::Io)?;
                String::from_utf8(name).map_err(|_| Error::Protocol("invalid domain".into()))?
            }
            0x04 => {
                let mut ip = [0u8; 16];
                stream.read_exact(&mut ip).await.map_err(Error::Io)?;
                std::net::Ipv6Addr::from(ip).to_string()
            }
            _ => return Err(Error::Protocol("invalid address type".into())),
        };
        let mut port_buf = [0u8; 2];
        stream.read_exact(&mut port_buf).await.map_err(Error::Io)?;
        let port = u16::from_be_bytes(port_buf);
        if port == 0 {
            return Err(Error::Protocol("invalid destination port 0".into()));
        }

        Ok(Target { host, port })
    }

    pub async fn reply(stream: &mut TcpStream, success: bool) -> Result<()> {
        let status = if success { 0x00 } else { 0x01 };
        let resp = [0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        stream.write_all(&resp).await.map_err(Error::Io)?;
        Ok(())
    }
}
