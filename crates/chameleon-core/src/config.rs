use crate::error::{Error, Result};
use crate::transport::TransportKind;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::Duration;
use std::{net::SocketAddr};

fn default_max_frame() -> usize {
    65535
}

fn default_auth_psk_b64() -> String {
    String::new()
}

fn default_handshake_timeout_ms() -> u64 {
    5000
}

fn default_connect_timeout_ms() -> u64 {
    8000
}

fn default_target_connect_timeout_ms() -> u64 {
    8000
}

fn default_relay_idle_timeout_ms() -> u64 {
    60000
}

fn default_shutdown_grace_ms() -> u64 {
    5000
}

fn default_max_connections() -> usize {
    10000
}

fn default_deny_private_targets() -> bool {
    true
}

fn default_web_ui_addr() -> String {
    "127.0.0.1:7777".to_string()
}

fn default_web_ui_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    pub client: Option<ClientConfig>,
    pub bridge: Option<BridgeConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientConfig {
    pub listen: String,
    pub bridge_addr: String,
    pub server_pubkey_b64: String,
    #[serde(default)]
    pub transport: TransportKind,
    #[serde(default = "default_max_frame")]
    pub max_frame: usize,
    #[serde(default = "default_auth_psk_b64")]
    pub auth_psk_b64: String,
    #[serde(default = "default_handshake_timeout_ms")]
    pub handshake_timeout_ms: u64,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_relay_idle_timeout_ms")]
    pub relay_idle_timeout_ms: u64,
    #[serde(default = "default_shutdown_grace_ms")]
    pub shutdown_grace_ms: u64,
    #[serde(default = "default_web_ui_addr")]
    pub web_ui_addr: String,
    #[serde(default = "default_web_ui_enabled")]
    pub web_ui_enabled: bool,
    #[serde(default)]
    pub web_ui_auth_token: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BridgeConfig {
    pub listen: String,
    pub server_privkey_b64: String,
    #[serde(default)]
    pub transport: TransportKind,
    #[serde(default)]
    pub allow_all: bool,
    #[serde(default)]
    pub allow_cidrs: Vec<String>,
    #[serde(default)]
    pub allow_domains: Vec<String>,
    #[serde(default = "default_max_frame")]
    pub max_frame: usize,
    #[serde(default = "default_auth_psk_b64")]
    pub auth_psk_b64: String,
    #[serde(default)]
    pub require_auth: bool,
    #[serde(default = "default_handshake_timeout_ms")]
    pub handshake_timeout_ms: u64,
    #[serde(default = "default_target_connect_timeout_ms")]
    pub target_connect_timeout_ms: u64,
    #[serde(default = "default_relay_idle_timeout_ms")]
    pub relay_idle_timeout_ms: u64,
    #[serde(default = "default_shutdown_grace_ms")]
    pub shutdown_grace_ms: u64,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_deny_private_targets")]
    pub deny_private_targets: bool,
    #[serde(default)]
    pub allow_loopback_targets: bool,
}

impl AppConfig {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = fs::read_to_string(path).map_err(Error::Io)?;
        let cfg: AppConfig = toml::from_str(&content)
            .map_err(|e| Error::Config(format!("toml parse error: {e}")))?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(client) = &self.client {
            client.validate()?;
        }
        if let Some(bridge) = &self.bridge {
            bridge.validate()?;
        }
        Ok(())
    }

    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self)
            .map_err(|e| Error::Config(format!("toml serialize error: {e}")))
    }
}

impl ClientConfig {
    pub fn validate(&self) -> Result<()> {
        if self.listen.trim().is_empty() {
            return Err(Error::Config("client.listen is empty".into()));
        }
        if self.bridge_addr.trim().is_empty() {
            return Err(Error::Config("client.bridge_addr is empty".into()));
        }
        if self.server_pubkey_b64.trim().is_empty() {
            return Err(Error::Config("client.server_pubkey_b64 is empty".into()));
        }
        if self.max_frame == 0 {
            return Err(Error::Config("client.max_frame must be > 0".into()));
        }
        validate_timeout_ms("client.handshake_timeout_ms", self.handshake_timeout_ms)?;
        validate_timeout_ms("client.connect_timeout_ms", self.connect_timeout_ms)?;
        validate_timeout_ms("client.relay_idle_timeout_ms", self.relay_idle_timeout_ms)?;
        validate_timeout_ms("client.shutdown_grace_ms", self.shutdown_grace_ms)?;
        self.validate_web_ui()?;
        Ok(())
    }

    pub fn handshake_timeout(&self) -> Duration {
        Duration::from_millis(self.handshake_timeout_ms)
    }

    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms)
    }

    pub fn relay_idle_timeout(&self) -> Duration {
        Duration::from_millis(self.relay_idle_timeout_ms)
    }

    pub fn shutdown_grace(&self) -> Duration {
        Duration::from_millis(self.shutdown_grace_ms)
    }

    pub fn web_ui_socket_addr(&self) -> Result<SocketAddr> {
        let addr: SocketAddr = self
            .web_ui_addr
            .parse()
            .map_err(|e| Error::Config(format!("invalid web_ui_addr: {e}")))?;
        if !addr.ip().is_loopback() {
            return Err(Error::Config(
                "web_ui_addr must be loopback (127.0.0.1 or ::1)".into(),
            ));
        }
        Ok(addr)
    }

    fn validate_web_ui(&self) -> Result<()> {
        if !self.web_ui_enabled {
            return Ok(());
        }
        let _ = self.web_ui_socket_addr()?;
        if self.web_ui_auth_token.len() > 512 {
            return Err(Error::Config(
                "client.web_ui_auth_token is too long".into(),
            ));
        }
        Ok(())
    }
}

impl BridgeConfig {
    pub fn validate(&self) -> Result<()> {
        if self.listen.trim().is_empty() {
            return Err(Error::Config("bridge.listen is empty".into()));
        }
        if self.server_privkey_b64.trim().is_empty() {
            return Err(Error::Config("bridge.server_privkey_b64 is empty".into()));
        }
        if self.max_frame == 0 {
            return Err(Error::Config("bridge.max_frame must be > 0".into()));
        }
        validate_timeout_ms("bridge.handshake_timeout_ms", self.handshake_timeout_ms)?;
        validate_timeout_ms(
            "bridge.target_connect_timeout_ms",
            self.target_connect_timeout_ms,
        )?;
        validate_timeout_ms("bridge.relay_idle_timeout_ms", self.relay_idle_timeout_ms)?;
        validate_timeout_ms("bridge.shutdown_grace_ms", self.shutdown_grace_ms)?;
        if self.max_connections == 0 {
            return Err(Error::Config("bridge.max_connections must be > 0".into()));
        }
        if self.require_auth && self.auth_psk_b64.trim().is_empty() {
            return Err(Error::Config(
                "bridge.require_auth=true requires bridge.auth_psk_b64".into(),
            ));
        }
        Ok(())
    }

    pub fn handshake_timeout(&self) -> Duration {
        Duration::from_millis(self.handshake_timeout_ms)
    }

    pub fn target_connect_timeout(&self) -> Duration {
        Duration::from_millis(self.target_connect_timeout_ms)
    }

    pub fn relay_idle_timeout(&self) -> Duration {
        Duration::from_millis(self.relay_idle_timeout_ms)
    }

    pub fn shutdown_grace(&self) -> Duration {
        Duration::from_millis(self.shutdown_grace_ms)
    }
}

pub fn load_client(path: impl AsRef<Path>) -> Result<ClientConfig> {
    let cfg = AppConfig::from_file(path)?;
    let client = cfg.client.ok_or_else(|| Error::Config("missing [client] section".into()))?;
    client.validate()?;
    Ok(client)
}

pub fn load_bridge(path: impl AsRef<Path>) -> Result<BridgeConfig> {
    let cfg = AppConfig::from_file(path)?;
    let bridge = cfg.bridge.ok_or_else(|| Error::Config("missing [bridge] section".into()))?;
    bridge.validate()?;
    Ok(bridge)
}

fn validate_timeout_ms(field: &str, value: u64) -> Result<()> {
    if value == 0 {
        return Err(Error::Config(format!("{field} must be > 0")));
    }
    if value > 600_000 {
        return Err(Error::Config(format!("{field} must be <= 600000")));
    }
    Ok(())
}
