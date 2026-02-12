use crate::error::{Error, Result};
use crate::transport::TransportKind;
use serde::Deserialize;
use std::fs;
use std::path::Path;

fn default_max_frame() -> usize {
    65535
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub client: Option<ClientConfig>,
    pub bridge: Option<BridgeConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    pub listen: String,
    pub bridge_addr: String,
    pub server_pubkey_b64: String,
    #[serde(default)]
    pub transport: TransportKind,
    #[serde(default = "default_max_frame")]
    pub max_frame: usize,
}

#[derive(Debug, Clone, Deserialize)]
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
}

impl AppConfig {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = fs::read_to_string(path).map_err(Error::Io)?;
        let cfg: AppConfig = toml::from_str(&content)
            .map_err(|e| Error::Config(format!("toml parse error: {e}")))?;
        Ok(cfg)
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
        Ok(())
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
