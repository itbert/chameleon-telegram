use crate::error::{Error, Result};
use serde::Deserialize;
use tokio::net::TcpStream;

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    Raw,
}

impl Default for TransportKind {
    fn default() -> Self {
        TransportKind::Raw
    }
}

pub async fn connect(kind: TransportKind, addr: &str) -> Result<TcpStream> {
    match kind {
        TransportKind::Raw => TcpStream::connect(addr)
            .await
            .map_err(Error::Io),
    }
}
