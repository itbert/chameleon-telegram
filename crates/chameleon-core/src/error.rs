use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("config: {0}")]
    Config(String),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("allowlist: {0}")]
    Allowlist(String),
    #[error("transport: {0}")]
    Transport(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn is_disconnect(&self) -> bool {
        match self {
            Error::Io(err) => matches!(
                err.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
            ),
            _ => false,
        }
    }
}
