use crate::error::{Error, Result};

pub const STATUS_OK: u8 = 0;
pub const STATUS_ERR: u8 = 1;

pub const ERR_NOT_ALLOWED: u8 = 1;
pub const ERR_CONNECT_FAIL: u8 = 2;
pub const ERR_PROTOCOL: u8 = 3;

#[derive(Debug, Clone)]
pub struct ConnectRequest {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct ConnectResponse {
    pub status: u8,
    pub error_code: u8,
}

impl ConnectRequest {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let host_bytes = self.host.as_bytes();
        if host_bytes.len() > u16::MAX as usize {
            return Err(Error::Protocol("host too long".into()));
        }
        let mut out = Vec::with_capacity(2 + host_bytes.len() + 2);
        out.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(host_bytes);
        out.extend_from_slice(&self.port.to_be_bytes());
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < 4 {
            return Err(Error::Protocol("connect request too short".into()));
        }
        let host_len = u16::from_be_bytes([input[0], input[1]]) as usize;
        if input.len() < 2 + host_len + 2 {
            return Err(Error::Protocol("connect request invalid length".into()));
        }
        let host = String::from_utf8(input[2..2 + host_len].to_vec())
            .map_err(|_| Error::Protocol("host is not valid utf-8".into()))?;
        let port_idx = 2 + host_len;
        let port = u16::from_be_bytes([input[port_idx], input[port_idx + 1]]);
        Ok(ConnectRequest { host, port })
    }
}

impl ConnectResponse {
    pub fn ok() -> Self {
        ConnectResponse {
            status: STATUS_OK,
            error_code: 0,
        }
    }

    pub fn err(code: u8) -> Self {
        ConnectResponse {
            status: STATUS_ERR,
            error_code: code,
        }
    }

    pub fn encode(self) -> [u8; 2] {
        [self.status, self.error_code]
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() != 2 {
            return Err(Error::Protocol("connect response invalid length".into()));
        }
        Ok(ConnectResponse {
            status: input[0],
            error_code: input[1],
        })
    }
}
