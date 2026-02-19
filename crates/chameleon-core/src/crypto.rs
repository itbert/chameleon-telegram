use crate::error::{Error, Result};
use crate::framing;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use snow::{params::NoiseParams, Builder, TransportState};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_SHA256";
const NOISE_TAG_LEN: usize = 16;
const HANDSHAKE_MAX: usize = 1024;

#[derive(Clone)]
pub struct NoiseChannel {
    state: Arc<Mutex<TransportState>>,
    max_frame: usize,
}

impl NoiseChannel {
    pub fn new(state: TransportState, max_frame: usize) -> Self {
        NoiseChannel {
            state: Arc::new(Mutex::new(state)),
            max_frame,
        }
    }

    pub fn max_frame(&self) -> usize {
        self.max_frame
    }

    pub async fn write_frame<W: AsyncWrite + Unpin>(&self, writer: &mut W, plaintext: &[u8]) -> Result<()> {
        if plaintext.len() > self.max_frame {
            return Err(Error::Protocol(format!(
                "plaintext length {} exceeds max_frame {}",
                plaintext.len(),
                self.max_frame
            )));
        }
        let mut buf = vec![0u8; plaintext.len() + NOISE_TAG_LEN];
        let mut state = self.state.lock().await;
        let len = state
            .write_message(plaintext, &mut buf)
            .map_err(|e| Error::Crypto(format!("noise write_message: {e}")))?;
        buf.truncate(len);
        framing::write_frame(writer, &buf).await
    }

    pub async fn read_frame<R: AsyncRead + Unpin>(&self, reader: &mut R) -> Result<Vec<u8>> {
        let max_cipher = self.max_frame + NOISE_TAG_LEN;
        let cipher = framing::read_frame(reader, max_cipher).await?;
        let mut out = vec![0u8; cipher.len()];
        let mut state = self.state.lock().await;
        let len = state
            .read_message(&cipher, &mut out)
            .map_err(|e| Error::Crypto(format!("noise read_message: {e}")))?;
        out.truncate(len);
        Ok(out)
    }
}

pub fn generate_keypair_b64() -> Result<(String, String)> {
    let params: NoiseParams = NOISE_PARAMS
        .parse()
        .map_err(|e| Error::Crypto(format!("noise params: {e}")))?;
    let builder = Builder::new(params);
    let keypair = builder
        .generate_keypair()
        .map_err(|e| Error::Crypto(format!("keypair: {e}")))?;
    let priv_b64 = B64.encode(keypair.private);
    let pub_b64 = B64.encode(keypair.public);
    Ok((priv_b64, pub_b64))
}

pub fn decode_key_b64(input: &str) -> Result<Vec<u8>> {
    let bytes = decode_b64(input)?;
    if bytes.len() != 32 {
        return Err(Error::Crypto(format!(
            "expected 32-byte key, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

pub fn decode_optional_b64(input: &str) -> Result<Vec<u8>> {
    if input.trim().is_empty() {
        return Ok(Vec::new());
    }
    decode_b64(input)
}

fn decode_b64(input: &str) -> Result<Vec<u8>> {
    B64.decode(input.trim())
        .map_err(|e| Error::Crypto(format!("base64 decode: {e}")))
}

pub async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    server_pub: &[u8],
    max_frame: usize,
) -> Result<NoiseChannel> {
    if server_pub.len() != 32 {
        return Err(Error::Crypto(format!(
            "server public key must be 32 bytes, got {}",
            server_pub.len()
        )));
    }
    let params: NoiseParams = NOISE_PARAMS
        .parse()
        .map_err(|e| Error::Crypto(format!("noise params: {e}")))?;
    let builder = Builder::new(params);
    let keypair = builder
        .generate_keypair()
        .map_err(|e| Error::Crypto(format!("keypair: {e}")))?;
    let mut noise = Builder::new(params)
        .local_private_key(&keypair.private)
        .remote_public_key(server_pub)
        .build_initiator()
        .map_err(|e| Error::Crypto(format!("build initiator: {e}")))?;

    let mut msg = vec![0u8; HANDSHAKE_MAX];
    let len = noise
        .write_message(&[], &mut msg)
        .map_err(|e| Error::Crypto(format!("handshake write: {e}")))?;
    msg.truncate(len);
    write_handshake(stream, &msg).await?;

    let msg_in = read_handshake(stream).await?;
    let mut out = vec![0u8; HANDSHAKE_MAX];
    noise
        .read_message(&msg_in, &mut out)
        .map_err(|e| Error::Crypto(format!("handshake read: {e}")))?;

    let transport = noise
        .into_transport_mode()
        .map_err(|e| Error::Crypto(format!("into transport: {e}")))?;
    Ok(NoiseChannel::new(transport, max_frame))
}

pub async fn server_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    server_priv: &[u8],
    max_frame: usize,
) -> Result<NoiseChannel> {
    if server_priv.len() != 32 {
        return Err(Error::Crypto(format!(
            "server private key must be 32 bytes, got {}",
            server_priv.len()
        )));
    }
    let params: NoiseParams = NOISE_PARAMS
        .parse()
        .map_err(|e| Error::Crypto(format!("noise params: {e}")))?;
    let mut noise = Builder::new(params)
        .local_private_key(server_priv)
        .build_responder()
        .map_err(|e| Error::Crypto(format!("build responder: {e}")))?;

    let msg_in = read_handshake(stream).await?;
    let mut out = vec![0u8; HANDSHAKE_MAX];
    noise
        .read_message(&msg_in, &mut out)
        .map_err(|e| Error::Crypto(format!("handshake read: {e}")))?;

    let mut msg = vec![0u8; HANDSHAKE_MAX];
    let len = noise
        .write_message(&[], &mut msg)
        .map_err(|e| Error::Crypto(format!("handshake write: {e}")))?;
    msg.truncate(len);
    write_handshake(stream, &msg).await?;

    let transport = noise
        .into_transport_mode()
        .map_err(|e| Error::Crypto(format!("into transport: {e}")))?;
    Ok(NoiseChannel::new(transport, max_frame))
}

async fn write_handshake<W: AsyncWrite + Unpin>(writer: &mut W, msg: &[u8]) -> Result<()> {
    if msg.len() > u16::MAX as usize {
        return Err(Error::Crypto("handshake message too large".into()));
    }
    let len = msg.len() as u16;
    writer
        .write_all(&len.to_be_bytes())
        .await
        .map_err(Error::Io)?;
    writer.write_all(msg).await.map_err(Error::Io)?;
    writer.flush().await.map_err(Error::Io)?;
    Ok(())
}

async fn read_handshake<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).await.map_err(Error::Io)?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len > HANDSHAKE_MAX {
        return Err(Error::Crypto(format!(
            "handshake message too large: {len}"
        )));
    }
    let mut msg = vec![0u8; len];
    if len > 0 {
        reader.read_exact(&mut msg).await.map_err(Error::Io)?;
    }
    Ok(msg)
}
