use crate::error::{Error, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R, max_len: usize) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await.map_err(Error::Io)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max_len {
        return Err(Error::Protocol(format!(
            "frame length {len} exceeds max {max_len}"
        )));
    }
    let mut buf = vec![0u8; len];
    if len > 0 {
        reader.read_exact(&mut buf).await.map_err(Error::Io)?;
    }
    Ok(buf)
}

pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    let len = data.len() as u32;
    writer
        .write_all(&len.to_be_bytes())
        .await
        .map_err(Error::Io)?;
    if !data.is_empty() {
        writer.write_all(data).await.map_err(Error::Io)?;
    }
    writer.flush().await.map_err(Error::Io)?;
    Ok(())
}
