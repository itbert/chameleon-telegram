use crate::crypto::NoiseChannel;
use crate::error::{Error, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn relay_plain_and_noise(
    plain: TcpStream,
    noise_stream: TcpStream,
    noise: NoiseChannel,
) -> Result<()> {
    let (mut plain_r, mut plain_w) = plain.into_split();
    let (mut noise_r, mut noise_w) = noise_stream.into_split();

    let noise_up = noise.clone();
    let noise_down = noise.clone();
    let max_frame = noise.max_frame();

    let upstream = tokio::spawn(async move {
        let mut buf = vec![0u8; max_frame];
        loop {
            let n = plain_r.read(&mut buf).await.map_err(Error::Io)?;
            if n == 0 {
                noise_w.shutdown().await.map_err(Error::Io)?;
                break;
            }
            noise_up.write_frame(&mut noise_w, &buf[..n]).await?;
        }
        Ok::<(), Error>(())
    });

    let downstream = tokio::spawn(async move {
        loop {
            let data = match noise_down.read_frame(&mut noise_r).await {
                Ok(data) => data,
                Err(err) if err.is_disconnect() => break,
                Err(err) => return Err(err),
            };
            if data.is_empty() {
                continue;
            }
            plain_w.write_all(&data).await.map_err(Error::Io)?;
        }
        Ok::<(), Error>(())
    });

    tokio::select! {
        res = upstream => {
            downstream.abort();
            match res {
                Ok(inner) => inner,
                Err(e) => Err(Error::Transport(format!("upstream task: {e}"))),
            }
        }
        res = downstream => {
            upstream.abort();
            match res {
                Ok(inner) => inner,
                Err(e) => Err(Error::Transport(format!("downstream task: {e}"))),
            }
        }
    }
}
