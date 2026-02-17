use crate::crypto::NoiseChannel;
use crate::error::{Error, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayCloseReason {
    UpstreamEof,
    DownstreamEof,
    IdleTimeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayStats {
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub close_reason: RelayCloseReason,
}

pub async fn relay_plain_and_noise(
    plain: TcpStream,
    noise_stream: TcpStream,
    noise: NoiseChannel,
    idle_timeout: Duration,
) -> Result<RelayStats> {
    let (mut plain_r, mut plain_w) = plain.into_split();
    let (mut noise_r, mut noise_w) = noise_stream.into_split();

    let noise_up = noise.clone();
    let noise_down = noise.clone();
    let max_frame = noise.max_frame();

    let upstream = tokio::spawn(async move {
        let mut buf = vec![0u8; max_frame];
        let mut bytes_up: u64 = 0;
        loop {
            let n = match timeout(idle_timeout, plain_r.read(&mut buf)).await {
                Ok(read_res) => read_res.map_err(Error::Io)?,
                Err(_) => {
                    return Ok::<TaskStats, Error>(TaskStats {
                        bytes: bytes_up,
                        reason: RelayCloseReason::IdleTimeout,
                    });
                }
            };
            if n == 0 {
                noise_w.shutdown().await.map_err(Error::Io)?;
                return Ok::<TaskStats, Error>(TaskStats {
                    bytes: bytes_up,
                    reason: RelayCloseReason::UpstreamEof,
                });
            }
            noise_up.write_frame(&mut noise_w, &buf[..n]).await?;
            bytes_up += n as u64;
        }
    });

    let downstream = tokio::spawn(async move {
        let mut bytes_down: u64 = 0;
        loop {
            let data = match timeout(idle_timeout, noise_down.read_frame(&mut noise_r)).await {
                Err(_) => {
                    return Ok::<TaskStats, Error>(TaskStats {
                        bytes: bytes_down,
                        reason: RelayCloseReason::IdleTimeout,
                    });
                }
                Ok(Ok(data)) => data,
                Ok(Err(err)) if err.is_disconnect() => {
                    return Ok::<TaskStats, Error>(TaskStats {
                        bytes: bytes_down,
                        reason: RelayCloseReason::DownstreamEof,
                    });
                }
                Ok(Err(err)) => return Err(err),
            };
            if data.is_empty() {
                continue;
            }
            plain_w.write_all(&data).await.map_err(Error::Io)?;
            bytes_down += data.len() as u64;
        }
    });

    let (up_join, down_join) = tokio::join!(upstream, downstream);
    let up = up_join.map_err(|e| Error::Transport(format!("upstream task: {e}")))??;
    let down = down_join
        .map_err(|e| Error::Transport(format!("downstream task: {e}")))??;

    let close_reason = choose_close_reason(up.reason, down.reason);

    Ok(RelayStats {
        bytes_up: up.bytes,
        bytes_down: down.bytes,
        close_reason,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TaskStats {
    bytes: u64,
    reason: RelayCloseReason,
}

fn choose_close_reason(up: RelayCloseReason, down: RelayCloseReason) -> RelayCloseReason {
    if up == RelayCloseReason::IdleTimeout || down == RelayCloseReason::IdleTimeout {
        RelayCloseReason::IdleTimeout
    } else if up == RelayCloseReason::UpstreamEof {
        RelayCloseReason::UpstreamEof
    } else {
        down
    }
}
