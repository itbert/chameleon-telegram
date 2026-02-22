use clap::{Parser, Subcommand};
use chameleon_core::config;
use chameleon_core::crypto;
use chameleon_core::protocol::{
    error_code_name, AuthRequest, AuthResponse, ConnectRequest, ConnectResponse, STATUS_OK,
};
use chameleon_core::relay;
use chameleon_core::transport;
use chameleon_core::{Error, Result};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Run { config } => run(config).await,
    }
}

async fn run(path: PathBuf) -> Result<()> {
    let cfg = config::load_client(path)?;
    let listen: SocketAddr = cfg
        .listen
        .parse()
        .map_err(|e| Error::Config(format!("invalid listen address: {e}")))?;
    let auth_psk = Arc::new(crypto::decode_optional_b64(&cfg.auth_psk_b64)?);

    let listener = TcpListener::bind(listen).await.map_err(Error::Io)?;
    info!(listen = %listen, "client listening");

    let active = Arc::new(AtomicUsize::new(0));
    let conn_seq = Arc::new(AtomicU64::new(1));
    let shutdown_grace = cfg.shutdown_grace();

    let shutdown = wait_shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutdown signal received; stop accepting new connections");
                break;
            }
            accept_res = listener.accept() => {
                let (socket, peer) = match accept_res {
                    Ok(v) => v,
                    Err(err) => {
                        warn!("accept error: {}", err);
                        continue;
                    }
                };
                let cfg = cfg.clone();
                let auth_psk = auth_psk.clone();
                let active = active.clone();
                let conn_id = conn_seq.fetch_add(1, Ordering::Relaxed);
                active.fetch_add(1, Ordering::Relaxed);

                tokio::spawn(async move {
                    let started = Instant::now();
                    let result = handle_client(conn_id, peer, socket, cfg, auth_psk).await;
                    let duration_ms = started.elapsed().as_millis() as u64;
                    match result {
                        Ok(()) => info!(conn_id, peer = %peer, duration_ms, "connection closed"),
                        Err(err) => warn!(conn_id, peer = %peer, duration_ms, error = %err, "connection failed"),
                    }
                    active.fetch_sub(1, Ordering::Relaxed);
                });
            }
        }
    }

    wait_for_active_connections(active, shutdown_grace).await;
    Ok(())
}

async fn handle_client(
    conn_id: u64,
    peer: SocketAddr,
    mut local: TcpStream,
    cfg: config::ClientConfig,
    auth_psk: Arc<Vec<u8>>,
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

async fn wait_for_active_connections(active: Arc<AtomicUsize>, grace: std::time::Duration) {
    let started = Instant::now();
    loop {
        let value = active.load(Ordering::Relaxed);
        if value == 0 {
            info!("all active connections drained");
            return;
        }
        if started.elapsed() >= grace {
            warn!(active_connections = value, "shutdown grace timeout reached");
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
