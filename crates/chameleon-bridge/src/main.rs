use clap::{Parser, Subcommand};
use chameleon_core::allowlist::{normalize_host, AllowList, HostDecision, HostPolicy};
use chameleon_core::config;
use chameleon_core::crypto;
use chameleon_core::protocol::{
    error_code_name, AuthRequest, AuthResponse, ConnectRequest, ConnectResponse, ERR_AUTH_FAILED,
    ERR_AUTH_REQUIRED, ERR_CONNECT_FAIL, ERR_NOT_ALLOWED, ERR_TARGET_DENIED_PRIVATE, ERR_TIMEOUT,
};
use chameleon_core::relay::{self, RelayCloseReason, RelayStats};
use chameleon_core::{Error, Result};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout};
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "chameleon-bridge")]
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
    Keygen,
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
        Commands::Keygen => keygen(),
    }
}

fn keygen() -> Result<()> {
    let (priv_b64, pub_b64) = crypto::generate_keypair_b64()?;
    println!("server_privkey_b64={}", priv_b64);
    println!("server_pubkey_b64={}", pub_b64);
    Ok(())
}

async fn run(path: PathBuf) -> Result<()> {
    let cfg = config::load_bridge(path)?;
    let listen: SocketAddr = cfg
        .listen
        .parse()
        .map_err(|e| Error::Config(format!("invalid listen address: {e}")))?;

    let allowlist = Arc::new(AllowList::new(
        cfg.allow_all,
        cfg.allow_cidrs.clone(),
        cfg.allow_domains.clone(),
    )?);
    let server_priv = Arc::new(crypto::decode_key_b64(&cfg.server_privkey_b64)?);
    let expected_psk = Arc::new(crypto::decode_optional_b64(&cfg.auth_psk_b64)?);

    let listener = TcpListener::bind(listen).await.map_err(Error::Io)?;
    let max_connections = cfg.max_connections;
    let conn_limiter = Arc::new(Semaphore::new(max_connections));
    let next_conn_id = Arc::new(AtomicU64::new(1));

    info!(
        listen = %listen,
        max_connections,
        require_auth = cfg.require_auth,
        deny_private_targets = cfg.deny_private_targets,
        allow_loopback_targets = cfg.allow_loopback_targets,
        "bridge started"
    );

    let shutdown = wait_shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutdown signal received, stopping accept loop");
                break;
            }
            accept_result = listener.accept() => {
                let (socket, peer) = match accept_result {
                    Ok(v) => v,
                    Err(err) => {
                        warn!("accept error: {}", err);
                        continue;
                    }
                };

                let permit = match conn_limiter.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        warn!(peer = %peer, "max_connections reached, dropping connection");
                        continue;
                    }
                };

                let conn_id = next_conn_id.fetch_add(1, Ordering::Relaxed);
                let cfg = cfg.clone();
                let allowlist = allowlist.clone();
                let server_priv = server_priv.clone();
                let expected_psk = expected_psk.clone();

                tokio::spawn(async move {
                    let _permit = permit;
                    let started = Instant::now();
                    let result = handle_bridge(
                        conn_id,
                        peer,
                        socket,
                        cfg,
                        server_priv,
                        allowlist,
                        expected_psk,
                    )
                    .await;
                    let duration_ms = started.elapsed().as_millis() as u64;

                    match result {
                        Ok(stats) => {
                            info!(
                                conn_id,
                                peer = %peer,
                                bytes_up = stats.bytes_up,
                                bytes_down = stats.bytes_down,
                                close_reason = relay_close_reason_name(stats.close_reason),
                                duration_ms,
                                "session closed"
                            );
                        }
                        Err(err) => {
                            warn!(conn_id, peer = %peer, duration_ms, error = %err, "session failed");
                        }
                    }
                });
            }
        }
    }

    wait_for_drain(conn_limiter, max_connections, cfg.shutdown_grace()).await;
    info!("bridge shutdown complete");
    Ok(())
}

async fn handle_bridge(
    conn_id: u64,
    peer: SocketAddr,
    mut client: TcpStream,
    cfg: config::BridgeConfig,
    server_priv: Arc<Vec<u8>>,
    allowlist: Arc<AllowList>,
    expected_psk: Arc<Vec<u8>>,
) -> Result<RelayStats> {
    let noise = timeout(
        cfg.handshake_timeout(),
        crypto::server_handshake(&mut client, &server_priv, cfg.max_frame),
    )
    .await
    .map_err(|_| Error::Protocol("noise handshake timeout".into()))??;
    info!(conn_id, peer = %peer, "noise handshake ok");

    let auth_frame = timeout(cfg.handshake_timeout(), noise.read_frame(&mut client))
        .await
        .map_err(|_| Error::Protocol("auth read timeout".into()))??;
    let auth = AuthRequest::decode(&auth_frame)?;

    if cfg.require_auth && auth.token.is_empty() {
        let _ = send_auth_response(
            &noise,
            &mut client,
            AuthResponse::err(ERR_AUTH_REQUIRED),
            cfg.handshake_timeout(),
        )
        .await;
        warn!(conn_id, peer = %peer, auth_result = "missing_token", "auth failed");
        return Err(Error::Protocol("auth required".into()));
    }

    if !expected_psk.is_empty() && auth.token != *expected_psk {
        let _ = send_auth_response(
            &noise,
            &mut client,
            AuthResponse::err(ERR_AUTH_FAILED),
            cfg.handshake_timeout(),
        )
        .await;
        warn!(conn_id, peer = %peer, auth_result = "token_mismatch", "auth failed");
        return Err(Error::Protocol("invalid auth token".into()));
    }

    send_auth_response(&noise, &mut client, AuthResponse::ok(), cfg.handshake_timeout()).await?;
    info!(conn_id, peer = %peer, auth_result = "ok", "auth completed");

    let req_bytes = timeout(cfg.handshake_timeout(), noise.read_frame(&mut client))
        .await
        .map_err(|_| Error::Protocol("connect request timeout".into()))??;
    let req = ConnectRequest::decode(&req_bytes)?;
    let host = normalize_host(&req.host)?;

    let decision = timeout(
        cfg.target_connect_timeout(),
        allowlist.evaluate(
            &host,
            HostPolicy {
                deny_private_targets: cfg.deny_private_targets,
                allow_loopback_targets: cfg.allow_loopback_targets,
            },
        ),
    )
    .await
    .map_err(|_| Error::Allowlist("allowlist evaluation timeout".into()))??;

    match decision {
        HostDecision::Allowed => {}
        HostDecision::Denied => {
            let _ = send_connect_response(
                &noise,
                &mut client,
                ConnectResponse::err(ERR_NOT_ALLOWED),
                cfg.handshake_timeout(),
            )
            .await;
            return Err(Error::Protocol("target not allowed".into()));
        }
        HostDecision::DeniedPrivate => {
            let _ = send_connect_response(
                &noise,
                &mut client,
                ConnectResponse::err(ERR_TARGET_DENIED_PRIVATE),
                cfg.handshake_timeout(),
            )
            .await;
            return Err(Error::Protocol("target denied by private-ip policy".into()));
        }
    }

    info!(conn_id, peer = %peer, target_host = %host, target_port = req.port, "target allowed");

    let target = match timeout(
        cfg.target_connect_timeout(),
        TcpStream::connect((host.as_str(), req.port)),
    )
    .await
    {
        Err(_) => {
            let _ = send_connect_response(
                &noise,
                &mut client,
                ConnectResponse::err(ERR_TIMEOUT),
                cfg.handshake_timeout(),
            )
            .await;
            return Err(Error::Transport(format!(
                "target connect timeout {}:{}",
                host, req.port
            )));
        }
        Ok(Err(err)) => {
            let _ = send_connect_response(
                &noise,
                &mut client,
                ConnectResponse::err(ERR_CONNECT_FAIL),
                cfg.handshake_timeout(),
            )
            .await;
            return Err(Error::Transport(format!("connect target failed: {err}")));
        }
        Ok(Ok(sock)) => sock,
    };

    send_connect_response(
        &noise,
        &mut client,
        ConnectResponse::ok(),
        cfg.handshake_timeout(),
    )
    .await?;

    relay::relay_plain_and_noise(target, client, noise, cfg.relay_idle_timeout()).await
}

async fn send_auth_response(
    noise: &crypto::NoiseChannel,
    stream: &mut TcpStream,
    resp: AuthResponse,
    io_timeout: Duration,
) -> Result<()> {
    timeout(io_timeout, noise.write_frame(stream, &resp.encode()))
        .await
        .map_err(|_| {
            Error::Protocol(format!(
                "auth response timeout ({})",
                error_code_name(resp.error_code)
            ))
        })??;
    Ok(())
}

async fn send_connect_response(
    noise: &crypto::NoiseChannel,
    stream: &mut TcpStream,
    resp: ConnectResponse,
    io_timeout: Duration,
) -> Result<()> {
    timeout(io_timeout, noise.write_frame(stream, &resp.encode()))
        .await
        .map_err(|_| {
            Error::Protocol(format!(
                "connect response timeout ({})",
                error_code_name(resp.error_code)
            ))
        })??;
    Ok(())
}

async fn wait_for_drain(limiter: Arc<Semaphore>, max_connections: usize, grace: Duration) {
    let started = Instant::now();
    loop {
        let active = max_connections.saturating_sub(limiter.available_permits());
        if active == 0 {
            return;
        }
        if started.elapsed() >= grace {
            warn!(active_connections = active, "shutdown grace expired");
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }
}

fn relay_close_reason_name(reason: RelayCloseReason) -> &'static str {
    match reason {
        RelayCloseReason::UpstreamEof => "upstream_eof",
        RelayCloseReason::DownstreamEof => "downstream_eof",
        RelayCloseReason::IdleTimeout => "idle_timeout",
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
