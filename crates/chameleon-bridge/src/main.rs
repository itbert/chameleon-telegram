use clap::{Parser, Subcommand};
use chameleon_core::allowlist::AllowList;
use chameleon_core::config;
use chameleon_core::crypto;
use chameleon_core::protocol::{ConnectRequest, ConnectResponse, ERR_CONNECT_FAIL, ERR_NOT_ALLOWED};
use chameleon_core::relay;
use chameleon_core::{Error, Result};
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::net::{TcpListener, TcpStream};
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

    let allowlist = AllowList::new(cfg.allow_all, cfg.allow_cidrs.clone(), cfg.allow_domains.clone())?;
    let server_priv = crypto::decode_key_b64(&cfg.server_privkey_b64)?;

    let listener = TcpListener::bind(listen).await.map_err(Error::Io)?;
    info!("bridge listening on {}", listen);

    loop {
        let (socket, peer) = listener.accept().await.map_err(Error::Io)?;
        let cfg = cfg.clone();
        let allowlist = allowlist.clone();
        let server_priv = server_priv.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_bridge(socket, cfg, server_priv, allowlist).await {
                warn!("bridge connection {} error: {}", peer, err);
            }
        });
    }
}

async fn handle_bridge(
    mut client: TcpStream,
    cfg: config::BridgeConfig,
    server_priv: Vec<u8>,
    allowlist: AllowList,
) -> Result<()> {
    let noise = crypto::server_handshake(&mut client, &server_priv, cfg.max_frame).await?;
    info!("noise handshake ok");

    let req_bytes = noise.read_frame(&mut client).await?;
    let req = ConnectRequest::decode(&req_bytes)?;
    info!("connect request {}:{}", req.host, req.port);

    if !allowlist.allows(&req.host).await? {
        let resp = ConnectResponse::err(ERR_NOT_ALLOWED);
        noise.write_frame(&mut client, &resp.encode()).await?;
        return Err(Error::Protocol("target not allowed".into()));
    }

    let target = match TcpStream::connect((req.host.as_str(), req.port)).await {
        Ok(sock) => sock,
        Err(err) => {
            let resp = ConnectResponse::err(ERR_CONNECT_FAIL);
            noise.write_frame(&mut client, &resp.encode()).await?;
            return Err(Error::Transport(format!("connect target failed: {err}")));
        }
    };

    let resp = ConnectResponse::ok();
    noise.write_frame(&mut client, &resp.encode()).await?;

    relay::relay_plain_and_noise(target, client, noise).await?;
    Ok(())
}
