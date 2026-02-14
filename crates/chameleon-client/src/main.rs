use clap::{Parser, Subcommand};
use chameleon_core::config;
use chameleon_core::crypto;
use chameleon_core::protocol::{ConnectRequest, ConnectResponse, STATUS_OK};
use chameleon_core::relay;
use chameleon_core::transport;
use chameleon_core::{Error, Result};
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::net::{TcpListener, TcpStream};
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

    let listener = TcpListener::bind(listen).await.map_err(Error::Io)?;
    info!("client listening on {}", listen);

    loop {
        let (socket, peer) = listener.accept().await.map_err(Error::Io)?;
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_client(socket, cfg).await {
                warn!("client connection {} error: {}", peer, err);
            }
        });
    }
}

async fn handle_client(mut local: TcpStream, cfg: config::ClientConfig) -> Result<()> {
    let target = socks5::handshake(&mut local).await?;
    info!("SOCKS5 connect {}:{}", target.host, target.port);

    let mut bridge = transport::connect(cfg.transport, &cfg.bridge_addr).await?;
    let server_pub = crypto::decode_key_b64(&cfg.server_pubkey_b64)?;
    let noise = crypto::client_handshake(&mut bridge, &server_pub, cfg.max_frame).await?;
    info!("noise handshake ok");

    let req = ConnectRequest {
        host: target.host.clone(),
        port: target.port,
    };
    let payload = req.encode()?;
    noise.write_frame(&mut bridge, &payload).await?;

    let resp_bytes = noise.read_frame(&mut bridge).await?;
    let resp = ConnectResponse::decode(&resp_bytes)?;
    if resp.status != STATUS_OK {
        socks5::reply(&mut local, false).await?;
        return Err(Error::Protocol(format!(
            "bridge отказал: status={} code={}",
            resp.status, resp.error_code
        )));
    }

    socks5::reply(&mut local, true).await?;
    info!("relay start {}:{}", target.host, target.port);

    relay::relay_plain_and_noise(local, bridge, noise).await?;
    Ok(())
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
            return Err(Error::Protocol("only CONNECT supported".into()));
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
                let mut name = vec![0u8; len[0] as usize];
                stream.read_exact(&mut name).await.map_err(Error::Io)?;
                String::from_utf8(name)
                    .map_err(|_| Error::Protocol("invalid domain".into()))?
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

        Ok(Target { host, port })
    }

    pub async fn reply(stream: &mut TcpStream, success: bool) -> Result<()> {
        let status = if success { 0x00 } else { 0x01 };
        let mut resp = vec![0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        stream.write_all(&mut resp).await.map_err(Error::Io)?;
        Ok(())
    }
}
