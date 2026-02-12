use chameleon_core::allowlist::AllowList;
use chameleon_core::config::{load_bridge, load_client, AppConfig};
use chameleon_core::crypto::{client_handshake, decode_key_b64, generate_keypair_b64, server_handshake};
use chameleon_core::framing::{read_frame, write_frame};
use chameleon_core::protocol::{ConnectRequest, ConnectResponse, ERR_NOT_ALLOWED, STATUS_ERR, STATUS_OK};
use std::fs;
use tokio::io::duplex;
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn framing_roundtrip() {
    let (mut a, mut b) = duplex(1024);
    let payload = b"hello";
    tokio::spawn(async move {
        write_frame(&mut a, payload).await.unwrap();
    });
    let out = read_frame(&mut b, 1024).await.unwrap();
    assert_eq!(out, payload);
}

#[tokio::test]
async fn noise_handshake_roundtrip() {
    let (priv_b64, pub_b64) = generate_keypair_b64().unwrap();
    let server_priv = decode_key_b64(&priv_b64).unwrap();
    let server_pub = decode_key_b64(&pub_b64).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let noise = server_handshake(&mut sock, &server_priv, 1024).await.unwrap();
        let data = noise.read_frame(&mut sock).await.unwrap();
        noise.write_frame(&mut sock, &data).await.unwrap();
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    let noise = client_handshake(&mut client, &server_pub, 1024).await.unwrap();
    noise.write_frame(&mut client, b"ping").await.unwrap();
    let out = noise.read_frame(&mut client).await.unwrap();
    assert_eq!(out, b"ping");

    server.await.unwrap();
}

#[tokio::test]
async fn allowlist_checks() {
    let allow = AllowList::new(
        false,
        vec!["127.0.0.0/8".into()],
        vec!["example.com".into()],
    )
    .unwrap();

    assert!(allow.allows("example.com").await.unwrap());
    assert!(allow.allows("sub.example.com").await.unwrap());
    assert!(allow.allows("127.0.0.1").await.unwrap());
    assert!(!allow.allows("example.net").await.unwrap());
}

#[test]
fn protocol_roundtrip() {
    let req = ConnectRequest {
        host: "example.com".into(),
        port: 443,
    };
    let enc = req.encode().unwrap();
    let dec = ConnectRequest::decode(&enc).unwrap();
    assert_eq!(dec.host, "example.com");
    assert_eq!(dec.port, 443);

    let resp = ConnectResponse::err(ERR_NOT_ALLOWED);
    let enc = resp.encode();
    let dec = ConnectResponse::decode(&enc).unwrap();
    assert_eq!(dec.status, STATUS_ERR);
    assert_eq!(dec.error_code, ERR_NOT_ALLOWED);
    let ok = ConnectResponse::ok();
    assert_eq!(ok.status, STATUS_OK);
}

#[test]
fn config_parse() {
    let toml = r#"
[client]
listen = "127.0.0.1:1080"
bridge_addr = "127.0.0.1:443"
server_pubkey_b64 = "AAAA"
transport = "raw"
max_frame = 65535

[bridge]
listen = "0.0.0.0:443"
server_privkey_b64 = "BBBB"
transport = "raw"
allow_all = false
allow_cidrs = ["127.0.0.0/8"]
allow_domains = ["example.com"]
max_frame = 65535
"#;
    let cfg: AppConfig = toml::from_str(toml).unwrap();
    assert!(cfg.client.is_some());
    assert!(cfg.bridge.is_some());

    let path = std::env::temp_dir().join("chameleon-test.toml");
    fs::write(&path, toml).unwrap();
    let client = load_client(&path).unwrap();
    assert_eq!(client.listen, "127.0.0.1:1080");
    let bridge = load_bridge(&path).unwrap();
    assert_eq!(bridge.listen, "0.0.0.0:443");
}
