use chameleon_core::allowlist::{is_private_or_special, AllowList, HostDecision, HostPolicy};
use chameleon_core::config::{load_bridge, load_client, AppConfig};
use chameleon_core::crypto::{client_handshake, decode_key_b64, generate_keypair_b64, server_handshake};
use chameleon_core::framing::{read_frame, write_frame};
use chameleon_core::protocol::{
    error_code_name, AuthRequest, AuthResponse, ConnectRequest, ConnectResponse,
    ERR_AUTH_FAILED, ERR_AUTH_REQUIRED, ERR_NOT_ALLOWED, STATUS_ERR, STATUS_OK,
};
use chameleon_core::relay::{relay_plain_and_noise, RelayCloseReason};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
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
async fn allowlist_policy_checks() {
    let allow = AllowList::new(
        false,
        vec!["127.0.0.0/8".into(), "10.0.0.0/8".into()],
        vec!["example.com".into()],
    )
    .unwrap();

    let decision = allow
        .evaluate(
            "example.com",
            HostPolicy {
                deny_private_targets: false,
                allow_loopback_targets: false,
            },
        )
        .await
        .unwrap();
    assert_eq!(decision, HostDecision::Allowed);

    let decision = allow
        .evaluate(
            "127.0.0.1",
            HostPolicy {
                deny_private_targets: true,
                allow_loopback_targets: false,
            },
        )
        .await
        .unwrap();
    assert_eq!(decision, HostDecision::DeniedPrivate);

    let decision = allow
        .evaluate(
            "127.0.0.1",
            HostPolicy {
                deny_private_targets: true,
                allow_loopback_targets: true,
            },
        )
        .await
        .unwrap();
    assert_eq!(decision, HostDecision::Allowed);

    assert!(is_private_or_special(
        "10.10.10.10".parse::<IpAddr>().unwrap(),
        false
    ));
    assert!(!is_private_or_special(
        "1.1.1.1".parse::<IpAddr>().unwrap(),
        false
    ));
}

#[tokio::test]
async fn relay_idle_timeout() {
    let (bridge_priv_b64, bridge_pub_b64) = generate_keypair_b64().unwrap();
    let bridge_priv = decode_key_b64(&bridge_priv_b64).unwrap();
    let bridge_pub = decode_key_b64(&bridge_pub_b64).unwrap();

    let plain_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let plain_addr = plain_listener.local_addr().unwrap();
    let plain_client_task = tokio::spawn(async move { TcpStream::connect(plain_addr).await.unwrap() });
    let (plain_server, _) = plain_listener.accept().await.unwrap();
    let plain_client = plain_client_task.await.unwrap();

    let noise_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let noise_addr = noise_listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut sock, _) = noise_listener.accept().await.unwrap();
        server_handshake(&mut sock, &bridge_priv, 4096).await.unwrap();
        sock
    });

    let mut noise_client = TcpStream::connect(noise_addr).await.unwrap();
    let relay_noise = client_handshake(&mut noise_client, &bridge_pub, 4096)
        .await
        .unwrap();
    let noise_peer = server.await.unwrap();

    let _keep_plain = plain_client;
    let _keep_noise_peer = noise_peer;

    let stats = relay_plain_and_noise(
        plain_server,
        noise_client,
        relay_noise,
        Duration::from_millis(50),
    )
    .await
    .unwrap();
    assert_eq!(stats.close_reason, RelayCloseReason::IdleTimeout);
    assert_eq!(stats.bytes_up, 0);
    assert_eq!(stats.bytes_down, 0);
}

#[tokio::test]
async fn auth_exchange_success_and_failure() {
    let (bridge_priv_b64, bridge_pub_b64) = generate_keypair_b64().unwrap();
    let bridge_priv = decode_key_b64(&bridge_priv_b64).unwrap();
    let bridge_pub = decode_key_b64(&bridge_pub_b64).unwrap();

    let expected_psk = b"psk-value".to_vec();
    let (addr_ok, bridge_task_ok) =
        spawn_mock_bridge(bridge_priv.clone(), expected_psk.clone(), true).await;

    let mut client_ok = TcpStream::connect(addr_ok).await.unwrap();
    let noise_ok = client_handshake(&mut client_ok, &bridge_pub, 4096)
        .await
        .unwrap();
    let auth_ok = AuthRequest {
        token: expected_psk.clone(),
    }
    .encode()
    .unwrap();
    noise_ok.write_frame(&mut client_ok, &auth_ok).await.unwrap();
    let auth_resp = AuthResponse::decode(&noise_ok.read_frame(&mut client_ok).await.unwrap()).unwrap();
    assert_eq!(auth_resp.status, STATUS_OK);

    let req = ConnectRequest {
        host: "example.com".into(),
        port: 443,
    }
    .encode()
    .unwrap();
    noise_ok.write_frame(&mut client_ok, &req).await.unwrap();
    let resp = ConnectResponse::decode(&noise_ok.read_frame(&mut client_ok).await.unwrap()).unwrap();
    assert_eq!(resp.status, STATUS_OK);
    bridge_task_ok.await.unwrap();

    let (addr_bad, bridge_task_bad) =
        spawn_mock_bridge(bridge_priv.clone(), expected_psk.clone(), true).await;
    let mut client_bad = TcpStream::connect(addr_bad).await.unwrap();
    let noise_bad = client_handshake(&mut client_bad, &bridge_pub, 4096)
        .await
        .unwrap();
    let auth_bad = AuthRequest {
        token: b"wrong".to_vec(),
    }
    .encode()
    .unwrap();
    noise_bad.write_frame(&mut client_bad, &auth_bad).await.unwrap();
    let auth_resp_bad =
        AuthResponse::decode(&noise_bad.read_frame(&mut client_bad).await.unwrap()).unwrap();
    assert_eq!(auth_resp_bad.status, STATUS_ERR);
    assert_eq!(auth_resp_bad.error_code, ERR_AUTH_FAILED);
    bridge_task_bad.await.unwrap();

    let (addr_empty, bridge_task_empty) = spawn_mock_bridge(bridge_priv, expected_psk, true).await;
    let mut client_empty = TcpStream::connect(addr_empty).await.unwrap();
    let noise_empty = client_handshake(&mut client_empty, &bridge_pub, 4096)
        .await
        .unwrap();
    let auth_empty = AuthRequest { token: vec![] }.encode().unwrap();
    noise_empty
        .write_frame(&mut client_empty, &auth_empty)
        .await
        .unwrap();
    let auth_resp_empty =
        AuthResponse::decode(&noise_empty.read_frame(&mut client_empty).await.unwrap()).unwrap();
    assert_eq!(auth_resp_empty.status, STATUS_ERR);
    assert_eq!(auth_resp_empty.error_code, ERR_AUTH_REQUIRED);
    bridge_task_empty.await.unwrap();
}

#[test]
fn protocol_roundtrip() {
    let auth = AuthRequest {
        token: b"secret".to_vec(),
    };
    let auth_enc = auth.encode().unwrap();
    let auth_dec = AuthRequest::decode(&auth_enc).unwrap();
    assert_eq!(auth_dec.token, b"secret");

    let auth_resp = AuthResponse::err(ERR_AUTH_FAILED);
    let auth_resp_enc = auth_resp.encode();
    let auth_resp_dec = AuthResponse::decode(&auth_resp_enc).unwrap();
    assert_eq!(auth_resp_dec.status, STATUS_ERR);
    assert_eq!(auth_resp_dec.error_code, ERR_AUTH_FAILED);

    let req = ConnectRequest {
        host: "example.com".into(),
        port: 443,
    };
    let enc = req.encode().unwrap();
    let dec = ConnectRequest::decode(&enc).unwrap();
    assert_eq!(dec.host, "example.com");
    assert_eq!(dec.port, 443);
    let mut bad = enc.clone();
    bad.push(0);
    assert!(ConnectRequest::decode(&bad).is_err());

    let resp = ConnectResponse::err(ERR_NOT_ALLOWED);
    let enc = resp.encode();
    let dec = ConnectResponse::decode(&enc).unwrap();
    assert_eq!(dec.status, STATUS_ERR);
    assert_eq!(dec.error_code, ERR_NOT_ALLOWED);
    let ok = ConnectResponse::ok();
    assert_eq!(ok.status, STATUS_OK);

    assert_eq!(error_code_name(ERR_AUTH_FAILED), "auth_failed");
}

#[test]
fn config_parse_backward_compatible_and_defaults() {
    let old_toml = r#"
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
    let cfg: AppConfig = toml::from_str(old_toml).unwrap();
    assert!(cfg.client.is_some());
    assert!(cfg.bridge.is_some());

    let path = std::env::temp_dir().join("chameleon-test-old.toml");
    fs::write(&path, old_toml).unwrap();
    let client = load_client(&path).unwrap();
    assert_eq!(client.handshake_timeout_ms, 5000);
    assert_eq!(client.connect_timeout_ms, 8000);
    assert_eq!(client.relay_idle_timeout_ms, 60000);
    assert_eq!(client.web_ui_addr, "127.0.0.1:7777");
    assert!(client.web_ui_enabled);
    assert!(client.web_ui_auth_token.is_empty());
    let bridge = load_bridge(&path).unwrap();
    assert_eq!(bridge.max_connections, 10000);
    assert!(bridge.deny_private_targets);
}

#[test]
fn config_invalid_values_rejected() {
    let invalid = r#"
[bridge]
listen = "0.0.0.0:443"
server_privkey_b64 = "BBBB"
transport = "raw"
allow_all = false
max_frame = 65535
require_auth = true
auth_psk_b64 = ""
"#;

    let path = std::env::temp_dir().join("chameleon-test-invalid.toml");
    fs::write(&path, invalid).unwrap();
    assert!(load_bridge(&path).is_err());
}

#[test]
fn config_rejects_non_loopback_web_ui() {
    let invalid = r#"
[client]
listen = "127.0.0.1:1080"
bridge_addr = "127.0.0.1:443"
server_pubkey_b64 = "AAAA"
transport = "raw"
max_frame = 65535
web_ui_enabled = true
web_ui_addr = "0.0.0.0:7777"
"#;
    let path = std::env::temp_dir().join("chameleon-test-webui.toml");
    std::fs::write(&path, invalid).unwrap();
    assert!(load_client(&path).is_err());
}

async fn spawn_mock_bridge(
    server_priv: Vec<u8>,
    expected_psk: Vec<u8>,
    require_auth: bool,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let noise = server_handshake(&mut socket, &server_priv, 4096)
            .await
            .unwrap();

        let auth_bytes = noise.read_frame(&mut socket).await.unwrap();
        let auth = AuthRequest::decode(&auth_bytes).unwrap();
        let auth_resp = if require_auth && auth.token.is_empty() {
            AuthResponse::err(ERR_AUTH_REQUIRED)
        } else if !expected_psk.is_empty() && auth.token != expected_psk {
            AuthResponse::err(ERR_AUTH_FAILED)
        } else {
            AuthResponse::ok()
        };
        noise
            .write_frame(&mut socket, &auth_resp.encode())
            .await
            .unwrap();
        if auth_resp.status != STATUS_OK {
            return;
        }

        let req_bytes = noise.read_frame(&mut socket).await.unwrap();
        let req = ConnectRequest::decode(&req_bytes).unwrap();
        let resp = if req.host == "example.com" && req.port == 443 {
            ConnectResponse::ok()
        } else {
            ConnectResponse::err(ERR_NOT_ALLOWED)
        };
        noise.write_frame(&mut socket, &resp.encode()).await.unwrap();
    });
    (addr, handle)
}
