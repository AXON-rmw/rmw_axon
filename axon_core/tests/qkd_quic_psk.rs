use axon_core::qkd::{QkdKeyMaterial, QkdKeyStore};
use axon_core::quic_transport::{configure_client_for_daemon, install_quic_crypto, QuicTransport};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

fn loopback(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
}

struct QkdEnvironment {
    kme_server: Option<JoinHandle<()>>,
}

impl QkdEnvironment {
    fn new() -> (Self, QkdKeyStore) {
        std::env::set_var("AXON_SECURITY_MODE", "qkd");
        std::env::set_var("AXON_QUIC_CIPHER", "chacha20");
        let (kme_url, kme_server) = spawn_mock_kme(4);
        std::env::set_var("AXON_QKD_KME_BASE_URL", kme_url);
        std::env::set_var("AXON_QKD_LOCAL_SAE_ID", "sae-local");
        std::env::set_var("AXON_QKD_ALLOW_INSECURE_HTTP", "1");
        let _ = QkdKeyStore::destroy();
        let store = QkdKeyStore::create("sae-local").unwrap();
        (
            Self {
                kme_server: Some(kme_server),
            },
            store,
        )
    }
}

impl Drop for QkdEnvironment {
    fn drop(&mut self) {
        if let Some(server) = self.kme_server.take() {
            let _ = server.join();
        }
        let _ = QkdKeyStore::destroy();
        std::env::remove_var("AXON_SECURITY_MODE");
        std::env::remove_var("AXON_QUIC_CIPHER");
        std::env::remove_var("AXON_QKD_KME_BASE_URL");
        std::env::remove_var("AXON_QKD_LOCAL_SAE_ID");
        std::env::remove_var("AXON_QKD_ALLOW_INSECURE_HTTP");
    }
}

/// A tiny ETSI QKD 014-shaped server used to exercise one fresh key request
/// for each outgoing message and its matching `dec_keys` request.
fn spawn_mock_kme(expected_requests: usize) -> (String, JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let issued = Arc::new(Mutex::new(HashMap::<String, [u8; 32]>::new()));
    let next_id = Arc::new(AtomicUsize::new(1));
    let handle = std::thread::spawn({
        let issued = issued.clone();
        let next_id = next_id.clone();
        move || {
            let deadline = Instant::now() + Duration::from_secs(20);
            let mut served = 0;
            while served < expected_requests && Instant::now() < deadline {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => break,
                };
                let mut request = [0u8; 4096];
                let count = match stream.read(&mut request) {
                    Ok(count) => count,
                    Err(_) => continue,
                };
                let first_line = String::from_utf8_lossy(&request[..count]);
                let path = first_line
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or_default();
                let (key_id, key) = if path.contains("/enc_keys") {
                    let id = format!("message-key-{}", next_id.fetch_add(1, Ordering::Relaxed));
                    let mut key = [0u8; 32];
                    key.fill((id.len() as u8).wrapping_add(0x40));
                    issued.lock().unwrap().insert(id.clone(), key);
                    (id, key)
                } else {
                    let id = path
                        .split("key_ID=")
                        .nth(1)
                        .and_then(|value| value.split('&').next())
                        .unwrap_or_default()
                        .to_string();
                    let key = issued.lock().unwrap().get(&id).copied().unwrap_or([0; 32]);
                    (id, key)
                };
                let body = format!(
                    "{{\"keys\":[{{\"key_ID\":\"{key_id}\",\"key\":\"{}\"}}]}}",
                    BASE64.encode(key)
                );
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.flush();
                served += 1;
            }
        }
    });
    (format!("http://{addr}/api/v1/keys"), handle)
}

fn assert_qkd_roundtrip(remote_daemon_id: u64, topic_hash: u64, payload: &'static [u8]) {
    let sender = QuicTransport::new(0).unwrap();
    sender.set_peer_daemon(remote_daemon_id, remote_daemon_id);
    sender.start();

    let receiver = QuicTransport::new(0).unwrap();
    let mut messages = receiver.register_recv_topic(topic_hash);
    let receiver_addr = loopback(receiver.local_addr().unwrap());
    receiver.start();

    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        sender
            .connect(remote_daemon_id, receiver_addr)
            .await
            .unwrap();
        sender
            .send_message(remote_daemon_id, topic_hash, payload)
            .await
            .unwrap();
    });

    let received = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), messages.recv())
            .await
            .unwrap()
            .unwrap()
    });
    assert_eq!(received, payload);
}

#[test]
fn qkd_external_psk_establishes_quic_without_a_key_share() {
    install_quic_crypto();
    let (_environment, store) = QkdEnvironment::new();
    let error = configure_client_for_daemon(Some(999))
        .expect_err("QKD must not construct a client config without a KME key");
    assert!(error.contains("no QKD key"), "unexpected error: {error}");

    let material = QkdKeyMaterial {
        key_id: "qkd-quic-test-key".into(),
        key: [0x6a; 32],
    };
    store.put(2, "sae-peer", &material, true).unwrap();

    assert_qkd_roundtrip(2, 0x514b44, b"protected by QKD TLS PSK");

    let client_with_original_key = configure_client_for_daemon(Some(2)).unwrap();
    let conflicting_material = QkdKeyMaterial {
        key_id: material.key_id.clone(),
        key: [0x35; 32],
    };
    store
        .put(2, "sae-peer", &conflicting_material, true)
        .unwrap();

    let rejecting_server = QuicTransport::new(0).unwrap();
    let rejecting_addr = loopback(rejecting_server.local_addr().unwrap());
    rejecting_server.start();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let connecting = endpoint
            .connect_with(client_with_original_key, rejecting_addr, "axon")
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), connecting)
            .await
            .expect("mismatched QKD handshake timed out");
        assert!(
            result.is_err(),
            "TLS accepted different QKD key material for the same key ID"
        );
    });

    std::env::set_var("AXON_QUIC_CIPHER", "aes256");
    store
        .put(
            3,
            "sae-peer-aes",
            &QkdKeyMaterial {
                key_id: "qkd-quic-aes256-key".into(),
                key: [0x91; 32],
            },
            true,
        )
        .unwrap();
    assert_qkd_roundtrip(3, 0x414553, b"QKD with AES-256-GCM");
}
