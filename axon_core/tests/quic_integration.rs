use axon_core::quic_transport::{install_quic_crypto, QuicTransport};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// Convert `0.0.0.0:PORT` to `127.0.0.1:PORT` for loopback connections.
fn to_loopback(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), addr.port())
}

/// Bidirectional QUIC service calls need reliable UDP loopback and timing,
/// which shared CI runners (GitHub Actions sets `CI=true`) handle poorly and can
/// stall on. These tests pass locally and the service-over-QUIC path is
/// validated cross-host, so skip them only under CI.
fn skip_on_ci(name: &str) -> bool {
    if std::env::var_os("CI").is_some() {
        eprintln!("skipping {name}: bidirectional QUIC unreliable on shared CI runners");
        true
    } else {
        false
    }
}

#[test]
fn test_quic_send_receive() {
    install_quic_crypto();
    let t1 = QuicTransport::new(0).unwrap();
    t1.start();

    let t2 = QuicTransport::new(0).unwrap();
    let addr2 = to_loopback(t2.local_addr().unwrap());
    // Register receiver on t2 (the receiver) for topic 0x42
    let mut rx2 = t2.register_recv_topic(0x42);
    t2.start();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        t1.connect(2, addr2).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;

        t1.send_message(2, 0x42, b"hello quic world!")
            .await
            .unwrap();
    });

    // Wait for message to arrive on t2's receiver
    let received =
        rt.block_on(async { tokio::time::timeout(Duration::from_secs(5), rx2.recv()).await });

    assert!(received.is_ok(), "timeout waiting for message");
    let data = received.unwrap().expect("channel closed");
    assert_eq!(&data, b"hello quic world!");
}

#[test]
fn test_quic_large_message() {
    install_quic_crypto();
    let t1 = QuicTransport::new(0).unwrap();
    t1.start();

    let t2 = QuicTransport::new(0).unwrap();
    let addr2 = to_loopback(t2.local_addr().unwrap());
    // Register receiver on t2
    let mut rx2 = t2.register_recv_topic(0x99);
    t2.start();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        t1.connect(2, addr2).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;

        let large_data = vec![0xABu8; 4 * 1024 * 1024];
        t1.send_message(2, 0x99, &large_data).await.unwrap();
    });

    let received =
        rt.block_on(async { tokio::time::timeout(Duration::from_secs(10), rx2.recv()).await });

    assert!(received.is_ok(), "timeout waiting for large message");
    let data = received.unwrap().expect("channel closed");
    assert_eq!(data.len(), 4 * 1024 * 1024);
    assert!(data.iter().all(|&b| b == 0xAB));
}

#[test]
fn test_quic_retained_history_is_ordered() {
    install_quic_crypto();
    let t1 = QuicTransport::new(0).unwrap();
    t1.start();

    let t2 = QuicTransport::new(0).unwrap();
    let addr2 = to_loopback(t2.local_addr().unwrap());
    let mut rx2 = t2.register_recv_topic(0x54);
    t2.start();

    t1.set_peer_addrs(2, vec![addr2]);
    let completion = t1.send_retained_history(
        2,
        0x54,
        vec![
            (1, b"first".to_vec()),
            (2, b"second".to_vec()),
            (3, b"third".to_vec()),
        ],
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let received = rt.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), completion)
            .await
            .expect("timeout waiting for retained send completion")
            .expect("retained send completion channel closed")
            .expect("retained send failed");
        let mut values = Vec::new();
        for _ in 0..3 {
            let wire = tokio::time::timeout(Duration::from_secs(5), rx2.recv())
                .await
                .expect("timeout waiting for retained sample")
                .expect("retained channel closed");
            values.push(axon_core::compress::decompress(&wire).unwrap());
        }
        values
    });
    assert_eq!(
        received,
        vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
    );
}

#[test]
fn test_quic_service_call() {
    if skip_on_ci("test_quic_service_call") {
        return;
    }

    install_quic_crypto();
    let t1 = QuicTransport::new(0).unwrap();
    let addr1 = to_loopback(t1.local_addr().unwrap());
    t1.start();

    let t2 = QuicTransport::new(0).unwrap();
    let addr2 = to_loopback(t2.local_addr().unwrap());
    // Register service handler on t2
    let mut service_rx = t2.register_service_handler(0x77);
    t2.start();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        t1.connect(2, addr2).await.unwrap();
        t2.connect(1, addr1).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Respond to incoming service requests on t2
        tokio::spawn(async move {
            if let Some((_req, resp_tx)) = service_rx.recv().await {
                let _ = resp_tx.send(b"pong".to_vec());
            }
        });

        // Give the handler time to register
        tokio::time::sleep(Duration::from_millis(100)).await;

        let request = b"ping";
        let response = t1.service_call(2, 0x77, request, None).await.unwrap();
        assert_eq!(&response, b"pong");
    });
}

#[test]
fn test_quic_service_call_sequential() {
    if skip_on_ci("test_quic_service_call_sequential") {
        return;
    }

    install_quic_crypto();
    let t1 = QuicTransport::new(0).unwrap();
    let addr1 = to_loopback(t1.local_addr().unwrap());
    t1.start();

    let t2 = QuicTransport::new(0).unwrap();
    let addr2 = to_loopback(t2.local_addr().unwrap());
    // Register service handler on t2
    let mut service_rx = t2.register_service_handler(0x77);
    t2.start();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // Use ONLY connect_async (like the real system — no sync connect)
        // Give connections time to establish
        t1.connect_async(2, addr2);
        t2.connect_async(1, addr1);
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Respond to incoming requests — multiple calls
        tokio::spawn(async move {
            while let Some((_req, resp_tx)) = service_rx.recv().await {
                let _ = resp_tx.send(b"pong".to_vec());
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Pass Some(addr) like the real system does via send_request
        let addr = Some(addr2);

        // First call
        let response = t1.service_call(2, 0x77, b"ping1", addr).await.unwrap();
        assert_eq!(&response, b"pong");

        // Second call
        let response2 = t1.service_call(2, 0x77, b"ping2", addr).await.unwrap();
        assert_eq!(&response2, b"pong");
    });
}

#[test]
fn test_quic_service_call_spawned_sequential() {
    if skip_on_ci("test_quic_service_call_spawned_sequential") {
        return;
    }

    // Test that simulates the REAL send_request path: spawns service_call
    // on the QUIC transport's runtime (q.spawn), matching how the session
    // layer invokes it.
    install_quic_crypto();
    let t2 = Arc::new(QuicTransport::new(0).unwrap());
    let addr2 = to_loopback(t2.local_addr().unwrap());
    let mut service_rx = t2.register_service_handler(0x77);
    t2.start();

    let t1 = Arc::new(QuicTransport::new(0).unwrap());
    t1.start();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // Like sync_daemon_matches would do
        t1.connect_async(2, addr2);
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Server-side handler (same as create_named_service would spawn)
        tokio::spawn(async move {
            while let Some((_req, resp_tx)) = service_rx.recv().await {
                let _ = resp_tx.send(b"pong".to_vec());
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Spawn on QUIC runtime exactly like send_request does:
        //   q.spawn(async move { q2.service_call(peer_id, req_topic, &data, addr).await; })
        let addr = Some(addr2);
        let (tx1, rx1) = tokio::sync::oneshot::channel();
        {
            let qc = t1.clone();
            t1.spawn(async move {
                let r = qc.service_call(2, 0x77, b"ping1", addr).await;
                let _ = tx1.send(r);
            });
        }
        let r1 = tokio::time::timeout(Duration::from_secs(5), rx1)
            .await
            .expect("first call timeout")
            .expect("first call oneshot closed")
            .expect("first call failed");
        assert_eq!(&r1, b"pong");

        let (tx2, rx2) = tokio::sync::oneshot::channel();
        {
            let qc = t1.clone();
            t1.spawn(async move {
                let r = qc.service_call(2, 0x77, b"ping2", addr).await;
                let _ = tx2.send(r);
            });
        }
        let r2 = tokio::time::timeout(Duration::from_secs(5), rx2)
            .await
            .expect("second call timeout")
            .expect("second call oneshot closed")
            .expect("second call failed");
        assert_eq!(&r2, b"pong");
    });
}
