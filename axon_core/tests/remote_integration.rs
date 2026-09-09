mod session_tests {
    use axon_core::session::Session;
    use axon_core::types::{fxhash, Durability, HistoryKind, Liveliness, QosProfile, Reliability};
    use std::collections::HashMap;

    #[test]
    fn test_counters_with_pubsub() {
        let session = Session::new(1, 0);
        let topic = "/test_counters";
        let topic_hash = fxhash(topic);

        session
            .create_publisher("topic", "", topic_hash, &QosProfile::default_sensor())
            .unwrap();
        assert_eq!(session.count_publishers(topic), 1);
        assert_eq!(session.count_subscribers(topic), 0);

        let _sub =
            session.create_subscription("topic", "", topic_hash, &QosProfile::default_sensor());
        assert_eq!(session.count_publishers(topic), 1);
        assert_eq!(session.count_subscribers(topic), 1);
    }

    #[test]
    fn test_service_availability() {
        let session = Session::new(1, 0);
        let service_name = "/test_service";
        let service_id = fxhash(service_name);

        assert!(!session.service_available(service_name));

        session
            .create_service(
                service_id,
                "test_srv/srv/Empty",
                &QosProfile::default_command(),
            )
            .unwrap();
        // Service is stored with hex(service_id) as name
        let stored_name = format!("{:x}", service_id);
        assert!(session.service_available(&stored_name));
    }

    #[test]
    fn test_loaned_message_roundtrip() {
        let session = Session::new(2, 0);
        let topic = "/test_loaned";
        let topic_hash = fxhash(topic);

        // Create publisher (creates SHM)
        session
            .create_publisher("topic", "", topic_hash, &QosProfile::default_sensor())
            .unwrap();

        // Publish a message via normal publish to get a sequence number
        let data = b"hello";
        let seq = session.publish(topic_hash, data).unwrap();

        // Create subscription (opens existing SHM)
        let _sub =
            session.create_subscription("topic", "", topic_hash, &QosProfile::default_sensor());

        // Take loaned message using the sequence number
        let (ptr, size) = session.take_loaned(topic_hash, seq).unwrap();
        let received = unsafe { std::slice::from_raw_parts(ptr, size) };
        assert_eq!(received, b"hello");

        // Return the loaned message
        session.return_loaned(topic_hash, ptr, size);
    }

    #[test]
    fn test_content_filter_set_get() {
        let session = Session::new(3, 0);
        let topic = "/test_filter";
        let name = "my_filter";
        let expression = "x > 5";

        session.set_content_filter(topic, name, expression, HashMap::new());

        let filter = session.get_content_filter(topic).unwrap();
        assert_eq!(filter.name, name);
        assert_eq!(filter.expression, expression);
    }

    #[test]
    fn test_qos_profiles() {
        let session = Session::new(4, 0);
        let topic = "/test_qos";
        let topic_hash = fxhash(topic);
        let qos = QosProfile {
            reliability: Reliability::Reliable,
            durability: Durability::TransientLocal,
            history: HistoryKind::KeepLast { depth: 10 },
            bandwidth_limit: None,
            max_message_size: 65536,
            deadline: None,
            lifespan: None,
            liveliness: Liveliness::Automatic,
            liveliness_lease_duration: None,
        };

        session
            .create_publisher(topic, "", topic_hash, &qos)
            .unwrap();
        let pub_qos = session.publisher_actual_qos(topic).unwrap();
        assert_eq!(pub_qos.reliability, Reliability::Reliable);
        assert_eq!(pub_qos.durability, Durability::TransientLocal);

        let _sub = session.create_subscription(topic, "", topic_hash, &qos);
        let sub_qos = session.subscription_actual_qos(topic).unwrap();
        assert_eq!(sub_qos.reliability, Reliability::Reliable);
    }

    #[test]
    fn test_by_node_queries() {
        let session = Session::new(5, 0);
        let topic = "/topic1";
        let topic_hash = fxhash(topic);

        session
            .create_publisher("topic", "", topic_hash, &QosProfile::default_sensor())
            .unwrap();

        // Query by the session's own node name
        let node_name = format!("node_{}", session.node_id);
        let pubs = session.get_publishers_by_node(&node_name, "");
        assert_eq!(pubs.len(), 1);
    }

    #[test]
    fn test_borrow_commit_loaned() {
        let topic = "/test_borrow";
        let topic_hash = fxhash(topic);
        // Clean any stale SHM segment from a previous run
        let _ = std::fs::remove_file(format!("/dev/shm/axon_domain_{}_topic_{}", 0, topic_hash));

        let session = Session::new(6, 0);

        session
            .create_publisher("topic", "", topic_hash, &QosProfile::default_sensor())
            .unwrap();

        // Borrow a buffer, write data, commit
        let (ptr, _max_size) = session.borrow_loaned(topic_hash, 64).unwrap();
        let write_size = 5;
        unsafe {
            std::ptr::copy_nonoverlapping(b"hello".as_ptr(), ptr, write_size);
        }
        assert!(session.commit_loaned(topic_hash, ptr, write_size));

        // Create subscription and take the message
        let _sub =
            session.create_subscription("topic", "", topic_hash, &QosProfile::default_sensor());
        let mut buf = vec![0u8; 64];
        let n = session.receive(topic_hash, 0, &mut buf).unwrap();
        assert_eq!(n, write_size);
        assert_eq!(&buf[..n], b"hello");
    }

    #[test]
    fn test_matched_counts() {
        let session = Session::new(7, 0);
        let topic = "/test_matched";
        let topic_hash = fxhash(topic);

        session
            .create_publisher("topic", "", topic_hash, &QosProfile::default_sensor())
            .unwrap();
        assert_eq!(session.count_matched_publishers(topic), 1);
        assert_eq!(session.count_matched_subscriptions(topic), 0);

        let _sub =
            session.create_subscription("topic", "", topic_hash, &QosProfile::default_sensor());
        assert_eq!(session.count_matched_publishers(topic), 1);
        assert_eq!(session.count_matched_subscriptions(topic), 1);
    }

    #[test]
    fn test_service_client_counts() {
        let session = Session::new(8, 0);
        let service_name = "/test_counts";
        let service_id = fxhash(service_name);
        let stored_name = format!("{:x}", service_id);

        assert_eq!(session.count_services(&stored_name), 0);

        session
            .create_service(service_id, "test_type", &QosProfile::default_command())
            .unwrap();
        assert_eq!(session.count_services(&stored_name), 1);

        // create_client also registers in local_services, so count increases
        session
            .create_client(service_id, "test_type", &QosProfile::default_command())
            .unwrap();
        assert!(session.count_services(&stored_name) >= 1);
    }

    #[test]
    fn test_get_topic_names_and_types() {
        let session = Session::new(9, 0);
        let topic = "/test_names";
        let topic_hash = fxhash(topic);

        session
            .create_publisher("topic", "", topic_hash, &QosProfile::default_sensor())
            .unwrap();
        let names = session.get_topic_names();
        assert!(!names.is_empty());

        let names_and_types = session.get_topic_names_and_types();
        assert!(!names_and_types.is_empty());
    }
}

#[test]
#[ignore = "requires an isolated live daemon and fixed cross-session timing"]
fn test_cross_session_large_message() {
    use axon_core::session::Session;
    use axon_core::types::fxhash;
    use std::time::Duration;

    let domain_id = 9999;
    let topic = "/cross_session_large";
    let topic_hash = fxhash(topic);

    // Publisher session
    let pub_session = Session::with_quic(100, 0, domain_id).unwrap();
    use axon_core::types::QosProfile;

    pub_session
        .create_publisher(
            topic,
            "sensor_msgs/msg/Image",
            topic_hash,
            &QosProfile::default_sensor(),
        )
        .unwrap();

    // Subscriber session
    let sub_session = Session::with_quic(200, 0, domain_id).unwrap();
    let sub_handle = sub_session
        .create_subscription(
            topic,
            "sensor_msgs/msg/Image",
            topic_hash,
            &QosProfile::default_sensor(),
        )
        .unwrap();

    // Wait for discovery (HELLO interval = 100ms)
    std::thread::sleep(Duration::from_millis(600));

    // Publish large message
    let large_data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
    let seq = pub_session.publish(topic_hash, &large_data).unwrap();
    eprintln!("Published seq={}, len={}", seq, large_data.len());

    // Wait for UDP delivery
    std::thread::sleep(Duration::from_millis(300));

    // Check eventfd
    let efd = sub_handle.eventfd;
    {
        let mut fds = [unsafe { std::mem::zeroed::<libc::pollfd>() }];
        fds[0].fd = efd;
        fds[0].events = libc::POLLIN;
        let poll_ret = unsafe { libc::poll(fds.as_mut_ptr(), 1, 100) };
        eprintln!("poll returned {}, revents={:#x}", poll_ret, fds[0].revents);
        if poll_ret > 0 {
            let mut val: u64 = 0;
            unsafe {
                libc::read(efd, &mut val as *mut _ as *mut libc::c_void, 8);
            }
        }
    }

    // receive_next with small buffer
    let seq_inout = sub_handle.initial_seq;
    let mut small_buf = [0u8; 65536];

    match sub_session.receive_next(topic_hash, seq_inout, &mut small_buf) {
        Ok((size, actual_seq)) => {
            eprintln!("Direct success: size={}, seq={}", size, actual_seq);
            assert_eq!(size, large_data.len());
            assert_eq!(&small_buf[..size], &large_data[..]);
        }
        Err(e) => {
            eprintln!("First receive failed: {}", e);
            let (size, actual_seq) = sub_session
                .peek_next_message_size(topic_hash, seq_inout)
                .expect("peek should succeed");
            eprintln!("Peek: size={}, seq={}", size, actual_seq);
            let mut big_buf = vec![0u8; size];
            let (got_size, _) = sub_session
                .receive_next(topic_hash, actual_seq, &mut big_buf)
                .expect("retry should succeed");
            assert_eq!(got_size, large_data.len());
            assert_eq!(&big_buf[..got_size], &large_data[..]);
        }
    }
}

#[test]
fn test_zstd_decompress_payload() {
    use axon_core::compress::{compress, decompress};
    let data = b"Hello, AXON with Zstd compression! Test of roundtrip.";

    let compressed = compress(&data[..]);
    let result = decompress(&compressed);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), &data[..]);
}

#[test]
fn test_zstd_large_payload_roundtrip() {
    use axon_core::compress::{compress, decompress};
    let data: Vec<u8> = (0..65536).map(|i| (i % 128) as u8).collect();

    let compressed = compress(&data);
    let decompressed = decompress(&compressed);
    assert!(decompressed.is_some());
    assert_eq!(decompressed.unwrap().len(), data.len());
}
