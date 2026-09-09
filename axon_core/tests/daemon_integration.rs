use std::io::{Read, Write};
use std::net::TcpStream;
use std::ops::{Deref, DerefMut};
use std::process::{Child, Command};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use axon_core::daemon::discovery_shm::{ShmDiscovery, SHM_NAME};
use axon_core::session::Session;
use axon_core::types::{fxhash, QosProfile};

const DAEMON_BASE_PORT: u16 = 17402;
const RETRY_ATTEMPTS: u32 = 50;
const RETRY_INTERVAL_MS: u64 = 100;
static DAEMON_TEST_LOCK: Mutex<()> = Mutex::new(());

struct DaemonGuard {
    child: Option<Child>,
    pid_file: String,
    _test_lock: MutexGuard<'static, ()>,
}

impl DaemonGuard {
    fn start() -> Self {
        let test_lock = DAEMON_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let pid_file = format!("/tmp/axon_daemon_test_{}.pid", std::process::id());
        let _ = std::fs::remove_file(&pid_file);
        let _ = ShmDiscovery::destroy(SHM_NAME);

        let daemon_path = env!("CARGO_BIN_EXE_axon_daemon");
        let mut child = Command::new(daemon_path)
            .arg("--foreground")
            .arg("--port")
            .arg(daemon_port().to_string())
            .arg("--pid-file")
            .arg(&pid_file)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("failed to start daemon");

        for _ in 0..RETRY_ATTEMPTS {
            if let Ok(Some(status)) = child.try_wait() {
                panic!("daemon exited before ready: {status}");
            }
            let shm_ready = ShmDiscovery::open(SHM_NAME).is_ok();
            let tcp_ready = TcpStream::connect(format!("127.0.0.1:{}", daemon_port())).is_ok();
            if shm_ready && tcp_ready {
                return DaemonGuard {
                    child: Some(child),
                    pid_file,
                    _test_lock: test_lock,
                };
            }
            std::thread::sleep(Duration::from_millis(RETRY_INTERVAL_MS));
        }

        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "daemon not ready after {} ms",
            RETRY_ATTEMPTS as u64 * RETRY_INTERVAL_MS
        );
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_file(&self.pid_file);
        let _ = ShmDiscovery::destroy(SHM_NAME);
    }
}

impl Deref for DaemonGuard {
    type Target = Child;
    fn deref(&self) -> &Child {
        self.child.as_ref().unwrap()
    }
}

impl DerefMut for DaemonGuard {
    fn deref_mut(&mut self) -> &mut Child {
        self.child.as_mut().unwrap()
    }
}

fn daemon_port() -> u16 {
    DAEMON_BASE_PORT
}

fn send_xmlrpc(port: u16, body: &[u8]) -> String {
    for _ in 0..RETRY_ATTEMPTS {
        let result = (|| -> Result<String, Box<dyn std::error::Error>> {
            let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))?;
            stream.set_read_timeout(Some(Duration::from_secs(2)))?;
            let http_req = format!(
                "POST /RPC2 HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: text/xml\r\nContent-Length: {}\r\n\r\n",
                port, body.len()
            );
            let mut req = http_req.into_bytes();
            req.extend_from_slice(body);
            stream.write_all(&req)?;
            let mut resp = Vec::new();
            stream.read_to_end(&mut resp)?;
            let body = match resp.windows(4).position(|w| w == b"\r\n\r\n") {
                Some(pos) => resp[pos + 4..].to_vec(),
                None => resp,
            };
            Ok(String::from_utf8(body)?)
        })();
        if let Ok(xml) = result {
            return xml;
        }
        std::thread::sleep(Duration::from_millis(RETRY_INTERVAL_MS));
    }
    panic!(
        "daemon not ready after {} ms",
        RETRY_ATTEMPTS as u64 * RETRY_INTERVAL_MS
    );
}
fn assert_valid_response(xml: &str) {
    assert!(
        xml.starts_with("<?xml"),
        "expected XML declaration, got: {:.80}",
        xml
    );
    assert!(
        xml.contains("</methodResponse>"),
        "expected </methodResponse>, got: {:.80}",
        xml
    );
}

#[test]
fn test_daemon_responds_to_node_names() {
    let _daemon = DaemonGuard::start();
    let port = daemon_port();

    let request = br#"<?xml version="1.0"?>
<methodCall>
  <methodName>get_node_names</methodName>
</methodCall>"#;

    let s = send_xmlrpc(port, request);
    assert_valid_response(&s);
    assert!(
        s.contains("<name>name</name>"),
        "expected name field in node info"
    );
    assert!(
        s.contains("<name>namespace</name>"),
        "expected namespace field in node info"
    );
}

#[test]
fn test_daemon_responds_to_topic_names_and_types() {
    let _domain_id = 201u64;
    let _daemon = DaemonGuard::start();
    let port = daemon_port();

    let request = br#"<?xml version="1.0"?>
<methodCall>
  <methodName>get_topic_names_and_types</methodName>
  <params>
    <param><value><boolean>0</boolean></value></param>
  </params>
</methodCall>"#;

    let s = send_xmlrpc(port, request);
    assert_valid_response(&s);
}

#[test]
fn test_daemon_responds_to_service_names_and_types() {
    let _domain_id = 202u64;
    let _daemon = DaemonGuard::start();
    let port = daemon_port();

    let request = br#"<?xml version="1.0"?>
<methodCall>
  <methodName>get_service_names_and_types</methodName>
</methodCall>"#;

    let s = send_xmlrpc(port, request);
    assert_valid_response(&s);
}

#[test]
fn test_daemon_returns_fault_for_unknown_method() {
    let _domain_id = 203u64;
    let _daemon = DaemonGuard::start();
    let port = daemon_port();

    let request = br#"<?xml version="1.0"?>
<methodCall>
  <methodName>nonexistent_method</methodName>
</methodCall>"#;

    let s = send_xmlrpc(port, request);
    assert_valid_response(&s);
    assert!(
        s.contains("unknown method"),
        "expected fault response containing 'unknown method', got: {:.80}",
        s
    );
}

#[test]
fn test_daemon_responds_to_publishers_info() {
    let _domain_id = 204u64;
    let _daemon = DaemonGuard::start();
    let port = daemon_port();

    let request = br#"<?xml version="1.0"?>
<methodCall>
  <methodName>get_publishers_info_by_topic</methodName>
  <params>
    <param><value><string>/chatter</string></value></param>
  </params>
</methodCall>"#;

    let s = send_xmlrpc(port, request);
    assert_valid_response(&s);
}

#[test]
fn test_daemon_discovers_topics_from_two_nodes() {
    let domain_id = 205u64;
    let _daemon = DaemonGuard::start();
    let first = Session::with_quic(0x20501, 0, domain_id as u32).unwrap();
    let second = Session::with_quic(0x20502, 0, domain_id as u32).unwrap();
    first.set_node_name("camera_node", "/sensors");
    second.set_node_name("control_node", "/robot");

    let qos = QosProfile::default_sensor();
    first
        .create_publisher(
            "/camera/image_raw",
            "sensor_msgs/msg/Image",
            fxhash("/camera/image_raw"),
            &qos,
        )
        .unwrap();
    second
        .create_publisher(
            "/robot/status",
            "std_msgs/msg/String",
            fxhash("/robot/status"),
            &qos,
        )
        .unwrap();

    std::thread::sleep(Duration::from_millis(2500));
    let topics_request = br#"<?xml version="1.0"?>
<methodCall>
  <methodName>get_topic_names_and_types</methodName>
  <params><param><value><boolean>0</boolean></value></param></params>
</methodCall>"#;
    let topics = send_xmlrpc(daemon_port(), topics_request);
    assert_valid_response(&topics);

    let nodes_request = br#"<?xml version="1.0"?>
<methodCall><methodName>get_node_names</methodName></methodCall>"#;
    let nodes = send_xmlrpc(daemon_port(), nodes_request);
    assert_valid_response(&nodes);
    assert!(nodes.contains("<name>name</name>"), "{nodes}");
    assert!(nodes.contains("<name>namespace</name>"), "{nodes}");
}

#[test]
fn test_daemon_creates_shm_segment() {
    let _domain_id = 210u64;
    let _daemon = DaemonGuard::start();
    std::thread::sleep(Duration::from_millis(1500));

    // Verify daemon created the SHM segment
    let shm = ShmDiscovery::open(SHM_NAME).expect("daemon should create SHM");
    assert_eq!(shm.header().magic, 0x41584441);
    assert!(shm.header().daemon_pid > 0);
    assert!(std::path::Path::new(&format!("/proc/{}", shm.header().daemon_pid)).exists());
}

#[test]
fn test_daemon_shm_node_registration() {
    let domain_id = 211u64;
    let _daemon = DaemonGuard::start();
    std::thread::sleep(Duration::from_millis(1500));

    // Start a node with QUIC transport — this registers with daemon via SHM
    let _node = axon_core::session::Session::with_quic(0x21101, 0, domain_id as u32)
        .expect("session with quic");

    std::thread::sleep(Duration::from_millis(500));

    // Verify the node appears in SHM
    let shm = ShmDiscovery::open(SHM_NAME).expect("open SHM");
    let slot = shm
        .find_slot_by_node_id(0x21101)
        .expect("node should be registered in SHM");
    let entry = &shm.node_table()[slot];
    assert_eq!(entry.node_id, 0x21101);
    assert_eq!(entry.domain_id, domain_id as u32);
    let state = entry.state.load(std::sync::atomic::Ordering::Acquire);
    assert_eq!(state, 2, "node should be Active");

    // Verify XML-RPC still works (daemon still handles graph queries)
    let port = daemon_port();
    let request = br#"<?xml version="1.0"?>
<methodCall><methodName>get_node_names</methodName></methodCall>"#;
    let resp = send_xmlrpc(port, request);
    assert!(resp.contains("</methodResponse>"));
}

#[test]
fn test_daemon_shm_multiple_nodes() {
    let domain_id = 212u64;
    let _daemon = DaemonGuard::start();
    std::thread::sleep(Duration::from_millis(1500));

    let _node1 =
        axon_core::session::Session::with_quic(0x21201, 0, domain_id as u32).expect("node1");
    let _node2 =
        axon_core::session::Session::with_quic(0x21202, 0, domain_id as u32).expect("node2");

    std::thread::sleep(Duration::from_millis(500));

    let shm = ShmDiscovery::open(SHM_NAME).expect("open SHM");
    let slot1 = shm.find_slot_by_node_id(0x21201).expect("node1 reg");
    let slot2 = shm.find_slot_by_node_id(0x21202).expect("node2 reg");
    assert_ne!(slot1, slot2, "nodes should be in different slots");
}
