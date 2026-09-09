pub mod events;
pub mod graph;
pub mod publish;
pub mod routing;
pub mod service;
pub mod subscribe;

// Submodules only add impl Session methods — no types to re-export

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

const SERVICE_REQUEST_PREFIX: &str = "__axon_service_request:";
const SERVICE_RESPONSE_PREFIX: &str = "__axon_service_response:";
const DAEMON_PID_FILE: &str = "/tmp/axon_daemon.pid";
const DAEMON_START_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Debug)]
pub(crate) struct GraphEventFd {
    pub original: i32,
    pub signal: i32,
}

impl Drop for GraphEventFd {
    fn drop(&mut self) {
        if self.signal >= 0 {
            let _ = unsafe { libc::close(self.signal) };
            self.signal = -1;
        }
    }
}

fn is_service_topic_metadata(name: &str) -> bool {
    name.starts_with(SERVICE_REQUEST_PREFIX) || name.starts_with(SERVICE_RESPONSE_PREFIX)
}

pub(crate) fn topic_message_capacity(topic_type: &str, configured: usize) -> usize {
    let type_capacity = match topic_type {
        "sensor_msgs/msg/Image" => 8 * 1024 * 1024,
        "sensor_msgs/msg/CompressedImage" => 4 * 1024 * 1024,
        "sensor_msgs/msg/PointCloud2" => 16 * 1024 * 1024,
        "nav_msgs/msg/OccupancyGrid" => 4 * 1024 * 1024,
        "nav2_msgs/msg/Costmap" => 16 * 1024 * 1024,
        "nav2_msgs/msg/VoxelGrid" => 16 * 1024 * 1024,
        "map_msgs/msg/OccupancyGridUpdate" => 4 * 1024 * 1024,
        "octomap_msgs/msg/Octomap" => 16 * 1024 * 1024,
        // RTAB-Map map messages carry variable-size graph data, descriptors,
        // compressed sensor payloads and sometimes raw images. The generic
        // 64KB default is too small and makes rtabmap abort on /mapData.
        "rtabmap_msgs/msg/MapData" => 64 * 1024 * 1024,
        "rtabmap_msgs/msg/SensorData" => 64 * 1024 * 1024,
        "rtabmap_msgs/msg/RGBDImage" => 64 * 1024 * 1024,
        "rtabmap_msgs/msg/Info" | "rtabmap_msgs/msg/OdomInfo" => 8 * 1024 * 1024,
        "rtabmap_msgs/msg/MapGraph" => 4 * 1024 * 1024,
        _ => configured,
    };
    std::env::var("AXON_MAX_MESSAGE_SIZE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(type_capacity)
        .max(configured)
}

pub(crate) fn topic_ring_depth(topic_name: &str, topic_type: &str, qos: &QosProfile) -> usize {
    match qos.history {
        HistoryKind::KeepAll => 256,
        HistoryKind::KeepLast { depth } => {
            let min_depth = if topic_name == "/clock" || topic_type == "rosgraph_msgs/msg/Clock" {
                // Gazebo Sim on Jazzy can publish /clock fast enough that a
                // KEEP_LAST(1) or KEEP_LAST(2) SHM ring is constantly
                // overwritten between rmw_wait() and rmw_take().
                64
            } else if topic_type == "sensor_msgs/msg/PointCloud2" {
                // Point clouds are commonly published as sensor data with
                // KEEP_LAST(1).  A single-slot queue is too brittle for large
                // frames over QUIC/WiFi or for slow CLI tools such as
                // `ros2 topic hz`, so keep a short real-time backlog.
                8
            } else {
                2
            };
            depth.clamp(min_depth, 4096)
        }
    }
}

/// Ensure the axon discovery daemon is running on this machine.
/// If not found, spawn it and wait for it to initialize.
fn ensure_daemon_running() -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    // A large launch starts many ROS processes concurrently. Without a
    // cross-process lock, several sessions can all observe "no daemon" and
    // terminate each other's just-spawned daemon before its SHM is ready.
    let lock_path = format!("/tmp/axon_daemon-{}.start.lock", unsafe { libc::geteuid() });
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(lock_path)?;
    let rc = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    ensure_daemon_running_locked()
}

fn ensure_daemon_running_locked() -> std::io::Result<()> {
    use crate::daemon::discovery_shm::{is_process_alive, ShmDiscovery, SHM_NAME};

    match open_live_daemon_shm(std::time::Duration::from_millis(0)) {
        Ok(shm) => {
            let pid = shm.header().daemon_pid;
            let st = shm.header().daemon_proc_starttime;
            if is_process_alive(pid, st) {
                return Ok(());
            }
            drop(shm);
            ShmDiscovery::destroy(SHM_NAME).ok();
            terminate_daemon_from_pid_file();
            terminate_orphan_daemon_processes();
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {
            if daemon_pid_file_process_alive() {
                if wait_for_live_daemon_shm(DAEMON_START_TIMEOUT)? {
                    return Ok(());
                }
                terminate_daemon_from_pid_file();
                ShmDiscovery::destroy(SHM_NAME).ok();
            }
            terminate_orphan_daemon_processes();
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::InvalidData => {
            if wait_for_live_daemon_shm(DAEMON_START_TIMEOUT)? {
                return Ok(());
            }
            ShmDiscovery::destroy(SHM_NAME).ok();
            terminate_daemon_from_pid_file();
            terminate_orphan_daemon_processes();
        }
        Err(e) => return Err(e),
    }

    let daemon_path = find_daemon_binary()?;

    let mut cmd = std::process::Command::new(&daemon_path);
    if let Ok(port) = std::env::var("AXON_DAEMON_PORT") {
        if !port.trim().is_empty() {
            cmd.arg("--port").arg(port.trim());
        }
    }
    if let Ok(pid_file) = std::env::var("AXON_DAEMON_PID_FILE") {
        if !pid_file.trim().is_empty() {
            cmd.arg("--pid-file").arg(pid_file.trim());
        }
    }
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| std::io::Error::other(format!("spawn daemon {}: {}", daemon_path, e)))?;

    let start = std::time::Instant::now();
    loop {
        if start.elapsed() >= DAEMON_START_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            let detail = format!("timed out (no SHM after {:?})", DAEMON_START_TIMEOUT);
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("daemon failed to start ({})", detail),
            ));
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stderr_buf = String::new();
                if let Some(ref mut stderr_pipe) = child.stderr {
                    let _ = std::io::Read::read_to_string(stderr_pipe, &mut stderr_buf);
                }
                if status.success() {
                    let remaining = DAEMON_START_TIMEOUT.saturating_sub(start.elapsed());
                    if wait_for_live_daemon_shm(remaining)? {
                        return Ok(());
                    }
                }
                if stderr_buf.contains("daemon already running") {
                    let remaining = DAEMON_START_TIMEOUT.saturating_sub(start.elapsed());
                    if wait_for_live_daemon_shm(remaining)? {
                        return Ok(());
                    }
                }
                return Err(std::io::Error::other(format!(
                    "daemon failed to start (exited with {}: {})",
                    status,
                    stderr_buf.trim()
                )));
            }
            Ok(None) => {}
            Err(_) => {}
        }

        if open_live_daemon_shm(std::time::Duration::from_millis(0)).is_ok() {
            // The daemon publishes SHM before all sockets are bound. Give
            // it a short stabilization window so a later bind failure
            // (common when another namespace already owns the daemon port)
            // is reported as a daemon startup error instead of as a stale
            // "daemon process is not alive" SHM connection failure.
            std::thread::sleep(std::time::Duration::from_millis(100));
            match child.try_wait() {
                Ok(Some(status)) => {
                    let mut stderr_buf = String::new();
                    if let Some(ref mut stderr_pipe) = child.stderr {
                        let _ = std::io::Read::read_to_string(stderr_pipe, &mut stderr_buf);
                    }
                    if status.success() {
                        return Ok(());
                    }
                    ShmDiscovery::destroy(SHM_NAME).ok();
                    if stderr_buf.contains("daemon already running") {
                        let remaining = DAEMON_START_TIMEOUT.saturating_sub(start.elapsed());
                        if wait_for_live_daemon_shm(remaining)? {
                            return Ok(());
                        }
                    }
                    return Err(std::io::Error::other(format!(
                        "daemon failed to start (exited with {}: {})",
                        status,
                        stderr_buf.trim()
                    )));
                }
                Ok(None) => return Ok(()),
                Err(_) => return Ok(()),
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

fn read_daemon_pid_file() -> Option<i32> {
    std::fs::read_to_string(DAEMON_PID_FILE)
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
        .filter(|pid| *pid > 0)
}

fn process_exists(pid: i32) -> bool {
    std::path::Path::new(&format!("/proc/{}", pid)).exists()
}

fn daemon_pid_file_process_alive() -> bool {
    read_daemon_pid_file().is_some_and(process_exists)
}

fn open_live_daemon_shm(
    timeout: std::time::Duration,
) -> std::io::Result<crate::daemon::discovery_shm::ShmDiscovery> {
    use crate::daemon::discovery_shm::{is_process_alive, ShmDiscovery, SHM_NAME};

    let start = std::time::Instant::now();
    loop {
        let current_err = match ShmDiscovery::open(SHM_NAME) {
            Ok(shm) => {
                let pid = shm.header().daemon_pid;
                let st = shm.header().daemon_proc_starttime;
                if is_process_alive(pid, st) {
                    return Ok(shm);
                }
                std::io::Error::new(std::io::ErrorKind::NotFound, "daemon process is not alive")
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.kind() == std::io::ErrorKind::InvalidData =>
            {
                std::io::Error::new(e.kind(), e.to_string())
            }
            Err(e) => return Err(e),
        };

        if start.elapsed() >= timeout {
            return Err(current_err);
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

fn wait_for_live_daemon_shm(timeout: std::time::Duration) -> std::io::Result<bool> {
    match open_live_daemon_shm(timeout) {
        Ok(_) => Ok(true),
        Err(ref e)
            if e.kind() == std::io::ErrorKind::NotFound
                || e.kind() == std::io::ErrorKind::InvalidData
                || e.kind() == std::io::ErrorKind::TimedOut =>
        {
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

fn terminate_daemon_from_pid_file() {
    let Some(pid) = read_daemon_pid_file() else {
        return;
    };

    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    let start = std::time::Instant::now();
    while process_exists(pid) && start.elapsed() < std::time::Duration::from_secs(1) {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    if process_exists(pid) {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }
    let _ = std::fs::remove_file(DAEMON_PID_FILE);
}

fn terminate_orphan_daemon_processes() {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return;
    };
    let current_pid = std::process::id() as i32;
    let current_uid = unsafe { libc::geteuid() };
    let mut pids = Vec::new();

    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        if pid <= 0 || pid == current_pid {
            continue;
        }

        let proc_dir = entry.path();
        let Ok(meta) = std::fs::metadata(&proc_dir) else {
            continue;
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.uid() != current_uid {
                continue;
            }
        }

        let comm = std::fs::read_to_string(proc_dir.join("comm")).unwrap_or_default();
        let exe_is_daemon = std::fs::read_link(proc_dir.join("exe"))
            .ok()
            .and_then(|path| path.file_name().map(|name| name == "axon_daemon"))
            .unwrap_or(false);
        let cmdline = std::fs::read(proc_dir.join("cmdline")).unwrap_or_default();
        let cmdline_args: Vec<String> = cmdline
            .split(|byte| *byte == 0)
            .filter(|arg| !arg.is_empty())
            .map(|arg| String::from_utf8_lossy(arg).to_string())
            .collect();
        let argv0_is_daemon = cmdline_args
            .first()
            .and_then(|arg| std::path::Path::new(arg).file_name())
            .map(|name| name == "axon_daemon")
            .unwrap_or(false);

        if comm.trim() != "axon_daemon" && !exe_is_daemon && !argv0_is_daemon {
            continue;
        }

        if let Some(pos) = cmdline_args.iter().position(|arg| arg == "--pid-file") {
            if cmdline_args.get(pos + 1).map(String::as_str) != Some(DAEMON_PID_FILE) {
                continue;
            }
        }

        pids.push(pid);
    }

    for pid in &pids {
        unsafe {
            libc::kill(*pid, libc::SIGTERM);
        }
    }

    let start = std::time::Instant::now();
    while start.elapsed() < std::time::Duration::from_secs(1) {
        if pids.iter().all(|pid| !process_exists(*pid)) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    for pid in pids {
        if process_exists(pid) {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
    }
}

fn find_daemon_binary() -> std::io::Result<String> {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_axon_daemon") {
        if std::path::Path::new(&path).exists() {
            return Ok(path);
        }
    }

    if let Ok(path) = std::env::var("AXON_DAEMON_PATH") {
        if std::path::Path::new(&path).exists() {
            return Ok(path);
        }
    }

    if let Some(lib_dir) = find_own_library_dir() {
        let lib_path = std::path::Path::new(&lib_dir);
        for candidate in &[
            lib_path.join("axon_daemon"),
            lib_path.join("../bin/axon_daemon"),
        ] {
            if candidate.exists() {
                return Ok(candidate.to_string_lossy().to_string());
            }
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("axon_daemon");
            if candidate.exists() {
                return Ok(candidate.to_string_lossy().to_string());
            }
        }
    }

    if let Ok(cwd) = std::env::current_dir() {
        for dir in &["target/release", "target/debug"] {
            let candidate = cwd.join(dir).join("axon_daemon");
            if candidate.exists() {
                return Ok(candidate.to_string_lossy().to_string());
            }
        }
    }

    if let Ok(paths) = std::env::var("PATH") {
        for dir in paths.split(':') {
            let candidate = std::path::Path::new(dir).join("axon_daemon");
            if candidate.exists() {
                return Ok(candidate.to_string_lossy().to_string());
            }
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "axon_daemon binary not found — set AXON_DAEMON_PATH or ensure it is installed with rmw_axon"
    ))
}

#[repr(C)]
#[derive(Copy, Clone)]
struct DlInfo {
    dli_fname: *const std::ffi::c_char,
    dli_fbase: *mut std::ffi::c_void,
    dli_sname: *const std::ffi::c_char,
    dli_saddr: *mut std::ffi::c_void,
}

extern "C" {
    fn dladdr(addr: *const std::ffi::c_void, info: *mut DlInfo) -> std::ffi::c_int;
}

fn dladdr_library_dir(fn_ptr: *const std::ffi::c_void) -> Option<String> {
    let mut info: DlInfo = unsafe { std::mem::zeroed() };
    let ret = unsafe { dladdr(fn_ptr, &mut info) };
    if ret == 0 || info.dli_fname.is_null() {
        return None;
    }
    let cstr = unsafe { std::ffi::CStr::from_ptr(info.dli_fname) };
    let path = cstr.to_string_lossy();
    std::path::Path::new(path.as_ref())
        .parent()
        .map(|p| p.to_string_lossy().to_string())
}

fn proc_maps_library_dir() -> Option<String> {
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    for line in maps.lines() {
        if line.contains("librmw_axon.so") || line.contains("libaxon_core") {
            if let Some(idx) = line.find('/') {
                let path = &line[idx..].trim_end();
                if let Some(parent) = std::path::Path::new(path).parent() {
                    return Some(parent.to_string_lossy().to_string());
                }
            }
        }
    }
    None
}

fn find_own_library_dir() -> Option<String> {
    if let Some(d) =
        dladdr_library_dir(crate::c_bridge::axon_session_create as *const std::ffi::c_void)
    {
        return Some(d);
    }
    if let Some(d) = proc_maps_library_dir() {
        return Some(d);
    }
    None
}

use crate::events::EventMonitor;
use crate::filter::ContentFilter;
use crate::local::LocalPubSub;
use crate::quic_transport::QuicTransport;
use crate::resource::LeakyBucket;
use crate::security::AclEngine;
use crate::types::{HistoryKind, NodeId, QosProfile, RemoteQos, ServiceId, TopicHash};

type RetainedRemoteSamples = HashMap<TopicHash, VecDeque<(u64, Vec<u8>)>>;

pub(crate) fn local_channel_name(domain_id: u32, topic_hash: TopicHash) -> String {
    format!("domain_{}_topic_{}", domain_id, topic_hash)
}

/// Collect all non-loopback local IP addresses (both IPv4 and IPv6).
fn collect_local_ips_non_loopback() -> Vec<std::net::IpAddr> {
    use std::sync::OnceLock;
    static LOCAL_IPS: OnceLock<Vec<std::net::IpAddr>> = OnceLock::new();
    LOCAL_IPS
        .get_or_init(|| {
            let mut ips = Vec::new();
            unsafe {
                let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
                if libc::getifaddrs(&mut ifap) == 0 {
                    let mut cur = ifap;
                    while !cur.is_null() {
                        let ifa = &*cur;
                        if !ifa.ifa_addr.is_null() {
                            let family = (*ifa.ifa_addr).sa_family as i32;
                            if family == libc::AF_INET || family == libc::AF_INET6 {
                                let ip = match family {
                                    libc::AF_INET => {
                                        let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                                        std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                                            sin.sin_addr.s_addr.to_ne_bytes(),
                                        ))
                                    }
                                    libc::AF_INET6 => {
                                        let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                                        std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                                            sin6.sin6_addr.s6_addr,
                                        ))
                                    }
                                    _ => unreachable!(),
                                };
                                if !ip.is_loopback() {
                                    ips.push(ip);
                                }
                            }
                        }
                        cur = (*cur).ifa_next;
                    }
                    libc::freeifaddrs(ifap);
                }
            }
            ips
        })
        .clone()
}

pub fn detect_local_ipv4s() -> Vec<[u8; 4]> {
    let mut addrs: Vec<[u8; 4]> = Vec::new();
    for addr in &collect_local_ips_non_loopback() {
        if let std::net::IpAddr::V4(ipv4) = addr {
            if !ipv4.is_unspecified() {
                addrs.push(ipv4.octets());
            }
        }
    }
    if addrs.is_empty() {
        addrs.push([127, 0, 0, 1]);
    }
    addrs
}

fn advertised_ipv4s() -> Vec<[u8; 4]> {
    let Ok(value) = std::env::var("AXON_ADVERTISE_ADDRS") else {
        return detect_local_ipv4s();
    };

    let mut addrs = Vec::new();
    for raw in value.split(',') {
        let candidate = raw.trim();
        if candidate.is_empty() {
            continue;
        }
        match candidate.parse::<std::net::Ipv4Addr>() {
            Ok(ip) if !ip.is_unspecified() => addrs.push(ip.octets()),
            _ => eprintln!("rmw_axon: ignoring invalid AXON_ADVERTISE_ADDRS entry '{candidate}'"),
        }
    }

    if addrs.is_empty() {
        detect_local_ipv4s()
    } else {
        addrs.truncate(crate::daemon::discovery_shm::MAX_QUIC_ADDRS);
        addrs
    }
}

use crate::graph_cache::GraphCache;

/// Information about a topic endpoint.
#[derive(Debug, Clone)]
pub struct TopicEndpointInfo {
    /// Node name owning the endpoint.
    pub node_name: String,
    /// Node namespace.
    pub node_namespace: String,
    /// Message type string.
    pub topic_type: String,
    /// Topic name.
    pub topic_name: String,
    /// Globally unique identifier.
    pub gid: [u8; 16],
    /// QoS profile.
    pub qos: QosProfile,
    /// Transport kind string.
    pub transport_kind: String,
}

/// Communication session managing pub/sub, services, and remote transport.
///
/// A `Session` owns all publishers, subscriptions, and service endpoints
/// for a single node. It handles local shared-memory communication and
/// optional remote QUIC transport with daemon-based discovery.
pub struct Session {
    /// Unique node identifier.
    pub node_id: NodeId,
    /// ROS domain ID for this session.
    pub domain_id: u32,
    /// Local publishers keyed by topic hash.
    publishers: Mutex<HashMap<TopicHash, Arc<LocalPubSub>>>,
    publisher_counts: Mutex<HashMap<TopicHash, usize>>,
    /// Local subscriptions keyed by topic hash.
    subscriptions: Mutex<HashMap<TopicHash, Arc<LocalPubSub>>>,
    subscription_counts: Mutex<HashMap<TopicHash, usize>>,
    /// Optional QUIC transport for data streams.
    pub quic_transport: Option<Arc<QuicTransport>>,
    /// Remote route table mapping topic hashes to peer addresses.
    pub remote_routes: Arc<Mutex<HashMap<TopicHash, Vec<SocketAddr>>>>,
    /// Service request subscriptions keyed by service ID.
    service_request_subs: Mutex<HashMap<ServiceId, Arc<LocalPubSub>>>,
    service_server_counts: Mutex<HashMap<ServiceId, usize>>,
    /// Service response publishers keyed by service ID.
    service_response_pubs: Mutex<HashMap<ServiceId, Arc<LocalPubSub>>>,
    /// Service request publishers keyed by service ID.
    service_request_pubs: Mutex<HashMap<ServiceId, Arc<LocalPubSub>>>,
    service_client_counts: Mutex<HashMap<ServiceId, usize>>,
    /// Service response subscriptions keyed by service ID.
    service_response_subs: Mutex<HashMap<ServiceId, Arc<LocalPubSub>>>,
    /// Monotonic per-session service request id returned to rcl/rclcpp.
    service_request_sequence: AtomicU64,
    /// Per-topic bandwidth rate limiters.
    publishers_budget: Mutex<HashMap<TopicHash, LeakyBucket>>,
    /// Access-control list engine.
    acl_engine: Mutex<AclEngine>,
    /// Cached graph state.
    graph_cache: GraphCache,
    /// Shared node name readable by the discovery background thread.
    node_name_shared: Arc<RwLock<String>>,
    /// Known node-to-address mapping.
    known_addrs: Arc<RwLock<HashMap<NodeId, SocketAddr>>>,
    /// Topics advertised to peers via discovery.
    published_topics: Arc<RwLock<Vec<TopicHash>>>,
    /// Subscriptions advertised to peers via discovery.
    subscribed_topics: Arc<RwLock<Vec<TopicHash>>>,
    /// Cache of topic hash → human-readable name, populated from discovery HELLOs.
    pub(crate) topic_name_cache: Arc<RwLock<HashMap<TopicHash, String>>>,
    /// Cache of topic hash → type string, populated from discovery HELLOs.
    pub(crate) topic_type_cache: Arc<RwLock<HashMap<TopicHash, String>>>,
    /// Cache of (node_id, topic_hash) → RemoteQos, populated from discovery
    /// HELLOs and local publisher/subscription creation.
    pub(crate) topic_qos_cache: Arc<RwLock<HashMap<(u64, TopicHash), RemoteQos>>>,
    /// Duplicated graph guard condition eventfds to trigger on topology changes.
    pub(crate) graph_event_fds: Arc<RwLock<Vec<GraphEventFd>>>,
    /// Event monitor for deadline/liveliness.
    event_monitor: Option<Arc<EventMonitor>>,
    event_monitor_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// Per-(topic, seq) publish timestamps for lifespan enforcement.
    message_timestamps: Mutex<HashMap<(TopicHash, u64), Instant>>,
    /// Content filters per topic.
    content_filters: Mutex<HashMap<TopicHash, ContentFilter>>,
    remote_recv_queues: Mutex<HashMap<TopicHash, Arc<crate::subscriber_queue::SubscriberQueue>>>,
    /// Serialized history retained for TRANSIENT_LOCAL late joiners and for
    /// reliable writers while their first remote match is being established.
    retained_remote_samples: Mutex<RetainedRemoteSamples>,
    /// Remote nodes that already received the retained history for a topic.
    retained_remote_peers: Arc<Mutex<HashMap<TopicHash, std::collections::HashSet<NodeId>>>>,
    /// Remote retained-history transfers currently running.
    retained_remote_pending: Arc<Mutex<HashMap<TopicHash, std::collections::HashSet<NodeId>>>>,
    /// Forces route synchronization to retry a retained-history transfer after
    /// an asynchronous QUIC failure, even when the daemon graph is unchanged.
    retained_remote_retry: Arc<AtomicBool>,
    /// Whether the first graph query has been made. When false, the first
    /// query waits briefly to let discovery populate remote topology.
    first_graph_query: AtomicBool,
    /// SHM connection to the local discovery daemon
    daemon_shm: Option<crate::daemon::discovery_shm::ShmDiscovery>,
    /// Slot index in the daemon's node table
    daemon_slot: usize,
    include_all_domains: bool,
    /// Last seen daemon response_gen for incremental match sync
    daemon_last_response_gen: AtomicU64,
    /// Stops background route synchronization as soon as the ROS context
    /// enters shutdown, before publishers and subscriptions are destroyed.
    shutdown_requested: AtomicBool,
}

impl Session {
    /// Create a local-only session.
    ///
    /// # Arguments
    /// * `node_id` - Unique node identifier
    pub fn new(node_id: NodeId, domain_id: u32) -> Self {
        let node_name = format!("node_{}", node_id);
        let node_name_shared = Arc::new(RwLock::new(node_name.clone()));
        let event_monitor = EventMonitor::new().map(Arc::new).ok();
        let event_monitor_thread = event_monitor.as_ref().map(|em| em.spawn_monitor());
        Self {
            node_id,
            domain_id,
            publishers: Mutex::new(HashMap::new()),
            publisher_counts: Mutex::new(HashMap::new()),
            subscriptions: Mutex::new(HashMap::new()),
            subscription_counts: Mutex::new(HashMap::new()),
            quic_transport: None,
            remote_routes: Arc::new(Mutex::new(HashMap::new())),
            service_request_subs: Mutex::new(HashMap::new()),
            service_server_counts: Mutex::new(HashMap::new()),
            service_response_pubs: Mutex::new(HashMap::new()),
            service_request_pubs: Mutex::new(HashMap::new()),
            service_client_counts: Mutex::new(HashMap::new()),
            service_response_subs: Mutex::new(HashMap::new()),
            service_request_sequence: AtomicU64::new(1),
            publishers_budget: Mutex::new(HashMap::new()),
            acl_engine: Mutex::new(AclEngine::from_env()),
            graph_cache: GraphCache::new(&node_name),
            node_name_shared,
            known_addrs: Arc::new(RwLock::new(HashMap::new())),
            published_topics: Arc::new(RwLock::new(Vec::new())),
            subscribed_topics: Arc::new(RwLock::new(Vec::new())),
            topic_name_cache: Arc::new(RwLock::new(HashMap::new())),
            topic_type_cache: Arc::new(RwLock::new(HashMap::new())),
            topic_qos_cache: Arc::new(RwLock::new(HashMap::new())),
            graph_event_fds: Arc::new(RwLock::new(Vec::new())),
            event_monitor,
            event_monitor_thread: Mutex::new(event_monitor_thread),
            message_timestamps: Mutex::new(HashMap::new()),
            content_filters: Mutex::new(HashMap::new()),
            remote_recv_queues: Mutex::new(HashMap::new()),
            retained_remote_samples: Mutex::new(HashMap::new()),
            retained_remote_peers: Arc::new(Mutex::new(HashMap::new())),
            retained_remote_pending: Arc::new(Mutex::new(HashMap::new())),
            retained_remote_retry: Arc::new(AtomicBool::new(false)),
            first_graph_query: AtomicBool::new(true),
            daemon_shm: None,
            daemon_slot: 0,
            include_all_domains: false,
            daemon_last_response_gen: AtomicU64::new(0),
            shutdown_requested: AtomicBool::new(false),
        }
    }

    /// Create a session with QUIC transport.
    ///
    /// # Arguments
    /// * `node_id` - Unique node identifier
    /// * `port` - QUIC listen port (0 for OS-assigned)
    ///
    /// # Returns
    /// `Ok(Session)` on success, or an I/O error if the QUIC endpoint cannot be created.
    pub fn with_quic(node_id: NodeId, port: u16, domain_id: u32) -> std::io::Result<Self> {
        use crate::daemon::discovery_shm::futex_wake;
        use crate::quic_transport::install_quic_crypto;

        // Reject invalid fail-closed profiles before waiting for a daemon
        // which will reject the same configuration and exit.
        crate::security::validate_pre_daemon_runtime()
            .map_err(|error| std::io::Error::other(format!("remote security setup: {error}")))?;

        // 1. Ensure daemon is running
        ensure_daemon_running()?;
        crate::security::validate_runtime()
            .map_err(|error| std::io::Error::other(format!("remote security setup: {error}")))?;

        // 2. Install crypto provider for rustls
        install_quic_crypto();

        // 3. Create QUIC transport
        let qt = QuicTransport::new(port)?;
        let quic_port = qt.local_addr().as_ref().map(|a| a.port()).unwrap_or(0);
        let quic_addrs = advertised_ipv4s();
        qt.start();

        // 3. Connect to daemon SHM. The daemon may have created the SHM name
        // before finishing header/table initialization, so wait for a live,
        // layout-compatible mapping instead of falling back to local-only mode.
        let shm = open_live_daemon_shm(DAEMON_START_TIMEOUT)
            .map_err(|e| std::io::Error::other(format!("shm connect: {}", e)))?;

        // 4. Find free slot and register
        let slot = shm
            .claim_free_slot()
            .ok_or_else(|| std::io::Error::other("no free slots in daemon"))?;

        {
            let entry = &mut shm.node_table_mut()[slot];
            entry.node_id = node_id;
            entry.domain_id = domain_id;
            entry.pid = std::process::id();
            entry.proc_starttime =
                crate::daemon::discovery_shm::read_proc_starttime(entry.pid).unwrap_or(0);
            entry.quic_port = quic_port;
            let count = quic_addrs
                .len()
                .min(crate::daemon::discovery_shm::MAX_QUIC_ADDRS);
            for (i, addr) in quic_addrs.iter().take(count).enumerate() {
                entry.quic_addrs[i] = *addr;
            }
            entry.quic_addr_count = count as u32;
            entry.pub_count = 0;
            entry.sub_count = 0;
            entry.match_count = 0;
            entry.last_seen_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            entry.state.store(1, std::sync::atomic::Ordering::Release); // Pending
        }

        // 5. Notify daemon
        shm.header()
            .generation
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        futex_wake(&shm.header().generation);

        // 6. Wait for daemon ack (poll response_gen)
        let wait_start = std::time::Instant::now();
        let entry = &mut shm.node_table_mut()[slot];
        while wait_start.elapsed() < std::time::Duration::from_secs(1) {
            let gen = entry
                .response_gen
                .load(std::sync::atomic::Ordering::Acquire);
            if gen != 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        let mut session = Self::new(node_id, domain_id);
        session.quic_transport = Some(Arc::new(qt));
        session.daemon_shm = Some(shm);
        session.daemon_slot = slot;
        session.sync_daemon_matches();
        Ok(session)
    }

    /// Assert liveliness for this node through the event monitor.
    pub fn assert_liveliness(&self) {
        if let Some(ref em) = self.event_monitor {
            em.assert_liveliness(self.node_id);
        }
    }

    pub fn request_shutdown(&self) {
        if self
            .shutdown_requested
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return;
        }
        if let Some(ref transport) = self.quic_transport {
            transport.shutdown();
        }
    }

    pub(crate) fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Signal all registered graph guard condition eventfds to notify the
    /// ROS 2 graph listener that topology has changed.
    pub(crate) fn signal_graph_eventfds(&self) {
        let mut fds = self.graph_event_fds.write().unwrap();
        if fds.is_empty() {
            return;
        }
        let val = 1u64.to_ne_bytes();
        fds.retain(|fd| {
            let ret =
                unsafe { libc::write(fd.signal, val.as_ptr() as *const libc::c_void, val.len()) };
            if ret == val.len() as libc::ssize_t {
                return true;
            }
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            matches!(errno, libc::EAGAIN | libc::EINTR)
        });
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(ref em) = self.event_monitor {
            em.shutdown();
        }
        if let Ok(mut handle) = self.event_monitor_thread.lock() {
            if let Some(handle) = handle.take() {
                let _ = handle.join();
            }
        }
        self.unregister_from_daemon();
    }
}

#[cfg(test)]
mod tests {
    use crate::make_gid;

    use super::*;
    use crate::events::EventKind;
    use crate::session::service::ServiceResponseTake;
    use crate::types::{
        fxhash, service_request_topic, service_response_topic, AclDirection, AuditDirection,
        Durability, HistoryKind,
    };
    use std::time::Duration;

    fn cleanup_domain_topic_shm(domain_id: u32, topic_hash: TopicHash) {
        let name = format!("/axon_{}", local_channel_name(domain_id, topic_hash));
        if let Ok(cname) = std::ffi::CString::new(name) {
            let _ = nix::sys::mman::shm_unlink(cname.as_c_str());
        }
    }

    fn cleanup_topic_shm(topic_hash: TopicHash) {
        cleanup_domain_topic_shm(0, topic_hash);
    }

    #[test]
    fn test_service_create_server_registers_topics() {
        let session = Session::new(500, 0);
        let qos = QosProfile::default_sensor();
        session.create_service(0x42, "test_type", &qos).unwrap();
        let res_topic = service_response_topic(0x42);
        let req_topic = service_request_topic(0x42);
        // Service internal topics should NOT pollute get_topic_names()
        let names = session.get_topic_names();
        assert!(
            names.is_empty(),
            "service topics should not appear in topic list"
        );
        // But they should still be in the internal graph cache
        let pubs = session.graph_cache.local_publishers.read().unwrap();
        assert!(
            pubs.contains_key(&res_topic),
            "response topic should be in graph cache"
        );
        let subs = session.graph_cache.local_subscriptions.read().unwrap();
        assert!(
            subs.contains_key(&req_topic),
            "request topic should be tracked as subscription"
        );
    }

    #[test]
    fn test_service_create_client_registers_topics() {
        let session = Session::new(501, 0);
        let qos = QosProfile::default_sensor();
        session.create_client(0x43, "test_type", &qos).unwrap();
        let req_topic = service_request_topic(0x43);
        let res_topic = service_response_topic(0x43);
        // Service internal topics should NOT pollute get_topic_names()
        let names = session.get_topic_names();
        assert!(
            names.is_empty(),
            "service topics should not appear in topic list"
        );
        // But they should still be in the internal graph cache
        let pubs = session.graph_cache.local_publishers.read().unwrap();
        assert!(
            pubs.contains_key(&req_topic),
            "request topic should be in graph cache"
        );
        let subs = session.graph_cache.local_subscriptions.read().unwrap();
        assert!(
            subs.contains_key(&res_topic),
            "response topic should be tracked as subscription"
        );
    }

    #[test]
    fn test_get_service_names_and_types_returns_expected() {
        let session = Session::new(101, 0);
        let qos = QosProfile::default_sensor();
        session.create_service(0x20, "test_type", &qos).unwrap();
        session.create_client(0x20, "test_type", &qos).unwrap();
        let entries = session.get_service_names_and_types();
        assert!(!entries.is_empty());
        for (name, typ) in &entries {
            assert!(!name.is_empty());
            assert!(!typ.is_empty());
        }
    }

    #[test]
    fn test_graphcache_local_entities() {
        let session = Session::new(100, 0);
        let qos = QosProfile::default_sensor();

        session
            .create_publisher("0xdead", "", 0xdead, &qos)
            .unwrap();
        session
            .create_publisher("0xbeef", "", 0xbeef, &qos)
            .unwrap();
        session
            .create_subscription("0xdead", "", 0xdead, &qos)
            .unwrap();
        session
            .create_subscription("0xbeef", "", 0xbeef, &qos)
            .unwrap();

        let names = session.get_node_names();
        assert_eq!(names.len(), 1);

        let topics = session.get_topic_names();
        assert_eq!(topics.len(), 2);
    }

    #[test]
    fn test_session_create_publisher() {
        let session = Session::new(42, 0);
        let qos = QosProfile::default_sensor();
        session
            .create_publisher("0xdead", "", 0xdead, &qos)
            .unwrap();
    }

    #[test]
    fn test_session_publish_subscribe_same_process() {
        cleanup_topic_shm(0xcafe);
        let session = Session::new(1, 0);
        let qos = QosProfile::default_sensor();

        session
            .create_publisher("0xcafe", "", 0xcafe, &qos)
            .unwrap();
        session
            .create_subscription("0xcafe", "", 0xcafe, &qos)
            .unwrap();

        let data = b"hello session";
        let seq = session.publish(0xcafe, data).unwrap();
        assert_eq!(seq, 0);

        let mut out = vec![0u8; 256];
        let n = session.receive(0xcafe, seq, &mut out).unwrap();
        assert_eq!(&out[..n], data);
    }

    #[test]
    fn test_same_topic_subscriptions_fan_out_in_one_session() {
        cleanup_topic_shm(fxhash("/fanout"));
        let session = Session::new(0x4244, 0);
        let qos = QosProfile::default_sensor();
        let topic = "/fanout";
        let topic_hash = fxhash(topic);

        session
            .create_publisher(topic, "std_msgs/msg/UInt8", topic_hash, &qos)
            .unwrap();
        let first = session
            .create_subscription(topic, "std_msgs/msg/UInt8", topic_hash, &qos)
            .unwrap();
        let second = session
            .create_subscription(topic, "std_msgs/msg/UInt8", topic_hash, &qos)
            .unwrap();
        session.publish(topic_hash, &[42]).unwrap();

        let mut first_out = [0u8; 8];
        let mut second_out = [0u8; 8];
        let (first_len, first_seq) = session
            .receive_next(topic_hash, first.initial_seq, &mut first_out)
            .unwrap();
        let (second_len, second_seq) = session
            .receive_next(topic_hash, second.initial_seq, &mut second_out)
            .unwrap();

        assert_eq!(first_seq, second_seq);
        assert_eq!(&first_out[..first_len], &[42]);
        assert_eq!(&second_out[..second_len], &[42]);
    }

    #[test]
    fn test_clock_topic_uses_burst_tolerant_depth() {
        let topic = "/clock";
        let topic_hash = fxhash(topic);
        cleanup_topic_shm(topic_hash);
        let session = Session::new(0x4242, 0);
        let qos = QosProfile {
            history: HistoryKind::KeepLast { depth: 1 },
            ..QosProfile::default_sensor()
        };

        session
            .create_publisher(topic, "rosgraph_msgs/msg/Clock", topic_hash, &qos)
            .unwrap();
        session
            .create_subscription(topic, "rosgraph_msgs/msg/Clock", topic_hash, &qos)
            .unwrap();

        for i in 0..32u8 {
            session.publish(topic_hash, &[i]).unwrap();
        }

        let mut out = [0u8; 8];
        let (n, actual_seq) = session.receive_next(topic_hash, 0, &mut out).unwrap();
        assert_eq!(actual_seq, 0);
        assert_eq!(&out[..n], &[0]);
    }

    #[test]
    fn test_receive_next_skips_to_latest_when_consumer_is_overwritten() {
        let topic = "/fast_volatile";
        let topic_hash = fxhash(topic);
        cleanup_topic_shm(topic_hash);
        let session = Session::new(0x4243, 0);
        let qos = QosProfile {
            history: HistoryKind::KeepLast { depth: 2 },
            ..QosProfile::default_sensor()
        };

        session
            .create_publisher(topic, "std_msgs/msg/UInt8", topic_hash, &qos)
            .unwrap();
        session
            .create_subscription(topic, "std_msgs/msg/UInt8", topic_hash, &qos)
            .unwrap();

        for i in 0..5u8 {
            session.publish(topic_hash, &[i]).unwrap();
        }

        let (peek_size, peek_seq) = session.peek_next_message_size(topic_hash, 0).unwrap();
        assert_eq!(peek_size, 1);
        assert_eq!(peek_seq, 4);

        let mut out = [0u8; 8];
        let (n, actual_seq) = session.receive_next(topic_hash, 0, &mut out).unwrap();
        assert_eq!(actual_seq, 4);
        assert_eq!(&out[..n], &[4]);
    }

    #[test]
    fn test_subscription_recreate_receives_new_messages() {
        cleanup_topic_shm(fxhash("/camera/image"));
        let session = Session::new(0x101, 0);
        let qos = QosProfile::default_sensor();
        let topic = "/camera/image";
        let topic_hash = fxhash(topic);

        session
            .create_publisher(topic, "sensor_msgs/msg/Image", topic_hash, &qos)
            .unwrap();
        let first = session
            .create_subscription(topic, "sensor_msgs/msg/Image", topic_hash, &qos)
            .unwrap();
        session.publish(topic_hash, b"first").unwrap();
        let mut out = [0u8; 32];
        let n = session
            .receive(topic_hash, first.initial_seq, &mut out)
            .unwrap();
        assert_eq!(&out[..n], b"first");

        session.destroy_subscription(topic_hash).unwrap();
        let second = session
            .create_subscription(topic, "sensor_msgs/msg/Image", topic_hash, &qos)
            .unwrap();
        session.publish(topic_hash, b"second").unwrap();
        let n = session
            .receive(topic_hash, second.initial_seq, &mut out)
            .unwrap();
        assert_eq!(&out[..n], b"second");
    }

    #[test]
    fn test_sessions_share_topic_ring_cross_process() {
        cleanup_topic_shm(fxhash("/isolated"));
        let publisher_session = Session::new(0x201, 0);
        let subscriber_session = Session::new(0x202, 0);
        let qos = QosProfile::default_sensor();
        let topic_hash = fxhash("/isolated");

        publisher_session
            .create_publisher("/isolated", "", topic_hash, &qos)
            .unwrap();
        subscriber_session
            .create_subscription("/isolated", "", topic_hash, &qos)
            .unwrap();
        publisher_session
            .publish(topic_hash, b"local only")
            .unwrap();

        let mut out = [0u8; 32];
        let n = subscriber_session.receive(topic_hash, 0, &mut out).unwrap();
        assert_eq!(&out[..n], b"local only");
    }

    #[test]
    fn test_local_topic_rings_are_isolated_by_ros_domain() {
        let topic_hash = fxhash("/domain_isolation");
        cleanup_domain_topic_shm(301, topic_hash);
        cleanup_domain_topic_shm(302, topic_hash);

        let publisher_domain_a = Session::new(0x301, 301);
        let subscriber_domain_b = Session::new(0x302, 302);
        let publisher_domain_b = Session::new(0x303, 302);
        let qos = QosProfile::default_sensor();

        publisher_domain_a
            .create_publisher("/domain_isolation", "", topic_hash, &qos)
            .unwrap();
        let subscription_b = subscriber_domain_b
            .create_subscription("/domain_isolation", "", topic_hash, &qos)
            .unwrap();
        publisher_domain_a
            .publish(topic_hash, b"wrong domain")
            .unwrap();

        let mut out = [0u8; 32];
        assert!(subscriber_domain_b
            .receive(topic_hash, subscription_b.initial_seq, &mut out)
            .is_err());

        publisher_domain_b
            .create_publisher("/domain_isolation", "", topic_hash, &qos)
            .unwrap();
        publisher_domain_b
            .publish(topic_hash, b"right domain")
            .unwrap();
        let n = subscriber_domain_b
            .receive(topic_hash, subscription_b.initial_seq, &mut out)
            .unwrap();
        assert_eq!(&out[..n], b"right domain");
    }

    #[test]
    fn test_transient_local_late_subscriber_replays_retained_history() {
        cleanup_topic_shm(fxhash("/knowledge_graph"));
        let session = Session::new(0x211, 0);
        let qos = QosProfile {
            durability: Durability::TransientLocal,
            history: HistoryKind::KeepLast { depth: 8 },
            ..QosProfile::default_command()
        };
        let topic = "/knowledge_graph";
        let topic_hash = fxhash(topic);

        session
            .create_publisher(topic, "test_msgs/msg/String", topic_hash, &qos)
            .unwrap();
        session.publish(topic_hash, b"node:worker1").unwrap();
        session.publish(topic_hash, b"node:worker2").unwrap();
        session
            .publish(topic_hash, b"edge:worker1->worker2")
            .unwrap();
        {
            let retained = session.retained_remote_samples.lock().unwrap();
            let history = retained.get(&topic_hash).unwrap();
            assert_eq!(history.len(), 3);
            assert_eq!(history.front().unwrap().1, b"node:worker1");
            assert_eq!(history.back().unwrap().1, b"edge:worker1->worker2");
        }

        let sub = session
            .create_subscription(topic, "test_msgs/msg/String", topic_hash, &qos)
            .unwrap();
        let mut seq = sub.initial_seq;
        let mut out = [0u8; 64];

        let (n, actual) = session.receive_next(topic_hash, seq, &mut out).unwrap();
        assert_eq!(actual, 0);
        assert_eq!(&out[..n], b"node:worker1");
        seq = actual + 1;

        let (n, actual) = session.receive_next(topic_hash, seq, &mut out).unwrap();
        assert_eq!(actual, 1);
        assert_eq!(&out[..n], b"node:worker2");
        seq = actual + 1;

        let (n, actual) = session.receive_next(topic_hash, seq, &mut out).unwrap();
        assert_eq!(actual, 2);
        assert_eq!(&out[..n], b"edge:worker1->worker2");
    }

    #[test]
    fn test_transient_local_cross_session_late_subscriber_replays_retained_history() {
        cleanup_topic_shm(fxhash("/knowledge_graph_cross"));
        let publisher_session = Session::new(0x212, 0);
        let subscriber_session = Session::new(0x213, 0);
        let qos = QosProfile {
            durability: Durability::TransientLocal,
            history: HistoryKind::KeepLast { depth: 8 },
            ..QosProfile::default_command()
        };
        let topic = "/knowledge_graph_cross";
        let topic_hash = fxhash(topic);

        publisher_session
            .create_publisher(topic, "test_msgs/msg/String", topic_hash, &qos)
            .unwrap();
        publisher_session
            .publish(topic_hash, b"node:worker1")
            .unwrap();
        publisher_session
            .publish(topic_hash, b"node:worker2")
            .unwrap();
        publisher_session
            .publish(topic_hash, b"edge:worker1->worker2")
            .unwrap();

        let sub = subscriber_session
            .create_subscription(topic, "test_msgs/msg/String", topic_hash, &qos)
            .unwrap();
        let mut seq = sub.initial_seq;
        let mut out = [0u8; 64];

        let (n, actual) = subscriber_session
            .receive_next(topic_hash, seq, &mut out)
            .unwrap();
        assert_eq!(actual, 0);
        assert_eq!(&out[..n], b"node:worker1");
        seq = actual + 1;

        let (n, actual) = subscriber_session
            .receive_next(topic_hash, seq, &mut out)
            .unwrap();
        assert_eq!(actual, 1);
        assert_eq!(&out[..n], b"node:worker2");
        seq = actual + 1;

        let (n, actual) = subscriber_session
            .receive_next(topic_hash, seq, &mut out)
            .unwrap();
        assert_eq!(actual, 2);
        assert_eq!(&out[..n], b"edge:worker1->worker2");
    }

    #[test]
    fn test_session_multiple_publishers() {
        cleanup_topic_shm(0x2001);
        cleanup_topic_shm(0x2002);
        let session = Session::new(2, 0);
        let qos = QosProfile::default_sensor();

        session
            .create_publisher("topic_2001", "", 0x2001, &qos)
            .unwrap();
        session
            .create_publisher("topic_2002", "", 0x2002, &qos)
            .unwrap();

        session.publish(0x2001, b"data_a").unwrap();
        session.publish(0x2002, b"data_b").unwrap();

        session
            .create_subscription("topic_2001", "", 0x2001, &qos)
            .unwrap();
        session
            .create_subscription("topic_2002", "", 0x2002, &qos)
            .unwrap();

        let mut out = vec![0u8; 256];

        let n = session.receive(0x2001, 0, &mut out).unwrap();
        assert_eq!(&out[..n], b"data_a");

        let n = session.receive(0x2002, 0, &mut out).unwrap();
        assert_eq!(&out[..n], b"data_b");
    }

    #[test]
    fn test_session_eventfds() {
        let session = Session::new(3, 0);
        let qos = QosProfile::default_sensor();

        session
            .create_publisher("topic_3001", "", 0x3001, &qos)
            .unwrap();
        session
            .create_publisher("topic_3002", "", 0x3002, &qos)
            .unwrap();
        session
            .create_subscription("topic_3001", "", 0x3001, &qos)
            .unwrap();
        session
            .create_subscription("topic_3002", "", 0x3002, &qos)
            .unwrap();

        let fds = session.subscription_eventfds();
        assert_eq!(fds.len(), 2);
        assert!(fds[0] >= 0);
        assert!(fds[1] >= 0);
    }

    #[test]
    fn test_service_request_response_roundtrip() {
        let session = Session::new(42, 0);
        let qos = QosProfile::default_command();

        let sid: ServiceId = 0x5e51563;
        cleanup_topic_shm(service_request_topic(sid));
        cleanup_topic_shm(service_response_topic(sid));
        session.create_service(sid, "test_type", &qos).unwrap();
        session.create_client(sid, "test_type", &qos).unwrap();

        let request = b"hello service";
        let request_ring_seq = session.service_initial_seq(sid);
        let request_seq = session.send_request(sid, request).unwrap();
        assert!(request_seq > 0);

        let mut req_buf = vec![0u8; 256];
        let n = session
            .take_request(sid, request_ring_seq, &mut req_buf)
            .unwrap();
        assert_eq!(&req_buf[..n], request);

        let response = b"response data";
        let res_seq = session.send_response(sid, response).unwrap();

        let mut res_buf = vec![0u8; 256];
        let n = session.take_response(sid, res_seq, &mut res_buf).unwrap();
        assert_eq!(&res_buf[..n], response);
    }

    #[test]
    fn test_service_multiple_requests() {
        let session = Session::new(43, 0);
        let qos = QosProfile::default_command();

        let sid: ServiceId = 0x5e51564;
        cleanup_topic_shm(service_request_topic(sid));
        cleanup_topic_shm(service_response_topic(sid));
        session.create_service(sid, "test_type", &qos).unwrap();
        session.create_client(sid, "test_type", &qos).unwrap();

        let first_ring_seq = session.service_initial_seq(sid);
        let seq1 = session.send_request(sid, b"req1").unwrap();
        let seq2 = session.send_request(sid, b"req2").unwrap();
        assert_eq!(seq2, seq1 + 1);

        let mut buf = vec![0u8; 64];

        let n = session.take_request(sid, first_ring_seq, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"req1");

        let n = session
            .take_request(sid, first_ring_seq + 1, &mut buf)
            .unwrap();
        assert_eq!(&buf[..n], b"req2");
    }

    #[test]
    fn test_service_responses_filter_by_client_gid() {
        let sid: ServiceId = 0x5e51565;
        cleanup_topic_shm(service_request_topic(sid));
        cleanup_topic_shm(service_response_topic(sid));

        let server = Session::new(0x901, 0);
        let client_a = Session::new(0x902, 0);
        let client_b = Session::new(0x903, 0);
        let qos = QosProfile::default_command();

        server.create_service(sid, "test_type", &qos).unwrap();
        client_a.create_client(sid, "test_type", &qos).unwrap();
        client_b.create_client(sid, "test_type", &qos).unwrap();

        let request_start = server.service_initial_seq(sid);
        let client_a_response_start = client_a.client_initial_seq(sid);
        let client_b_response_start = client_b.client_initial_seq(sid);
        let seq_a = client_a.send_request(sid, b"req-a").unwrap() as i64;
        let seq_b = client_b.send_request(sid, b"req-b").unwrap() as i64;

        let mut request_buf = [0u8; 64];
        let (n, gid_a, request_seq_a) = server
            .take_request_with_info(sid, request_start, &mut request_buf)
            .unwrap();
        assert_eq!(&request_buf[..n], b"req-a");
        assert_eq!(request_seq_a, seq_a);

        let (n, gid_b, request_seq_b) = server
            .take_request_with_info(sid, request_start + 1, &mut request_buf)
            .unwrap();
        assert_eq!(&request_buf[..n], b"req-b");
        assert_eq!(request_seq_b, seq_b);
        assert_ne!(gid_a, gid_b);

        server
            .send_response_with_info(sid, gid_b, request_seq_b, b"resp-b")
            .unwrap();
        server
            .send_response_with_info(sid, gid_a, request_seq_a, b"resp-a")
            .unwrap();

        let mut response_buf = [0u8; 64];
        match client_a
            .take_response_for_client(sid, client_a_response_start, gid_a, &mut response_buf)
            .unwrap()
        {
            ServiceResponseTake::Taken {
                size,
                request_sequence,
                ..
            } => {
                assert_eq!(request_sequence, seq_a);
                assert_eq!(&response_buf[..size], b"resp-a");
            }
            other => panic!("expected client A response, got {:?}", other),
        }

        match client_b
            .take_response_for_client(sid, client_b_response_start, gid_b, &mut response_buf)
            .unwrap()
        {
            ServiceResponseTake::Taken {
                size,
                request_sequence,
                ..
            } => {
                assert_eq!(request_sequence, seq_b);
                assert_eq!(&response_buf[..size], b"resp-b");
            }
            other => panic!("expected client B response, got {:?}", other),
        }
    }

    #[test]
    fn test_service_response_scanner_keeps_cursor_on_in_progress_slot() {
        let sid: ServiceId = 0x5e51568;
        cleanup_topic_shm(service_request_topic(sid));
        cleanup_topic_shm(service_response_topic(sid));

        let session = Session::new(0x905, 0);
        let qos = QosProfile::default_command();
        session.create_service(sid, "test_type", &qos).unwrap();
        session.create_client(sid, "test_type", &qos).unwrap();

        let start_seq = session.client_initial_seq(sid);
        let response_pub = session
            .service_response_pubs
            .lock()
            .unwrap()
            .get(&sid)
            .cloned()
            .unwrap();
        let (_ptr, _cap) = response_pub
            .borrow_buffer(32)
            .expect("borrow should reserve one response slot");

        let mut out = [0u8; 64];
        let client_gid = make_gid("pub", session.node_id, service_request_topic(sid));
        assert_eq!(
            session
                .take_response_for_client(sid, start_seq, client_gid, &mut out)
                .unwrap(),
            ServiceResponseTake::NoMatch {
                next_seq: start_seq
            },
            "in-progress response slots must not be skipped"
        );
    }

    #[test]
    fn test_session_bandwidth_budget_enforced() {
        let session = Session::new(500, 0);
        let mut qos = QosProfile::default_sensor();
        qos.bandwidth_limit = Some(100);
        qos.max_message_size = 65536;

        session
            .create_publisher("0xb00d", "", 0xb00d, &qos)
            .unwrap();

        let result = session.publish(0xb00d, b"hello worl");
        assert!(result.is_ok(), "first message should succeed");

        let result = session.publish(0xb00d, b"hello worl");
        assert!(result.is_ok(), "second message should succeed");

        let big = vec![0u8; 80];
        let result = session.publish(0xb00d, &big);
        assert!(result.is_ok(), "third message (100 total) should succeed");

        let result = session.publish(0xb00d, b"x");
        assert!(result.is_err(), "should exceed bandwidth budget");
    }

    #[test]
    fn test_session_custom_max_message_size() {
        cleanup_topic_shm(0xabcd);
        let session = Session::new(600, 0);
        let mut qos = QosProfile::default_sensor();
        qos.max_message_size = 128;
        qos.bandwidth_limit = None;

        session
            .create_publisher("0xabcd", "", 0xabcd, &qos)
            .unwrap();
        session
            .create_subscription("0xabcd", "", 0xabcd, &qos)
            .unwrap();

        let small_msg = b"fits";
        let seq = session.publish(0xabcd, small_msg).unwrap();

        let mut out = vec![0u8; 128];
        let n = session.receive(0xabcd, seq, &mut out).unwrap();
        assert_eq!(&out[..n], small_msg);

        let big_msg = vec![0u8; 200];
        let result = session.publish(0xabcd, &big_msg);
        assert!(
            result.is_err(),
            "message exceeding max_message_size should fail"
        );
    }

    #[test]
    fn test_rtabmap_mapdata_uses_large_topic_capacity() {
        assert!(topic_message_capacity("rtabmap_msgs/msg/MapData", 65536) >= 64 * 1024 * 1024);
        assert!(topic_message_capacity("rtabmap_msgs/msg/SensorData", 65536) >= 64 * 1024 * 1024);
        assert!(topic_message_capacity("rtabmap_msgs/msg/RGBDImage", 65536) >= 64 * 1024 * 1024);
        assert!(topic_message_capacity("rtabmap_msgs/msg/Info", 65536) >= 8 * 1024 * 1024);
        assert!(topic_message_capacity("rtabmap_msgs/msg/MapGraph", 65536) >= 4 * 1024 * 1024);
    }

    #[test]
    fn test_nav2_costmap_uses_large_topic_capacity() {
        assert!(topic_message_capacity("nav2_msgs/msg/Costmap", 65536) >= 16 * 1024 * 1024);
        assert!(topic_message_capacity("nav2_msgs/msg/VoxelGrid", 65536) >= 16 * 1024 * 1024);
        assert!(
            topic_message_capacity("map_msgs/msg/OccupancyGridUpdate", 65536) >= 4 * 1024 * 1024
        );
        assert!(topic_message_capacity("octomap_msgs/msg/Octomap", 65536) >= 16 * 1024 * 1024);
    }

    #[test]
    fn test_sensor_streams_use_burst_tolerant_depths() {
        let clock_qos = QosProfile {
            history: HistoryKind::KeepLast { depth: 1 },
            ..QosProfile::default_sensor()
        };
        assert_eq!(
            topic_ring_depth("/clock", "rosgraph_msgs/msg/Clock", &clock_qos),
            64
        );

        let points_qos = QosProfile {
            history: HistoryKind::KeepLast { depth: 1 },
            ..QosProfile::default_sensor()
        };
        assert_eq!(
            topic_ring_depth("/camera/points", "sensor_msgs/msg/PointCloud2", &points_qos),
            8
        );
    }

    #[test]
    fn test_session_unlimited_bandwidth() {
        let session = Session::new(501, 0);
        let qos = QosProfile {
            history: HistoryKind::KeepLast { depth: 256 },
            ..QosProfile::default_sensor()
        };

        session
            .create_publisher("0xfeed", "", 0xfeed, &qos)
            .unwrap();

        for _ in 0..100 {
            let big = vec![0u8; 1000];
            let result = session.publish(0xfeed, &big);
            assert!(result.is_ok(), "unlimited budget should never drop");
        }
    }

    #[test]
    fn test_session_bandwidth_and_memory_limits() {
        cleanup_topic_shm(0x1337);
        use std::sync::Arc;
        use std::thread;

        let session = Session::new(700, 0);
        let mut qos = QosProfile::default_sensor();
        qos.bandwidth_limit = Some(100);
        qos.max_message_size = 64;

        session
            .create_publisher("0x1337", "", 0x1337, &qos)
            .unwrap();
        session
            .create_subscription("0x1337", "", 0x1337, &qos)
            .unwrap();

        let session_arc = Arc::new(session);
        let session_pub = session_arc.clone();
        let session_sub = session_arc.clone();

        let producer = thread::spawn(move || {
            let mut sent = 0u64;
            for _ in 0..50 {
                let msg = b"small_msg_";
                match session_pub.publish(0x1337, msg) {
                    Ok(seq) => {
                        sent = seq + 1;
                    }
                    Err(_) => { /* dropped by budget */ }
                }
                thread::yield_now();
            }
            sent
        });

        let consumer = thread::spawn(move || {
            let mut received = 0u64;
            let mut out = vec![0u8; 64];
            for seq in 0..50 {
                let mut timeout_count = 0u32;
                loop {
                    match session_sub.receive(0x1337, seq, &mut out) {
                        Ok(_) => {
                            received = seq + 1;
                            break;
                        }
                        Err(_) => {
                            thread::yield_now();
                            thread::park_timeout(std::time::Duration::from_millis(50));
                            timeout_count += 1;
                            if timeout_count > 10 {
                                break;
                            }
                        }
                    }
                }
            }
            received
        });

        let sent = producer.join().unwrap();
        let received = consumer.join().unwrap();

        assert!(sent > 0, "should have sent at least some messages");
        assert!(received > 0, "should have received at least some messages");
        assert!(received <= sent, "received should not exceed sent");
        assert!(
            sent < 50 || received < 50,
            "bandwidth limit should cause some drops"
        );
    }

    #[test]
    fn test_acl_globs_match_topic_names() {
        let allowed = "/robot1/cmd_vel";
        let denied = "/other/cmd_vel";
        cleanup_topic_shm(fxhash(allowed));
        cleanup_topic_shm(fxhash(denied));

        let session = Session::new(0x777, 0);
        let qos = QosProfile::default_sensor();
        session.add_acl(AclDirection::Publish, "/robot1/*", true);
        session.add_acl(AclDirection::Subscribe, "/robot1/*", true);

        session
            .create_publisher(allowed, "t", fxhash(allowed), &qos)
            .unwrap();
        session
            .create_publisher(denied, "t", fxhash(denied), &qos)
            .unwrap();
        assert!(
            session.publish(fxhash(allowed), b"ok").is_ok(),
            "name-glob ACL must allow matching topic"
        );
        assert!(
            session.publish(fxhash(denied), b"no").is_err(),
            "name-glob ACL must deny non-matching topic"
        );

        assert!(session
            .create_subscription(allowed, "t", fxhash(allowed), &qos)
            .is_ok());
        assert!(session
            .create_subscription(denied, "t", fxhash(denied), &qos)
            .is_err());
    }

    #[test]
    fn test_service_send_request_acl_denied() {
        let session = Session::new(700, 0);
        let qos = QosProfile::default_sensor();
        session.create_client(0x60, "test_type", &qos).unwrap();
        // Add allow rule for a different topic so the request topic is denied
        session.add_acl(AclDirection::Publish, "other_topic", true);
        let result = session.send_request(0x60, b"test");
        assert!(result.is_err(), "ACL should deny publish on request topic");
    }

    #[test]
    fn test_destroy_service_cleans_up() {
        let session = Session::new(901, 0);
        let qos = QosProfile::default_sensor();
        session.create_service(0x81, "test_type", &qos).unwrap();
        session.destroy_service(0x81).unwrap();
        let req_fd = session.service_request_eventfd(0x81);
        assert!(req_fd.is_none(), "eventfd should be removed after destroy");
    }

    #[test]
    fn test_destroy_client_cleans_up() {
        let session = Session::new(902, 0);
        let qos = QosProfile::default_sensor();
        session.create_client(0x82, "test_type", &qos).unwrap();
        session.destroy_client(0x82).unwrap();
        let res_fd = session.service_response_eventfd(0x82);
        assert!(res_fd.is_none(), "eventfd should be removed after destroy");
    }

    #[test]
    fn test_duplicate_clients_are_reference_counted() {
        let sid: ServiceId = 0x5e51566;
        cleanup_topic_shm(service_request_topic(sid));
        cleanup_topic_shm(service_response_topic(sid));

        let session = Session::new(903, 0);
        let qos = QosProfile::default_sensor();
        session.create_client(sid, "test_type", &qos).unwrap();
        session.create_client(sid, "test_type", &qos).unwrap();

        session.destroy_client(sid).unwrap();
        assert!(
            session.send_request(sid, b"still alive").is_ok(),
            "destroying one duplicate client must not invalidate the other"
        );

        session.destroy_client(sid).unwrap();
        assert!(
            session.send_request(sid, b"gone").is_err(),
            "last client destroy should remove the request publisher"
        );
    }

    #[test]
    fn test_duplicate_services_are_reference_counted() {
        let sid: ServiceId = 0x5e51567;
        cleanup_topic_shm(service_request_topic(sid));
        cleanup_topic_shm(service_response_topic(sid));

        let session = Session::new(904, 0);
        let qos = QosProfile::default_sensor();
        session.create_service(sid, "test_type", &qos).unwrap();
        session.create_service(sid, "test_type", &qos).unwrap();

        session.destroy_service(sid).unwrap();
        assert!(
            session.send_response(sid, b"still alive").is_ok(),
            "destroying one duplicate service must not invalidate the other"
        );

        session.destroy_service(sid).unwrap();
        assert!(
            session.send_response(sid, b"gone").is_err(),
            "last service destroy should remove the response publisher"
        );
    }

    #[test]
    fn test_graphcache_and_audit_integration() {
        use crate::security::AuditLog;
        use std::sync::Arc;

        // Part 1: GraphCache with remote topology
        let session = Session::new(5001, 0);
        let qos = QosProfile::default_sensor();

        session
            .create_publisher("topic_5001", "", 0x5001, &qos)
            .unwrap();
        session
            .create_publisher("topic_5002", "", 0x5002, &qos)
            .unwrap();
        session
            .create_subscription("topic_5002", "", 0x5002, &qos)
            .unwrap();

        let topics = session.get_topic_names();
        assert!(topics.contains(&"topic_5001".to_string()));
        assert!(topics.contains(&"topic_5002".to_string()));

        let nodes = session.get_node_names();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0], "node_5001");

        // Part 2: Audit log
        let audit = Arc::new(AuditLog::new(4096));
        audit.log(AuditDirection::Send, "face", 16);
        let entries = audit.recent();
        assert!(!entries.is_empty());
        assert_eq!(entries[0].0, AuditDirection::Send);
        assert_eq!(entries[0].2, 16);
    }

    #[test]
    fn test_get_topic_names_excludes_service_internal_topics() {
        let session = Session::new(100, 0);
        let qos = QosProfile::default_sensor();
        // Create a real publisher (should appear in topic list)
        session
            .create_publisher("/chatter", "", fxhash("/chatter"), &qos)
            .unwrap();
        // Create a service with a realistic hash (matches what axon_session_create_service does)
        let service_name = "/node/describe_parameters";
        let service_id = fxhash(service_name);
        session
            .create_service(service_id, "test_srv", &qos)
            .unwrap();

        let names = session.get_topic_names();
        // Only the real topic should appear
        assert_eq!(
            names,
            vec!["/chatter"],
            "only real topics should be listed, got: {:?}",
            names
        );
        // Verify the service internal topics would have had hex names
        let req_topic = service_request_topic(service_id);
        let res_topic = service_response_topic(service_id);
        // These should be in local_publishers/subscriptions but hidden from get_topic_names
        let pubs = session.graph_cache.local_publishers.read().unwrap();
        assert!(
            pubs.contains_key(&res_topic),
            "service pub should be in graph cache"
        );
        let subs = session.graph_cache.local_subscriptions.read().unwrap();
        assert!(
            subs.contains_key(&req_topic),
            "service sub should be in graph cache"
        );
    }

    #[test]
    fn test_count_publishers_and_subscribers() {
        let session = Session::new(1, 0);
        let qos = QosProfile::default_sensor();
        let gid = [0u8; 16];
        let h1 = fxhash("test_topic");
        let h2 = fxhash("test_topic2");
        session
            .graph_cache
            .register_publisher(h1, "test_topic", "", 1, qos, gid);
        session
            .graph_cache
            .register_publisher(h2, "test_topic2", "", 2, qos, gid);
        session
            .graph_cache
            .register_subscription(h1, "test_topic", "", 1, qos, gid);
        assert_eq!(session.count_publishers("test_topic"), 1);
        assert_eq!(session.count_publishers("test_topic2"), 1);
        assert_eq!(session.count_subscribers("test_topic"), 1);
        assert_eq!(session.count_publishers("other"), 0);
        assert_eq!(session.count_subscribers("other"), 0);
    }

    #[test]
    fn test_by_node_queries() {
        let session = Session::new(1, 0);
        let qos = QosProfile::default_sensor();
        let gid = [0u8; 16];
        let service_id = 0x7157;
        cleanup_topic_shm(service_request_topic(service_id));
        cleanup_topic_shm(service_response_topic(service_id));
        session
            .graph_cache
            .register_publisher(fxhash("t1"), "t1", "", 1, qos, gid);
        session
            .graph_cache
            .register_subscription(fxhash("t2"), "t2", "", 1, qos, gid);
        session
            .create_service(service_id, "std_srvs/srv/Empty", &qos)
            .unwrap();
        session
            .create_client(service_id, "std_srvs/srv/Empty", &qos)
            .unwrap();
        let pubs = session.get_publishers_by_node("node_1", "");
        assert_eq!(pubs.len(), 1);
        assert_eq!(pubs[0].0, "t1");
        let subs = session.get_subscribers_by_node("node_1", "");
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].0, "t2");
        let svcs = session.get_services_by_node("node_1", "");
        assert_eq!(svcs.len(), 1);
        let clients = session.get_clients_by_node("node_1", "");
        assert_eq!(clients.len(), 1);
        assert!(session.get_publishers_by_node("node_999", "").is_empty());
    }

    #[test]
    fn test_lifespan_enforcement_drops_expired() {
        cleanup_topic_shm(0xcafe);
        let session = Session::new(502, 0);
        let qos = QosProfile {
            lifespan: Some(Duration::from_millis(50)),
            ..QosProfile::default_sensor()
        };

        session
            .create_publisher("0xcafe", "", 0xcafe, &qos)
            .unwrap();
        session
            .create_subscription("0xcafe", "", 0xcafe, &qos)
            .unwrap();

        let seq = session.publish(0xcafe, b"hello").unwrap();
        std::thread::sleep(Duration::from_millis(60));

        let mut out = vec![0u8; 64];
        let result = session.receive(0xcafe, seq, &mut out);
        assert!(result.is_err(), "expired message should be rejected");
        assert!(result.unwrap_err().contains("lifespan"));
    }

    #[test]
    fn test_lifespan_enforcement_allows_fresh() {
        cleanup_topic_shm(0xdead);
        let session = Session::new(503, 0);
        let qos = QosProfile {
            lifespan: Some(Duration::from_secs(10)),
            ..QosProfile::default_sensor()
        };

        session
            .create_publisher("0xdead", "", 0xdead, &qos)
            .unwrap();
        session
            .create_subscription("0xdead", "", 0xdead, &qos)
            .unwrap();

        let seq = session.publish(0xdead, b"fresh").unwrap();
        let mut out = vec![0u8; 64];
        let n = session.receive(0xdead, seq, &mut out).unwrap();
        assert_eq!(&out[..n], b"fresh");
    }

    #[test]
    fn test_lifespan_none_allows_any_age() {
        cleanup_topic_shm(0xbeef);
        let session = Session::new(504, 0);
        let qos = QosProfile {
            lifespan: None,
            ..QosProfile::default_sensor()
        };

        session
            .create_publisher("0xbeef", "", 0xbeef, &qos)
            .unwrap();
        session
            .create_subscription("0xbeef", "", 0xbeef, &qos)
            .unwrap();

        let seq = session.publish(0xbeef, b"old").unwrap();
        std::thread::sleep(Duration::from_millis(100));

        let mut out = vec![0u8; 64];
        let n = session.receive(0xbeef, seq, &mut out).unwrap();
        assert_eq!(&out[..n], b"old");
    }

    #[test]
    fn test_deadline_monitor_triggers_on_miss() {
        let session = Session::new(505, 0);
        let event_monitor = session.event_monitor.as_ref().unwrap();
        let handle = event_monitor.create_event(EventKind::DeadlineMissed);
        event_monitor.register_deadline_monitor(handle, 0xfeed, 0, Duration::from_millis(50));

        std::thread::sleep(Duration::from_millis(60));
        event_monitor.check_deadlines();

        let result = event_monitor.take_event(handle);
        assert!(result.is_some(), "deadline should have been missed");
        let (count, _, _, _) = result.unwrap();
        assert!(count > 0, "deadline miss count should be positive");
    }

    #[test]
    fn test_deadline_monitor_no_trigger_when_fresh() {
        let session = Session::new(506, 0);
        let event_monitor = session.event_monitor.as_ref().unwrap();
        let handle = event_monitor.create_event(EventKind::DeadlineMissed);
        event_monitor.register_deadline_monitor(handle, 0xfeed, 0, Duration::from_secs(10));

        std::thread::sleep(Duration::from_millis(10));
        event_monitor.check_deadlines();

        let result = event_monitor.take_event(handle);
        assert!(result.is_none(), "deadline should not be missed");
    }

    #[test]
    fn test_liveliness_monitor_triggers_on_expiry() {
        let session = Session::new(507, 0);
        let event_monitor = session.event_monitor.as_ref().unwrap();
        let handle = event_monitor.create_event(EventKind::LivelinessLost);
        event_monitor.register_liveliness_monitor(handle, 999, Duration::from_millis(50));

        std::thread::sleep(Duration::from_millis(60));
        event_monitor.check_liveliness();

        let result = event_monitor.take_event(handle);
        assert!(result.is_some(), "liveliness should have been lost");
        let (count, _, _, _) = result.unwrap();
        assert!(count > 0, "liveliness loss count should be positive");
    }

    #[test]
    fn test_liveliness_monitor_reset_on_assert() {
        let session = Session::new(508, 0);
        let event_monitor = session.event_monitor.as_ref().unwrap();
        let handle = event_monitor.create_event(EventKind::LivelinessLost);
        event_monitor.register_liveliness_monitor(handle, 999, Duration::from_millis(100));

        std::thread::sleep(Duration::from_millis(60));
        event_monitor.assert_liveliness(999);
        std::thread::sleep(Duration::from_millis(30));
        event_monitor.check_liveliness();

        let result = event_monitor.take_event(handle);
        assert!(
            result.is_none(),
            "liveliness should not be lost after assert"
        );
    }
}
