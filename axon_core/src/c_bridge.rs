use std::collections::HashMap;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[path = "c_bridge_graph.rs"]
pub(crate) mod c_bridge_graph;
#[path = "c_bridge_service.rs"]
pub(crate) mod c_bridge_service;

use once_cell::sync::Lazy;
use ring::rand::{SecureRandom, SystemRandom};

use crate::session::{GraphEventFd, Session};
use crate::types::{
    fxhash, make_gid, Durability, HistoryKind, Liveliness, QosProfile, Reliability,
    DEFAULT_MAX_MESSAGE_SIZE,
};
#[cfg(test)]
use crate::types::{service_request_topic, service_response_topic};
use crate::wait::WaitSet;

static SESSIONS: Lazy<Mutex<HashMap<u64, Arc<Session>>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static WAIT_SETS: Lazy<Mutex<HashMap<u64, HashMap<u64, WaitSet>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_WS_HANDLE: AtomicU64 = AtomicU64::new(1);

fn new_node_id() -> u64 {
    let rng = SystemRandom::new();
    loop {
        let mut bytes = [0u8; 8];
        rng.fill(&mut bytes).expect("generate AXON node identity");
        let id = u64::from_le_bytes(bytes);
        if id != 0 {
            return id;
        }
    }
}

/// RMW_DURATION_INFINITE is INT64_MAX nanoseconds split into rmw_time_t parts.
const RMW_DURATION_INFINITE_SEC: u64 = 9_223_372_036;
const RMW_DURATION_INFINITE_NSEC: u32 = 854_775_807;

pub(crate) fn duration_from_rmw_parts(sec: u64, nsec: u32) -> Option<Duration> {
    if sec == 0 && nsec == 0 {
        return None;
    }
    if sec > RMW_DURATION_INFINITE_SEC
        || (sec == RMW_DURATION_INFINITE_SEC && nsec >= RMW_DURATION_INFINITE_NSEC)
    {
        return None;
    }

    let extra_secs = (nsec / 1_000_000_000) as u64;
    let normalized_nsec = nsec % 1_000_000_000;
    let normalized_sec = sec.checked_add(extra_secs)?;
    if normalized_sec > RMW_DURATION_INFINITE_SEC
        || (normalized_sec == RMW_DURATION_INFINITE_SEC
            && normalized_nsec >= RMW_DURATION_INFINITE_NSEC)
    {
        return None;
    }

    Some(Duration::new(normalized_sec, normalized_nsec))
}

pub(crate) fn liveliness_from_ffi(liveliness: i32) -> Liveliness {
    match liveliness {
        1 => Liveliness::ManualByTopic,
        2 => Liveliness::ManualByParticipant,
        _ => Liveliness::Automatic,
    }
}

pub(crate) fn with_session<F, R>(session_id: u64, f: F) -> Result<R, String>
where
    F: FnOnce(&Session) -> Result<R, String>,
{
    let session = {
        let sessions = SESSIONS.lock().unwrap();
        sessions.get(&session_id).cloned().ok_or_else(|| {
            format!(
                "session {} not found ({} sessions exist)",
                session_id,
                sessions.len()
            )
        })?
    };
    f(&session)
}

/// `rmw_wait` and `rmw_take` can race when another consumer advances a shared
/// ring between the readiness check and the read.  The RMW contract treats
/// that case as an empty take, not as a middleware failure.
fn is_expected_empty_receive(error: &str) -> bool {
    error.ends_with("no data at this sequence number")
}
extern "C" fn sigbus_handler(sig: i32) {
    use std::sync::atomic::AtomicBool;
    static HANDLED: AtomicBool = AtomicBool::new(false);
    if HANDLED.swap(true, Ordering::Relaxed) {
        return;
    }
    let msg = format!("\n=== SIGBUS (signal {}) ===\n", sig);
    unsafe {
        libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
    }
    let bt = std::backtrace::Backtrace::force_capture();
    let bt_s = format!("{:#?}\n", bt);
    unsafe {
        libc::write(2, bt_s.as_ptr() as *const libc::c_void, bt_s.len());
    }
    std::process::abort();
}

fn install_sigbus_once() {
    static ONCE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
        let handler = sigbus_handler as *const () as usize;
        unsafe {
            libc::signal(libc::SIGBUS, handler);
        }
    });
}

fn install_quic_crypto_once() {
    use std::sync::OnceLock;
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}
#[no_mangle]
pub extern "C" fn axon_session_create(domain_id: i32) -> i64 {
    install_sigbus_once();
    install_quic_crypto_once();
    let session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    // PIDs and local session counters are not globally unique: separate
    // machines and Docker containers routinely assign the same values.  A
    // random 64-bit identity prevents remote graph entries from overwriting
    // local nodes when those processes meet through daemon discovery.
    let node_id = new_node_id();
    let session = match create_session_with_quic_candidates(node_id, domain_id as u32) {
        Ok(session) => session,
        Err(error)
            if crate::security_mode::SecurityMode::from_env()
                .map(|mode| mode == crate::security_mode::SecurityMode::Qkd)
                .unwrap_or(true) =>
        {
            eprintln!("rmw_axon: QKD session creation failed closed: {}", error);
            return -1;
        }
        Err(error) => {
            eprintln!(
                "rmw_axon: daemon-based session unavailable ({}), falling back",
                error
            );
            Session::new(node_id, domain_id as u32)
        }
    };
    let session = Arc::new(session);
    SESSIONS.lock().unwrap().insert(session_id, session.clone());
    if session.quic_transport.is_some() {
        let weak_session = Arc::downgrade(&session);
        let _ = std::thread::Builder::new()
            .name(format!("axon-route-sync-{session_id}"))
            .spawn(move || loop {
                std::thread::sleep(Duration::from_millis(50));
                let Some(session) = weak_session.upgrade() else {
                    break;
                };
                if session.is_shutdown_requested() {
                    break;
                }
                session.sync_daemon_matches();
            });
    }
    session_id as i64
}

fn create_session_with_quic_candidates(node_id: u64, domain_id: u32) -> Result<Session, String> {
    let ports = quic_port_candidates();
    let mut last_err = None;
    for port in ports {
        match Session::with_quic(node_id, port, domain_id) {
            Ok(session) => return Ok(session),
            Err(e) => last_err = Some(format!("port {}: {}", port, e)),
        }
    }
    Err(last_err.unwrap_or_else(|| "no QUIC port candidates".to_string()))
}

fn quic_port_candidates() -> Vec<u16> {
    if let Ok(value) = std::env::var("AXON_QUIC_PORT") {
        if let Ok(port) = value.trim().parse::<u16>() {
            return vec![port];
        }
        eprintln!("rmw_axon: ignoring invalid AXON_QUIC_PORT={}", value);
    }

    if let Ok(value) = std::env::var("AXON_QUIC_PORT_RANGE") {
        if let Some((start, end)) = parse_port_range(&value) {
            return (start..=end).take(1024).collect();
        }
        eprintln!("rmw_axon: ignoring invalid AXON_QUIC_PORT_RANGE={}", value);
    }

    vec![0]
}

fn parse_port_range(value: &str) -> Option<(u16, u16)> {
    let (start, end) = value.split_once('-')?;
    let start = start.trim().parse::<u16>().ok()?;
    let end = end.trim().parse::<u16>().ok()?;
    if start == 0 || end < start {
        return None;
    }
    Some((start, end))
}

#[no_mangle]
pub extern "C" fn axon_session_shutdown(session_id: u64) -> i32 {
    match with_session(session_id, |session| {
        session.request_shutdown();
        Ok(())
    }) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Refresh remote routes from the discovery daemon.
///
/// RMW calls this from its bounded wait loop so publishers that become idle
/// after a short startup burst can still establish a secured route and flush
/// their reliable startup history.
#[no_mangle]
pub extern "C" fn axon_session_sync_routes(session_id: u64) -> i32 {
    match with_session(session_id, |session| {
        session.sync_daemon_matches();
        Ok(())
    }) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn axon_session_destroy(session_id: u64) -> i32 {
    // Remove the session from SESSIONS and release the lock BEFORE
    // the Arc is dropped (Session::drop runs outside the SESSIONS lock
    // so any panic during teardown won't poison SESSIONS).
    let session = {
        let mut sessions = match SESSIONS.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                eprintln!("rmw_axon: SESSIONS mutex was poisoned, ignoring");
                poisoned.into_inner()
            }
        };
        sessions.remove(&session_id)
    };
    if session.is_some() {
        // Catch any panic from dropping the session (e.g. during QuicTransport
        // cleanup) so it doesn't propagate through the extern "C" boundary
        // and cause SIGABRT.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drop(session);
        }));
        if let Ok(mut guard) = WAIT_SETS.lock() {
            guard.remove(&session_id);
        }
        0
    } else {
        -1
    }
}
#[no_mangle]
pub extern "C" fn axon_session_register_graph_event_fd(session_id: u64, event_fd: i32) -> i32 {
    if event_fd < 0 {
        return -1;
    }
    let sessions = SESSIONS.lock().unwrap();
    let Some(session) = sessions.get(&session_id) else {
        return -1;
    };
    let mut fds = session.graph_event_fds.write().unwrap();
    if fds.iter().any(|fd| fd.original == event_fd) {
        return 0;
    }
    let signal_fd = unsafe { libc::dup(event_fd) };
    if signal_fd < 0 {
        return -1;
    }
    fds.push(GraphEventFd {
        original: event_fd,
        signal: signal_fd,
    });
    0
}
#[no_mangle]
pub extern "C" fn axon_session_unregister_graph_event_fd(session_id: u64, event_fd: i32) -> i32 {
    if event_fd < 0 {
        return -1;
    }
    let sessions = SESSIONS.lock().unwrap();
    let Some(session) = sessions.get(&session_id) else {
        return -1;
    };
    let mut fds = session.graph_event_fds.write().unwrap();
    fds.retain(|fd| fd.original != event_fd);
    0
}

/// Add an ACL rule to a session. `direction` is 0 for publish, 1 for
/// subscribe; `pattern` is a glob matched against topic names. Returns 0 on
/// success, -1 on bad arguments. Rules can also be set at session creation via
/// the `AXON_ACL_PUBLISH` / `AXON_ACL_SUBSCRIBE` environment variables.
#[no_mangle]
pub extern "C" fn axon_session_add_acl(
    session_id: u64,
    direction: i32,
    pattern: *const c_char,
) -> i32 {
    if pattern.is_null() {
        return -1;
    }
    let Ok(pat) = (unsafe { CStr::from_ptr(pattern) }).to_str() else {
        return -1;
    };
    let dir = match direction {
        0 => crate::types::AclDirection::Publish,
        1 => crate::types::AclDirection::Subscribe,
        _ => return -1,
    };
    match with_session(session_id, |s| {
        if s.add_acl(dir, pat, true) {
            Ok(())
        } else {
            Err(format!("invalid ACL pattern: {}", pat))
        }
    }) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn axon_session_create_publisher_with_qos(
    session_id: u64,
    topic_name: *const c_char,
    topic_type: *const c_char,
    reliability: i32,
    durability: i32,
    history_kind: i32,
    depth: i32,
    deadline_s: u64,
    deadline_ns: u32,
    lifespan_s: u64,
    lifespan_ns: u32,
    liveliness: i32,
    liveliness_lease_s: u64,
    liveliness_lease_ns: u32,
) -> i32 {
    if topic_name.is_null() || topic_type.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(topic_name) }).to_str() else {
        return -1;
    };
    let Ok(typ) = (unsafe { CStr::from_ptr(topic_type) }).to_str() else {
        return -1;
    };
    let hash = fxhash(name);
    let deadline = duration_from_rmw_parts(deadline_s, deadline_ns);
    let lifespan = duration_from_rmw_parts(lifespan_s, lifespan_ns);
    let liveliness = liveliness_from_ffi(liveliness);
    let liveliness_lease_duration =
        duration_from_rmw_parts(liveliness_lease_s, liveliness_lease_ns);
    let qos = QosProfile {
        reliability: if reliability == 0 {
            Reliability::BestEffort
        } else {
            Reliability::Reliable
        },
        durability: if durability == 0 {
            Durability::Volatile
        } else {
            Durability::TransientLocal
        },
        history: match history_kind {
            1 => HistoryKind::KeepLast {
                depth: depth as usize,
            },
            _ => HistoryKind::KeepAll,
        },
        bandwidth_limit: None,
        max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
        deadline,
        lifespan,
        liveliness,
        liveliness_lease_duration,
    };
    match with_session(session_id, |s| s.create_publisher(name, typ, hash, &qos)) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!(
                "[rmw_axon] axon_session_create_publisher('{}'): {}",
                name, e
            );
            -1
        }
    }
}
#[no_mangle]
pub extern "C" fn axon_session_create_publisher(
    session_id: u64,
    topic_name: *const c_char,
    topic_type: *const c_char,
    reliability: i32,
    history_kind: i32,
    depth: i32,
) -> i32 {
    axon_session_create_publisher_with_qos(
        session_id,
        topic_name,
        topic_type,
        reliability,
        0,
        history_kind,
        depth,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )
}
#[no_mangle]
pub extern "C" fn axon_session_publish(
    session_id: u64,
    topic_name: *const c_char,
    data: *const u8,
    len: u32,
) -> i64 {
    if topic_name.is_null() || data.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(topic_name) }).to_str() else {
        return -1;
    };
    let hash = fxhash(name);
    let data_slice = unsafe { std::slice::from_raw_parts(data, len as usize) };
    match with_session(session_id, |s| {
        let gid = make_gid("pub", s.node_id, hash);
        let publisher_gid = u64::from_le_bytes(gid[..8].try_into().unwrap());
        s.publish_with_gid(hash, data_slice, publisher_gid)
    }) {
        Ok(seq) => seq as i64,
        Err(e) => {
            eprintln!("[rmw_axon] axon_session_publish('{}'): {}", name, e);
            -1
        }
    }
}
#[no_mangle]
pub extern "C" fn axon_session_create_subscription_with_qos(
    session_id: u64,
    topic_name: *const c_char,
    topic_type: *const c_char,
    reliability: i32,
    durability: i32,
    history_kind: i32,
    depth: i32,
    deadline_s: u64,
    deadline_ns: u32,
    lifespan_s: u64,
    lifespan_ns: u32,
    liveliness: i32,
    liveliness_lease_s: u64,
    liveliness_lease_ns: u32,
    initial_seq_out: *mut u64,
) -> i64 {
    if topic_name.is_null() || topic_type.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(topic_name) }).to_str() else {
        return -1;
    };
    let Ok(typ) = (unsafe { CStr::from_ptr(topic_type) }).to_str() else {
        return -1;
    };
    let hash = fxhash(name);
    let deadline = duration_from_rmw_parts(deadline_s, deadline_ns);
    let lifespan = duration_from_rmw_parts(lifespan_s, lifespan_ns);
    let liveliness = liveliness_from_ffi(liveliness);
    let liveliness_lease_duration =
        duration_from_rmw_parts(liveliness_lease_s, liveliness_lease_ns);
    let qos = QosProfile {
        reliability: if reliability == 0 {
            Reliability::BestEffort
        } else {
            Reliability::Reliable
        },
        durability: if durability == 0 {
            Durability::Volatile
        } else {
            Durability::TransientLocal
        },
        history: if history_kind == 0 {
            HistoryKind::KeepAll
        } else {
            HistoryKind::KeepLast {
                depth: if depth <= 0 { 10 } else { depth as usize },
            }
        },
        bandwidth_limit: None,
        max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
        deadline,
        lifespan,
        liveliness,
        liveliness_lease_duration,
    };
    match with_session(session_id, |s| s.create_subscription(name, typ, hash, &qos)) {
        Ok(handle) => {
            if !initial_seq_out.is_null() {
                unsafe {
                    *initial_seq_out = handle.initial_seq;
                }
            }
            handle.eventfd as i64
        }
        Err(e) => {
            eprintln!(
                "[rmw_axon] axon_session_create_subscription('{}'): {}",
                name, e
            );
            -1
        }
    }
}
#[no_mangle]
pub extern "C" fn axon_session_create_subscription(
    session_id: u64,
    topic_name: *const c_char,
    topic_type: *const c_char,
    reliability: i32,
    history_kind: i32,
    depth: i32,
    initial_seq_out: *mut u64,
) -> i64 {
    axon_session_create_subscription_with_qos(
        session_id,
        topic_name,
        topic_type,
        reliability,
        0,
        history_kind,
        depth,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        initial_seq_out,
    )
}
#[no_mangle]
pub extern "C" fn axon_session_destroy_publisher(
    session_id: u64,
    topic_name: *const c_char,
) -> i32 {
    if topic_name.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(topic_name) }).to_str() else {
        return -1;
    };
    let hash = fxhash(name);
    with_session(session_id, |s| s.destroy_publisher(hash)).map_or(-1, |_| 0)
}
#[no_mangle]
pub extern "C" fn axon_session_destroy_subscription(
    session_id: u64,
    topic_name: *const c_char,
) -> i32 {
    if topic_name.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(topic_name) }).to_str() else {
        return -1;
    };
    let hash = fxhash(name);
    with_session(session_id, |s| s.destroy_subscription(hash)).map_or(-1, |_| 0)
}
#[no_mangle]
pub extern "C" fn axon_session_take(
    session_id: u64,
    topic_name: *const c_char,
    seq: u64,
    out: *mut u8,
    out_len: *mut u32,
) -> i32 {
    if topic_name.is_null() || out_len.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(topic_name) }).to_str() else {
        return -1;
    };
    let hash = fxhash(name);
    let capacity = (unsafe { *out_len }) as usize;

    // If caller provided an empty buffer, peek at the actual data size,
    // report it via out_len, and return -1 so the caller may resize & retry.
    // In this mode `out` may be NULL — we never dereference it.
    if capacity == 0 {
        return match with_session(session_id, |s| s.peek_message_size(hash, seq)) {
            Ok(sz) => {
                unsafe {
                    *out_len = sz as u32;
                }
                -1
            }
            Err(_) => -1,
        };
    }

    if out.is_null() {
        return -1;
    }

    let out_slice = unsafe { std::slice::from_raw_parts_mut(out, capacity) };
    match with_session(session_id, |s| s.receive(hash, seq, out_slice)) {
        Ok(n) => {
            if n > capacity {
                unsafe {
                    *out_len = n as u32;
                }
                -1
            } else {
                unsafe {
                    *out_len = n as u32;
                }
                0
            }
        }
        Err(_) => {
            // receive failed (e.g. buffer too small) — peek at actual size
            // so the caller can resize & retry
            if let Ok(sz) = with_session(session_id, |s| s.peek_message_size(hash, seq)) {
                unsafe {
                    *out_len = sz as u32;
                }
            }
            -1
        }
    }
}
#[no_mangle]
pub extern "C" fn axon_session_take_next(
    session_id: u64,
    topic_name: *const c_char,
    seq_inout: *mut u64,
    out: *mut u8,
    out_len: *mut u32,
) -> i32 {
    if topic_name.is_null() || seq_inout.is_null() || out_len.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(topic_name) }).to_str() else {
        return -1;
    };
    let hash = fxhash(name);
    let requested_seq = unsafe { *seq_inout };
    let capacity = (unsafe { *out_len }) as usize;

    if capacity == 0 {
        return match with_session(session_id, |s| {
            s.peek_next_message_size(hash, requested_seq)
        }) {
            Ok((size, actual_seq)) => {
                unsafe {
                    *out_len = size as u32;
                    *seq_inout = actual_seq;
                }
                -1
            }
            Err(_) => -1,
        };
    }
    if out.is_null() {
        return -1;
    }

    let out_slice = unsafe { std::slice::from_raw_parts_mut(out, capacity) };
    match with_session(session_id, |s| {
        s.receive_next(hash, requested_seq, out_slice)
            .map_err(|e| format!("receive_next: {}", e))
    }) {
        Ok((size, actual_seq)) => {
            if size > capacity {
                unsafe {
                    *out_len = size as u32;
                    *seq_inout = actual_seq;
                }
                -2
            } else {
                unsafe {
                    *out_len = size as u32;
                    *seq_inout = actual_seq + 1;
                }
                0
            }
        }
        Err(e) => {
            if let Ok((size, actual_seq)) = with_session(session_id, |s| {
                s.peek_next_message_size(hash, requested_seq)
                    .map_err(|e| format!("peek_next_message_size: {}", e))
            }) {
                unsafe {
                    *out_len = size as u32;
                    *seq_inout = actual_seq;
                }
                -2
            } else {
                if !is_expected_empty_receive(&e) {
                    eprintln!(
                        "take_next error: topic={} seq={} err={}",
                        name, requested_seq, e
                    );
                }
                -3
            }
        }
    }
}
#[no_mangle]
pub extern "C" fn axon_set_node_addr(session_id: u64, node_id: u64, addr: *const c_char) {
    if addr.is_null() {
        return;
    }
    let Ok(addr_str) = (unsafe { CStr::from_ptr(addr) }).to_str() else {
        return;
    };
    let sock_addr: std::net::SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => {
            return;
        }
    };
    let sessions = SESSIONS.lock().unwrap();
    if let Some(session) = sessions.get(&session_id) {
        session.set_node_addr(node_id, sock_addr);
    }
}
#[no_mangle]
pub extern "C" fn axon_add_remote_service_route(
    session_id: u64,
    service_name: *const c_char,
    node_id: u64,
) -> i32 {
    if service_name.is_null() {
        return -1;
    }
    let Ok(name) = (unsafe { CStr::from_ptr(service_name) }).to_str() else {
        return -1;
    };
    let sid = fxhash(name);
    let sessions = SESSIONS.lock().unwrap();
    match sessions.get(&session_id) {
        Some(session) => {
            session.add_remote_service_route(sid, node_id);
            0
        }
        None => -1,
    }
}
#[no_mangle]
pub extern "C" fn axon_session_set_node_name(
    session_id: u64,
    name: *const c_char,
    namespace_: *const c_char,
) -> i32 {
    if name.is_null() || namespace_.is_null() {
        return -1;
    }
    let Ok(n) = (unsafe { CStr::from_ptr(name) }).to_str() else {
        return -1;
    };
    let Ok(ns) = (unsafe { CStr::from_ptr(namespace_) }).to_str() else {
        return -1;
    };
    let sessions = SESSIONS.lock().unwrap();
    match sessions.get(&session_id) {
        Some(session) => {
            session.set_node_name(n, ns);
            0
        }
        None => -1,
    }
}
#[no_mangle]
pub extern "C" fn axon_session_create_waitset(session_id: u64) -> i64 {
    let ws = match WaitSet::new() {
        Ok(ws) => ws,
        Err(_) => {
            return -1;
        }
    };
    let handle = NEXT_WS_HANDLE.fetch_add(1, Ordering::Relaxed);
    WAIT_SETS
        .lock()
        .unwrap()
        .entry(session_id)
        .or_default()
        .insert(handle, ws);
    handle as i64
}
#[no_mangle]
pub extern "C" fn axon_session_destroy_waitset(session_id: u64, ws_handle: u64) -> i32 {
    let mut ws_registry = WAIT_SETS.lock().unwrap();
    if let Some(session_ws) = ws_registry.get_mut(&session_id) {
        if session_ws.remove(&ws_handle).is_some() {
            return 0;
        }
    }
    -1
}
#[no_mangle]
pub extern "C" fn axon_session_get_node_name(session_id: u64) -> *mut c_char {
    match with_session(session_id, |s| {
        let name = s.get_node_name();
        Ok(std::ffi::CString::new(name).unwrap_or_default().into_raw())
    }) {
        Ok(ptr) => ptr,
        Err(_) => std::ptr::null_mut(),
    }
}
#[no_mangle]
pub extern "C" fn axon_session_get_node_namespace(session_id: u64) -> *mut c_char {
    match with_session(session_id, |s| {
        let ns = s.get_node_namespace();
        Ok(std::ffi::CString::new(ns).unwrap_or_default().into_raw())
    }) {
        Ok(ptr) => ptr,
        Err(_) => std::ptr::null_mut(),
    }
}
#[no_mangle]
pub extern "C" fn axon_session_borrow_loaned(
    session_id: u64,
    topic: *const c_char,
    max_size: usize,
) -> *mut u8 {
    if topic.is_null() {
        return std::ptr::null_mut();
    }
    let Ok(topic_str) = (unsafe { CStr::from_ptr(topic) }).to_str() else {
        return std::ptr::null_mut();
    };
    match with_session(session_id, |s| {
        let topic_hash = fxhash(topic_str);
        let (ptr, _) = s.borrow_loaned(topic_hash, max_size).ok_or("not found")?;
        Ok(ptr)
    }) {
        Ok(ptr) => ptr,
        Err(_) => std::ptr::null_mut(),
    }
}
#[no_mangle]
pub extern "C" fn axon_session_publish_loaned(
    session_id: u64,
    topic: *const c_char,
    ptr: *const u8,
    size: usize,
) -> i32 {
    if topic.is_null() || ptr.is_null() {
        return -1;
    }
    let Ok(topic_str) = (unsafe { CStr::from_ptr(topic) }).to_str() else {
        return -1;
    };
    match with_session(session_id, |s| {
        let topic_hash = fxhash(topic_str);
        if s.commit_loaned(topic_hash, ptr, size) {
            Ok(())
        } else {
            Err("commit failed".into())
        }
    }) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
#[no_mangle]
pub extern "C" fn axon_session_take_loaned(
    session_id: u64,
    topic: *const c_char,
    seq: u64,
    size_out: *mut usize,
) -> *const u8 {
    if topic.is_null() || size_out.is_null() {
        return std::ptr::null();
    }
    let Ok(topic_str) = (unsafe { CStr::from_ptr(topic) }).to_str() else {
        return std::ptr::null();
    };
    match with_session(session_id, |s| {
        let topic_hash = fxhash(topic_str);
        let (ptr, size) = s.take_loaned(topic_hash, seq).ok_or("not found")?;
        unsafe {
            *size_out = size;
        }
        Ok(ptr)
    }) {
        Ok(ptr) => ptr,
        Err(_) => std::ptr::null(),
    }
}
#[no_mangle]
pub extern "C" fn axon_session_return_loaned(
    session_id: u64,
    topic: *const c_char,
    ptr: *const u8,
    size: usize,
) -> i32 {
    if topic.is_null() {
        return -1;
    }
    let Ok(topic_str) = (unsafe { CStr::from_ptr(topic) }).to_str() else {
        return -1;
    };
    match with_session(session_id, |s| {
        let topic_hash = fxhash(topic_str);
        s.return_loaned(topic_hash, ptr, size);
        Ok(())
    }) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
#[no_mangle]
pub extern "C" fn axon_session_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            drop(std::ffi::CString::from_raw(s));
        }
    }
}
#[cfg(test)]
#[allow(unused_unsafe)]
mod tests {
    use super::c_bridge_graph::*;
    use super::c_bridge_service::*;
    use super::*;
    use std::ffi::CString;

    fn test_type_cstr() -> std::ffi::CString {
        std::ffi::CString::new("test_msgs/msg/Test").unwrap()
    }

    #[test]
    fn expected_empty_receive_is_not_reported_as_transport_error() {
        assert!(is_expected_empty_receive(
            "receive_next: no data at this sequence number"
        ));
        assert!(!is_expected_empty_receive("receive_next: slot overwritten"));
    }

    #[test]
    fn test_rmw_duration_parts_normalization() {
        assert_eq!(duration_from_rmw_parts(0, 0), None);
        assert_eq!(
            duration_from_rmw_parts(RMW_DURATION_INFINITE_SEC, RMW_DURATION_INFINITE_NSEC),
            None
        );
        assert_eq!(
            duration_from_rmw_parts(1, 1_500_000_000),
            Some(std::time::Duration::new(2, 500_000_000))
        );
    }

    #[test]
    fn test_liveliness_from_ffi_wire_values() {
        assert_eq!(liveliness_from_ffi(0), Liveliness::Automatic);
        assert_eq!(liveliness_from_ffi(1), Liveliness::ManualByTopic);
        assert_eq!(liveliness_from_ffi(2), Liveliness::ManualByParticipant);
        assert_eq!(liveliness_from_ffi(3), Liveliness::Automatic);
    }

    fn cleanup_topic_shm(name: &str) {
        let hash = fxhash(name);
        let shm_name = format!("/axon_{}", crate::session::local_channel_name(0, hash));
        if let Ok(cname) = std::ffi::CString::new(shm_name) {
            let _ = nix::sys::mman::shm_unlink(cname.as_c_str());
        }
    }

    #[test]
    fn test_create_destroy_session() {
        let sid = axon_session_create(0);
        assert!(sid >= 0, "session ID should be non-negative");

        let ret = axon_session_destroy(sid as u64);
        assert_eq!(ret, 0, "destroy should succeed");
    }

    #[test]
    fn test_session_shutdown_is_idempotent() {
        let sid = axon_session_create(0) as u64;
        assert_eq!(axon_session_shutdown(sid), 0);
        assert_eq!(axon_session_shutdown(sid), 0);
        assert_eq!(axon_session_destroy(sid), 0);
    }

    #[test]
    fn test_graph_eventfd_registration_owns_duplicate() {
        let sid = axon_session_create(0) as u64;
        let event_fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        assert!(event_fd >= 0, "eventfd should be created");

        assert_eq!(axon_session_register_graph_event_fd(sid, event_fd), 0);
        let signal_fd = {
            let sessions = SESSIONS.lock().unwrap();
            let session = sessions.get(&sid).unwrap();
            let fds = session.graph_event_fds.read().unwrap();
            assert_eq!(fds.len(), 1);
            assert_eq!(fds[0].original, event_fd);
            assert_ne!(fds[0].signal, event_fd);
            fds[0].signal
        };

        assert_eq!(unsafe { libc::close(event_fd) }, 0);
        {
            let sessions = SESSIONS.lock().unwrap();
            let session = sessions.get(&sid).unwrap();
            session.signal_graph_eventfds();
            let fds = session.graph_event_fds.read().unwrap();
            assert_eq!(fds.len(), 1);
        }

        let mut val = 0u64;
        let ret = unsafe {
            libc::read(
                signal_fd,
                &mut val as *mut u64 as *mut libc::c_void,
                std::mem::size_of::<u64>(),
            )
        };
        assert_eq!(ret, std::mem::size_of::<u64>() as libc::ssize_t);
        assert_eq!(val, 1);

        assert_eq!(axon_session_unregister_graph_event_fd(sid, event_fd), 0);
        {
            let sessions = SESSIONS.lock().unwrap();
            let session = sessions.get(&sid).unwrap();
            assert!(session.graph_event_fds.read().unwrap().is_empty());
        }
        assert_eq!(axon_session_destroy(sid), 0);
    }

    #[test]
    fn test_pub_sub_roundtrip() {
        let sid = axon_session_create(0) as u64;
        let topic = CString::new("/test_c_bridge_pubsub").unwrap();

        assert_eq!(
            axon_session_create_publisher(sid, topic.as_ptr(), test_type_cstr().as_ptr(), 0, 1, 1),
            0,
            "create publisher"
        );
        let mut initial_seq: u64 = 0;
        let efd = axon_session_create_subscription(
            sid,
            topic.as_ptr(),
            test_type_cstr().as_ptr(),
            0,
            1,
            1,
            &mut initial_seq,
        );
        assert!(efd >= 0, "create subscription should return eventfd");

        let data = b"hello from c_bridge";
        let seq = axon_session_publish(sid, topic.as_ptr(), data.as_ptr(), data.len() as u32);
        assert!(seq >= 0, "publish should return sequence number");

        let mut out = vec![0u8; 256];
        let mut out_len: u32 = 256;
        assert_eq!(
            axon_session_take(
                sid,
                topic.as_ptr(),
                seq as u64,
                out.as_mut_ptr(),
                &mut out_len as *mut u32
            ),
            0,
            "take should succeed"
        );
        assert_eq!(out_len as usize, data.len(), "data length should match");
        assert_eq!(&out[..out_len as usize], data, "data should match");

        assert_eq!(axon_session_destroy(sid), 0);
    }

    #[test]
    fn test_service_roundtrip() {
        let sid = axon_session_create(0) as u64;
        let svc = CString::new("/test_c_bridge_svc").unwrap();
        let svc_type = CString::new("test_c_bridge_type").unwrap();

        assert_eq!(
            axon_session_create_service(sid, svc.as_ptr(), svc_type.as_ptr(), 1),
            0
        );
        assert_eq!(
            axon_session_create_client(sid, svc.as_ptr(), svc_type.as_ptr(), 1),
            0
        );

        let request = b"service request from c_bridge";
        let req_ring_seq = axon_session_service_initial_seq(sid, svc.as_ptr());
        assert!(req_ring_seq >= 0, "service_initial_seq should succeed");
        let seq =
            axon_session_send_request(sid, svc.as_ptr(), request.as_ptr(), request.len() as u32);
        assert!(seq >= 0, "send_request should return sequence number");

        let mut out = vec![0u8; 256];
        let mut out_len: u32 = 256;
        assert_eq!(
            axon_session_take_request(
                sid,
                svc.as_ptr(),
                req_ring_seq as u64,
                out.as_mut_ptr(),
                &mut out_len as *mut u32
            ),
            0,
            "take_request should succeed"
        );
        assert_eq!(out_len as usize, request.len());
        assert_eq!(&out[..out_len as usize], request);

        let response = b"service response from c_bridge";
        let res_seq =
            axon_session_send_response(sid, svc.as_ptr(), response.as_ptr(), response.len() as u32);
        assert!(res_seq >= 0, "send_response should return sequence number");

        let mut res_out = vec![0u8; 256];
        let mut res_len: u32 = 256;
        assert_eq!(
            axon_session_take_response(
                sid,
                svc.as_ptr(),
                res_seq as u64,
                res_out.as_mut_ptr(),
                &mut res_len as *mut u32
            ),
            0,
            "take_response should succeed"
        );
        assert_eq!(res_len as usize, response.len());
        assert_eq!(&res_out[..res_len as usize], response);

        assert_eq!(axon_session_destroy(sid), 0);
    }

    #[test]
    fn test_service_many_sequential_calls() {
        let sid = axon_session_create(0) as u64;
        let svc = CString::new("/test_many_seq").unwrap();
        let svc_type = CString::new("test_type").unwrap();

        assert_eq!(
            axon_session_create_service(sid, svc.as_ptr(), svc_type.as_ptr(), 1),
            0
        );
        assert_eq!(
            axon_session_create_client(sid, svc.as_ptr(), svc_type.as_ptr(), 1),
            0
        );

        let mut out = vec![0u8; 4096];
        let mut out_len: u32;

        for i in 0..30 {
            let req_data = format!("request_{}", i);
            let req_bytes = req_data.as_bytes();
            let req_ring_seq = axon_session_service_initial_seq(sid, svc.as_ptr());
            assert!(
                req_ring_seq >= 0,
                "service_initial_seq {} should succeed",
                i
            );
            let seq = axon_session_send_request(
                sid,
                svc.as_ptr(),
                req_bytes.as_ptr(),
                req_bytes.len() as u32,
            );
            assert!(seq >= 0, "send_request {} should succeed, got {}", i, seq);

            // Take request
            out_len = 4096;
            let ret = axon_session_take_request(
                sid,
                svc.as_ptr(),
                req_ring_seq as u64,
                out.as_mut_ptr(),
                &mut out_len,
            );
            assert_eq!(ret, 0, "take_request {} should succeed", i);
            assert_eq!(
                out_len as usize,
                req_bytes.len(),
                "request {} length mismatch",
                i
            );

            // Send response
            let resp_data = format!("response_{}", i);
            let resp_bytes = resp_data.as_bytes();
            let res_seq = axon_session_send_response(
                sid,
                svc.as_ptr(),
                resp_bytes.as_ptr(),
                resp_bytes.len() as u32,
            );
            assert!(
                res_seq >= 0,
                "send_response {} should succeed, got {}",
                i,
                res_seq
            );

            // Take response
            out_len = 4096;
            let ret = axon_session_take_response(
                sid,
                svc.as_ptr(),
                res_seq as u64,
                out.as_mut_ptr(),
                &mut out_len,
            );
            assert_eq!(ret, 0, "take_response {} should succeed", i);
            assert_eq!(
                out_len as usize,
                resp_bytes.len(),
                "response {} length mismatch",
                i
            );
        }

        assert_eq!(axon_session_destroy(sid), 0);
    }

    #[test]
    fn test_service_retry_path_small_buffer() {
        let sid = axon_session_create(0) as u64;
        let svc = CString::new("/test_svc_small_buf").unwrap();
        let svc_type = CString::new("test_type").unwrap();

        assert_eq!(
            axon_session_create_service(sid, svc.as_ptr(), svc_type.as_ptr(), 1),
            0
        );
        assert_eq!(
            axon_session_create_client(sid, svc.as_ptr(), svc_type.as_ptr(), 1),
            0
        );

        let req = b"small request";
        let req_ring_seq = axon_session_service_initial_seq(sid, svc.as_ptr());
        assert!(req_ring_seq >= 0);
        let seq = axon_session_send_request(sid, svc.as_ptr(), req.as_ptr(), req.len() as u32);
        assert!(seq >= 0);

        // Take with tiny buffer to trigger -2 retry path
        let mut tiny_buf = [0u8; 1];
        let mut out_len: u32 = 1;
        let ret = axon_session_take_request(
            sid,
            svc.as_ptr(),
            req_ring_seq as u64,
            tiny_buf.as_mut_ptr(),
            &mut out_len,
        );
        // Should return -2 (buffer too small) with actual size
        assert_eq!(ret, -2, "take_request with tiny buf should return -2");
        assert!(out_len > 1, "should report actual size > 1");

        // Now take with correct size
        let mut buf = vec![0u8; out_len as usize];
        let mut actual_len = out_len;
        let ret = axon_session_take_request(
            sid,
            svc.as_ptr(),
            req_ring_seq as u64,
            buf.as_mut_ptr(),
            &mut actual_len,
        );
        assert_eq!(ret, 0, "take_request retry should succeed");
        assert_eq!(actual_len as usize, req.len());

        // Send response
        let resp = b"response_data";
        let res_seq =
            axon_session_send_response(sid, svc.as_ptr(), resp.as_ptr(), resp.len() as u32);
        assert!(res_seq >= 0);

        // Take response with tiny buffer
        out_len = 1;
        let ret = axon_session_take_response(
            sid,
            svc.as_ptr(),
            res_seq as u64,
            tiny_buf.as_mut_ptr(),
            &mut out_len,
        );
        assert_eq!(ret, -2, "take_response with tiny buf should return -2");
        assert!(out_len > 1);

        // Retry with correct size
        let mut res_buf = vec![0u8; out_len as usize];
        actual_len = out_len;
        let ret = axon_session_take_response(
            sid,
            svc.as_ptr(),
            res_seq as u64,
            res_buf.as_mut_ptr(),
            &mut actual_len,
        );
        assert_eq!(ret, 0, "take_response retry should succeed");
        assert_eq!(actual_len as usize, resp.len());

        assert_eq!(axon_session_destroy(sid), 0);
    }

    #[test]
    fn test_multiple_sessions_independent() {
        let sid1 = axon_session_create(1) as u64;
        let sid2 = axon_session_create(2) as u64;

        let topic1 = CString::new("/c_bridge_multi_1").unwrap();
        let topic2 = CString::new("/c_bridge_multi_2").unwrap();

        assert_eq!(
            axon_session_create_publisher(
                sid1,
                topic1.as_ptr(),
                test_type_cstr().as_ptr(),
                0,
                1,
                1
            ),
            0
        );
        assert_eq!(
            axon_session_create_publisher(
                sid2,
                topic2.as_ptr(),
                test_type_cstr().as_ptr(),
                0,
                1,
                1
            ),
            0
        );

        let data1 = b"data for session 1";
        let data2 = b"data for session 2";

        let seq1 = axon_session_publish(sid1, topic1.as_ptr(), data1.as_ptr(), data1.len() as u32);
        assert!(seq1 >= 0);

        let seq2 = axon_session_publish(sid2, topic2.as_ptr(), data2.as_ptr(), data2.len() as u32);
        assert!(seq2 >= 0);

        assert_eq!(axon_session_destroy(sid1), 0);
        assert_eq!(axon_session_destroy(sid2), 0);
    }

    #[test]
    fn test_graph_introspection() {
        let sid = axon_session_create(0) as u64;
        let topic = CString::new("/c_bridge_graph").unwrap();

        assert_eq!(
            axon_session_create_publisher(sid, topic.as_ptr(), test_type_cstr().as_ptr(), 0, 1, 1),
            0
        );

        let mut names_buf = vec![0u8; 256];
        let mut names_count: u32 = 0;
        let ret = axon_session_get_topic_names(
            sid,
            names_buf.as_mut_ptr(),
            names_buf.len() as u32,
            &mut names_count as *mut u32,
        );
        assert_eq!(ret, 0, "get_topic_names should succeed");
        assert!(names_count >= 1, "should have at least 1 topic");

        assert_eq!(axon_session_destroy(sid), 0);
    }

    #[test]
    fn test_graph_introspection_reports_small_buffer() {
        let sid = axon_session_create(0) as u64;
        let topic = CString::new("/c_bridge_graph_small_buffer").unwrap();

        assert_eq!(
            axon_session_create_publisher(sid, topic.as_ptr(), test_type_cstr().as_ptr(), 0, 1, 1),
            0
        );

        let mut tiny_buf = [0u8; 1];
        let mut names_count: u32 = 0;
        let ret = axon_session_get_topic_names(
            sid,
            tiny_buf.as_mut_ptr(),
            tiny_buf.len() as u32,
            &mut names_count as *mut u32,
        );
        assert_eq!(ret, -2, "tiny topic-name buffer should request retry");
        assert!(names_count >= 1, "should report total topic count");

        assert_eq!(axon_session_destroy(sid), 0);
    }

    #[test]
    fn test_endpoint_info_reports_small_buffer() {
        let sid = axon_session_create(0) as u64;
        let topic = CString::new("/c_bridge_endpoint_small_buffer").unwrap();

        assert_eq!(
            axon_session_create_publisher(sid, topic.as_ptr(), test_type_cstr().as_ptr(), 0, 1, 1),
            0
        );

        let mut tiny_buf = [0u8; 1];
        let mut count: u32 = 0;
        let ret = unsafe {
            axon_session_get_publishers_info(
                sid,
                topic.as_ptr(),
                &mut count,
                tiny_buf.as_mut_ptr(),
                tiny_buf.len() as u32,
            )
        };
        assert_eq!(ret, -2, "tiny endpoint-info buffer should request retry");
        assert!(count >= 1, "should report total publisher endpoint count");

        assert_eq!(axon_session_destroy(sid), 0);
    }

    #[test]
    fn test_set_node_addr_and_service_route() {
        let sid = axon_session_create(0) as u64;

        let addr = CString::new("127.0.0.1:9999").unwrap();
        let svc_name = CString::new("test_service").unwrap();
        let node_id: u64 = 0x42;

        axon_set_node_addr(sid, node_id, addr.as_ptr());
        axon_add_remote_service_route(sid, svc_name.as_ptr(), node_id);

        // Verify via the session's remote routes
        let sid_hash = fxhash("test_service");
        let req_topic = service_request_topic(sid_hash);
        let res_topic = service_response_topic(sid_hash);
        let expected_addr: std::net::SocketAddr = "127.0.0.1:9999".parse().unwrap();
        {
            let sessions = SESSIONS.lock().unwrap();
            let session = sessions.get(&sid).unwrap();
            let routes = session.remote_routes.lock().unwrap();
            assert!(routes
                .get(&req_topic)
                .is_some_and(|v| v.contains(&expected_addr)));
            assert!(routes
                .get(&res_topic)
                .is_some_and(|v| v.contains(&expected_addr)));
        } // SESSIONS lock released here

        assert_eq!(axon_session_destroy(sid), 0);
    }

    #[test]
    fn test_set_node_addr_null() {
        let sid = axon_session_create(0) as u64;
        axon_set_node_addr(sid, 0, std::ptr::null());
        // Should not crash — null is silently handled
        assert_eq!(axon_session_destroy(sid), 0);
    }

    #[test]
    fn test_add_remote_service_route_null() {
        let sid = axon_session_create(0) as u64;
        axon_add_remote_service_route(sid, std::ptr::null(), 0);
        // Should not crash
        assert_eq!(axon_session_destroy(sid), 0);
    }

    #[test]
    fn test_null_handling() {
        let sid = axon_session_create(0) as u64;

        assert_eq!(
            axon_session_create_publisher(sid, std::ptr::null(), std::ptr::null(), 0, 1, 1),
            -1
        );
        assert!(
            axon_session_create_subscription(
                sid,
                std::ptr::null(),
                std::ptr::null(),
                0,
                1,
                1,
                std::ptr::null_mut()
            ) < 0
        );
        assert_eq!(
            axon_session_publish(sid, std::ptr::null(), std::ptr::null(), 0),
            -1
        );
        assert_eq!(
            axon_session_take(
                sid,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut()
            ),
            -1
        );
        assert_eq!(
            axon_session_create_service(sid, std::ptr::null(), std::ptr::null(), 0),
            -1
        );
        assert_eq!(
            axon_session_send_request(sid, std::ptr::null(), std::ptr::null(), 0),
            -1
        );
        assert_eq!(
            axon_session_get_node_names(sid, std::ptr::null_mut(), 0, std::ptr::null_mut()),
            -1
        );
        assert_eq!(
            axon_session_get_topic_names(sid, std::ptr::null_mut(), 0, std::ptr::null_mut()),
            -1
        );

        assert_eq!(axon_session_destroy(sid), 0);
    }

    #[test]
    fn test_service_eventfd_accessors() {
        let sid = axon_session_create(0) as u64;
        let svc = CString::new("/test_svc_eventfd").unwrap();
        let svc_type = CString::new("test_type").unwrap();

        // Before create_service/create_client, accessors should return -1
        assert_eq!(
            axon_session_service_request_eventfd(sid, svc.as_ptr()),
            -1,
            "eventfd should be -1 before service creation"
        );
        assert_eq!(
            axon_session_service_response_eventfd(sid, svc.as_ptr()),
            -1,
            "eventfd should be -1 before client creation"
        );

        assert_eq!(
            axon_session_create_service(sid, svc.as_ptr(), svc_type.as_ptr(), 1),
            0
        );
        assert_eq!(
            axon_session_create_client(sid, svc.as_ptr(), svc_type.as_ptr(), 1),
            0
        );

        // After creation, eventfds should be valid (>= 0)
        let req_efd = axon_session_service_request_eventfd(sid, svc.as_ptr());
        assert!(
            req_efd >= 0,
            "request eventfd should be valid, got {}",
            req_efd
        );

        let res_efd = axon_session_service_response_eventfd(sid, svc.as_ptr());
        assert!(
            res_efd >= 0,
            "response eventfd should be valid, got {}",
            res_efd
        );

        // Verify they're valid fds by sending a request and taking it
        let request = b"test request";
        let req_ring_seq = axon_session_service_initial_seq(sid, svc.as_ptr());
        assert!(req_ring_seq >= 0);
        let seq =
            axon_session_send_request(sid, svc.as_ptr(), request.as_ptr(), request.len() as u32);
        assert!(seq >= 0);

        let mut out = vec![0u8; 256];
        let mut out_len: u32 = 256;
        assert_eq!(
            axon_session_take_request(
                sid,
                svc.as_ptr(),
                req_ring_seq as u64,
                out.as_mut_ptr(),
                &mut out_len as *mut u32
            ),
            0,
            "take_request should succeed"
        );
        assert_eq!(out_len as usize, request.len());
        assert_eq!(&out[..out_len as usize], request);

        // Null name should return -1
        assert_eq!(
            axon_session_service_request_eventfd(sid, std::ptr::null()),
            -1
        );
        assert_eq!(
            axon_session_service_response_eventfd(sid, std::ptr::null()),
            -1
        );

        assert_eq!(axon_session_destroy(sid), 0);
    }

    #[test]
    fn test_count_bridge_functions() {
        let sid = axon_session_create(0) as u64;
        let topic = CString::new("count_test").unwrap();
        axon_session_create_publisher(sid, topic.as_ptr(), test_type_cstr().as_ptr(), 0, 1, 1);
        let mut count: u32 = 0;
        axon_session_count_publishers(sid, topic.as_ptr(), &mut count);
        assert_eq!(count, 1);
        axon_session_count_subscribers(sid, topic.as_ptr(), &mut count);
        assert_eq!(count, 0);
        assert_eq!(axon_session_destroy(sid), 0);
    }

    #[test]
    fn test_qos_bridge_functions() {
        let sid = axon_session_create(0) as u64;
        let topic = CString::new("qos_test").unwrap();
        unsafe {
            axon_session_create_publisher(sid, topic.as_ptr(), test_type_cstr().as_ptr(), 1, 1, 1);
        }
        let mut rel: i32 = -1;
        let mut dur: i32 = -1;
        unsafe {
            axon_session_publisher_actual_qos(sid, topic.as_ptr(), &mut rel, &mut dur);
        }
        assert_eq!(rel, 1); // reliable
        assert_eq!(dur, 0); // volatile
        assert_eq!(axon_session_destroy(sid), 0);
    }

    #[test]
    fn test_bridge_event_lifecycle() {
        let sid = axon_session_create(1) as u64;
        let handle = axon_session_create_event(sid, 0, 1); // LivelinessChanged
        assert_ne!(handle, 0, "event handle should be non-zero");

        let mut count: i64 = 0;
        let mut timestamp: i64 = 0;
        let mut alive_count: i64 = 0;
        let mut not_alive_count: i64 = 0;
        let ret = axon_session_take_event(
            sid,
            handle,
            &mut count,
            &mut timestamp,
            &mut alive_count,
            &mut not_alive_count,
        );
        // take_event returns 0 on success, -1 if no event
        assert!(ret == 0 || ret == -1);

        let ret = axon_session_destroy_event(sid, handle);
        assert_eq!(ret, 0);

        assert_eq!(axon_session_destroy(sid), 0);
    }

    #[test]
    fn test_bridge_content_filter() {
        let sid = axon_session_create(1) as u64;
        let topic = CString::new("/test").unwrap();
        let name = CString::new("f1").unwrap();
        let expr = CString::new("x > 0").unwrap();

        let ret = unsafe {
            axon_session_set_content_filter(
                sid,
                topic.as_ptr(),
                name.as_ptr(),
                expr.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
            )
        };
        assert_eq!(ret, 0, "set_content_filter should succeed");

        let mut name_buf = [0u8; 64];
        let mut expr_buf = [0u8; 128];
        let ret = unsafe {
            axon_session_get_content_filter(
                sid,
                topic.as_ptr(),
                name_buf.as_mut_ptr(),
                name_buf.len() as u32,
                expr_buf.as_mut_ptr(),
                expr_buf.len() as u32,
            )
        };
        assert_eq!(ret, 0, "get_content_filter should succeed");
        assert_eq!(&name_buf[..2], b"f1");
        assert_eq!(&expr_buf[..5], b"x > 0");

        assert_eq!(axon_session_destroy(sid), 0);
    }

    #[test]
    fn test_bridge_service_available() {
        let sid = axon_session_create(0) as u64;
        let svc = CString::new("/test_avail").unwrap();
        let svc_type = CString::new("test_type").unwrap();

        let mut available: i32 = -1;
        unsafe {
            axon_session_service_available(sid, svc.as_ptr(), &mut available);
        }
        assert_eq!(
            available, 0,
            "service should not be available before creation"
        );

        assert_eq!(
            axon_session_create_service(sid, svc.as_ptr(), svc_type.as_ptr(), 1),
            0
        );

        unsafe {
            axon_session_service_available(sid, svc.as_ptr(), &mut available);
        }
        assert_eq!(available, 1, "service should be available after creation");

        assert_eq!(axon_session_destroy(sid), 0);
    }

    #[test]
    fn test_bridge_loan_message() {
        cleanup_topic_shm("/test_loan");
        let sid = axon_session_create(0) as u64;
        let topic = CString::new("/test_loan").unwrap();

        // Create publisher
        unsafe {
            axon_session_create_publisher(sid, topic.as_ptr(), test_type_cstr().as_ptr(), 0, 1, 1);
        }

        // Borrow loaned buffer
        let ptr = unsafe { axon_session_borrow_loaned(sid, topic.as_ptr(), 64) };
        assert!(
            !ptr.is_null(),
            "borrow_loaned should return non-null pointer"
        );

        // Write data
        unsafe {
            std::ptr::copy_nonoverlapping(b"hello".as_ptr(), ptr, 5);
        }

        // Publish loaned
        let ret = unsafe { axon_session_publish_loaned(sid, topic.as_ptr(), ptr, 5) };
        assert_eq!(ret, 0, "publish_loaned should succeed");

        // Create subscription
        unsafe {
            axon_session_create_subscription(
                sid,
                topic.as_ptr(),
                test_type_cstr().as_ptr(),
                0,
                1,
                1,
                std::ptr::null_mut(),
            );
        }

        // Take loaned
        let mut size: usize = 0;
        let data_ptr = unsafe { axon_session_take_loaned(sid, topic.as_ptr(), 0, &mut size) };
        assert!(
            !data_ptr.is_null(),
            "take_loaned should return non-null pointer"
        );
        assert_eq!(size, 5);
        let received = unsafe { std::slice::from_raw_parts(data_ptr, size) };
        assert_eq!(received, b"hello");

        // Return loaned
        let ret = unsafe { axon_session_return_loaned(sid, topic.as_ptr(), data_ptr, size) };
        assert_eq!(ret, 0);

        assert_eq!(axon_session_destroy(sid), 0);
    }

    #[test]
    fn test_bridge_flow_endpoints() {
        let sid = axon_session_create(0) as u64;
        let topic = CString::new("/test_flow").unwrap();

        unsafe {
            axon_session_create_publisher(sid, topic.as_ptr(), test_type_cstr().as_ptr(), 0, 1, 1);
        }

        let mut count: usize = 0;
        let ret = unsafe {
            axon_session_publisher_flow_endpoints(
                sid,
                topic.as_ptr(),
                &mut count,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(ret, 0);
        assert_eq!(count, 0, "no remote endpoints for local-only session");

        assert_eq!(axon_session_destroy(sid), 0);
    }

    #[test]
    fn test_bridge_serialized_message_with_info() {
        let sid = axon_session_create(0) as u64;
        let topic = CString::new("/test_info").unwrap();

        unsafe {
            axon_session_create_publisher(sid, topic.as_ptr(), test_type_cstr().as_ptr(), 0, 1, 1);
        }
        unsafe {
            axon_session_create_subscription(
                sid,
                topic.as_ptr(),
                test_type_cstr().as_ptr(),
                0,
                1,
                1,
                std::ptr::null_mut(),
            );
        }

        let data = b"info_test";
        let seq =
            unsafe { axon_session_publish(sid, topic.as_ptr(), data.as_ptr(), data.len() as u32) };
        assert!(seq >= 0);

        let mut out = vec![0u8; 256];
        let mut out_len: u32 = 256;
        let mut source_ts: i64 = 0;
        let mut received_ts: i64 = 0;
        let mut seq_out: i64 = 0;
        let ret = unsafe {
            axon_session_take_serialized_message_with_info(
                sid,
                topic.as_ptr(),
                seq as u64,
                out.as_mut_ptr(),
                &mut out_len,
                &mut source_ts,
                &mut received_ts,
                &mut seq_out,
            )
        };
        assert_eq!(ret, 0);
        assert_eq!(out_len as usize, data.len());
        assert!(source_ts > 0, "source timestamp should be set");
        assert!(received_ts > 0, "received timestamp should be set");
        assert_eq!(seq_out, seq);

        assert_eq!(axon_session_destroy(sid), 0);
    }

    #[test]
    fn test_bridge_node_names_with_enclaves() {
        let sid = axon_session_create(0) as u64;
        let node_name = CString::new("enclave_node").unwrap();
        let node_namespace = CString::new("/enclave_ns").unwrap();
        assert_eq!(
            axon_session_set_node_name(sid, node_name.as_ptr(), node_namespace.as_ptr()),
            0
        );

        let mut names_buf = vec![0u8; 256];
        let mut names_count: u32 = 0;
        let ret = unsafe {
            axon_session_get_node_names_with_enclaves(
                sid,
                names_buf.as_mut_ptr(),
                names_buf.len() as u32,
                &mut names_count,
            )
        };
        assert_eq!(ret, 0);
        assert!(names_count >= 1, "should have at least 1 node");
        // Scan through all name\0namespace\0 entries to find our node
        let mut offset = 0;
        let mut found = false;
        for _ in 0..names_count {
            let name_len = names_buf[offset..]
                .iter()
                .position(|byte| *byte == 0)
                .unwrap();
            let ns_start = offset + name_len + 1;
            let remaining = &names_buf[ns_start..];
            let ns_len = remaining.iter().position(|byte| *byte == 0).unwrap();
            if &names_buf[offset..offset + name_len] == b"enclave_node" {
                assert_eq!(&names_buf[ns_start..ns_start + ns_len], b"/enclave_ns");
                found = true;
                break;
            }
            offset = ns_start + ns_len + 1;
        }
        assert!(found, "enclave_node not found in node list");

        assert_eq!(axon_session_destroy(sid), 0);
    }

    #[test]
    fn test_bridge_get_serialized_message_size() {
        let sid = axon_session_create(0) as u64;
        let type_name = CString::new("std_msgs/msg/String").unwrap();

        let mut size: usize = 0;
        let ret =
            unsafe { axon_session_get_serialized_message_size(sid, type_name.as_ptr(), &mut size) };
        assert_eq!(ret, 0);
        assert_eq!(size, 65536, "should return default max message size");

        assert_eq!(axon_session_destroy(sid), 0);
    }

    #[test]
    fn test_bridge_by_node_queries() {
        let sid = axon_session_create(0) as u64;
        let topic = CString::new("/by_node_test").unwrap();

        unsafe {
            axon_session_create_publisher(sid, topic.as_ptr(), test_type_cstr().as_ptr(), 0, 1, 1);
        }

        // Get the session's node name
        let sessions = SESSIONS.lock().unwrap();
        let session = sessions.get(&sid).unwrap();
        let node_name_str = format!("node_{}", session.node_id);
        drop(sessions);
        let node_name = CString::new(node_name_str).unwrap();

        let mut count: usize = 0;
        let mut names: *mut *mut c_char = std::ptr::null_mut();
        let mut types: *mut *mut c_char = std::ptr::null_mut();
        let ret = unsafe {
            axon_session_get_publishers_by_node(
                sid,
                node_name.as_ptr(),
                std::ptr::null(),
                &mut count,
                &mut names,
                &mut types,
            )
        };
        assert_eq!(ret, 0);
        assert_eq!(count, 1, "should find 1 publisher for this node");

        assert_eq!(axon_session_destroy(sid), 0);
    }

    #[test]
    fn test_bridge_matched_counts() {
        let sid = axon_session_create(0) as u64;
        let topic = CString::new("/matched_test").unwrap();

        unsafe {
            axon_session_create_publisher(sid, topic.as_ptr(), test_type_cstr().as_ptr(), 0, 1, 1);
        }
        unsafe {
            axon_session_create_subscription(
                sid,
                topic.as_ptr(),
                test_type_cstr().as_ptr(),
                0,
                1,
                1,
                std::ptr::null_mut(),
            );
        }

        let mut count: u32 = 0;
        unsafe {
            axon_session_count_matched_pubs(sid, topic.as_ptr(), &mut count);
        }
        assert_eq!(count, 1);

        unsafe {
            axon_session_count_matched_subs(sid, topic.as_ptr(), &mut count);
        }
        assert_eq!(count, 1);

        assert_eq!(axon_session_destroy(sid), 0);
    }

    #[test]
    fn test_bridge_large_message_resize_path() {
        // Test data delivery with a message larger than the typical initial
        // stack buffer (65536 bytes).  Uses "sensor_msgs/msg/Image" type to
        // get 8MB SHM slots without env vars.
        let sid = axon_session_create(0) as u64;
        let topic = CString::new("/large_resize").unwrap();
        let image_type = CString::new("sensor_msgs/msg/Image").unwrap();
        let large_data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        assert!(large_data.len() > 65536, "test needs data > 64KB");

        unsafe {
            axon_session_create_publisher(sid, topic.as_ptr(), image_type.as_ptr(), 0, 1, 1);
        }
        unsafe {
            axon_session_create_subscription(
                sid,
                topic.as_ptr(),
                image_type.as_ptr(),
                0,
                1,
                1,
                std::ptr::null_mut(),
            );
        }

        let seq = unsafe {
            axon_session_publish(
                sid,
                topic.as_ptr(),
                large_data.as_ptr(),
                large_data.len() as u32,
            )
        };
        assert!(seq >= 0, "publish should succeed");

        // take_next with small buffer (mimics rmw_take's small_buf[65536])
        let mut small_buf = [0u8; 65536];
        let mut out_len: u32 = 65536;
        let mut next_seq: u64 = 0;

        let ret = unsafe {
            axon_session_take_next(
                sid,
                topic.as_ptr(),
                &mut next_seq,
                small_buf.as_mut_ptr(),
                &mut out_len,
            )
        };

        if ret == 0 {
            assert_eq!(out_len as usize, large_data.len());
            assert_eq!(&small_buf[..out_len as usize], &large_data[..]);
        } else {
            assert!(
                out_len > 65536,
                "peek should return size > 64KB, got {}",
                out_len
            );
            let mut buf = vec![0u8; out_len as usize];
            let mut actual_len = out_len;
            let ret2 = unsafe {
                axon_session_take_next(
                    sid,
                    topic.as_ptr(),
                    &mut next_seq,
                    buf.as_mut_ptr(),
                    &mut actual_len,
                )
            };
            assert_eq!(ret2, 0, "retry should succeed");
            assert_eq!(
                actual_len as usize,
                large_data.len(),
                "retry size mismatch: got {} expected {}",
                actual_len,
                large_data.len()
            );
            assert_eq!(&buf[..actual_len as usize], &large_data[..]);
        }

        assert_eq!(axon_session_destroy(sid), 0);
    }

    #[test]
    fn test_service_large_response_with_qos() {
        let sid = axon_session_create(0) as u64;
        let svc = CString::new("/test_large_response").unwrap();
        let svc_type = CString::new("test_type").unwrap();

        // Use _with_qos variant which defaults to 8MB slot size
        assert_eq!(
            axon_session_create_service_with_qos(
                sid,
                svc.as_ptr(),
                svc_type.as_ptr(),
                1,
                0,
                1,
                10, // reliable, volatile, KeepLast depth 10
                0,
                0,
                0,
                0, // no deadline, no lifespan
                0,
                0,
                0 // automatic liveliness
            ),
            0
        );
        assert_eq!(
            axon_session_create_client_with_qos(
                sid,
                svc.as_ptr(),
                svc_type.as_ptr(),
                1,
                0,
                1,
                10,
                0,
                0,
                0,
                0,
                0,
                0,
                0
            ),
            0
        );

        // Build a large response (~500KB) to simulate describe_parameters with many params
        let large_response = {
            let mut data = Vec::with_capacity(500_000);
            for _ in 0..50_000 {
                data.extend_from_slice(b"0123456789");
            }
            data
        };
        assert!(large_response.len() > 400_000, "response should be large");

        // Send request (small)
        let req = b"describe_params";
        let req_ring_seq = axon_session_service_initial_seq(sid, svc.as_ptr());
        assert!(req_ring_seq >= 0, "service_initial_seq should succeed");
        let seq = axon_session_send_request(sid, svc.as_ptr(), req.as_ptr(), req.len() as u32);
        assert!(seq >= 0, "send_request should succeed");

        // Take request
        let mut out = vec![0u8; 4096];
        let mut out_len: u32 = 4096;
        let ret = axon_session_take_request(
            sid,
            svc.as_ptr(),
            req_ring_seq as u64,
            out.as_mut_ptr(),
            &mut out_len,
        );
        assert_eq!(ret, 0, "take_request should succeed");
        assert_eq!(out_len as usize, req.len());

        // Send large response
        let res_seq = axon_session_send_response(
            sid,
            svc.as_ptr(),
            large_response.as_ptr(),
            large_response.len() as u32,
        );
        assert!(res_seq >= 0, "send_response should succeed");

        // Take large response (with -2 retry path: small_buf=65536 < large_response)
        let big_buf_len = large_response.len() + 4096;
        let mut big_buf = vec![0u8; big_buf_len];
        let mut actual_len: u32 = big_buf_len as u32;
        let ret = axon_session_take_response(
            sid,
            svc.as_ptr(),
            res_seq as u64,
            big_buf.as_mut_ptr(),
            &mut actual_len,
        );
        assert_eq!(ret, 0, "take_response should succeed");
        assert_eq!(actual_len as usize, large_response.len());
        assert_eq!(&big_buf[..actual_len as usize], &large_response[..]);

        assert_eq!(axon_session_destroy(sid), 0);
    }
}
