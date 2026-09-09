use std::env;
use std::ffi::CString;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::{Endpoint, EndpointConfig, TokioRuntime};
use ring::rand::{SecureRandom, SystemRandom};

use axon_core::daemon::discovery_shm::topic_entry_qos_compatible;
use axon_core::daemon::discovery_shm::{futex_wake, MatchEntry};
use axon_core::daemon::discovery_shm::{
    ShmDiscovery, MAX_MATCHES, MAX_NODES, MAX_NODE_NAME_LEN, MAX_NODE_NS_LEN, MAX_QUIC_ADDRS,
    MAX_TOPICS_PER_NODE, MAX_TOPIC_NAME_LEN, MAX_TOPIC_TYPE_LEN, SHM_NAME,
};
use axon_core::daemon::handler::handle_call;
use axon_core::daemon::peer_discovery::{
    bind_per_interface_sockets, encode_hello_daemon, send_hello_multicast,
    send_hello_multicast_all_interfaces, start_daemon_multicast_listener, HelloDaemon,
    HelloDaemonMessage, QkdControlMessage, DAEMON_HELLO_INTERVAL_MS, DAEMON_MULTICAST_PORT,
};
use axon_core::daemon::rpc::parse_request;
use axon_core::qkd::{QkdDaemonManager, QkdKeyStore};
use axon_core::quic_transport::{
    configure_client_for_daemon, configure_server, generate_self_signed_certs, install_quic_crypto,
};
use axon_core::security_mode::SecurityMode;
use axon_core::session::Session;

const DEFAULT_BASE_PORT: u16 = 7402;
const DEFAULT_FALLBACK_PORT_END: u16 = 7420;
type KnownPeers = std::collections::HashMap<u64, (SocketAddr, u64, Vec<u32>, Instant)>;

fn record_peer_hello(
    known_peers: &mut KnownPeers,
    daemon_id: u64,
    peer_addr: SocketAddr,
    generation: u64,
    local_domains: &[u32],
    now: Instant,
) -> bool {
    use std::collections::hash_map::Entry;

    match known_peers.entry(daemon_id) {
        Entry::Vacant(entry) => {
            entry.insert((peer_addr, generation, local_domains.to_vec(), now));
            true
        }
        Entry::Occupied(mut entry) => {
            let known = entry.get_mut();
            known.0 = peer_addr;
            known.3 = now;
            if generation > known.1 {
                known.1 = generation;
                known.2 = local_domains.to_vec();
                true
            } else if known.2 != local_domains {
                known.2 = local_domains.to_vec();
                true
            } else {
                false
            }
        }
    }
}

struct Config {
    port: u16,
    port_candidates: Vec<u16>,
    pid_file: String,
    foreground: bool,
}

fn parse_args() -> Config {
    let args: Vec<String> = env::args().collect();

    let port_candidates = daemon_port_candidates_from_env();
    let default_port = port_candidates
        .first()
        .copied()
        .unwrap_or(DEFAULT_BASE_PORT);

    let mut cfg = Config {
        port: default_port,
        port_candidates,
        pid_file: "/tmp/axon_daemon.pid".to_string(),
        foreground: false,
    };

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--foreground" => cfg.foreground = true,
            "--port" => {
                i += 1;
                if let Some(v) = args.get(i).and_then(|v| v.parse().ok()) {
                    cfg.port = v;
                    cfg.port_candidates = vec![v];
                }
            }
            "--port-range" => {
                i += 1;
                if let Some(v) = args.get(i).and_then(|v| parse_port_range(v)) {
                    cfg.port = v[0];
                    cfg.port_candidates = v;
                }
            }
            "--pid-file" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    cfg.pid_file = v.clone();
                }
            }
            "--status" => match fs::read_to_string(&cfg.pid_file) {
                Ok(s) => {
                    let pid: u32 = s.trim().parse().unwrap_or(0);
                    if pid > 0 && std::path::Path::new(&format!("/proc/{}", pid)).exists() {
                        println!("axon_daemon is running (PID {})", pid);
                        process::exit(0);
                    } else {
                        println!("axon_daemon is not running (stale PID file)");
                        fs::remove_file(&cfg.pid_file).ok();
                        process::exit(1);
                    }
                }
                Err(_) => {
                    println!("axon_daemon is not running");
                    process::exit(1);
                }
            },
            "--help" => {
                println!("AXON Daemon - persistent graph cache for ros2 CLI");
                println!();
                println!("USAGE:");
                println!("  axon_daemon [FLAGS] [OPTIONS]");
                println!();
                println!("FLAGS:");
                println!("  --foreground    Run in foreground (don't daemonize)");
                println!("  --status        Check if daemon is running");
                println!("  --help          Print this help");
                println!();
                println!("OPTIONS:");
                println!("  --port PORT     TCP/UDP daemon port (default: 7402, with automatic fallback)");
                println!("  --port-range A-B TCP/UDP daemon ports to try in order");
                println!("  --pid-file PATH PID file path (default: /tmp/axon_daemon.pid)");
                println!();
                println!("The daemon handles all ROS domain IDs automatically via SHM.");
                process::exit(0);
            }
            _ => {
                eprintln!("Unknown flag: {}", args[i]);
                process::exit(1);
            }
        }
        i += 1;
    }
    cfg
}

fn default_daemon_port_candidates() -> Vec<u16> {
    let mut ports = vec![DEFAULT_BASE_PORT];
    for port in (DEFAULT_BASE_PORT + 1)..=DEFAULT_FALLBACK_PORT_END {
        if port != DAEMON_MULTICAST_PORT {
            ports.push(port);
        }
    }
    ports
}

fn parse_port_range(value: &str) -> Option<Vec<u16>> {
    let (start, end) = value.split_once('-')?;
    let start = start.trim().parse::<u16>().ok()?;
    let end = end.trim().parse::<u16>().ok()?;
    if start == 0 || end < start {
        return None;
    }
    let ports: Vec<u16> = (start..=end)
        .filter(|port| *port != DAEMON_MULTICAST_PORT)
        .take(1024)
        .collect();
    (!ports.is_empty()).then_some(ports)
}

fn daemon_port_candidates_from_env() -> Vec<u16> {
    if let Ok(value) = env::var("AXON_DAEMON_PORT") {
        if let Ok(port) = value.trim().parse::<u16>() {
            if port != 0 {
                return vec![port];
            }
        }
        eprintln!("axon_daemon: ignoring invalid AXON_DAEMON_PORT={value}");
    }

    if let Ok(value) = env::var("AXON_DAEMON_PORT_RANGE") {
        if let Some(ports) = parse_port_range(&value) {
            return ports;
        }
        eprintln!("axon_daemon: ignoring invalid AXON_DAEMON_PORT_RANGE={value}");
    }

    default_daemon_port_candidates()
}

fn bind_daemon_endpoints(ports: &[u16]) -> Result<(u16, UdpSocket, TcpListener), String> {
    let mut last_err = String::new();
    for &port in ports {
        let udp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
        let udp = match UdpSocket::bind(udp_addr) {
            Ok(socket) => socket,
            Err(e) => {
                last_err = format!("UDP {udp_addr}: {e}");
                continue;
            }
        };

        let selected_port = match udp.local_addr() {
            Ok(addr) => addr.port(),
            Err(e) => {
                last_err = format!("UDP {udp_addr} local_addr: {e}");
                continue;
            }
        };
        let tcp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), selected_port);
        match TcpListener::bind(tcp_addr) {
            Ok(listener) => return Ok((selected_port, udp, listener)),
            Err(e) => {
                last_err = format!("TCP {tcp_addr}: {e}");
                drop(udp);
            }
        }
    }

    Err(format!(
        "no daemon port available in {:?}: {}",
        ports, last_err
    ))
}

fn parse_static_daemon_peers() -> Vec<SocketAddr> {
    let Ok(value) = env::var("AXON_DAEMON_PEERS") else {
        return Vec::new();
    };

    let mut peers = Vec::new();
    for token in value.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        match token.to_socket_addrs() {
            Ok(addrs) => {
                for addr in addrs {
                    if addr.is_ipv4() && !peers.contains(&addr) {
                        peers.push(addr);
                    }
                }
            }
            Err(e) => eprintln!("axon_daemon: ignoring AXON_DAEMON_PEERS entry '{token}': {e}"),
        }
    }
    peers
}

/// Daemon identities cross host and container boundaries, where PID and port
/// pairs routinely collide. Generate a fresh non-zero identity per daemon
/// lifetime instead of deriving one from local process metadata.
fn daemon_node_id() -> u64 {
    let rng = SystemRandom::new();
    loop {
        let mut bytes = [0u8; 8];
        rng.fill(&mut bytes).expect("generate AXON daemon identity");
        let id = u64::from_le_bytes(bytes);
        if id != 0 {
            return id;
        }
    }
}

fn check_pid(path: &str) -> Result<(), String> {
    match fs::read_to_string(path) {
        Ok(s) => {
            match s.trim().parse::<u32>() {
                Ok(pid) => {
                    if std::path::Path::new(&format!("/proc/{}", pid)).exists() {
                        return Err(format!("daemon already running (PID {})", pid));
                    }
                }
                Err(_) => {
                    // Corrupt or unparseable PID file — remove and proceed
                    // as if no PID file existed.
                }
            }
            fs::remove_file(path).ok();
            Ok(())
        }
        Err(_) => Ok(()),
    }
}

fn write_pid(path: &str) -> Result<(), String> {
    fs::write(path, format!("{}\n", process::id())).map_err(|e| format!("write PID: {}", e))
}

fn remove_pid(path: &str) {
    fs::remove_file(path).ok();
}

fn daemonize() -> Result<(), String> {
    match unsafe { libc::fork() } {
        -1 => Err("fork failed".into()),
        0 => {
            unsafe {
                libc::setsid();
                let devnull = CString::new("/dev/null").unwrap();
                let fd = libc::open(devnull.as_ptr(), libc::O_RDWR);
                if fd >= 0 {
                    libc::dup2(fd, 0);
                    libc::dup2(fd, 1);
                    libc::dup2(fd, 2);
                    libc::close(fd);
                }
            }
            Ok(())
        }
        _ => {
            process::exit(0);
        }
    }
}

fn handle_client(session: &Session, mut stream: TcpStream) {
    let mut buf = [0u8; 65536];
    let n = match stream.read(&mut buf) {
        Ok(n) if n > 0 => n,
        _ => return,
    };

    let body_start = match buf.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(p) => p + 4,
        None => return,
    };

    let body = &buf[body_start..n];
    let body_end = body.iter().position(|&b| b == 0).unwrap_or(body.len());
    let body = &body[..body_end];

    let response = match parse_request(body) {
        Ok(call) => match handle_call(session, &call) {
            Ok(xml) => xml,
            Err(e) => fault_xml(-1, &e),
        },
        Err(e) => fault_xml(-1, &format!("parse error: {}", e)),
    };

    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.len()
    );
    let mut out = header.into_bytes();
    out.extend_from_slice(&response);
    stream.write_all(&out).ok();
}

fn fault_xml(code: i32, msg: &str) -> Vec<u8> {
    use axon_core::daemon::rpc::serialize_fault;
    serialize_fault(code, msg).unwrap_or_else(|_| {
        format!(
            r#"<?xml version="1.0"?><methodResponse><fault><value><struct><member><name>faultCode</name><value><int>{}</int></value></member><member><name>faultString</name><value><string>{}</string></value></member></struct></value></fault></methodResponse>"#,
            code, msg
        ).into_bytes()
    })
}

fn push_matches_for_all_addrs(
    matches: &mut Vec<MatchEntry>,
    node_id: u64,
    topic_hash: u64,
    port: u16,
    addrs: &[[u8; 4]],
    addr_count: usize,
) {
    let limit = std::cmp::min(addr_count, MAX_QUIC_ADDRS);
    let space = MAX_MATCHES.saturating_sub(matches.len());
    let to_add = std::cmp::min(limit, space);
    for &addr in addrs.iter().take(to_add) {
        matches.push(MatchEntry {
            node_id,
            topic_hash,
            port,
            addr,
        });
    }
}

fn active_domains(shm: &ShmDiscovery) -> Vec<u32> {
    let mut domains = Vec::new();
    for entry in shm.node_table() {
        let state = entry.state.load(Ordering::Acquire);
        if state != 0 && state != 3 && entry.daemon_origin == 0 {
            let domain_id = entry.domain_id;
            if !domains.contains(&domain_id) {
                domains.push(domain_id);
            }
        }
    }
    domains
}

fn push_match_for_all_addrs_dedup(
    matches: &mut Vec<MatchEntry>,
    node_id: u64,
    topic_hash: u64,
    port: u16,
    addrs: &[[u8; 4]],
    addr_count: usize,
) {
    let limit = std::cmp::min(addr_count, MAX_QUIC_ADDRS);
    for &addr in addrs.iter().take(limit) {
        let entry = MatchEntry {
            node_id,
            topic_hash,
            port,
            addr,
        };
        if !matches.iter().any(|m| {
            m.node_id == entry.node_id && m.topic_hash == entry.topic_hash && m.addr == entry.addr
        }) && matches.len() < MAX_MATCHES
        {
            matches.push(entry);
        }
    }
}

fn process_pending_registrations(
    shm: &ShmDiscovery,
    topology_changed: &std::sync::atomic::AtomicBool,
) {
    let node_table = shm.node_table_mut();
    for i in 0..node_table.len() {
        let state = node_table[i].state.load(Ordering::Acquire);
        if state == 1 {
            // Pending -> Active
            node_table[i].state.store(2, Ordering::Release);
            topology_changed.store(true, Ordering::Release);

            let domain_id = node_table[i].domain_id;
            let sub_count = node_table[i].sub_count;
            let pub_count = node_table[i].pub_count;
            let sub_entries: Vec<axon_core::daemon::discovery_shm::TopicEntry> =
                node_table[i].subscribed_topics[..sub_count as usize].to_vec();

            let mut my_matches: Vec<MatchEntry> = Vec::new();

            for j in 0..node_table.len() {
                if i == j {
                    continue;
                }
                if node_table[j].state.load(Ordering::Acquire) != 2 {
                    continue;
                }
                if node_table[j].domain_id != domain_id {
                    continue;
                }

                let j_pub_count = node_table[j].pub_count;
                let j_sub_count = node_table[j].sub_count;

                // i subscribes to j's published topics → add match to i (pointing to j)
                for pub_entry in &node_table[j].published_topics[..j_pub_count as usize] {
                    if sub_entries.iter().any(|s| {
                        s.hash == pub_entry.hash && topic_entry_qos_compatible(pub_entry, s)
                    }) {
                        let port = node_table[j].quic_port;
                        let count = node_table[j].quic_addr_count;
                        let addrs = &node_table[j].quic_addrs;
                        push_matches_for_all_addrs(
                            &mut my_matches,
                            node_table[j].node_id,
                            pub_entry.hash,
                            port,
                            addrs,
                            count as usize,
                        );
                    }
                }

                // j subscribes to i's published topics → add match to j (pointing to i)
                // AND add match to i (pointing to j)
                for pub_entry in &node_table[i].published_topics[..pub_count as usize] {
                    let j_sub_entries: Vec<axon_core::daemon::discovery_shm::TopicEntry> =
                        node_table[j].subscribed_topics[..j_sub_count as usize].to_vec();
                    if j_sub_entries.iter().any(|s| {
                        s.hash == pub_entry.hash && topic_entry_qos_compatible(pub_entry, s)
                    }) {
                        // Add match to j pointing to i (all IPs of i)
                        {
                            let i_port = node_table[i].quic_port;
                            let i_count = node_table[i].quic_addr_count;
                            let i_addrs = &node_table[i].quic_addrs;
                            let limit = std::cmp::min(i_count as usize, MAX_QUIC_ADDRS);
                            let j_cur = node_table[j].match_count as usize;
                            let j_space = MAX_MATCHES.saturating_sub(j_cur);
                            let to_add = std::cmp::min(limit, j_space);
                            let mut added = 0usize;
                            for &addr in i_addrs.iter().take(to_add) {
                                let entry = MatchEntry {
                                    node_id: node_table[i].node_id,
                                    topic_hash: pub_entry.hash,
                                    port: i_port,
                                    addr,
                                };
                                if !node_table[j].remote_matches[..j_cur].iter().any(|m| {
                                    m.node_id == entry.node_id
                                        && m.topic_hash == entry.topic_hash
                                        && m.addr == entry.addr
                                }) {
                                    node_table[j].remote_matches[j_cur + added] = entry;
                                    added += 1;
                                }
                            }
                            if added > 0 {
                                node_table[j].match_count += added as u32;
                                node_table[j].response_gen.fetch_add(1, Ordering::Release);
                                futex_wake(&node_table[j].response_gen);
                            }
                        }
                        // Add match to i (my_matches) pointing to j
                        let j_port = node_table[j].quic_port;
                        let j_count = node_table[j].quic_addr_count;
                        let j_addrs = &node_table[j].quic_addrs;
                        push_match_for_all_addrs_dedup(
                            &mut my_matches,
                            node_table[j].node_id,
                            pub_entry.hash,
                            j_port,
                            j_addrs,
                            j_count as usize,
                        );
                    }
                }
            }

            let validated_matches: Vec<MatchEntry> = my_matches
                .into_iter()
                .filter(|m| {
                    shm.find_slot_by_node_id(m.node_id)
                        .is_some_and(|idx| node_table[idx].state.load(Ordering::Acquire) == 2)
                })
                .collect();

            for (k, m) in validated_matches.iter().enumerate() {
                node_table[i].remote_matches[k] = *m;
            }
            node_table[i].match_count = validated_matches.len() as u32;

            // Wake the node
            node_table[i].response_gen.fetch_add(1, Ordering::Release);
            futex_wake(&node_table[i].response_gen);
        }
    }
}

fn process_topic_updates(shm: &ShmDiscovery, topology_changed: &std::sync::atomic::AtomicBool) {
    let node_table = shm.node_table_mut();
    for i in 0..node_table.len() {
        if node_table[i].state.load(Ordering::Acquire) != 2 {
            continue;
        }
        let domain_id = node_table[i].domain_id;
        let pub_count = node_table[i].pub_count;
        if pub_count == 0 {
            continue;
        }

        for j in 0..node_table.len() {
            if i == j {
                continue;
            }
            if node_table[j].state.load(Ordering::Acquire) != 2 {
                continue;
            }
            if node_table[j].domain_id != domain_id {
                continue;
            }

            let sub_count = node_table[j].sub_count;
            if sub_count == 0 {
                continue;
            }

            let mut j_changed = false;
            let mut i_changed = false;
            for pub_entry in &node_table[i].published_topics[..pub_count as usize] {
                let subscribed = node_table[j].subscribed_topics[..sub_count as usize]
                    .iter()
                    .any(|s| s.hash == pub_entry.hash && topic_entry_qos_compatible(pub_entry, s));
                if !subscribed {
                    continue;
                }

                // Add matches to j (pointing to i) for all IPs of i
                {
                    let i_port = node_table[i].quic_port;
                    let i_count = node_table[i].quic_addr_count;
                    let i_addrs = &node_table[i].quic_addrs;
                    let limit = std::cmp::min(i_count as usize, MAX_QUIC_ADDRS);
                    let j_cur = node_table[j].match_count as usize;
                    let j_space = MAX_MATCHES.saturating_sub(j_cur);
                    let to_add = std::cmp::min(limit, j_space);
                    let mut added = 0usize;
                    for &addr in i_addrs.iter().take(to_add) {
                        let entry = MatchEntry {
                            node_id: node_table[i].node_id,
                            topic_hash: pub_entry.hash,
                            port: i_port,
                            addr,
                        };
                        if !node_table[j].remote_matches[..j_cur].iter().any(|m| {
                            m.node_id == entry.node_id
                                && m.topic_hash == entry.topic_hash
                                && m.addr == entry.addr
                        }) {
                            node_table[j].remote_matches[j_cur + added] = entry;
                            added += 1;
                        }
                    }
                    if added > 0 {
                        node_table[j].match_count += added as u32;
                        j_changed = true;
                    }
                }

                // Add matches to i (pointing to j) for all IPs of j
                {
                    let j_port = node_table[j].quic_port;
                    let j_count = node_table[j].quic_addr_count;
                    let j_addrs = &node_table[j].quic_addrs;
                    let limit = std::cmp::min(j_count as usize, MAX_QUIC_ADDRS);
                    let i_cur = node_table[i].match_count as usize;
                    let i_space = MAX_MATCHES.saturating_sub(i_cur);
                    let to_add = std::cmp::min(limit, i_space);
                    let mut added = 0usize;
                    for &addr in j_addrs.iter().take(to_add) {
                        let entry = MatchEntry {
                            node_id: node_table[j].node_id,
                            topic_hash: pub_entry.hash,
                            port: j_port,
                            addr,
                        };
                        if !node_table[i].remote_matches[..i_cur].iter().any(|m| {
                            m.node_id == entry.node_id
                                && m.topic_hash == entry.topic_hash
                                && m.addr == entry.addr
                        }) {
                            node_table[i].remote_matches[i_cur + added] = entry;
                            added += 1;
                        }
                    }
                    if added > 0 {
                        node_table[i].match_count += added as u32;
                        i_changed = true;
                    }
                }
            }

            if j_changed {
                node_table[j].response_gen.fetch_add(1, Ordering::Release);
                futex_wake(&node_table[j].response_gen);
                topology_changed.store(true, Ordering::Release);
            }
            if i_changed {
                node_table[i].response_gen.fetch_add(1, Ordering::Release);
                futex_wake(&node_table[i].response_gen);
                topology_changed.store(true, Ordering::Release);
            }
        }
    }

    // Remove any match entries that point to inactive (state != 2) nodes
    let mut active_node_ids: Vec<u64> = Vec::new();
    for entry in node_table.iter() {
        if entry.state.load(Ordering::Acquire) == 2 && entry.node_id != 0 {
            active_node_ids.push(entry.node_id);
        }
    }
    for entry in node_table.iter_mut() {
        if entry.state.load(Ordering::Acquire) != 2 {
            continue;
        }
        let count = entry.match_count as usize;
        if count == 0 {
            continue;
        }
        let limit = std::cmp::min(count, MAX_MATCHES);
        let mut write_idx = 0usize;
        for read_idx in 0..limit {
            let m = &entry.remote_matches[read_idx];
            if active_node_ids.contains(&m.node_id) {
                if write_idx != read_idx {
                    entry.remote_matches[write_idx] = *m;
                }
                write_idx += 1;
            }
        }
        if write_idx < count {
            for i in write_idx..limit {
                entry.remote_matches[i] = MatchEntry {
                    node_id: 0,
                    topic_hash: 0,
                    port: 0,
                    addr: [0u8; 4],
                };
            }
            entry.match_count = write_idx as u32;
            entry.response_gen.fetch_add(1, Ordering::Release);
            futex_wake(&entry.response_gen);
            topology_changed.store(true, Ordering::Release);
        }
    }
}

fn remove_matches_for_node(
    node_table: &mut [axon_core::daemon::discovery_shm::NodeTableEntry],
    dead_node_id: u64,
) {
    use std::sync::atomic::Ordering;

    for entry in node_table.iter_mut() {
        if entry.state.load(Ordering::Acquire) != 2 {
            continue;
        }
        let count = entry.match_count as usize;
        if count == 0 {
            continue;
        }
        let limit = std::cmp::min(count, MAX_MATCHES);
        let mut write_idx = 0usize;
        for read_idx in 0..limit {
            let m = &entry.remote_matches[read_idx];
            if m.node_id != dead_node_id {
                if write_idx != read_idx {
                    entry.remote_matches[write_idx] = *m;
                }
                write_idx += 1;
            }
        }
        if write_idx < count {
            for i in write_idx..limit {
                entry.remote_matches[i] = MatchEntry {
                    node_id: 0,
                    topic_hash: 0,
                    port: 0,
                    addr: [0u8; 4],
                };
            }
            entry.match_count = write_idx as u32;
            entry.response_gen.fetch_add(1, Ordering::Release);
            futex_wake(&entry.response_gen);
        }
    }
}

fn process_departed_nodes(shm: &ShmDiscovery, topo_flag: &AtomicBool) {
    use axon_core::daemon::discovery_shm::is_process_alive;
    let node_table = shm.node_table_mut();
    let mut local_channels_before = std::collections::HashSet::new();
    for entry in node_table.iter() {
        if entry.state.load(Ordering::Acquire) == 0 || entry.daemon_origin != 0 {
            continue;
        }
        let domain_id = entry.domain_id;
        for topic in entry
            .published_topics
            .iter()
            .take((entry.pub_count as usize).min(entry.published_topics.len()))
            .chain(
                entry
                    .subscribed_topics
                    .iter()
                    .take((entry.sub_count as usize).min(entry.subscribed_topics.len())),
            )
        {
            if topic.hash != 0 {
                local_channels_before.insert((domain_id, topic.hash));
            }
        }
    }
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut changed = false;
    let mut cleared_node_ids: Vec<u64> = Vec::new();
    for entry in node_table.iter_mut() {
        let state = entry.state.load(Ordering::Acquire);
        if state == 3 {
            let nid = entry.node_id;
            entry.state.store(0, Ordering::Release);
            entry.node_id = 0;
            entry.domain_id = 0;
            entry.pub_count = 0;
            entry.sub_count = 0;
            entry.match_count = 0;
            entry.pid = 0;
            entry.proc_starttime = 0;
            entry.daemon_origin = 0;
            entry.last_seen_secs = 0;
            entry.quic_addr_count = 0;
            entry.response_gen.store(0, Ordering::Release);
            entry.node_name = [0u8; MAX_NODE_NAME_LEN];
            entry.node_namespace = [0u8; MAX_NODE_NS_LEN];
            for t in entry.published_topics.iter_mut() {
                *t = axon_core::daemon::discovery_shm::TopicEntry {
                    hash: 0,
                    type_hash: 0,
                    qos_reliability: 0,
                    qos_durability: 0,
                    qos_history_kind: 0,
                    qos_history_depth: 0,
                    qos_deadline_sec: 0,
                    qos_deadline_nsec: 0,
                    qos_lifespan_sec: 0,
                    qos_lifespan_nsec: 0,
                    qos_liveliness: 0,
                    qos_liveliness_lease_sec: 0,
                    qos_liveliness_lease_nsec: 0,
                    topic_name: [0u8; MAX_TOPIC_NAME_LEN],
                    topic_type: [0u8; MAX_TOPIC_TYPE_LEN],
                    ..Default::default()
                };
            }
            for t in entry.subscribed_topics.iter_mut() {
                *t = axon_core::daemon::discovery_shm::TopicEntry {
                    hash: 0,
                    type_hash: 0,
                    qos_reliability: 0,
                    qos_durability: 0,
                    qos_history_kind: 0,
                    qos_history_depth: 0,
                    qos_deadline_sec: 0,
                    qos_deadline_nsec: 0,
                    qos_lifespan_sec: 0,
                    qos_lifespan_nsec: 0,
                    qos_liveliness: 0,
                    qos_liveliness_lease_sec: 0,
                    qos_liveliness_lease_nsec: 0,
                    topic_name: [0u8; MAX_TOPIC_NAME_LEN],
                    topic_type: [0u8; MAX_TOPIC_TYPE_LEN],
                    ..Default::default()
                };
            }
            for m in entry.remote_matches.iter_mut() {
                *m = MatchEntry {
                    node_id: 0,
                    topic_hash: 0,
                    port: 0,
                    addr: [0u8; 4],
                };
            }
            if nid != 0 {
                cleared_node_ids.push(nid);
            }
            changed = true;
        } else if state == 1 && entry.last_seen_secs > 0 {
            if now_secs.saturating_sub(entry.last_seen_secs) > 2 {
                let nid = entry.node_id;
                entry.state.store(0, Ordering::Release);
                entry.node_id = 0;
                entry.domain_id = 0;
                entry.pub_count = 0;
                entry.sub_count = 0;
                entry.match_count = 0;
                entry.pid = 0;
                entry.proc_starttime = 0;
                entry.daemon_origin = 0;
                entry.last_seen_secs = 0;
                entry.quic_addr_count = 0;
                entry.response_gen.store(0, Ordering::Release);
                entry.node_name = [0u8; MAX_NODE_NAME_LEN];
                entry.node_namespace = [0u8; MAX_NODE_NS_LEN];
                for t in entry.published_topics.iter_mut() {
                    *t = axon_core::daemon::discovery_shm::TopicEntry {
                        hash: 0,
                        type_hash: 0,
                        qos_reliability: 0,
                        qos_durability: 0,
                        qos_history_kind: 0,
                        qos_history_depth: 0,
                        qos_deadline_sec: 0,
                        qos_deadline_nsec: 0,
                        qos_lifespan_sec: 0,
                        qos_lifespan_nsec: 0,
                        qos_liveliness: 0,
                        qos_liveliness_lease_sec: 0,
                        qos_liveliness_lease_nsec: 0,
                        topic_name: [0u8; MAX_TOPIC_NAME_LEN],
                        topic_type: [0u8; MAX_TOPIC_TYPE_LEN],
                        ..Default::default()
                    };
                }
                for t in entry.subscribed_topics.iter_mut() {
                    *t = axon_core::daemon::discovery_shm::TopicEntry {
                        hash: 0,
                        type_hash: 0,
                        qos_reliability: 0,
                        qos_durability: 0,
                        qos_history_kind: 0,
                        qos_history_depth: 0,
                        qos_deadline_sec: 0,
                        qos_deadline_nsec: 0,
                        qos_lifespan_sec: 0,
                        qos_lifespan_nsec: 0,
                        qos_liveliness: 0,
                        qos_liveliness_lease_sec: 0,
                        qos_liveliness_lease_nsec: 0,
                        topic_name: [0u8; MAX_TOPIC_NAME_LEN],
                        topic_type: [0u8; MAX_TOPIC_TYPE_LEN],
                        ..Default::default()
                    };
                }
                for m in entry.remote_matches.iter_mut() {
                    *m = MatchEntry {
                        node_id: 0,
                        topic_hash: 0,
                        port: 0,
                        addr: [0u8; 4],
                    };
                }
                if nid != 0 {
                    cleared_node_ids.push(nid);
                }
                changed = true;
            }
        } else if state == 2 && entry.pid > 0 {
            if !is_process_alive(entry.pid, entry.proc_starttime) {
                let nid = entry.node_id;
                entry.state.store(0, Ordering::Release);
                entry.node_id = 0;
                entry.domain_id = 0;
                entry.pub_count = 0;
                entry.sub_count = 0;
                entry.match_count = 0;
                entry.pid = 0;
                entry.proc_starttime = 0;
                entry.daemon_origin = 0;
                entry.last_seen_secs = 0;
                entry.quic_addr_count = 0;
                entry.response_gen.store(0, Ordering::Release);
                entry.node_name = [0u8; MAX_NODE_NAME_LEN];
                entry.node_namespace = [0u8; MAX_NODE_NS_LEN];
                for t in entry.published_topics.iter_mut() {
                    *t = axon_core::daemon::discovery_shm::TopicEntry {
                        hash: 0,
                        type_hash: 0,
                        qos_reliability: 0,
                        qos_durability: 0,
                        qos_history_kind: 0,
                        qos_history_depth: 0,
                        qos_deadline_sec: 0,
                        qos_deadline_nsec: 0,
                        qos_lifespan_sec: 0,
                        qos_lifespan_nsec: 0,
                        qos_liveliness: 0,
                        qos_liveliness_lease_sec: 0,
                        qos_liveliness_lease_nsec: 0,
                        topic_name: [0u8; MAX_TOPIC_NAME_LEN],
                        topic_type: [0u8; MAX_TOPIC_TYPE_LEN],
                        ..Default::default()
                    };
                }
                for t in entry.subscribed_topics.iter_mut() {
                    *t = axon_core::daemon::discovery_shm::TopicEntry {
                        hash: 0,
                        type_hash: 0,
                        qos_reliability: 0,
                        qos_durability: 0,
                        qos_history_kind: 0,
                        qos_history_depth: 0,
                        qos_deadline_sec: 0,
                        qos_deadline_nsec: 0,
                        qos_lifespan_sec: 0,
                        qos_lifespan_nsec: 0,
                        qos_liveliness: 0,
                        qos_liveliness_lease_sec: 0,
                        qos_liveliness_lease_nsec: 0,
                        topic_name: [0u8; MAX_TOPIC_NAME_LEN],
                        topic_type: [0u8; MAX_TOPIC_TYPE_LEN],
                        ..Default::default()
                    };
                }
                for m in entry.remote_matches.iter_mut() {
                    *m = MatchEntry {
                        node_id: 0,
                        topic_hash: 0,
                        port: 0,
                        addr: [0u8; 4],
                    };
                }
                if nid != 0 {
                    cleared_node_ids.push(nid);
                }
                changed = true;
            } else {
                entry.last_seen_secs = now_secs;
            }
        } else if state == 2
            && entry.daemon_origin != 0
            && entry.last_seen_secs > 0
            && now_secs.saturating_sub(entry.last_seen_secs) > 30
        {
            let nid = entry.node_id;
            entry.state.store(0, Ordering::Release);
            entry.node_id = 0;
            entry.domain_id = 0;
            entry.pub_count = 0;
            entry.sub_count = 0;
            entry.match_count = 0;
            entry.pid = 0;
            entry.proc_starttime = 0;
            entry.daemon_origin = 0;
            entry.last_seen_secs = 0;
            entry.quic_addr_count = 0;
            entry.response_gen.store(0, Ordering::Release);
            entry.node_name = [0u8; MAX_NODE_NAME_LEN];
            entry.node_namespace = [0u8; MAX_NODE_NS_LEN];
            for t in entry.published_topics.iter_mut() {
                *t = axon_core::daemon::discovery_shm::TopicEntry {
                    hash: 0,
                    type_hash: 0,
                    qos_reliability: 0,
                    qos_durability: 0,
                    qos_history_kind: 0,
                    qos_history_depth: 0,
                    qos_deadline_sec: 0,
                    qos_deadline_nsec: 0,
                    qos_lifespan_sec: 0,
                    qos_lifespan_nsec: 0,
                    qos_liveliness: 0,
                    qos_liveliness_lease_sec: 0,
                    qos_liveliness_lease_nsec: 0,
                    topic_name: [0u8; MAX_TOPIC_NAME_LEN],
                    topic_type: [0u8; MAX_TOPIC_TYPE_LEN],
                    ..Default::default()
                };
            }
            for t in entry.subscribed_topics.iter_mut() {
                *t = axon_core::daemon::discovery_shm::TopicEntry {
                    hash: 0,
                    type_hash: 0,
                    qos_reliability: 0,
                    qos_durability: 0,
                    qos_history_kind: 0,
                    qos_history_depth: 0,
                    qos_deadline_sec: 0,
                    qos_deadline_nsec: 0,
                    qos_lifespan_sec: 0,
                    qos_lifespan_nsec: 0,
                    qos_liveliness: 0,
                    qos_liveliness_lease_sec: 0,
                    qos_liveliness_lease_nsec: 0,
                    topic_name: [0u8; MAX_TOPIC_NAME_LEN],
                    topic_type: [0u8; MAX_TOPIC_TYPE_LEN],
                    ..Default::default()
                };
            }
            for m in entry.remote_matches.iter_mut() {
                *m = MatchEntry {
                    node_id: 0,
                    topic_hash: 0,
                    port: 0,
                    addr: [0u8; 4],
                };
            }
            if nid != 0 {
                cleared_node_ids.push(nid);
            }
            changed = true;
        }
        let state = entry.state.load(Ordering::Acquire);
        if state == 2
            && entry.daemon_origin == 0
            && entry.node_id != 0
            && entry.last_seen_secs > 0
            && now_secs.saturating_sub(entry.last_seen_secs) > 10
        {
            let nid = entry.node_id;
            entry.state.store(0, Ordering::Release);
            entry.node_id = 0;
            entry.domain_id = 0;
            entry.pub_count = 0;
            entry.sub_count = 0;
            entry.match_count = 0;
            entry.pid = 0;
            entry.proc_starttime = 0;
            entry.daemon_origin = 0;
            entry.last_seen_secs = 0;
            entry.quic_addr_count = 0;
            entry.response_gen.store(0, Ordering::Release);
            entry.node_name = [0u8; MAX_NODE_NAME_LEN];
            entry.node_namespace = [0u8; MAX_NODE_NS_LEN];
            for t in entry.published_topics.iter_mut() {
                *t = axon_core::daemon::discovery_shm::TopicEntry {
                    hash: 0,
                    type_hash: 0,
                    qos_reliability: 0,
                    qos_durability: 0,
                    qos_history_kind: 0,
                    qos_history_depth: 0,
                    qos_deadline_sec: 0,
                    qos_deadline_nsec: 0,
                    qos_lifespan_sec: 0,
                    qos_lifespan_nsec: 0,
                    qos_liveliness: 0,
                    qos_liveliness_lease_sec: 0,
                    qos_liveliness_lease_nsec: 0,
                    topic_name: [0u8; MAX_TOPIC_NAME_LEN],
                    topic_type: [0u8; MAX_TOPIC_TYPE_LEN],
                    ..Default::default()
                };
            }
            for t in entry.subscribed_topics.iter_mut() {
                *t = axon_core::daemon::discovery_shm::TopicEntry {
                    hash: 0,
                    type_hash: 0,
                    qos_reliability: 0,
                    qos_durability: 0,
                    qos_history_kind: 0,
                    qos_history_depth: 0,
                    qos_deadline_sec: 0,
                    qos_deadline_nsec: 0,
                    qos_lifespan_sec: 0,
                    qos_lifespan_nsec: 0,
                    qos_liveliness: 0,
                    qos_liveliness_lease_sec: 0,
                    qos_liveliness_lease_nsec: 0,
                    topic_name: [0u8; MAX_TOPIC_NAME_LEN],
                    topic_type: [0u8; MAX_TOPIC_TYPE_LEN],
                    ..Default::default()
                };
            }
            for m in entry.remote_matches.iter_mut() {
                *m = MatchEntry {
                    node_id: 0,
                    topic_hash: 0,
                    port: 0,
                    addr: [0u8; 4],
                };
            }
            if nid != 0 {
                cleared_node_ids.push(nid);
            }
            changed = true;
        }
    }
    for nid in &cleared_node_ids {
        remove_matches_for_node(node_table, *nid);
    }
    if changed {
        let mut local_channels_after = std::collections::HashSet::new();
        for entry in node_table.iter() {
            if entry.state.load(Ordering::Acquire) == 0 || entry.daemon_origin != 0 {
                continue;
            }
            let domain_id = entry.domain_id;
            for topic in entry
                .published_topics
                .iter()
                .take((entry.pub_count as usize).min(entry.published_topics.len()))
                .chain(
                    entry
                        .subscribed_topics
                        .iter()
                        .take((entry.sub_count as usize).min(entry.subscribed_topics.len())),
                )
            {
                if topic.hash != 0 {
                    local_channels_after.insert((domain_id, topic.hash));
                }
            }
        }
        for (domain_id, topic_hash) in local_channels_before.difference(&local_channels_after) {
            let name = format!("/axon_domain_{domain_id}_topic_{topic_hash}");
            if let Ok(name) = CString::new(name) {
                let _ = nix::sys::mman::shm_unlink(name.as_c_str());
            }
        }
    }
    if changed {
        topo_flag.store(true, Ordering::Release);
        shm.header().generation.fetch_add(1, Ordering::Release);
        futex_wake(&shm.header().generation);
    }
}

fn main() {
    let mut cfg = parse_args();

    if let Err(e) = check_pid(&cfg.pid_file) {
        eprintln!("axon_daemon: {}", e);
        process::exit(1);
    }

    let (selected_port, quic_socket, listener) = match bind_daemon_endpoints(&cfg.port_candidates) {
        Ok(bound) => bound,
        Err(e) => {
            eprintln!("axon_daemon: {}", e);
            process::exit(1);
        }
    };
    cfg.port = selected_port;

    // Daemonize BEFORE creating the Session to avoid duplicating
    // file descriptors (UDP sockets, eventfds, SHM) across fork.
    if !cfg.foreground {
        if let Err(e) = daemonize() {
            eprintln!("axon_daemon: daemonize failed: {}", e);
            process::exit(1);
        }
    }

    let node_id = daemon_node_id();
    axon_core::axon_trace!(
        "event=daemon_identity daemon_id={} pid={} port={} security={:?}",
        node_id,
        process::id(),
        cfg.port,
        SecurityMode::from_env().unwrap_or(SecurityMode::Classic)
    );
    let security_mode = match SecurityMode::from_env() {
        Ok(mode) => mode,
        Err(error) => {
            eprintln!("axon_daemon: {error}");
            process::exit(1);
        }
    };
    let qkd_manager = if security_mode == SecurityMode::Qkd {
        match QkdDaemonManager::from_env() {
            Ok(manager) => {
                eprintln!(
                    "axon_daemon: QKD mode enabled for SAE {}",
                    manager.local_sae_id()
                );
                Some(Arc::new(manager))
            }
            Err(error) => {
                eprintln!("axon_daemon: QKD initialization failed: {error}");
                process::exit(1);
            }
        }
    } else {
        let _ = QkdKeyStore::purge();
        None
    };
    if let Err(error) = axon_core::security::validate_runtime() {
        eprintln!("axon_daemon: invalid security configuration: {error}");
        process::exit(1);
    }
    eprintln!("axon_daemon: security mode {}", security_mode.name());
    let mut session = Session::new(node_id, 0);

    if let Err(e) = write_pid(&cfg.pid_file) {
        eprintln!("axon_daemon: {}", e);
        process::exit(1);
    }

    // Warm up the graph cache: trigger wait_for_discovery so the first
    // XML-RPC request doesn't return an empty graph. This is especially
    // important in Docker where discovery can be slower.
    let _ = session.get_node_names();
    let _ = session.get_topic_names_and_types();

    let mut sigset: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut sigset);
        libc::sigaddset(&mut sigset, libc::SIGTERM);
        libc::sigaddset(&mut sigset, libc::SIGINT);
        libc::pthread_sigmask(libc::SIG_BLOCK, &sigset, std::ptr::null_mut());
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    std::thread::spawn(move || {
        unsafe {
            let mut sig = 0i32;
            libc::sigwait(&sigset, &mut sig);
        }
        r.store(false, Ordering::SeqCst);
    });

    // Create SHM discovery segment (remove stale if any)
    ShmDiscovery::destroy(SHM_NAME).ok();
    let shm = Arc::new(
        ShmDiscovery::create(SHM_NAME, MAX_NODES as u32, MAX_TOPICS_PER_NODE as u32)
            .expect("failed to create discovery SHM"),
    );

    session.set_daemon_shm(
        ShmDiscovery::open(SHM_NAME).expect("open SHM for session"),
        0,
        true,
    );

    let topology_changed = Arc::new(AtomicBool::new(false));
    let topo_changed_monitor = topology_changed.clone();
    let topo_changed_sync = topology_changed.clone();

    // Run discovery monitoring in a background thread
    let r = running.clone();
    let shm_monitor = shm.clone();
    std::thread::spawn(move || {
        while r.load(Ordering::SeqCst) {
            process_pending_registrations(&shm_monitor, &topo_changed_monitor);
            process_topic_updates(&shm_monitor, &topo_changed_monitor);
            process_departed_nodes(&shm_monitor, &topo_changed_monitor);
            std::thread::sleep(Duration::from_millis(10));
        }
    });

    // Create QUIC endpoint for daemon↔daemon sync
    install_quic_crypto();
    let (cert, key) = generate_self_signed_certs();
    let server_config = configure_server(cert, key);

    // Spawn QUIC connection acceptor (create endpoint inside tokio runtime)
    let r4 = running.clone();
    let shm_quic = shm.clone();
    let qkd_accept = qkd_manager.clone();
    let security_mode_accept = security_mode;
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime for daemon QUIC");
        let _guard = rt.enter();
        let daemon_endpoint = Endpoint::new(
            EndpointConfig::default(),
            Some(server_config),
            quic_socket,
            Arc::new(TokioRuntime),
        )
        .expect("create QUIC daemon endpoint");
        drop(_guard);
        rt.block_on(async {
            while r4.load(Ordering::SeqCst) {
                match tokio::time::timeout(
                    Duration::from_secs(1),
                    daemon_endpoint.accept(),
                ).await {
                    Ok(Some(incoming)) => {
                        let shm = shm_quic.clone();
                        let qkd = qkd_accept.clone();
                        let mode = security_mode_accept;
                        tokio::spawn(async move {
                            match incoming.await {
                                Ok(connection) => {
                                    eprintln!("axon_daemon: peer QUIC connection accepted");
                                    while let Ok(stream) = connection.accept_bi().await {
                                        let (mut send, mut recv) = stream;
                                        match recv.read_to_end(1048576).await {
                                            Ok(data) => {
                                                let sync_allowed =
                                                    if mode == SecurityMode::Qkd {
                                                        match (
                                                            qkd.as_ref(),
                                                            axon_core::daemon::peer_sync::sync_request_daemon_id(&data),
                                                        ) {
                                                            (
                                                                Some(manager),
                                                                Ok(Some(remote_daemon_id)),
                                                            ) => manager
                                                                .has_active_session(remote_daemon_id),
                                                            _ => false,
                                                        }
                                                    } else {
                                                        true
                                                    };
                                                if sync_allowed {
                                                    if let Err(error) =
                                                        axon_core::daemon::peer_sync::handle_sync_message(
                                                            &shm, 0, &data, &mut send,
                                                        )
                                                        .await
                                                    {
                                                        eprintln!(
                                                            "axon_daemon: sync handler error: {}",
                                                            error
                                                        );
                                                    }
                                                } else {
                                                    eprintln!(
                                                        "axon_daemon: rejected graph sync without an active QKD TLS session"
                                                    );
                                                }
                                                let _ = send.finish();
                                            }
                                            Err(e) => {
                                                eprintln!("axon_daemon: stream read error: {}", e);
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("axon_daemon: QUIC handshake failed: {}", e);
                                }
                            }
                        });
                    }
                    Ok(None) => break,
                    Err(_) => continue, // timeout, check running
                }
            }
        });
    });

    // Start daemon-to-daemon UDP multicast discovery
    let (hello_tx, hello_rx) = std::sync::mpsc::channel::<HelloDaemonMessage>();
    let (qkd_control_tx, qkd_control_rx) = std::sync::mpsc::channel::<QkdControlMessage>();
    if let Err(e) = start_daemon_multicast_listener(DAEMON_MULTICAST_PORT, hello_tx, qkd_control_tx)
    {
        eprintln!("axon_daemon: multicast listener: {}", e);
    }

    let hello_socket = UdpSocket::bind("0.0.0.0:0").expect("hello socket");
    let hello_sockets = bind_per_interface_sockets();
    let static_daemon_peers = parse_static_daemon_peers();
    let configured_peer_sae = env::var("AXON_QKD_PEER_SAE_ID")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if !static_daemon_peers.is_empty() {
        eprintln!(
            "axon_daemon: static daemon peers: {:?}",
            static_daemon_peers
        );
    }

    // Periodic HelloDaemon sender
    let daemon_id = node_id;
    let local_qkd_sae = qkd_manager
        .as_ref()
        .map(|manager| manager.local_sae_id().to_string());
    let r2 = running.clone();
    let shm_hello = shm.clone();
    let unicast_hello_peers = static_daemon_peers.clone();
    std::thread::spawn(move || {
        // The generation identifies topology revisions, not heartbeats. Peers
        // still receive periodic HELLOs for liveness, but only a changed
        // generation triggers an expensive daemon-to-daemon graph sync.
        let mut hello_gen = 1u64;
        let mut last_sent = std::time::Instant::now();
        while r2.load(Ordering::SeqCst) {
            let changed = topology_changed.swap(false, Ordering::Acquire);
            let should_send =
                last_sent.elapsed() >= Duration::from_millis(DAEMON_HELLO_INTERVAL_MS) || changed;
            if should_send {
                if changed {
                    hello_gen = hello_gen.wrapping_add(1);
                    if hello_gen == 0 {
                        hello_gen = 1;
                    }
                }
                let domains = active_domains(&shm_hello);
                let hello = HelloDaemon {
                    daemon_id,
                    quic_port: cfg.port,
                    domains,
                    generation: hello_gen,
                    qkd_sae_id: local_qkd_sae.clone(),
                    security_mode,
                };
                if hello_sockets.is_empty() {
                    send_hello_multicast(&hello_socket, &hello, DAEMON_MULTICAST_PORT);
                } else {
                    send_hello_multicast_all_interfaces(
                        &hello_sockets,
                        &hello,
                        DAEMON_MULTICAST_PORT,
                    );
                }
                // Docker and some routed networks do not forward multicast.
                // Send the same real HELLO directly to configured peers so
                // both ends agree on daemon identity and QKD initiator order.
                if !unicast_hello_peers.is_empty() {
                    let encoded = encode_hello_daemon(&hello);
                    for peer in &unicast_hello_peers {
                        let target = SocketAddr::new(peer.ip(), DAEMON_MULTICAST_PORT);
                        if let Err(error) = hello_socket.send_to(&encoded, target) {
                            eprintln!("axon_daemon: HELLO unicast to {} failed: {}", target, error);
                        }
                    }
                }
                last_sent = std::time::Instant::now();
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    });

    // Process incoming HelloDaemon messages — connect to peer daemons, sync topology
    let r3 = running.clone();
    let shm_sync = shm.clone();
    let daemon_id_sync = daemon_id;
    let shm_sync2 = shm.clone();
    let qkd_sync = qkd_manager.clone();
    let fallback_peer_sae = configured_peer_sae.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime for daemon sync");
        let _guard = rt.enter();
        let sync_socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                eprintln!("axon_daemon: cannot bind sync socket: {}", e);
                return;
            }
        };
        let sync_endpoint = match quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            sync_socket,
            Arc::new(TokioRuntime),
        ) {
            Ok(mut ep) => {
                if security_mode == SecurityMode::Classic {
                    ep.set_default_client_config(
                        configure_client_for_daemon(None)
                            .expect("classic daemon QUIC client config"),
                    );
                }
                ep
            }
            Err(e) => {
                eprintln!("axon_daemon: cannot create sync endpoint: {}", e);
                return;
            }
        };
        drop(_guard);
        let qkd_control_socket =
            Arc::new(UdpSocket::bind("0.0.0.0:0").expect("QKD control socket"));

        let mut known_peers = KnownPeers::new();

        while r3.load(Ordering::SeqCst) {
            while let Ok(control) = qkd_control_rx.try_recv() {
                let Some(manager) = qkd_sync.as_ref() else {
                    continue;
                };
                match control.data.first().copied() {
                    Some(axon_core::qkd::MSG_QKD_KEY_ANNOUNCE) => {
                        let response = match axon_core::qkd::decode_key_announcement(&control.data)
                        {
                            Ok(announcement) => {
                                // Multicast is looped back to the sender. Do
                                // not ask our own KME for a dec_keys copy of
                                // an announcement we just emitted: QuKayDee
                                // correctly rejects self-keys with 403.
                                if announcement.sae_id == manager.local_sae_id() {
                                    continue;
                                }
                                match rt.block_on(manager.accept_inbound(
                                    announcement.daemon_id,
                                    &announcement.sae_id,
                                    &announcement.key_id,
                                )) {
                                    Ok(()) => {
                                        eprintln!(
                                            "axon_daemon: imported QKD key {} for daemon {}",
                                            announcement.key_id, announcement.daemon_id
                                        );
                                        // Force one fresh graph synchronization now
                                        // that the QKD session can authenticate QUIC.
                                        known_peers.remove(&announcement.daemon_id);
                                        axon_core::qkd::encode_key_ack(&announcement.key_id)
                                            .unwrap_or_else(|error| {
                                                axon_core::qkd::encode_key_error(&error)
                                            })
                                    }
                                    Err(error) => axon_core::qkd::encode_key_error(&error),
                                }
                            }
                            Err(error) => axon_core::qkd::encode_key_error(&error),
                        };
                        let target = SocketAddr::new(control.src_addr.ip(), DAEMON_MULTICAST_PORT);
                        let _ = qkd_control_socket.send_to(&response, target);
                    }
                    Some(axon_core::qkd::MSG_QKD_KEY_ACK) => {
                        match axon_core::qkd::decode_key_ack(&control.data) {
                            Ok(key_id) => {
                                if let Some(remote_daemon_id) =
                                    manager.activate_outbound_by_key_id(&key_id)
                                {
                                    eprintln!(
                                        "axon_daemon: QKD session {} established with daemon {}",
                                        key_id, remote_daemon_id
                                    );
                                    known_peers.remove(&remote_daemon_id);
                                }
                            }
                            Err(error) => eprintln!("axon_daemon: QKD ACK rejected: {error}"),
                        }
                    }
                    Some(axon_core::qkd::MSG_QKD_KEY_ERROR) => {
                        if let Err(error) = axon_core::qkd::decode_key_ack(&control.data) {
                            eprintln!("axon_daemon: {error}");
                        }
                    }
                    _ => {}
                }
            }
            while let Ok(msg) = hello_rx.try_recv() {
                let HelloDaemonMessage { hello, src_addr } = msg;
                if hello.daemon_id == daemon_id_sync {
                    continue;
                }
                if hello.security_mode != security_mode {
                    eprintln!(
                        "axon_daemon: ignoring daemon {} with incompatible security profile {} (local {})",
                        hello.daemon_id,
                        hello.security_mode.name(),
                        security_mode.name()
                    );
                    continue;
                }
                let peer_addr = SocketAddr::new(src_addr.ip(), hello.quic_port);
                let now = std::time::Instant::now();
                let mut local_domains = active_domains(&shm_sync);
                local_domains.sort_unstable();
                // A peer sends the same HELLO generation on every usable
                // interface and on every heartbeat. Process a topology
                // revision once, but re-evaluate an unchanged peer when this
                // daemon joins or leaves a domain. That second condition is
                // required when the lower-ID QKD initiator joins after it
                // already observed the peer's HELLO.
                let topology_changed = record_peer_hello(
                    &mut known_peers,
                    hello.daemon_id,
                    peer_addr,
                    hello.generation,
                    &local_domains,
                    now,
                );
                let qkd_bootstrap_pending = qkd_sync
                    .as_ref()
                    .is_some_and(|manager| !manager.has_active_session(hello.daemon_id));
                if !topology_changed && !qkd_bootstrap_pending {
                    continue;
                }
                eprintln!(
                    "axon_daemon: discovered peer daemon {} at {}:{}",
                    hello.daemon_id,
                    src_addr.ip(),
                    hello.quic_port
                );
                let intersection_domains: Vec<u32> = {
                    hello
                        .domains
                        .iter()
                        .filter(|d| local_domains.contains(d))
                        .copied()
                        .collect()
                };
                if intersection_domains.is_empty() {
                    continue;
                }
                eprintln!(
                    "axon_daemon: syncing domains {:?} with daemon {}",
                    intersection_domains, hello.daemon_id
                );
                let daemon_clone = sync_endpoint.clone();
                let shm = shm_sync.clone();
                let daemon_id_val = hello.daemon_id;
                let local_daemon_id = daemon_id_sync;
                let qkd = qkd_sync.clone();
                let qkd_control_sender = qkd_control_socket.clone();
                let remote_qkd_sae = hello
                    .qkd_sae_id
                    .clone()
                    .or_else(|| fallback_peer_sae.clone());
                let sync_succeeded = rt.block_on(async move {
                    if let Some(manager) = qkd.as_ref() {
                        if !manager.has_active_session(daemon_id_val) {
                            if local_daemon_id < daemon_id_val {
                                let Some(remote_sae_id) = remote_qkd_sae.as_deref() else {
                                    eprintln!(
                                        "axon_daemon: peer daemon {} did not advertise a QKD SAE ID",
                                        daemon_id_val
                                    );
                                    return false;
                                };
                                match manager
                                    .prepare_outbound(daemon_id_val, remote_sae_id)
                                    .await
                                    .and_then(|session| {
                                        axon_core::qkd::encode_key_announcement(
                                            &axon_core::qkd::QkdKeyAnnouncement {
                                                daemon_id: local_daemon_id,
                                                sae_id: manager.local_sae_id().to_string(),
                                                key_id: session.key_id.clone(),
                                            },
                                        )
                                    }) {
                                    Ok(announcement) => {
                                        let target = SocketAddr::new(
                                            peer_addr.ip(),
                                            DAEMON_MULTICAST_PORT,
                                        );
                                        let _ =
                                            qkd_control_sender.send_to(&announcement, target);
                                    }
                                    Err(error) => eprintln!(
                                        "axon_daemon: QKD key setup for daemon {} failed: {}",
                                        daemon_id_val, error
                                    ),
                                }
                            }
                            return false;
                        }
                    }

                    let connecting = match configure_client_for_daemon(Some(daemon_id_val)) {
                        Ok(config) => daemon_clone.connect_with(config, peer_addr, "axon"),
                        Err(error) => {
                            eprintln!(
                                "axon_daemon: client security config for daemon {} failed: {}",
                                daemon_id_val, error
                            );
                            return false;
                        }
                    };
                    match connecting {
                        Ok(connecting) => {
                            match tokio::time::timeout(Duration::from_secs(5), connecting).await {
                                Ok(Ok(connection)) => {
                                    let mut synced_all = true;
                                    eprintln!("axon_daemon: QUIC connected to peer daemon {}", daemon_id_val);
                                    for domain_id in &intersection_domains {
                                        let local_nodes =
                                            axon_core::daemon::peer_sync::collect_domain_nodes(
                                                &shm,
                                                *domain_id,
                                            );
                                        let req = axon_core::daemon::peer_sync::encode_sync_request_with_nodes(
                                            *domain_id,
                                            local_daemon_id,
                                            &local_nodes,
                                        );
                                        match connection.open_bi().await {
                                            Ok((mut send, mut recv)) => {
                                                if let Err(e) = send.write_all(&req).await {
                                                    eprintln!("axon_daemon: sync request write failed: {}", e);
                                                    synced_all = false;
                                                    continue;
                                                }
                                                let _ = send.finish();
                                                match recv.read_to_end(1048576).await {
                                                    Ok(resp_data) => {
                                                        match axon_core::daemon::peer_sync::decode_sync_response(&resp_data) {
                                                            Ok((dom, nodes)) => {
                                                                eprintln!("axon_daemon: sync response from daemon {}: {} nodes in domain {}",
                                                                    daemon_id_val, nodes.len(), dom);
                                                                {
                                                                let node_table = shm.node_table_mut();
                                    let max = std::cmp::min(MAX_NODES, node_table.len());
                                                                let mut cleared_node_ids: Vec<u64> = Vec::new();
                                                                for entry in node_table.iter_mut() {
                                                                    if entry.state.load(Ordering::Acquire) != 0
                                                                        && entry.daemon_origin == daemon_id_val
                                                                        && !nodes.iter().any(|node| node.node_id == entry.node_id)
                                                                    {
                                                                        let nid = entry.node_id;
                                                                        entry.state.store(0, Ordering::Release);
                                                                        entry.node_id = 0;
                                                                        entry.domain_id = 0;
                                                                        entry.pub_count = 0;
                                                                        entry.sub_count = 0;
                                                                        entry.match_count = 0;
                                                                        entry.daemon_origin = 0;
                                                                        entry.pid = 0;
                                                                        entry.last_seen_secs = 0;
                                                                        entry.quic_addr_count = 0;
                                                                        entry.response_gen.store(0, Ordering::Release);
                                                                        entry.node_name = [0u8; MAX_NODE_NAME_LEN];
                                                                        entry.node_namespace = [0u8; MAX_NODE_NS_LEN];
                                                                        for t in entry.published_topics.iter_mut() { *t = axon_core::daemon::discovery_shm::TopicEntry {
    hash: 0, type_hash: 0,
    qos_reliability: 0, qos_durability: 0, qos_history_kind: 0, qos_history_depth: 0,
    qos_deadline_sec: 0, qos_deadline_nsec: 0,
    qos_lifespan_sec: 0, qos_lifespan_nsec: 0,
    qos_liveliness: 0, qos_liveliness_lease_sec: 0, qos_liveliness_lease_nsec: 0,
    topic_name: [0u8; MAX_TOPIC_NAME_LEN], topic_type: [0u8; MAX_TOPIC_TYPE_LEN],
..Default::default()
}; }
                                                                        for t in entry.subscribed_topics.iter_mut() { *t = axon_core::daemon::discovery_shm::TopicEntry {
    hash: 0, type_hash: 0,
    qos_reliability: 0, qos_durability: 0, qos_history_kind: 0, qos_history_depth: 0,
    qos_deadline_sec: 0, qos_deadline_nsec: 0,
    qos_lifespan_sec: 0, qos_lifespan_nsec: 0,
    qos_liveliness: 0, qos_liveliness_lease_sec: 0, qos_liveliness_lease_nsec: 0,
    topic_name: [0u8; MAX_TOPIC_NAME_LEN], topic_type: [0u8; MAX_TOPIC_TYPE_LEN],
..Default::default()
}; }
                                                                        for m in entry.remote_matches.iter_mut() { *m = MatchEntry { node_id: 0, topic_hash: 0, port: 0, addr: [0u8; 4] }; }
                                                                        if nid != 0 {
                                                                            cleared_node_ids.push(nid);
                                                                        }
                                                                    }
                                                                }
                                                                for nid in &cleared_node_ids {
                                                                    remove_matches_for_node(node_table, *nid);
                                                                }
                                                                for node in &nodes {
                                                                    let existing_slot = (0..max).find(|idx| {
                                                                        node_table[*idx].state.load(Ordering::Acquire) != 0
                                                                            && node_table[*idx].node_id == node.node_id
                                                                    });
                                                                    let slot = existing_slot.or_else(|| (0..max).find(|idx| {
                                                                        node_table[*idx].state.load(Ordering::Acquire) == 0
                                                                    }));
                                                                    if let Some(idx) = slot {
                                                                        let endpoints_changed = existing_slot
                                                                            .map(|existing| !axon_core::daemon::peer_sync::peer_node_endpoints_match(
                                                                                &node_table[existing],
                                                                                node,
                                                                            ))
                                                                            .unwrap_or(false);
                                                                        if endpoints_changed {
                                                                            remove_matches_for_node(node_table, node.node_id);
                                                                        }
                                                                        let entry = &mut node_table[idx];
                                                                        let is_new = existing_slot.is_none();
                                                                        entry.state.store(2, Ordering::Release);
                                                                        entry.node_id = node.node_id;
                                                                        entry.domain_id = node.domain_id;
                                                                        entry.pid = 0;
                                                                        entry.quic_port = node.quic_port;
                                                                        let addr_count = node.quic_addrs.len().min(MAX_QUIC_ADDRS);
                                                                        for (k, a) in node.quic_addrs.iter().take(addr_count).enumerate() {
                                                                            entry.quic_addrs[k] = *a;
                                                                        }
                                                                        entry.quic_addr_count = addr_count as u32;
                                                                        entry.daemon_origin = daemon_id_val;
                                                                        entry.last_seen_secs = std::time::SystemTime::now()
                                                                            .duration_since(std::time::UNIX_EPOCH)
                                                                            .unwrap_or_default()
                                                                            .as_secs();
                                                                        entry.pub_count = std::cmp::min(node.published_topics.len() as u32, MAX_TOPICS_PER_NODE as u32);
                                                                        entry.sub_count = std::cmp::min(node.subscribed_topics.len() as u32, MAX_TOPICS_PER_NODE as u32);
                                                                        for (k, topic) in node.published_topics.iter().take(MAX_TOPICS_PER_NODE).enumerate() {
                                                                            let mut name_buf = [0u8; MAX_TOPIC_NAME_LEN];
                                                                            let name_bytes = topic.name.as_bytes();
                                                                            let copy = name_bytes.len().min(MAX_TOPIC_NAME_LEN - 1);
                                                                            name_buf[..copy].copy_from_slice(&name_bytes[..copy]);
                                                                            let mut type_buf = [0u8; MAX_TOPIC_TYPE_LEN];
                                                                            let type_bytes = topic.topic_type.as_bytes();
                                                                            let copy = type_bytes.len().min(MAX_TOPIC_TYPE_LEN - 1);
                                                                            type_buf[..copy].copy_from_slice(&type_bytes[..copy]);
                                                                            let mut node_name_buf = [0u8; MAX_NODE_NAME_LEN];
                                                                            let node_name_bytes = topic.node_name.as_bytes();
                                                                            let copy = node_name_bytes.len().min(MAX_NODE_NAME_LEN - 1);
                                                                            node_name_buf[..copy].copy_from_slice(&node_name_bytes[..copy]);
                                                                            let mut node_ns_buf = [0u8; MAX_NODE_NS_LEN];
                                                                            let node_ns_bytes = topic.node_namespace.as_bytes();
                                                                            let copy = node_ns_bytes.len().min(MAX_NODE_NS_LEN - 1);
                                                                            node_ns_buf[..copy].copy_from_slice(&node_ns_bytes[..copy]);
                                                                            entry.published_topics[k] = axon_core::daemon::discovery_shm::TopicEntry {
                                                                                hash: topic.hash,
                                                                                type_hash: topic.type_hash,
                                                                                qos_reliability: topic.qos_reliability,
                                                                                qos_durability: topic.qos_durability,
                                                                                qos_history_kind: topic.qos_history_kind,
                                                                                qos_history_depth: topic.qos_history_depth,
                                                                                qos_deadline_sec: topic.qos_deadline_sec,
                                                                                qos_deadline_nsec: topic.qos_deadline_nsec,
                                                                                qos_lifespan_sec: topic.qos_lifespan_sec,
                                                                                qos_lifespan_nsec: topic.qos_lifespan_nsec,
                                                                                qos_liveliness: topic.qos_liveliness,
                                                                                qos_liveliness_lease_sec: topic.qos_liveliness_lease_sec,
                                                                                qos_liveliness_lease_nsec: topic.qos_liveliness_lease_nsec,
                                                                                topic_name: name_buf,
                                                                                topic_type: type_buf,
                                                                                node_name: node_name_buf,
                                                                                node_namespace: node_ns_buf,
                                                                            };
                                                                        }
                                                                        for (k, topic) in node.subscribed_topics.iter().take(MAX_TOPICS_PER_NODE).enumerate() {
                                                                            let mut name_buf = [0u8; MAX_TOPIC_NAME_LEN];
                                                                            let name_bytes = topic.name.as_bytes();
                                                                            let copy = name_bytes.len().min(MAX_TOPIC_NAME_LEN - 1);
                                                                            name_buf[..copy].copy_from_slice(&name_bytes[..copy]);
                                                                            let mut type_buf = [0u8; MAX_TOPIC_TYPE_LEN];
                                                                            let type_bytes = topic.topic_type.as_bytes();
                                                                            let copy = type_bytes.len().min(MAX_TOPIC_TYPE_LEN - 1);
                                                                            type_buf[..copy].copy_from_slice(&type_bytes[..copy]);
                                                                            let mut node_name_buf = [0u8; MAX_NODE_NAME_LEN];
                                                                            let node_name_bytes = topic.node_name.as_bytes();
                                                                            let copy = node_name_bytes.len().min(MAX_NODE_NAME_LEN - 1);
                                                                            node_name_buf[..copy].copy_from_slice(&node_name_bytes[..copy]);
                                                                            let mut node_ns_buf = [0u8; MAX_NODE_NS_LEN];
                                                                            let node_ns_bytes = topic.node_namespace.as_bytes();
                                                                            let copy = node_ns_bytes.len().min(MAX_NODE_NS_LEN - 1);
                                                                            node_ns_buf[..copy].copy_from_slice(&node_ns_bytes[..copy]);
                                                                            entry.subscribed_topics[k] = axon_core::daemon::discovery_shm::TopicEntry {
                                                                                hash: topic.hash,
                                                                                type_hash: topic.type_hash,
                                                                                qos_reliability: topic.qos_reliability,
                                                                                qos_durability: topic.qos_durability,
                                                                                qos_history_kind: topic.qos_history_kind,
                                                                                qos_history_depth: topic.qos_history_depth,
                                                                                qos_deadline_sec: topic.qos_deadline_sec,
                                                                                qos_deadline_nsec: topic.qos_deadline_nsec,
                                                                                qos_lifespan_sec: topic.qos_lifespan_sec,
                                                                                qos_lifespan_nsec: topic.qos_lifespan_nsec,
                                                                                qos_liveliness: topic.qos_liveliness,
                                                                                qos_liveliness_lease_sec: topic.qos_liveliness_lease_sec,
                                                                                qos_liveliness_lease_nsec: topic.qos_liveliness_lease_nsec,
                                                                                topic_name: name_buf,
                                                                                topic_type: type_buf,
                                                                                node_name: node_name_buf,
                                                                                node_namespace: node_ns_buf,
                                                                            };
                                                                        }
                                                                        {
                                                                            let mut name_buf = [0u8; MAX_NODE_NAME_LEN];
                                                                            let name_bytes = node.node_name.as_bytes();
                                                                            let copy = name_bytes.len().min(MAX_NODE_NAME_LEN - 1);
                                                                            name_buf[..copy].copy_from_slice(&name_bytes[..copy]);
                                                                            entry.node_name = name_buf;
                                                                        }
                                                                        {
                                                                            let mut ns_buf = [0u8; MAX_NODE_NS_LEN];
                                                                            let ns_bytes = node.node_namespace.as_bytes();
                                                                            let copy = ns_bytes.len().min(MAX_NODE_NS_LEN - 1);
                                                                            ns_buf[..copy].copy_from_slice(&ns_bytes[..copy]);
                                                                            entry.node_namespace = ns_buf;
                                                                        }
                                                                        if is_new {
                                                                            entry.match_count = 0;
                                                                            entry.response_gen.store(0, Ordering::Release);
                                                                        }
                                                                    }
                                                                }
                                                                let hdr = shm.header();
                                                                hdr.generation.fetch_add(1, Ordering::Release);
                                                                futex_wake(&hdr.generation);
                                                            }
                                                                process_topic_updates(&shm, &std::sync::atomic::AtomicBool::new(false));
                                                            }
                                                            Err(error) => {
                                                                synced_all = false;
                                                                eprintln!(
                                                                    "axon_daemon: invalid sync response from daemon {}: {}",
                                                                    daemon_id_val, error
                                                                );
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        synced_all = false;
                                                        eprintln!("axon_daemon: sync response read failed: {}", e);
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                synced_all = false;
                                                eprintln!("axon_daemon: sync bidir open failed: {}", e);
                                                break;
                                            }
                                        }
                                    }
                                    connection.close(0u32.into(), b"done");
                                    synced_all
                                }
                                Ok(Err(e)) => {
                                    eprintln!("axon_daemon: QUIC handshake with {} failed: {}", peer_addr, e);
                                    false
                                }
                                Err(_) => {
                                    eprintln!("axon_daemon: QUIC timeout connecting to {}", peer_addr);
                                    false
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("axon_daemon: QUIC connect to {} failed: {}", peer_addr, e);
                            false
                        }
                    }
                });
                if !sync_succeeded {
                    // A QKD receiver can complete its TLS handshake just before
                    // the initiator processes the ACK.  The peer then rejects
                    // that first graph push.  Forget the attempted generation
                    // so the next HELLO retries after both sides are active.
                    known_peers.remove(&daemon_id_val);
                }
            }
            let now = std::time::Instant::now();
            let stale: Vec<u64> = known_peers
                .iter()
                .filter(|(_, (_, _, _, t))| now.duration_since(*t) > Duration::from_secs(10))
                .map(|(id, _)| *id)
                .collect();
            for id in stale {
                eprintln!("axon_daemon: removing stale peer daemon {}", id);
                known_peers.remove(&id);
                if let Some(manager) = qkd_sync.as_ref() {
                    manager.remove_session(id);
                }
                let mut cleared_node_ids: Vec<u64> = Vec::new();
                let node_table = shm_sync2.node_table_mut();
                for entry in node_table.iter_mut() {
                    let s = entry.state.load(Ordering::Acquire);
                    if (s == 2 || s == 1) && entry.daemon_origin == id && entry.pid == 0 {
                        let nid = entry.node_id;
                        entry.state.store(0, Ordering::Release);
                        entry.node_id = 0;
                        entry.domain_id = 0;
                        entry.pub_count = 0;
                        entry.sub_count = 0;
                        entry.match_count = 0;
                        entry.daemon_origin = 0;
                        entry.pid = 0;
                        entry.last_seen_secs = 0;
                        entry.quic_addr_count = 0;
                        entry.response_gen.store(0, Ordering::Release);
                        entry.node_name = [0u8; MAX_NODE_NAME_LEN];
                        entry.node_namespace = [0u8; MAX_NODE_NS_LEN];
                        for t in entry.published_topics.iter_mut() {
                            *t = axon_core::daemon::discovery_shm::TopicEntry {
                                hash: 0,
                                type_hash: 0,
                                qos_reliability: 0,
                                qos_durability: 0,
                                qos_history_kind: 0,
                                qos_history_depth: 0,
                                qos_deadline_sec: 0,
                                qos_deadline_nsec: 0,
                                qos_lifespan_sec: 0,
                                qos_lifespan_nsec: 0,
                                qos_liveliness: 0,
                                qos_liveliness_lease_sec: 0,
                                qos_liveliness_lease_nsec: 0,
                                topic_name: [0u8; MAX_TOPIC_NAME_LEN],
                                topic_type: [0u8; MAX_TOPIC_TYPE_LEN],
                                ..Default::default()
                            };
                        }
                        for t in entry.subscribed_topics.iter_mut() {
                            *t = axon_core::daemon::discovery_shm::TopicEntry {
                                hash: 0,
                                type_hash: 0,
                                qos_reliability: 0,
                                qos_durability: 0,
                                qos_history_kind: 0,
                                qos_history_depth: 0,
                                qos_deadline_sec: 0,
                                qos_deadline_nsec: 0,
                                qos_lifespan_sec: 0,
                                qos_lifespan_nsec: 0,
                                qos_liveliness: 0,
                                qos_liveliness_lease_sec: 0,
                                qos_liveliness_lease_nsec: 0,
                                topic_name: [0u8; MAX_TOPIC_NAME_LEN],
                                topic_type: [0u8; MAX_TOPIC_TYPE_LEN],
                                ..Default::default()
                            };
                        }
                        for m in entry.remote_matches.iter_mut() {
                            *m = MatchEntry {
                                node_id: 0,
                                topic_hash: 0,
                                port: 0,
                                addr: [0u8; 4],
                            };
                        }
                        if nid != 0 {
                            cleared_node_ids.push(nid);
                        }
                    }
                }
                for nid in &cleared_node_ids {
                    remove_matches_for_node(node_table, *nid);
                }
                let hdr = shm_sync2.header();
                hdr.generation.fetch_add(1, Ordering::Release);
                futex_wake(&hdr.generation);
                topo_changed_sync.store(true, Ordering::Release);
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    });

    let addr = format!("127.0.0.1:{}", cfg.port);

    eprintln!("axon_daemon: listening on {} (PID {})", addr, process::id());

    listener.set_nonblocking(true).ok();
    while running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                handle_client(&session, stream);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    remove_pid(&cfg.pid_file);
    if security_mode == SecurityMode::Qkd {
        if let Some(manager) = qkd_manager.as_ref() {
            manager.clear_sessions();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_hello_only_syncs_new_topology_generations() {
        let daemon_id = 42;
        let addr_a: SocketAddr = "192.168.1.10:7402".parse().unwrap();
        let addr_b: SocketAddr = "10.0.0.10:7402".parse().unwrap();
        let started = Instant::now();
        let mut peers = KnownPeers::new();

        assert!(record_peer_hello(
            &mut peers,
            daemon_id,
            addr_a,
            1,
            &[],
            started
        ));
        assert!(!record_peer_hello(
            &mut peers,
            daemon_id,
            addr_b,
            1,
            &[],
            started + Duration::from_millis(10)
        ));
        assert!(!record_peer_hello(
            &mut peers,
            daemon_id,
            addr_a,
            0,
            &[],
            started + Duration::from_millis(20)
        ));
        assert_eq!(peers[&daemon_id].1, 1);
        assert!(record_peer_hello(
            &mut peers,
            daemon_id,
            addr_a,
            1,
            &[90],
            started + Duration::from_millis(25)
        ));
        assert!(!record_peer_hello(
            &mut peers,
            daemon_id,
            addr_b,
            1,
            &[90],
            started + Duration::from_millis(27)
        ));
        assert!(record_peer_hello(
            &mut peers,
            daemon_id,
            addr_b,
            2,
            &[90],
            started + Duration::from_millis(30)
        ));
        assert_eq!(peers[&daemon_id].1, 2);
    }

    #[test]
    fn daemon_identity_is_unique_across_isolated_instances() {
        let role_one = daemon_node_id();
        let role_two = daemon_node_id();
        assert_ne!(role_one, role_two);
        assert_ne!(role_one, 0);
        assert_ne!(role_two, 0);
    }
}
