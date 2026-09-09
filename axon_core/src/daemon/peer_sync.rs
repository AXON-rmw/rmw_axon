use std::sync::atomic::Ordering;
use std::time::Duration;

use quinn::SendStream;

use crate::daemon::discovery_shm::{
    futex_wake, MatchEntry, NodeTableEntry, ShmDiscovery, TopicEntry, MAX_MATCHES,
    MAX_NODE_NAME_LEN, MAX_NODE_NS_LEN, MAX_QUIC_ADDRS, MAX_TOPIC_NAME_LEN, MAX_TOPIC_TYPE_LEN,
};

pub const PEER_HEARTBEAT_MS: u64 = 10000;
pub const PEER_TIMEOUT_MS: u64 = 30000;

// Sync message types
const MSG_SYNC_REQUEST: u8 = 0x01;
const MSG_SYNC_RESPONSE: u8 = 0x02;
const MSG_PING: u8 = 0x04;
const MSG_PONG: u8 = 0x05;

#[derive(Debug, Clone)]
pub struct PeerTopicInfo {
    pub hash: u64,
    pub type_hash: u64,
    pub qos_reliability: u8,
    pub qos_durability: u8,
    pub qos_history_kind: u8,
    pub qos_history_depth: i32,
    pub qos_deadline_sec: u32,
    pub qos_deadline_nsec: u32,
    pub qos_lifespan_sec: u32,
    pub qos_lifespan_nsec: u32,
    pub qos_liveliness: u8,
    pub qos_liveliness_lease_sec: u32,
    pub qos_liveliness_lease_nsec: u32,
    pub name: String,
    pub topic_type: String,
    pub node_name: String,
    pub node_namespace: String,
}

#[derive(Debug, Clone)]
pub struct PeerNodeInfo {
    pub node_id: u64,
    pub domain_id: u32,
    pub published_topics: Vec<PeerTopicInfo>,
    pub subscribed_topics: Vec<PeerTopicInfo>,
    pub quic_port: u16,
    pub quic_addrs: Vec<[u8; 4]>,
    pub node_name: String,
    pub node_namespace: String,
}

#[derive(Debug)]
pub struct PeerConnection {
    pub daemon_id: u64,
    pub connection: quinn::Connection,
    pub last_heartbeat: std::time::Instant,
}

impl PeerConnection {
    pub fn is_stale(&self, timeout: Duration) -> bool {
        self.last_heartbeat.elapsed() > timeout
    }
}

/// Build a NodeInfo from a NodeTableEntry for sync transmission
pub fn node_entry_to_info(
    entry: &NodeTableEntry,
    node_name: &str,
    node_namespace: &str,
) -> PeerNodeInfo {
    use crate::daemon::discovery_shm::{
        MAX_NODE_NAME_LEN, MAX_NODE_NS_LEN, MAX_TOPIC_NAME_LEN, MAX_TOPIC_TYPE_LEN,
    };

    let published_topics: Vec<PeerTopicInfo> = entry.published_topics[..entry.pub_count as usize]
        .iter()
        .map(|t| {
            let name_end = t
                .topic_name
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(MAX_TOPIC_NAME_LEN);
            let type_end = t
                .topic_type
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(MAX_TOPIC_TYPE_LEN);
            let name = std::str::from_utf8(&t.topic_name[..name_end])
                .unwrap_or("")
                .to_string();
            let topic_type = std::str::from_utf8(&t.topic_type[..type_end])
                .unwrap_or("")
                .to_string();
            let node_name_end = t
                .node_name
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(MAX_NODE_NAME_LEN);
            let topic_node_name = std::str::from_utf8(&t.node_name[..node_name_end])
                .unwrap_or(node_name)
                .to_string();
            let node_ns_end = t
                .node_namespace
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(MAX_NODE_NS_LEN);
            let topic_node_namespace = std::str::from_utf8(&t.node_namespace[..node_ns_end])
                .unwrap_or(node_namespace)
                .to_string();
            PeerTopicInfo {
                hash: t.hash,
                type_hash: t.type_hash,
                qos_reliability: t.qos_reliability,
                qos_durability: t.qos_durability,
                qos_history_kind: t.qos_history_kind,
                qos_history_depth: t.qos_history_depth,
                qos_deadline_sec: t.qos_deadline_sec,
                qos_deadline_nsec: t.qos_deadline_nsec,
                qos_lifespan_sec: t.qos_lifespan_sec,
                qos_lifespan_nsec: t.qos_lifespan_nsec,
                qos_liveliness: t.qos_liveliness,
                qos_liveliness_lease_sec: t.qos_liveliness_lease_sec,
                qos_liveliness_lease_nsec: t.qos_liveliness_lease_nsec,
                name,
                topic_type,
                node_name: if topic_node_name.is_empty() {
                    node_name.to_string()
                } else {
                    topic_node_name
                },
                node_namespace: if topic_node_namespace.is_empty() {
                    node_namespace.to_string()
                } else {
                    topic_node_namespace
                },
            }
        })
        .collect();
    let subscribed_topics: Vec<PeerTopicInfo> = entry.subscribed_topics[..entry.sub_count as usize]
        .iter()
        .map(|t| {
            let name_end = t
                .topic_name
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(MAX_TOPIC_NAME_LEN);
            let type_end = t
                .topic_type
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(MAX_TOPIC_TYPE_LEN);
            let name = std::str::from_utf8(&t.topic_name[..name_end])
                .unwrap_or("")
                .to_string();
            let topic_type = std::str::from_utf8(&t.topic_type[..type_end])
                .unwrap_or("")
                .to_string();
            let node_name_end = t
                .node_name
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(MAX_NODE_NAME_LEN);
            let topic_node_name = std::str::from_utf8(&t.node_name[..node_name_end])
                .unwrap_or(node_name)
                .to_string();
            let node_ns_end = t
                .node_namespace
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(MAX_NODE_NS_LEN);
            let topic_node_namespace = std::str::from_utf8(&t.node_namespace[..node_ns_end])
                .unwrap_or(node_namespace)
                .to_string();
            PeerTopicInfo {
                hash: t.hash,
                type_hash: t.type_hash,
                qos_reliability: t.qos_reliability,
                qos_durability: t.qos_durability,
                qos_history_kind: t.qos_history_kind,
                qos_history_depth: t.qos_history_depth,
                qos_deadline_sec: t.qos_deadline_sec,
                qos_deadline_nsec: t.qos_deadline_nsec,
                qos_lifespan_sec: t.qos_lifespan_sec,
                qos_lifespan_nsec: t.qos_lifespan_nsec,
                qos_liveliness: t.qos_liveliness,
                qos_liveliness_lease_sec: t.qos_liveliness_lease_sec,
                qos_liveliness_lease_nsec: t.qos_liveliness_lease_nsec,
                name,
                topic_type,
                node_name: if topic_node_name.is_empty() {
                    node_name.to_string()
                } else {
                    topic_node_name
                },
                node_namespace: if topic_node_namespace.is_empty() {
                    node_namespace.to_string()
                } else {
                    topic_node_namespace
                },
            }
        })
        .collect();
    PeerNodeInfo {
        node_id: entry.node_id,
        domain_id: entry.domain_id,
        published_topics,
        subscribed_topics,
        quic_port: entry.quic_port,
        quic_addrs: entry.quic_addrs[..(entry.quic_addr_count as usize).min(MAX_QUIC_ADDRS)]
            .to_vec(),
        node_name: node_name.to_string(),
        node_namespace: node_namespace.to_string(),
    }
}

/// Collect all active nodes for a given domain from the SHM node table
pub fn collect_domain_nodes(shm: &ShmDiscovery, domain_id: u32) -> Vec<PeerNodeInfo> {
    use crate::daemon::discovery_shm::{is_process_alive, MAX_NODE_NAME_LEN, MAX_NODE_NS_LEN};
    let mut nodes = Vec::new();
    for entry in shm.node_table().iter() {
        let state = entry.state.load(Ordering::Acquire);
        if state != 2 {
            continue;
        }
        if entry.domain_id != domain_id {
            continue;
        }
        if entry.daemon_origin != 0 {
            continue;
        }
        if entry.pid > 0 && !is_process_alive(entry.pid, entry.proc_starttime) {
            continue;
        }
        let name_end = entry
            .node_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(MAX_NODE_NAME_LEN);
        let ns_end = entry
            .node_namespace
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(MAX_NODE_NS_LEN);
        let name = std::str::from_utf8(&entry.node_name[..name_end]).unwrap_or("");
        let ns = std::str::from_utf8(&entry.node_namespace[..ns_end]).unwrap_or("/");
        nodes.push(node_entry_to_info(entry, name, ns));
    }
    nodes
}

// ── Serialization ──────────────────────────────────────────────────

pub fn encode_sync_request(domain_id: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(5);
    buf.push(MSG_SYNC_REQUEST);
    buf.extend(&domain_id.to_le_bytes());
    buf
}

pub fn encode_sync_request_with_nodes(
    domain_id: u32,
    daemon_id: u64,
    nodes: &[PeerNodeInfo],
) -> Vec<u8> {
    let mut buf = encode_sync_request(domain_id);
    buf.extend(&daemon_id.to_le_bytes());
    buf.extend(encode_sync_response(domain_id, nodes));
    buf
}

pub fn decode_sync_request(buf: &[u8]) -> Result<u32, &'static str> {
    if buf.len() < 5 || buf[0] != MSG_SYNC_REQUEST {
        return Err("bad sync request");
    }
    Ok(u32::from_le_bytes(buf[1..5].try_into().unwrap()))
}

/// Return the daemon identity carried by a graph push without decoding its
/// node payload. Legacy five-byte requests do not carry an identity.
pub fn sync_request_daemon_id(buf: &[u8]) -> Result<Option<u64>, &'static str> {
    if buf.len() < 5 || buf[0] != MSG_SYNC_REQUEST {
        return Err("bad sync request");
    }
    if buf.len() == 5 {
        return Ok(None);
    }
    if buf.len() < 13 {
        return Err("truncated sync request daemon id");
    }
    Ok(Some(u64::from_le_bytes(buf[5..13].try_into().unwrap())))
}

pub fn decode_sync_request_push(
    buf: &[u8],
) -> Result<Option<(u64, Vec<PeerNodeInfo>)>, &'static str> {
    if buf.len() == 5 {
        return Ok(None);
    }
    if buf.len() < 14 || buf[0] != MSG_SYNC_REQUEST {
        return Err("bad sync request push");
    }
    let daemon_id = u64::from_le_bytes(buf[5..13].try_into().unwrap());
    let (_domain_id, nodes) = decode_sync_response(&buf[13..])?;
    Ok(Some((daemon_id, nodes)))
}

pub fn encode_sync_response(domain_id: u32, nodes: &[PeerNodeInfo]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(MSG_SYNC_RESPONSE);
    buf.extend(&domain_id.to_le_bytes());
    buf.extend(&(nodes.len() as u32).to_le_bytes());
    for node in nodes {
        buf.extend(&node.node_id.to_le_bytes());
        buf.extend(&node.domain_id.to_le_bytes());
        let name_bytes = node.node_name.as_bytes();
        buf.extend(&(name_bytes.len() as u16).to_le_bytes());
        buf.extend(name_bytes);
        let ns_bytes = node.node_namespace.as_bytes();
        buf.extend(&(ns_bytes.len() as u16).to_le_bytes());
        buf.extend(ns_bytes);
        let pub_count = node.published_topics.len() as u32;
        buf.extend(&pub_count.to_le_bytes());
        for topic in &node.published_topics {
            buf.extend(&topic.hash.to_le_bytes());
            buf.extend(&topic.type_hash.to_le_bytes());
            buf.push(topic.qos_reliability);
            buf.push(topic.qos_durability);
            buf.push(topic.qos_history_kind);
            buf.extend(&topic.qos_history_depth.to_le_bytes());
            buf.extend(&topic.qos_deadline_sec.to_le_bytes());
            buf.extend(&topic.qos_deadline_nsec.to_le_bytes());
            buf.extend(&topic.qos_lifespan_sec.to_le_bytes());
            buf.extend(&topic.qos_lifespan_nsec.to_le_bytes());
            buf.push(topic.qos_liveliness);
            buf.extend(&topic.qos_liveliness_lease_sec.to_le_bytes());
            buf.extend(&topic.qos_liveliness_lease_nsec.to_le_bytes());
            let tn = topic.name.as_bytes();
            buf.extend(&(tn.len() as u16).to_le_bytes());
            buf.extend(tn);
            let tt = topic.topic_type.as_bytes();
            buf.extend(&(tt.len() as u16).to_le_bytes());
            buf.extend(tt);
            let nn = topic.node_name.as_bytes();
            buf.extend(&(nn.len() as u16).to_le_bytes());
            buf.extend(nn);
            let ns = topic.node_namespace.as_bytes();
            buf.extend(&(ns.len() as u16).to_le_bytes());
            buf.extend(ns);
        }
        let sub_count = node.subscribed_topics.len() as u32;
        buf.extend(&sub_count.to_le_bytes());
        for topic in &node.subscribed_topics {
            buf.extend(&topic.hash.to_le_bytes());
            buf.extend(&topic.type_hash.to_le_bytes());
            buf.push(topic.qos_reliability);
            buf.push(topic.qos_durability);
            buf.push(topic.qos_history_kind);
            buf.extend(&topic.qos_history_depth.to_le_bytes());
            buf.extend(&topic.qos_deadline_sec.to_le_bytes());
            buf.extend(&topic.qos_deadline_nsec.to_le_bytes());
            buf.extend(&topic.qos_lifespan_sec.to_le_bytes());
            buf.extend(&topic.qos_lifespan_nsec.to_le_bytes());
            buf.push(topic.qos_liveliness);
            buf.extend(&topic.qos_liveliness_lease_sec.to_le_bytes());
            buf.extend(&topic.qos_liveliness_lease_nsec.to_le_bytes());
            let tn = topic.name.as_bytes();
            buf.extend(&(tn.len() as u16).to_le_bytes());
            buf.extend(tn);
            let tt = topic.topic_type.as_bytes();
            buf.extend(&(tt.len() as u16).to_le_bytes());
            buf.extend(tt);
            let nn = topic.node_name.as_bytes();
            buf.extend(&(nn.len() as u16).to_le_bytes());
            buf.extend(nn);
            let ns = topic.node_namespace.as_bytes();
            buf.extend(&(ns.len() as u16).to_le_bytes());
            buf.extend(ns);
        }
        buf.extend(&node.quic_port.to_le_bytes());
        let addr_count = node.quic_addrs.len() as u32;
        buf.extend(&addr_count.to_le_bytes());
        for addr in &node.quic_addrs {
            buf.extend(addr);
        }
    }
    buf
}

pub fn decode_sync_response(buf: &[u8]) -> Result<(u32, Vec<PeerNodeInfo>), &'static str> {
    fn read_string(buf: &[u8], off: &mut usize) -> Result<String, &'static str> {
        if *off + 2 > buf.len() {
            return Err("truncated len");
        }
        let len = u16::from_le_bytes(buf[*off..*off + 2].try_into().unwrap()) as usize;
        *off += 2;
        if *off + len > buf.len() {
            return Err("truncated string");
        }
        let s = std::str::from_utf8(&buf[*off..*off + len])
            .map_err(|_| "bad utf8")?
            .to_string();
        *off += len;
        Ok(s)
    }

    fn read_topic(buf: &[u8], off: &mut usize) -> Result<PeerTopicInfo, &'static str> {
        if *off + 48 > buf.len() {
            return Err("truncated topic");
        }
        let hash = u64::from_le_bytes(buf[*off..*off + 8].try_into().unwrap());
        let type_hash = u64::from_le_bytes(buf[*off + 8..*off + 16].try_into().unwrap());
        let qos_reliability = buf[*off + 16];
        let qos_durability = buf[*off + 17];
        let qos_history_kind = buf[*off + 18];
        let qos_history_depth = i32::from_le_bytes(buf[*off + 19..*off + 23].try_into().unwrap());
        let qos_deadline_sec = u32::from_le_bytes(buf[*off + 23..*off + 27].try_into().unwrap());
        let qos_deadline_nsec = u32::from_le_bytes(buf[*off + 27..*off + 31].try_into().unwrap());
        let qos_lifespan_sec = u32::from_le_bytes(buf[*off + 31..*off + 35].try_into().unwrap());
        let qos_lifespan_nsec = u32::from_le_bytes(buf[*off + 35..*off + 39].try_into().unwrap());
        let qos_liveliness = buf[*off + 39];
        let qos_liveliness_lease_sec =
            u32::from_le_bytes(buf[*off + 40..*off + 44].try_into().unwrap());
        let qos_liveliness_lease_nsec =
            u32::from_le_bytes(buf[*off + 44..*off + 48].try_into().unwrap());
        *off += 48;
        let name = read_string(buf, off)?;
        let topic_type = read_string(buf, off)?;
        let node_name = read_string(buf, off)?;
        let node_namespace = read_string(buf, off)?;
        Ok(PeerTopicInfo {
            hash,
            type_hash,
            qos_reliability,
            qos_durability,
            qos_history_kind,
            qos_history_depth,
            qos_deadline_sec,
            qos_deadline_nsec,
            qos_lifespan_sec,
            qos_lifespan_nsec,
            qos_liveliness,
            qos_liveliness_lease_sec,
            qos_liveliness_lease_nsec,
            name,
            topic_type,
            node_name,
            node_namespace,
        })
    }

    if buf.len() < 9 || buf[0] != MSG_SYNC_RESPONSE {
        return Err("bad sync response");
    }
    let domain_id = u32::from_le_bytes(buf[1..5].try_into().unwrap());
    let count = u32::from_le_bytes(buf[5..9].try_into().unwrap()) as usize;
    let mut nodes = Vec::with_capacity(count);
    let mut off = 9;
    for _ in 0..count {
        if off + 12 > buf.len() {
            return Err("truncated node header");
        }
        let node_id = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
        let dom_id = u32::from_le_bytes(buf[off + 8..off + 12].try_into().unwrap());
        off += 12;
        let node_name = read_string(buf, &mut off)?;
        let node_namespace = read_string(buf, &mut off)?;
        if off + 4 > buf.len() {
            return Err("truncated pub count");
        }
        let pub_count = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        let mut published_topics = Vec::with_capacity(pub_count);
        for _ in 0..pub_count {
            published_topics.push(read_topic(buf, &mut off)?);
        }
        if off + 4 > buf.len() {
            return Err("truncated sub count");
        }
        let sub_count = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        let mut subscribed_topics = Vec::with_capacity(sub_count);
        for _ in 0..sub_count {
            subscribed_topics.push(read_topic(buf, &mut off)?);
        }
        if off + 6 > buf.len() {
            return Err("truncated endpoint");
        }
        let quic_port = u16::from_le_bytes(buf[off..off + 2].try_into().unwrap());
        off += 2;
        if off + 4 > buf.len() {
            return Err("truncated addr count");
        }
        let addr_count = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        let limit = addr_count.min(MAX_QUIC_ADDRS);
        if off + limit * 4 > buf.len() {
            return Err("truncated addrs");
        }
        let mut quic_addrs = Vec::with_capacity(limit);
        for _ in 0..limit {
            let mut addr = [0u8; 4];
            addr.copy_from_slice(&buf[off..off + 4]);
            off += 4;
            quic_addrs.push(addr);
        }
        nodes.push(PeerNodeInfo {
            node_id,
            domain_id: dom_id,
            published_topics,
            subscribed_topics,
            quic_port,
            quic_addrs,
            node_name,
            node_namespace,
        });
    }
    Ok((domain_id, nodes))
}

fn copy_str<const N: usize>(dst: &mut [u8; N], value: &str) {
    *dst = [0u8; N];
    let bytes = value.as_bytes();
    let copy = bytes.len().min(N.saturating_sub(1));
    dst[..copy].copy_from_slice(&bytes[..copy]);
}

fn topic_info_to_entry(topic: &PeerTopicInfo) -> TopicEntry {
    let mut entry = TopicEntry {
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
        ..Default::default()
    };
    copy_str::<MAX_TOPIC_NAME_LEN>(&mut entry.topic_name, &topic.name);
    copy_str::<MAX_TOPIC_TYPE_LEN>(&mut entry.topic_type, &topic.topic_type);
    copy_str::<MAX_NODE_NAME_LEN>(&mut entry.node_name, &topic.node_name);
    copy_str::<MAX_NODE_NS_LEN>(&mut entry.node_namespace, &topic.node_namespace);
    entry
}

pub fn peer_node_endpoints_match(entry: &NodeTableEntry, node: &PeerNodeInfo) -> bool {
    if entry.domain_id != node.domain_id
        || entry.quic_port != node.quic_port
        || entry.quic_addr_count as usize != node.quic_addrs.len().min(MAX_QUIC_ADDRS)
        || entry.quic_addrs[..(entry.quic_addr_count as usize).min(entry.quic_addrs.len())]
            != node.quic_addrs[..node.quic_addrs.len().min(MAX_QUIC_ADDRS)]
    {
        return false;
    }

    let pub_count = node
        .published_topics
        .len()
        .min(entry.published_topics.len());
    if entry.pub_count as usize != pub_count
        || !entry.published_topics[..pub_count]
            .iter()
            .zip(node.published_topics.iter())
            .all(|(current, incoming)| *current == topic_info_to_entry(incoming))
    {
        return false;
    }

    let sub_count = node
        .subscribed_topics
        .len()
        .min(entry.subscribed_topics.len());
    entry.sub_count as usize == sub_count
        && entry.subscribed_topics[..sub_count]
            .iter()
            .zip(node.subscribed_topics.iter())
            .all(|(current, incoming)| *current == topic_info_to_entry(incoming))
}

fn clear_node_entry(entry: &mut NodeTableEntry) {
    entry.state.store(0, Ordering::Release);
    entry.node_id = 0;
    entry.domain_id = 0;
    entry.pid = 0;
    entry.proc_starttime = 0;
    entry.pub_count = 0;
    entry.sub_count = 0;
    entry.quic_port = 0;
    entry.match_count = 0;
    entry.response_gen.store(0, Ordering::Release);
    entry.quic_addr_count = 0;
    entry.quic_addrs = [[0u8; 4]; MAX_QUIC_ADDRS];
    entry.daemon_origin = 0;
    entry.last_seen_secs = 0;
    entry.node_name = [0u8; MAX_NODE_NAME_LEN];
    entry.node_namespace = [0u8; MAX_NODE_NS_LEN];
    for topic in entry.published_topics.iter_mut() {
        *topic = TopicEntry::default();
    }
    for topic in entry.subscribed_topics.iter_mut() {
        *topic = TopicEntry::default();
    }
    for m in entry.remote_matches.iter_mut() {
        *m = MatchEntry {
            node_id: 0,
            topic_hash: 0,
            port: 0,
            addr: [0u8; 4],
        };
    }
}

fn remove_matches_for_node(node_table: &mut [NodeTableEntry], dead_node_id: u64) {
    for entry in node_table.iter_mut() {
        if entry.state.load(Ordering::Acquire) != 2 {
            continue;
        }
        let count = (entry.match_count as usize).min(MAX_MATCHES);
        let mut write_idx = 0usize;
        for read_idx in 0..count {
            let m = entry.remote_matches[read_idx];
            if m.node_id != dead_node_id {
                if write_idx != read_idx {
                    entry.remote_matches[write_idx] = m;
                }
                write_idx += 1;
            }
        }
        if write_idx < count {
            for idx in write_idx..count {
                entry.remote_matches[idx] = MatchEntry {
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

pub fn merge_remote_nodes(shm: &ShmDiscovery, daemon_origin: u64, nodes: &[PeerNodeInfo]) {
    if daemon_origin == 0 {
        return;
    }

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let node_table = shm.node_table_mut();
    let mut cleared_node_ids = Vec::new();
    let incoming_node_ids: Vec<u64> = nodes.iter().map(|node| node.node_id).collect();

    for entry in node_table.iter_mut() {
        let state = entry.state.load(Ordering::Acquire);
        if state == 0 {
            continue;
        }
        let stale_from_origin =
            entry.daemon_origin == daemon_origin && !incoming_node_ids.contains(&entry.node_id);
        let duplicate_remote = entry.daemon_origin != 0
            && entry.daemon_origin != daemon_origin
            && incoming_node_ids.contains(&entry.node_id);
        if stale_from_origin || duplicate_remote {
            let node_id = entry.node_id;
            clear_node_entry(entry);
            if node_id != 0 {
                cleared_node_ids.push(node_id);
            }
        }
    }
    for node_id in cleared_node_ids {
        remove_matches_for_node(node_table, node_id);
    }

    for node in nodes {
        let existing_idx = node_table.iter().position(|entry| {
            entry.state.load(Ordering::Acquire) != 0 && entry.node_id == node.node_id
        });
        let Some(idx) = existing_idx.or_else(|| {
            node_table
                .iter()
                .position(|entry| entry.state.load(Ordering::Acquire) == 0)
        }) else {
            break;
        };

        let endpoints_changed = existing_idx
            .map(|existing| !peer_node_endpoints_match(&node_table[existing], node))
            .unwrap_or(false);
        if endpoints_changed {
            remove_matches_for_node(node_table, node.node_id);
        }
        let entry = &mut node_table[idx];
        let is_new = existing_idx.is_none();
        if is_new {
            clear_node_entry(entry);
        }
        entry.node_id = node.node_id;
        entry.domain_id = node.domain_id;
        entry.pid = 0;
        entry.proc_starttime = 0;
        entry.quic_port = node.quic_port;
        entry.quic_addrs = [[0u8; 4]; MAX_QUIC_ADDRS];
        let addr_count = node.quic_addrs.len().min(MAX_QUIC_ADDRS);
        for (i, addr) in node.quic_addrs.iter().take(addr_count).enumerate() {
            entry.quic_addrs[i] = *addr;
        }
        entry.quic_addr_count = addr_count as u32;
        entry.daemon_origin = daemon_origin;
        entry.last_seen_secs = now_secs;
        copy_str::<MAX_NODE_NAME_LEN>(&mut entry.node_name, &node.node_name);
        copy_str::<MAX_NODE_NS_LEN>(&mut entry.node_namespace, &node.node_namespace);

        let pub_count = node
            .published_topics
            .len()
            .min(entry.published_topics.len());
        entry.pub_count = pub_count as u32;
        for topic in entry.published_topics.iter_mut() {
            *topic = TopicEntry::default();
        }
        for (i, topic) in node.published_topics.iter().take(pub_count).enumerate() {
            entry.published_topics[i] = topic_info_to_entry(topic);
        }

        let sub_count = node
            .subscribed_topics
            .len()
            .min(entry.subscribed_topics.len());
        entry.sub_count = sub_count as u32;
        for topic in entry.subscribed_topics.iter_mut() {
            *topic = TopicEntry::default();
        }
        for (i, topic) in node.subscribed_topics.iter().take(sub_count).enumerate() {
            entry.subscribed_topics[i] = topic_info_to_entry(topic);
        }

        entry.state.store(2, Ordering::Release);
    }

    shm.header().generation.fetch_add(1, Ordering::Release);
    futex_wake(&shm.header().generation);
}

pub fn encode_ping() -> Vec<u8> {
    vec![MSG_PING]
}

pub fn encode_pong() -> Vec<u8> {
    vec![MSG_PONG]
}

/// Process a graph-control request without coupling protocol parsing to QUIC.
/// QUIC provides packet confidentiality and integrity for remote calls; this
/// function only parses and produces the graph-control payload.
pub fn handle_sync_payload(shm: &ShmDiscovery, data: &[u8]) -> Result<Vec<u8>, String> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    match data[0] {
        MSG_SYNC_REQUEST => {
            let req_domain = decode_sync_request(data).map_err(|e| e.to_string())?;
            if let Some((daemon_id, pushed_nodes)) =
                decode_sync_request_push(data).map_err(|e| e.to_string())?
            {
                merge_remote_nodes(shm, daemon_id, &pushed_nodes);
            }
            let nodes = collect_domain_nodes(shm, req_domain);
            Ok(encode_sync_response(req_domain, &nodes))
        }
        MSG_PING => Ok(encode_pong()),
        _ => Err("unsupported daemon sync message".into()),
    }
}

/// Handle an incoming sync message (runs on acceptor thread)
pub async fn handle_sync_message(
    shm: &ShmDiscovery,
    _domain_id: u32,
    data: &[u8],
    send_stream: &mut SendStream,
) -> Result<(), String> {
    let response = handle_sync_payload(shm, data)?;
    if !response.is_empty() {
        send_stream
            .write_all(&response)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_response_roundtrip() {
        let nodes = vec![PeerNodeInfo {
            node_id: 0x1001,
            domain_id: 0,
            published_topics: vec![PeerTopicInfo {
                hash: 0x42,
                type_hash: 0x100,
                qos_reliability: 1,
                qos_durability: 0,
                qos_history_kind: 1,
                qos_history_depth: 5,
                qos_deadline_sec: 2,
                qos_deadline_nsec: 25,
                qos_lifespan_sec: 9,
                qos_lifespan_nsec: 50,
                qos_liveliness: 1,
                qos_liveliness_lease_sec: 7,
                qos_liveliness_lease_nsec: 75,
                name: "topic_a".into(),
                topic_type: "std_msgs/msg/String".into(),
                node_name: "camera_node".into(),
                node_namespace: "/sensors".into(),
            }],
            subscribed_topics: vec![PeerTopicInfo {
                hash: 0x43,
                type_hash: 0x101,
                qos_reliability: 1,
                qos_durability: 0,
                qos_history_kind: 0,
                qos_history_depth: 0,
                qos_deadline_sec: 3,
                qos_deadline_nsec: 125,
                qos_lifespan_sec: 10,
                qos_lifespan_nsec: 250,
                qos_liveliness: 2,
                qos_liveliness_lease_sec: 8,
                qos_liveliness_lease_nsec: 500,
                name: "topic_b".into(),
                topic_type: "std_msgs/msg/Int32".into(),
                node_name: "consumer_node".into(),
                node_namespace: "/tools".into(),
            }],
            quic_port: 12345,
            quic_addrs: vec![[127, 0, 0, 1], [192, 168, 1, 1]],
            node_name: "my_node".into(),
            node_namespace: "/".into(),
        }];
        let encoded = encode_sync_response(0, &nodes);
        let (dom, decoded) = decode_sync_response(&encoded).unwrap();
        assert_eq!(dom, 0);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].node_id, 0x1001);
        assert_eq!(decoded[0].node_name, "my_node");
        assert_eq!(decoded[0].published_topics[0].hash, 0x42);
        assert_eq!(decoded[0].published_topics[0].name, "topic_a");
        assert_eq!(decoded[0].published_topics[0].node_name, "camera_node");
        assert_eq!(decoded[0].published_topics[0].node_namespace, "/sensors");
        assert_eq!(decoded[0].published_topics[0].qos_deadline_sec, 2);
        assert_eq!(decoded[0].published_topics[0].qos_deadline_nsec, 25);
        assert_eq!(decoded[0].published_topics[0].qos_lifespan_sec, 9);
        assert_eq!(decoded[0].published_topics[0].qos_lifespan_nsec, 50);
        assert_eq!(decoded[0].published_topics[0].qos_liveliness, 1);
        assert_eq!(decoded[0].published_topics[0].qos_liveliness_lease_sec, 7);
        assert_eq!(decoded[0].published_topics[0].qos_liveliness_lease_nsec, 75);
        assert_eq!(decoded[0].subscribed_topics[0].name, "topic_b");
        assert_eq!(decoded[0].subscribed_topics[0].node_name, "consumer_node");
        assert_eq!(decoded[0].subscribed_topics[0].node_namespace, "/tools");
        assert_eq!(decoded[0].subscribed_topics[0].qos_deadline_sec, 3);
        assert_eq!(decoded[0].subscribed_topics[0].qos_deadline_nsec, 125);
        assert_eq!(decoded[0].subscribed_topics[0].qos_lifespan_sec, 10);
        assert_eq!(decoded[0].subscribed_topics[0].qos_lifespan_nsec, 250);
        assert_eq!(decoded[0].subscribed_topics[0].qos_liveliness, 2);
        assert_eq!(decoded[0].subscribed_topics[0].qos_liveliness_lease_sec, 8);
        assert_eq!(
            decoded[0].subscribed_topics[0].qos_liveliness_lease_nsec,
            500
        );
        assert_eq!(decoded[0].quic_addrs.len(), 2);
        assert_eq!(decoded[0].quic_addrs[0], [127, 0, 0, 1]);
        assert_eq!(decoded[0].quic_addrs[1], [192, 168, 1, 1]);
    }

    #[test]
    fn test_sync_response_empty() {
        let encoded = encode_sync_response(0, &[]);
        let (dom, decoded) = decode_sync_response(&encoded).unwrap();
        assert_eq!(dom, 0);
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_sync_request_roundtrip() {
        let encoded = encode_sync_request(42);
        let decoded = decode_sync_request(&encoded).unwrap();
        assert_eq!(decoded, 42);
        assert!(decode_sync_request_push(&encoded).unwrap().is_none());
    }

    #[test]
    fn test_sync_request_with_nodes_roundtrip() {
        let nodes = vec![PeerNodeInfo {
            node_id: 0x2001,
            domain_id: 42,
            published_topics: Vec::new(),
            subscribed_topics: Vec::new(),
            quic_port: 17601,
            quic_addrs: vec![[172, 17, 0, 2]],
            node_name: "docker_node".into(),
            node_namespace: "/docker".into(),
        }];
        let encoded = encode_sync_request_with_nodes(42, 0x9abc, &nodes);

        assert_eq!(decode_sync_request(&encoded).unwrap(), 42);
        let (daemon_id, pushed_nodes) = decode_sync_request_push(&encoded).unwrap().unwrap();
        assert_eq!(daemon_id, 0x9abc);
        assert_eq!(pushed_nodes.len(), 1);
        assert_eq!(pushed_nodes[0].node_id, 0x2001);
        assert_eq!(pushed_nodes[0].domain_id, 42);
        assert_eq!(pushed_nodes[0].quic_port, 17601);
        assert_eq!(pushed_nodes[0].quic_addrs, vec![[172, 17, 0, 2]]);
        assert_eq!(pushed_nodes[0].node_name, "docker_node");
        assert_eq!(pushed_nodes[0].node_namespace, "/docker");
    }

    #[test]
    fn sync_request_identity_distinguishes_legacy_and_daemon_pushes() {
        assert_eq!(
            sync_request_daemon_id(&encode_sync_request(42)).unwrap(),
            None
        );

        let request = encode_sync_request_with_nodes(42, 0x9abc, &[]);
        assert_eq!(sync_request_daemon_id(&request).unwrap(), Some(0x9abc));
        assert!(sync_request_daemon_id(&[MSG_SYNC_REQUEST, 0, 0, 0, 0, 1]).is_err());
    }

    #[test]
    fn test_collect_domain_nodes_empty() {
        // This tests the encode/decode logic; integration test covers full flow
        let request = encode_sync_request(0);
        assert_eq!(request.len(), 5);
        assert_eq!(request[0], MSG_SYNC_REQUEST);
    }

    #[test]
    fn repeated_remote_merge_preserves_matches_until_node_disappears() {
        let name = format!("/axon_peer_merge_test_{}", std::process::id());
        let _ = ShmDiscovery::destroy(&name);
        let shm = ShmDiscovery::create(&name, 8, 8).unwrap();
        let local_node_id = 0x1001;
        let remote_node_id = 0x2002;
        let daemon_origin = 0x3003;

        {
            let local = &mut shm.node_table_mut()[0];
            local.node_id = local_node_id;
            local.domain_id = 42;
            local.state.store(2, Ordering::Release);
        }

        let remote = PeerNodeInfo {
            node_id: remote_node_id,
            domain_id: 42,
            published_topics: vec![PeerTopicInfo {
                hash: 0x55,
                type_hash: 0,
                qos_reliability: 1,
                qos_durability: 0,
                qos_history_kind: 1,
                qos_history_depth: 10,
                qos_deadline_sec: 0,
                qos_deadline_nsec: 0,
                qos_lifespan_sec: 0,
                qos_lifespan_nsec: 0,
                qos_liveliness: 0,
                qos_liveliness_lease_sec: 0,
                qos_liveliness_lease_nsec: 0,
                name: "/remote".into(),
                topic_type: "std_msgs/msg/String".into(),
                node_name: "remote_node".into(),
                node_namespace: "/".into(),
            }],
            subscribed_topics: Vec::new(),
            quic_port: 17400,
            quic_addrs: vec![[192, 168, 1, 20]],
            node_name: "remote_node".into(),
            node_namespace: "/".into(),
        };

        merge_remote_nodes(&shm, daemon_origin, std::slice::from_ref(&remote));
        let original_slot = shm.find_slot_by_node_id(remote_node_id).unwrap();
        {
            let local = &mut shm.node_table_mut()[0];
            local.remote_matches[0] = MatchEntry {
                node_id: remote_node_id,
                topic_hash: 0x55,
                port: 17400,
                addr: [192, 168, 1, 20],
            };
            local.match_count = 1;
            local.response_gen.store(7, Ordering::Release);
        }

        merge_remote_nodes(&shm, daemon_origin, std::slice::from_ref(&remote));
        assert_eq!(
            shm.find_slot_by_node_id(remote_node_id),
            Some(original_slot),
            "an unchanged remote node must be updated in place"
        );
        assert_eq!(shm.node_table()[0].match_count, 1);
        assert_eq!(shm.node_table()[0].response_gen.load(Ordering::Acquire), 7);

        merge_remote_nodes(&shm, daemon_origin, &[]);
        assert!(shm.find_slot_by_node_id(remote_node_id).is_none());
        assert_eq!(shm.node_table()[0].match_count, 0);

        drop(shm);
        ShmDiscovery::destroy(&name).unwrap();
    }
}
