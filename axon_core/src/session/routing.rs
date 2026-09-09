use super::Session;
use crate::types::*;
use std::sync::atomic::Ordering;

impl Session {
    /// Synchronize daemon matches: read remote_matches from SHM, populate known_addrs,
    /// remote_routes, and initiate QUIC connections to peer nodes.
    pub fn sync_daemon_matches(&self) {
        use crate::daemon::discovery_shm::MAX_MATCHES;
        use std::collections::{HashMap, HashSet};
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let shm = match self.daemon_shm.as_ref() {
            Some(s) => s,
            None => return,
        };

        let node_table = shm.node_table();
        let entry = &node_table[self.daemon_slot];

        if entry.state.load(Ordering::Acquire) != 2 {
            self.remote_routes.lock().unwrap().clear();
            self.known_addrs.write().unwrap().clear();
            self.retained_remote_peers.lock().unwrap().clear();
            self.retained_remote_pending.lock().unwrap().clear();
            return;
        }

        let current_gen = entry.response_gen.load(Ordering::Acquire);
        let last_gen = self.daemon_last_response_gen.load(Ordering::Relaxed);
        let retry_retained = self.retained_remote_retry.swap(false, Ordering::AcqRel);

        if last_gen == current_gen && current_gen != 0 && !retry_retained {
            return;
        }
        self.daemon_last_response_gen
            .store(current_gen, Ordering::Relaxed);

        let match_count = entry.match_count as usize;
        if match_count == 0 {
            self.remote_routes.lock().unwrap().clear();
            self.known_addrs.write().unwrap().clear();
            self.retained_remote_peers.lock().unwrap().clear();
            self.retained_remote_pending.lock().unwrap().clear();
            return;
        }

        let limit = std::cmp::min(match_count, MAX_MATCHES);
        let raw_matches: Vec<(u64, u64, u16, [u8; 4])> = entry.remote_matches[..limit]
            .iter()
            .map(|m| (m.node_id, m.topic_hash, m.port, m.addr))
            .collect();

        let valid: Vec<(u64, u64, u16, [u8; 4], u64)> = raw_matches
            .into_iter()
            .filter_map(|(node_id, topic_hash, port, addr)| {
                let slot = shm.find_slot_by_node_id(node_id)?;
                let remote = &node_table[slot];
                (remote.state.load(Ordering::Acquire) == 2
                        // Local-daemon matches are delivered through SHM. Sending
                        // them over QUIC as well can duplicate high-rate topics
                        // such as /clock and make ROS time appear to jump back.
                        && remote.daemon_origin != 0)
                    .then_some((node_id, topic_hash, port, addr, remote.daemon_origin))
            })
            .collect();

        self.known_addrs.write().unwrap().clear();
        self.remote_routes.lock().unwrap().clear();

        if valid.is_empty() {
            self.retained_remote_peers.lock().unwrap().clear();
            self.retained_remote_pending.lock().unwrap().clear();
            return;
        }

        let mut peer_addrs: HashMap<u64, Vec<SocketAddr>> = HashMap::new();
        for (node_id, _, port, addr, _) in &valid {
            let sock_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(*addr)), *port);
            let addrs = peer_addrs.entry(*node_id).or_default();
            if !addrs.contains(&sock_addr) {
                addrs.push(sock_addr);
            }
        }

        {
            let mut known = self.known_addrs.write().unwrap();
            for (node_id, addrs) in &peer_addrs {
                if let Some(sock_addr) = addrs.first().copied() {
                    known.insert(*node_id, sock_addr);
                }
            }
        }

        {
            let known = self.known_addrs.read().unwrap();
            let mut routes = self.remote_routes.lock().unwrap();
            let mut routed_peers = HashSet::new();
            for (node_id, topic_hash, _, _, _) in &valid {
                if !routed_peers.insert((*node_id, *topic_hash)) {
                    continue;
                }
                if let Some(sock_addr) = known.get(node_id).copied() {
                    let addrs = routes.entry(*topic_hash).or_default();
                    if !addrs.contains(&sock_addr) {
                        addrs.push(sock_addr);
                    }
                }
            }
        }

        if let Some(ref qt) = self.quic_transport {
            for (node_id, _, _, _, daemon_id) in &valid {
                qt.set_peer_daemon(*node_id, *daemon_id);
            }
            for (node_id, addrs) in peer_addrs {
                qt.set_peer_addrs(node_id, addrs.clone());
                if let Some(sock_addr) = addrs.first().copied() {
                    qt.connect_async(node_id, sock_addr);
                }
            }
            self.send_retained_history_to_new_peers(&valid, qt);
        }
        self.signal_graph_eventfds();
    }

    fn send_retained_history_to_new_peers(
        &self,
        matches: &[(u64, u64, u16, [u8; 4], u64)],
        transport: &crate::quic_transport::QuicTransport,
    ) {
        use std::collections::{HashMap, HashSet};

        let mut active: HashMap<TopicHash, HashSet<NodeId>> = HashMap::new();
        for (node_id, topic_hash, _, _, _) in matches {
            active.entry(*topic_hash).or_default().insert(*node_id);
        }

        let retained = self.retained_remote_samples.lock().unwrap();
        let mut in_flight = self.retained_remote_pending.lock().unwrap();
        let mut delivered = self.retained_remote_peers.lock().unwrap();
        in_flight.retain(|topic_hash, peers| {
            if let Some(active_peers) = active.get(topic_hash) {
                peers.retain(|peer| active_peers.contains(peer));
                true
            } else {
                false
            }
        });
        delivered.retain(|topic_hash, peers| {
            if let Some(active_peers) = active.get(topic_hash) {
                peers.retain(|peer| active_peers.contains(peer));
                true
            } else {
                false
            }
        });

        let mut pending = Vec::new();
        for (topic_hash, samples) in retained.iter() {
            if samples.is_empty() {
                continue;
            }
            let Some(peers) = active.get(topic_hash) else {
                continue;
            };
            let sent = delivered.entry(*topic_hash).or_default();
            let pending_peers = in_flight.entry(*topic_hash).or_default();
            for peer in peers {
                if !sent.contains(peer) && pending_peers.insert(*peer) {
                    pending.push((
                        *peer,
                        *topic_hash,
                        samples.iter().cloned().collect::<Vec<_>>(),
                    ));
                }
            }
        }
        drop(delivered);
        drop(in_flight);
        drop(retained);

        for (peer, topic_hash, samples) in pending {
            let completion = transport.send_retained_history(peer, topic_hash, samples);
            let delivered = self.retained_remote_peers.clone();
            let in_flight = self.retained_remote_pending.clone();
            let retry = self.retained_remote_retry.clone();
            transport.spawn(async move {
                let succeeded = matches!(completion.await, Ok(Ok(())));
                let was_pending = {
                    let mut pending = in_flight.lock().unwrap();
                    let removed = if let Some(peers) = pending.get_mut(&topic_hash) {
                        let removed = peers.remove(&peer);
                        if peers.is_empty() {
                            pending.remove(&topic_hash);
                        }
                        removed
                    } else {
                        false
                    };
                    removed
                };
                if succeeded && was_pending {
                    delivered
                        .lock()
                        .unwrap()
                        .entry(topic_hash)
                        .or_default()
                        .insert(peer);
                } else if was_pending {
                    retry.store(true, Ordering::Release);
                }
            });
        }
    }

    /// Seed a cross-host route directly from the daemon's imported graph.
    ///
    /// A one-shot service client can send its request before the daemon has
    /// materialized the corresponding `remote_matches` entry. The remote node
    /// and endpoint metadata are already present at that point, so derive the
    /// route from the remote subscription instead of dropping the request into
    /// local SHM only. Regular topic matching remains daemon-driven.
    pub(crate) fn seed_remote_service_route(&self, topic_hash: TopicHash) {
        use crate::daemon::discovery_shm::topic_entry_qos_compatible;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let shm = match self.daemon_shm.as_ref() {
            Some(shm) => shm,
            None => return,
        };
        let node_table = shm.node_table();
        let local = &node_table[self.daemon_slot];
        if local.state.load(Ordering::Acquire) != 2 {
            return;
        }

        let local_pub = local.published_topics
            [..(local.pub_count as usize).min(local.published_topics.len())]
            .iter()
            .find(|entry| entry.hash == topic_hash);
        let Some(local_pub) = local_pub else {
            return;
        };

        let mut peers = Vec::new();
        for remote in node_table {
            if remote.state.load(Ordering::Acquire) != 2
                || remote.node_id == self.node_id
                || remote.domain_id != local.domain_id
                || remote.daemon_origin == 0
            {
                continue;
            }

            let subscriptions = &remote.subscribed_topics
                [..(remote.sub_count as usize).min(remote.subscribed_topics.len())];
            if !subscriptions.iter().any(|subscription| {
                subscription.hash == topic_hash
                    && topic_entry_qos_compatible(local_pub, subscription)
            }) {
                continue;
            }

            let addresses: Vec<SocketAddr> = remote.quic_addrs
                [..(remote.quic_addr_count as usize).min(remote.quic_addrs.len())]
                .iter()
                .map(|addr| SocketAddr::new(IpAddr::V4(Ipv4Addr::from(*addr)), remote.quic_port))
                .filter(|addr| addr.port() != 0 && !addr.ip().is_unspecified())
                .collect();
            if !addresses.is_empty() {
                peers.push((remote.node_id, remote.daemon_origin, addresses));
            }
        }

        for (peer_id, daemon_id, addresses) in peers {
            if let Some(first) = addresses.first().copied() {
                self.known_addrs.write().unwrap().insert(peer_id, first);
            }
            {
                let mut routes = self.remote_routes.lock().unwrap();
                let topic_routes = routes.entry(topic_hash).or_default();
                for address in &addresses {
                    if !topic_routes.contains(address) {
                        topic_routes.push(*address);
                    }
                }
            }
            if let Some(ref qt) = self.quic_transport {
                qt.set_peer_daemon(peer_id, daemon_id);
                qt.set_peer_addrs(peer_id, addresses.clone());
                if let Some(first) = addresses.first().copied() {
                    qt.connect_async(peer_id, first);
                }
            }
        }
    }

    /// Register a published topic with the local discovery daemon.
    pub fn register_published_topic_with_daemon(
        &self,
        topic_hash: u64,
        topic_name: &str,
        topic_type: &str,
        qos: &QosProfile,
    ) {
        use crate::daemon::discovery_shm::futex_wake;
        use crate::daemon::discovery_shm::{
            MAX_NODE_NAME_LEN, MAX_NODE_NS_LEN, MAX_TOPIC_NAME_LEN, MAX_TOPIC_TYPE_LEN,
        };

        if let Some(ref shm) = self.daemon_shm {
            let entry = &mut shm.node_table_mut()[self.daemon_slot];
            let count = entry.pub_count as usize;
            if count < crate::daemon::discovery_shm::MAX_TOPICS_PER_NODE {
                let mut name_buf = [0u8; MAX_TOPIC_NAME_LEN];
                let name_bytes = topic_name.as_bytes();
                let copy_len = name_bytes.len().min(MAX_TOPIC_NAME_LEN - 1);
                name_buf[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
                let mut type_buf = [0u8; MAX_TOPIC_TYPE_LEN];
                let type_bytes = topic_type.as_bytes();
                let copy_len = type_bytes.len().min(MAX_TOPIC_TYPE_LEN - 1);
                type_buf[..copy_len].copy_from_slice(&type_bytes[..copy_len]);
                let owner_name = self.graph_cache.node_name.read().unwrap().clone();
                let mut node_name_buf = [0u8; MAX_NODE_NAME_LEN];
                let node_name_bytes = owner_name.as_bytes();
                let copy_len = node_name_bytes.len().min(MAX_NODE_NAME_LEN - 1);
                node_name_buf[..copy_len].copy_from_slice(&node_name_bytes[..copy_len]);
                let owner_ns = self.graph_cache.node_namespace.read().unwrap().clone();
                let mut node_ns_buf = [0u8; MAX_NODE_NS_LEN];
                let node_ns_bytes = owner_ns.as_bytes();
                let copy_len = node_ns_bytes.len().min(MAX_NODE_NS_LEN - 1);
                node_ns_buf[..copy_len].copy_from_slice(&node_ns_bytes[..copy_len]);
                let (
                    rel,
                    dur,
                    hist_kind,
                    hist_depth,
                    dl_sec,
                    dl_nsec,
                    ls_sec,
                    ls_nsec,
                    liv,
                    ll_sec,
                    ll_nsec,
                ) = Self::qos_to_entry_fields(qos);
                entry.published_topics[count] = crate::daemon::discovery_shm::TopicEntry {
                    hash: topic_hash,
                    type_hash: 0,
                    qos_reliability: rel,
                    qos_durability: dur,
                    qos_history_kind: hist_kind,
                    qos_history_depth: hist_depth,
                    qos_deadline_sec: dl_sec,
                    qos_deadline_nsec: dl_nsec,
                    qos_lifespan_sec: ls_sec,
                    qos_lifespan_nsec: ls_nsec,
                    qos_liveliness: liv,
                    qos_liveliness_lease_sec: ll_sec,
                    qos_liveliness_lease_nsec: ll_nsec,
                    topic_name: name_buf,
                    topic_type: type_buf,
                    node_name: node_name_buf,
                    node_namespace: node_ns_buf,
                };
                entry.pub_count = (count + 1) as u32;
                shm.header().generation.fetch_add(1, Ordering::Release);
                futex_wake(&shm.header().generation);
            }
        }
    }

    /// Register a subscribed topic with the local discovery daemon.
    pub fn register_subscribed_topic_with_daemon(
        &self,
        topic_hash: u64,
        topic_name: &str,
        topic_type: &str,
        qos: &QosProfile,
    ) {
        use crate::daemon::discovery_shm::futex_wake;
        use crate::daemon::discovery_shm::{
            MAX_NODE_NAME_LEN, MAX_NODE_NS_LEN, MAX_TOPIC_NAME_LEN, MAX_TOPIC_TYPE_LEN,
        };

        if let Some(ref shm) = self.daemon_shm {
            let entry = &mut shm.node_table_mut()[self.daemon_slot];
            let count = entry.sub_count as usize;
            if count < crate::daemon::discovery_shm::MAX_TOPICS_PER_NODE {
                let mut name_buf = [0u8; MAX_TOPIC_NAME_LEN];
                let name_bytes = topic_name.as_bytes();
                let copy_len = name_bytes.len().min(MAX_TOPIC_NAME_LEN - 1);
                name_buf[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
                let mut type_buf = [0u8; MAX_TOPIC_TYPE_LEN];
                let type_bytes = topic_type.as_bytes();
                let copy_len = type_bytes.len().min(MAX_TOPIC_TYPE_LEN - 1);
                type_buf[..copy_len].copy_from_slice(&type_bytes[..copy_len]);
                let owner_name = self.graph_cache.node_name.read().unwrap().clone();
                let mut node_name_buf = [0u8; MAX_NODE_NAME_LEN];
                let node_name_bytes = owner_name.as_bytes();
                let copy_len = node_name_bytes.len().min(MAX_NODE_NAME_LEN - 1);
                node_name_buf[..copy_len].copy_from_slice(&node_name_bytes[..copy_len]);
                let owner_ns = self.graph_cache.node_namespace.read().unwrap().clone();
                let mut node_ns_buf = [0u8; MAX_NODE_NS_LEN];
                let node_ns_bytes = owner_ns.as_bytes();
                let copy_len = node_ns_bytes.len().min(MAX_NODE_NS_LEN - 1);
                node_ns_buf[..copy_len].copy_from_slice(&node_ns_bytes[..copy_len]);
                let (
                    rel,
                    dur,
                    hist_kind,
                    hist_depth,
                    dl_sec,
                    dl_nsec,
                    ls_sec,
                    ls_nsec,
                    liv,
                    ll_sec,
                    ll_nsec,
                ) = Self::qos_to_entry_fields(qos);
                entry.subscribed_topics[count] = crate::daemon::discovery_shm::TopicEntry {
                    hash: topic_hash,
                    type_hash: 0,
                    qos_reliability: rel,
                    qos_durability: dur,
                    qos_history_kind: hist_kind,
                    qos_history_depth: hist_depth,
                    qos_deadline_sec: dl_sec,
                    qos_deadline_nsec: dl_nsec,
                    qos_lifespan_sec: ls_sec,
                    qos_lifespan_nsec: ls_nsec,
                    qos_liveliness: liv,
                    qos_liveliness_lease_sec: ll_sec,
                    qos_liveliness_lease_nsec: ll_nsec,
                    topic_name: name_buf,
                    topic_type: type_buf,
                    node_name: node_name_buf,
                    node_namespace: node_ns_buf,
                };
                entry.sub_count = (count + 1) as u32;
                shm.header().generation.fetch_add(1, Ordering::Release);
                futex_wake(&shm.header().generation);
            }
        }
    }

    fn qos_to_entry_fields(
        qos: &QosProfile,
    ) -> (u8, u8, u8, i32, u32, u32, u32, u32, u8, u32, u32) {
        use crate::types::{Durability, HistoryKind, Liveliness, Reliability};
        let rel = match qos.reliability {
            Reliability::BestEffort => 0u8,
            Reliability::Reliable => 1u8,
        };
        let dur = match qos.durability {
            Durability::Volatile => 0u8,
            Durability::TransientLocal => 1u8,
        };
        let (hist_kind, hist_depth) = match qos.history {
            HistoryKind::KeepLast { depth } => (1u8, depth as i32),
            HistoryKind::KeepAll => (0u8, -1i32),
        };
        fn duration_to_entry_fields(duration: Option<std::time::Duration>) -> (u32, u32) {
            duration
                .map(|d| (d.as_secs().min(u32::MAX as u64) as u32, d.subsec_nanos()))
                .unwrap_or((0, 0))
        }

        let (dl_sec, dl_nsec) = duration_to_entry_fields(qos.deadline);
        let (ls_sec, ls_nsec) = duration_to_entry_fields(qos.lifespan);
        let liv = match qos.liveliness {
            Liveliness::Automatic => 0u8,
            Liveliness::ManualByTopic => 1u8,
            Liveliness::ManualByParticipant => 2u8,
            Liveliness::Unknown => 0u8,
        };
        let (ll_sec, ll_nsec) = duration_to_entry_fields(qos.liveliness_lease_duration);
        (
            rel, dur, hist_kind, hist_depth, dl_sec, dl_nsec, ls_sec, ls_nsec, liv, ll_sec, ll_nsec,
        )
    }

    #[allow(clippy::too_many_arguments)] // Decodes the fixed shared-memory QoS layout.
    pub(crate) fn entry_fields_to_qos(
        rel: u8,
        dur: u8,
        hist_kind: u8,
        hist_depth: i32,
        dl_sec: u32,
        dl_nsec: u32,
        ls_sec: u32,
        ls_nsec: u32,
        liv: u8,
        ll_sec: u32,
        ll_nsec: u32,
    ) -> QosProfile {
        use crate::types::{Durability, HistoryKind, Liveliness, Reliability};
        let mut qos = QosProfile::default_command();
        qos.reliability = if rel == 0 {
            Reliability::BestEffort
        } else {
            Reliability::Reliable
        };
        qos.durability = if dur == 0 {
            Durability::Volatile
        } else {
            Durability::TransientLocal
        };
        qos.history = if hist_kind == 0 {
            HistoryKind::KeepAll
        } else {
            HistoryKind::KeepLast {
                depth: if hist_depth <= 0 {
                    10
                } else {
                    hist_depth as usize
                },
            }
        };
        qos.deadline = if dl_sec == 0 && dl_nsec == 0 {
            None
        } else {
            Some(std::time::Duration::new(dl_sec as u64, dl_nsec))
        };
        qos.lifespan = if ls_sec == 0 && ls_nsec == 0 {
            None
        } else {
            Some(std::time::Duration::new(ls_sec as u64, ls_nsec))
        };
        qos.liveliness = match liv {
            1 => Liveliness::ManualByTopic,
            2 => Liveliness::ManualByParticipant,
            _ => Liveliness::Automatic,
        };
        qos.liveliness_lease_duration = if ll_sec == 0 && ll_nsec == 0 {
            None
        } else {
            Some(std::time::Duration::new(ll_sec as u64, ll_nsec))
        };
        qos
    }

    pub fn set_daemon_shm(
        &mut self,
        shm: crate::daemon::discovery_shm::ShmDiscovery,
        slot: usize,
        include_all_domains: bool,
    ) {
        self.daemon_shm = Some(shm);
        self.daemon_slot = slot;
        self.include_all_domains = include_all_domains;
    }

    pub(crate) fn open_daemon_shm(&self) -> Option<crate::daemon::discovery_shm::ShmDiscovery> {
        self.daemon_shm.as_ref()?;
        crate::daemon::discovery_shm::ShmDiscovery::open(crate::daemon::discovery_shm::SHM_NAME)
            .ok()
    }

    /// Unregister from the local discovery daemon on shutdown.
    pub fn unregister_from_daemon(&self) {
        if let Some(ref shm) = self.daemon_shm {
            let entry = &mut shm.node_table_mut()[self.daemon_slot];
            entry.state.store(3, Ordering::Release); // Leaving
            shm.header().generation.fetch_add(1, Ordering::Release);
        }
    }

    /// Set the human-readable node name and namespace for graph introspection.
    ///
    /// # Arguments
    /// * `name` - Human-readable node name
    /// * `namespace_` - Node namespace
    pub fn set_node_name(&self, name: &str, namespace_: &str) {
        let ns = if namespace_.is_empty() {
            "/"
        } else {
            namespace_
        };
        let full_name = if ns == "/" {
            name.to_string()
        } else {
            format!("{}/{}", ns.trim_end_matches('/'), name)
        };
        *self.graph_cache.node_name.write().unwrap() = name.to_string();
        *self.graph_cache.node_namespace.write().unwrap() = ns.to_string();
        *self.node_name_shared.write().unwrap() = full_name;
        if let Some(ref shm) = self.daemon_shm {
            use crate::daemon::discovery_shm::{futex_wake, MAX_NODE_NAME_LEN, MAX_NODE_NS_LEN};
            let entry = &mut shm.node_table_mut()[self.daemon_slot];
            let mut name_buf = [0u8; MAX_NODE_NAME_LEN];
            let name_bytes = name.as_bytes();
            let copy = name_bytes.len().min(MAX_NODE_NAME_LEN - 1);
            name_buf[..copy].copy_from_slice(&name_bytes[..copy]);
            entry.node_name = name_buf;
            let mut ns_buf = [0u8; MAX_NODE_NS_LEN];
            let ns_bytes = ns.as_bytes();
            let copy = ns_bytes.len().min(MAX_NODE_NS_LEN - 1);
            ns_buf[..copy].copy_from_slice(&ns_bytes[..copy]);
            entry.node_namespace = ns_buf;
            shm.header().generation.fetch_add(1, Ordering::Release);
            futex_wake(&shm.header().generation);
        }
        self.signal_graph_eventfds();
    }
}
