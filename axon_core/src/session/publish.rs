use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

static TRACE_PUB_COUNTER: AtomicU64 = AtomicU64::new(0);

use super::{topic_message_capacity, topic_ring_depth, Session};
use crate::events::EventKind;
use crate::local::LocalPubSub;
use crate::resource::LeakyBucket;
use crate::types::*;

impl Session {
    /// Check the ACL for a topic, matching against the human-readable topic
    /// name when it is known (the documented `AXON_ACL_*` glob semantics) and
    /// falling back to the hex topic-hash string for topics whose name has
    /// not been registered yet. With no rules configured both checks allow.
    pub(crate) fn acl_allows(&self, direction: AclDirection, topic_hash: TopicHash) -> bool {
        let name = self
            .topic_name_cache
            .read()
            .unwrap()
            .get(&topic_hash)
            .cloned();
        let acl = self.acl_engine.lock().unwrap();
        if let Some(name) = name {
            // Service internal topics are cached with a marker prefix; match
            // ACL rules against the bare service name.
            let label = name
                .strip_prefix(super::SERVICE_REQUEST_PREFIX)
                .or_else(|| name.strip_prefix(super::SERVICE_RESPONSE_PREFIX))
                .unwrap_or(&name);
            if acl.check(direction, label) {
                return true;
            }
        }
        acl.check(direction, &format!("{:x}", topic_hash))
    }

    /// Manually add a remote route for a topic.
    ///
    /// # Arguments
    /// * `topic_hash` - Hashed topic identifier
    /// * `addr` - Remote peer socket address
    pub fn add_remote_route(&self, topic_hash: TopicHash, addr: SocketAddr) {
        let mut routes = self.remote_routes.lock().unwrap();
        let addrs = routes.entry(topic_hash).or_default();
        if !addrs.contains(&addr) {
            addrs.push(addr);
        }
    }

    /// Add an ACL rule for a topic pattern.
    ///
    /// # Arguments
    /// * `direction` - Publish or Subscribe
    /// * `topic_pattern` - Topic name or pattern to match
    /// * `allowed` - Whether the direction is permitted
    ///
    /// # Returns
    /// Whether the rule was added successfully.
    pub fn add_acl(&self, direction: AclDirection, topic_pattern: &str, _allowed: bool) -> bool {
        self.acl_engine
            .lock()
            .unwrap()
            .add_rule(direction, topic_pattern)
    }

    /// Register a node's network address for routing.
    ///
    /// # Arguments
    /// * `node_id` - Remote node identifier
    /// * `addr` - Remote node socket address
    pub fn set_node_addr(&self, node_id: NodeId, addr: SocketAddr) {
        self.known_addrs.write().unwrap().insert(node_id, addr);
    }

    /// Add remote routes for both request and response topics of a service.
    ///
    /// # Arguments
    /// * `service_id` - Unique service identifier
    /// * `node_id` - Remote node hosting the service
    pub fn add_remote_service_route(&self, service_id: ServiceId, node_id: NodeId) {
        let addr = match self.known_addrs.read().unwrap().get(&node_id).copied() {
            Some(a) => a,
            None => {
                return;
            }
        };
        let req = service_request_topic(service_id);
        let res = service_response_topic(service_id);
        let mut routes = self.remote_routes.lock().unwrap();
        routes.entry(req).or_default().push(addr);
        routes.entry(res).or_default().push(addr);
    }

    /// Register a topic hash for discovery advertisement.
    ///
    /// # Arguments
    /// * `topic_hash` - Hashed topic identifier
    pub fn add_published_topic(&self, topic_hash: TopicHash) {
        let mut topics = self.published_topics.write().unwrap();
        if !topics.contains(&topic_hash) {
            topics.push(topic_hash);
        }
    }

    pub(crate) fn add_subscribed_topic(&self, topic_hash: TopicHash) {
        let mut topics = self.subscribed_topics.write().unwrap();
        if !topics.contains(&topic_hash) {
            topics.push(topic_hash);
        }
    }

    /// Create a publisher on the given topic.
    ///
    /// # Arguments
    /// * `topic_name` - Human-readable topic name
    /// * `topic_hash` - Hashed topic identifier
    /// * `qos` - Quality-of-service profile
    ///
    /// # Returns
    /// `Ok(())` on success, or an error string if SHM creation fails.
    pub fn create_publisher(
        &self,
        topic_name: &str,
        topic_type: &str,
        topic_hash: TopicHash,
        qos: &QosProfile,
    ) -> Result<(), String> {
        let effective_depth = topic_ring_depth(topic_name, topic_type, qos);
        let name = super::local_channel_name(self.domain_id, topic_hash);
        let slot_size =
            topic_message_capacity(topic_type, qos.max_message_size).min(u32::MAX as usize) as u32;
        let existing_publisher = self.publishers.lock().unwrap().get(&topic_hash).cloned();
        let existing_subscription = self.subscriptions.lock().unwrap().get(&topic_hash).cloned();
        // First publisher for this topic in this session — used to stamp a new
        // generation so a reused (orphaned) SHM segment doesn't leak the
        // previous run's retained data to late TRANSIENT_LOCAL subscribers.
        let is_first_publisher = existing_publisher.is_none();
        let existing = existing_publisher.or(existing_subscription);
        let pubsub = match existing {
            Some(pubsub) if pubsub.payload_capacity() >= (slot_size as usize) => pubsub,
            _ => Arc::new(
                LocalPubSub::create_or_open(
                    &name,
                    effective_depth as u32,
                    slot_size,
                    matches!(qos.history, HistoryKind::KeepAll),
                )
                .map_err(|e| format!("failed to create publisher: {}", e))?,
            ),
        };
        if is_first_publisher {
            pubsub.mark_generation();
        }
        if self
            .subscription_counts
            .lock()
            .unwrap()
            .contains_key(&topic_hash)
        {
            self.subscriptions
                .lock()
                .unwrap()
                .insert(topic_hash, pubsub.clone());
        }
        self.publishers.lock().unwrap().insert(topic_hash, pubsub);
        *self
            .publisher_counts
            .lock()
            .unwrap()
            .entry(topic_hash)
            .or_default() += 1;
        let gid = make_gid("pub", self.node_id, topic_hash);
        self.graph_cache.register_publisher(
            topic_hash,
            topic_name,
            topic_type,
            self.node_id,
            *qos,
            gid,
        );
        self.add_published_topic(topic_hash);
        self.register_published_topic_with_daemon(topic_hash, topic_name, topic_type, qos);
        self.topic_name_cache
            .write()
            .unwrap()
            .insert(topic_hash, topic_name.to_string());
        self.topic_type_cache
            .write()
            .unwrap()
            .insert(topic_hash, topic_type.to_string());
        self.topic_qos_cache
            .write()
            .unwrap()
            .insert((self.node_id, topic_hash), RemoteQos::from_qos_profile(qos));
        if qos.durability == Durability::TransientLocal && is_first_publisher {
            self.retained_remote_samples
                .lock()
                .unwrap()
                .insert(topic_hash, std::collections::VecDeque::new());
            self.retained_remote_peers
                .lock()
                .unwrap()
                .remove(&topic_hash);
            self.retained_remote_pending
                .lock()
                .unwrap()
                .remove(&topic_hash);
        }

        if let Some(limit) = qos.bandwidth_limit {
            self.publishers_budget
                .lock()
                .unwrap()
                .insert(topic_hash, LeakyBucket::new(limit));
        }
        if let Some(ref em) = self.event_monitor {
            if let Some(deadline) = qos.deadline {
                if !deadline.is_zero() {
                    let handle = em.create_event(EventKind::DeadlineMissed);
                    let publisher_gid = u64::from_le_bytes(gid[..8].try_into().unwrap());
                    em.register_deadline_monitor(handle, topic_hash, publisher_gid, deadline);
                }
            }
        }
        self.signal_graph_eventfds();
        Ok(())
    }

    /// Destroy one publisher endpoint for a topic.
    pub fn destroy_publisher(&self, topic_hash: TopicHash) -> Result<(), String> {
        let mut counts = self.publisher_counts.lock().unwrap();
        let count = counts.get_mut(&topic_hash).ok_or("publisher not found")?;
        *count -= 1;
        if *count > 0 {
            return Ok(());
        }
        counts.remove(&topic_hash);
        drop(counts);
        self.publishers.lock().unwrap().remove(&topic_hash);
        self.publishers_budget.lock().unwrap().remove(&topic_hash);
        self.retained_remote_samples
            .lock()
            .unwrap()
            .remove(&topic_hash);
        self.retained_remote_peers
            .lock()
            .unwrap()
            .remove(&topic_hash);
        self.retained_remote_pending
            .lock()
            .unwrap()
            .remove(&topic_hash);
        self.graph_cache
            .local_publishers
            .write()
            .unwrap()
            .remove(&topic_hash);
        self.published_topics
            .write()
            .unwrap()
            .retain(|hash| *hash != topic_hash);
        if !self
            .subscription_counts
            .lock()
            .unwrap()
            .contains_key(&topic_hash)
        {
            self.topic_qos_cache
                .write()
                .unwrap()
                .remove(&(self.node_id, topic_hash));
            self.topic_name_cache.write().unwrap().remove(&topic_hash);
            self.topic_type_cache.write().unwrap().remove(&topic_hash);
        }
        self.signal_graph_eventfds();
        Ok(())
    }

    /// Publish a message to the given topic (legacy, no GID — assumes gid=0).
    ///
    /// # Arguments
    /// * `topic_hash` - Hashed topic identifier
    /// * `data` - Raw message bytes
    ///
    /// # Returns
    /// Sequence number on success, or an error if ACL denies or budget is exceeded.
    pub fn publish(&self, topic_hash: TopicHash, data: &[u8]) -> Result<u64, String> {
        self.publish_with_gid(topic_hash, data, 0)
    }

    /// Publish a message to the given topic with a publisher GID.
    ///
    /// When `publisher_gid` is non-zero, the deadline monitor for that specific
    /// publisher is reset instead of all monitors for the topic.
    ///
    /// # Arguments
    /// * `topic_hash` - Hashed topic identifier
    /// * `data` - Raw message bytes
    /// * `publisher_gid` - Unique GID for the publishing endpoint
    ///
    /// # Returns
    /// Sequence number on success, or an error if ACL denies or budget is exceeded.
    pub fn publish_with_gid(
        &self,
        topic_hash: TopicHash,
        data: &[u8],
        publisher_gid: u64,
    ) -> Result<u64, String> {
        if !self.acl_allows(AclDirection::Publish, topic_hash) {
            return Err("access denied".into());
        }
        let mut budget_exceeded = false;
        {
            let budgets = self.publishers_budget.lock().unwrap();
            if let Some(bucket) = budgets.get(&topic_hash) {
                if !bucket.try_send(data.len()) {
                    tracing::warn!(
                        topic_hash = topic_hash,
                        bytes = data.len(),
                        "bandwidth budget exceeded, dropping message"
                    );
                    budget_exceeded = true;
                }
            }
        }
        if budget_exceeded {
            return Err("bandwidth budget exceeded".into());
        }

        let pubsub = self
            .publishers
            .lock()
            .unwrap()
            .get(&topic_hash)
            .cloned()
            .ok_or("publisher not found")?;
        let seq = pubsub
            .publish_with_gid(data, publisher_gid)
            .map_err(|e| e.to_string())?;

        crate::axon_trace!(
            "event=shm_publish topic_hash={} seq={} bytes={} publisher_gid={} transport=shared_memory",
            topic_hash,
            seq,
            data.len(),
            publisher_gid
        );

        // Record publish timestamp for lifespan enforcement
        self.message_timestamps
            .lock()
            .unwrap()
            .insert((topic_hash, seq), Instant::now());
        self.retain_remote_sample(topic_hash, seq, data);

        // The subscriber take path prunes these maps, but a publish-only
        // process (e.g. a camera node whose consumers are remote) never takes
        // locally, so without periodic pruning they grow without bound.
        // Prune every 128 publishes to keep the amortized cost negligible.
        if seq % 128 == 0 {
            let oldest = pubsub.oldest_available_seq();
            self.message_timestamps
                .lock()
                .unwrap()
                .retain(|(th, s), _| *th != topic_hash || *s >= oldest);
            pubsub
                .timestamps
                .lock()
                .unwrap()
                .retain(|&s, _| s >= oldest);
            pubsub
                .publisher_gids
                .lock()
                .unwrap()
                .retain(|&s, _| s >= oldest);
        }

        // Update deadline monitoring — per-publisher when GID is known
        if let Some(ref em) = self.event_monitor {
            em.update_deadline_publish_time(topic_hash, publisher_gid);
        }

        // Assert liveliness — only for Automatic mode.
        // ManualByTopic / ManualByParticipant require explicit app assertion.
        if let Some(ref em) = self.event_monitor {
            let is_automatic = self
                .topic_qos_cache
                .read()
                .unwrap()
                .get(&(self.node_id, topic_hash))
                .is_none_or(|rq| rq.liveliness == crate::types::Liveliness::Automatic);
            if is_automatic {
                em.assert_liveliness(self.node_id);
            }
        }

        // Forward to remote subscribers via QUIC
        if let Some(ref qt) = self.quic_transport {
            self.sync_daemon_matches();
            let send_depth = self.publisher_send_depth(topic_hash);
            let routes = self.remote_routes.lock().unwrap();
            if let Some(addrs) = routes.get(&topic_hash) {
                let known = self.known_addrs.read().unwrap();
                let mut seen_peers = std::collections::HashSet::new();
                // Copy once and share among remote peers.
                let data_owned = data.to_vec();
                let orig_size = data.len();
                for addr in addrs {
                    if let Some((peer_id, _)) = known.iter().find(|(_, a)| **a == *addr) {
                        if seen_peers.insert(*peer_id) {
                            qt.send_message_reuse(
                                *peer_id,
                                topic_hash,
                                data_owned.clone(),
                                seq,
                                send_depth,
                            );
                        }
                    }
                }
                let c = TRACE_PUB_COUNTER.fetch_add(1, Ordering::Relaxed);
                if crate::trace::enabled() || c.is_multiple_of(30) {
                    tracing::info!(target: "axon_latency", topic_hash, size = orig_size, peers = seen_peers.len(), "publish_dispatched");
                }
                crate::axon_trace!(
                    "event=remote_route_enqueued topic_hash={} seq={} bytes={} peers={} transport=quic",
                    topic_hash,
                    seq,
                    orig_size,
                    seen_peers.len()
                );
            }
        }

        Ok(seq)
    }

    fn retain_remote_sample(&self, topic_hash: TopicHash, seq: u64, data: &[u8]) {
        let qos = self
            .topic_qos_cache
            .read()
            .unwrap()
            .get(&(self.node_id, topic_hash))
            .copied();
        let Some(qos) = qos else {
            return;
        };
        let transient = qos.durability == Durability::TransientLocal;
        let reliable_startup = qos.reliability == crate::qos::Reliability::Reliable;
        if !transient && !reliable_startup {
            return;
        }

        // A reliable writer can publish while discovery and the secured QUIC
        // connection are still converging. Preserve its bounded startup
        // history until the first remote reader receives it; otherwise a
        // short-lived synchronization request can disappear before matching.
        // Unlike TRANSIENT_LOCAL history, this is not updated for later
        // joiners once a first delivery is active or complete.
        if !transient
            && (self
                .retained_remote_peers
                .lock()
                .unwrap()
                .get(&topic_hash)
                .is_some_and(|peers| !peers.is_empty())
                || self
                    .retained_remote_pending
                    .lock()
                    .unwrap()
                    .get(&topic_hash)
                    .is_some_and(|peers| !peers.is_empty()))
        {
            return;
        }

        // KeepAll must still be bounded in a finite middleware process. The
        // local SHM path uses the same 256-sample cap.
        let depth = match qos.history {
            HistoryKind::KeepLast { depth } => depth.clamp(1, 256),
            HistoryKind::KeepAll => 256,
        };
        let mut retained = self.retained_remote_samples.lock().unwrap();
        let history = retained.entry(topic_hash).or_default();
        history.push_back((seq, data.to_vec()));
        while history.len() > depth {
            history.pop_front();
        }
    }

    /// Borrow a loaned message buffer from a publisher.
    pub fn borrow_loaned(
        &self,
        topic_hash: TopicHash,
        max_size: usize,
    ) -> Option<(*mut u8, usize)> {
        let pubs = self.publishers.lock().unwrap();
        let pubsub = pubs.get(&topic_hash)?;
        pubsub.borrow_buffer(max_size)
    }

    /// Commit a loaned message buffer for publishing.
    pub fn commit_loaned(&self, topic_hash: TopicHash, ptr: *const u8, size: usize) -> bool {
        let pubs = self.publishers.lock().unwrap();
        if let Some(pubsub) = pubs.get(&topic_hash) {
            pubsub.commit_buffer(ptr, size, 0)
        } else {
            false
        }
    }

    /// Return the send-channel depth hint for a publisher.
    ///
    /// Reliable publishers use an unbounded ordered queue so middleware does
    /// not silently lose graph or command updates. Best-effort publishers use
    /// their configured history depth.
    pub fn publisher_send_depth(&self, topic_hash: TopicHash) -> usize {
        let qos = self
            .topic_qos_cache
            .read()
            .unwrap()
            .get(&(self.node_id, topic_hash))
            .copied();
        let Some(qos) = qos else {
            return 1;
        };
        if qos.reliability == crate::qos::Reliability::Reliable {
            return usize::MAX;
        }
        match qos.history {
            HistoryKind::KeepLast { depth } => depth.max(1),
            HistoryKind::KeepAll => 256,
        }
    }

    /// Get actual QoS for a publisher.
    ///
    /// # Arguments
    /// * `topic_name` - Human-readable topic name
    ///
    /// # Returns
    /// The QoS profile if a publisher exists for the topic.
    pub fn publisher_actual_qos(&self, topic_name: &str) -> Option<QosProfile> {
        let topic_hash = fxhash(topic_name);
        let pubs = self.graph_cache.local_publishers.read().unwrap();
        pubs.values()
            .find(|e| e.topic_hash == topic_hash)
            .map(|e| e.qos)
    }

    /// Get the 16-byte GID for a publisher on the given topic.
    ///
    /// # Arguments
    /// * `topic_name` - Human-readable topic name
    ///
    /// # Returns
    /// `Some(gid)` if a publisher exists for the topic.
    pub fn publisher_gid(&self, topic_name: &str) -> Option<[u8; 16]> {
        let topic_hash = fxhash(topic_name);
        let pubs = self.graph_cache.local_publishers.read().unwrap();
        pubs.values()
            .find(|e| e.topic_hash == topic_hash)
            .map(|e| e.gid)
    }

    /// Get remote flow endpoints for a publisher.
    ///
    /// # Arguments
    /// * `topic_name` - Human-readable topic name
    ///
    /// # Returns
    /// Vector of remote socket addresses.
    pub fn publisher_flow_endpoints(&self, topic_name: &str) -> Vec<std::net::SocketAddr> {
        let topic_hash = fxhash(topic_name);
        let routes = self.remote_routes.lock().unwrap();
        routes.get(&topic_hash).cloned().unwrap_or_default()
    }

    /// Count the number of publishers for a given topic (local + remote).
    ///
    /// # Arguments
    /// * `topic` - Topic name string
    ///
    /// # Returns
    /// Total publisher count.
    pub fn get_publisher_count(&self, topic: &str) -> usize {
        let mut count = 0;
        {
            let pubs = self.graph_cache.local_publishers.read().unwrap();
            for entity in pubs.values() {
                if entity.topic_name == topic {
                    count += 1;
                }
            }
        }
        count
    }
}
