use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

static TRACE_RECV_NEXT: AtomicU64 = AtomicU64::new(0);
use super::{topic_message_capacity, topic_ring_depth, Session};
use crate::events::EventKind;
use crate::filter::ContentFilter;
use crate::local::LocalPubSub;
use crate::types::*;

impl Session {
    /// Create a subscription on the given topic.
    ///
    /// # Arguments
    /// * `topic_name` - Human-readable topic name
    /// * `topic_hash` - Hashed topic identifier
    /// * `qos` - Quality-of-service profile
    ///
    /// # Returns
    /// `Ok(SubscriptionHandle)` on success, or an error string if ACL denies access or SHM open fails.
    pub fn create_subscription(
        &self,
        topic_name: &str,
        topic_type: &str,
        topic_hash: TopicHash,
        qos: &QosProfile,
    ) -> Result<SubscriptionHandle, String> {
        // Match ACL globs against the real topic name (documented AXON_ACL_*
        // semantics), keeping the hex-hash fallback for compatibility with
        // rules written against internal hash strings.
        {
            let acl = self.acl_engine.lock().unwrap();
            if !acl.check(AclDirection::Subscribe, topic_name)
                && !acl.check(AclDirection::Subscribe, &format!("{:x}", topic_hash))
            {
                return Err("access denied".into());
            }
        }
        let name = super::local_channel_name(self.domain_id, topic_hash);
        let effective_depth = topic_ring_depth(topic_name, topic_type, qos);
        let slot_size =
            topic_message_capacity(topic_type, qos.max_message_size).min(u32::MAX as usize) as u32;
        // Cross-host delivery is owned by the QUIC receiver. Sharing a
        // publisher's SHM mapping across processes would write every remote
        // packet into the same ring a second time and duplicate messages.
        let existing_subscription = self.subscriptions.lock().unwrap().get(&topic_hash).cloned();
        let existing_publisher = self.publishers.lock().unwrap().get(&topic_hash).cloned();
        let existing = existing_subscription.or(existing_publisher);
        let pubsub = match existing {
            Some(pubsub) if pubsub.payload_capacity() >= (slot_size as usize) => pubsub,
            _ => Arc::new(
                LocalPubSub::create_or_open(
                    &name,
                    effective_depth as u32,
                    slot_size,
                    matches!(qos.history, HistoryKind::KeepAll),
                )
                .map_err(|e| format!("failed to create subscription: {}", e))?,
            ),
        };
        if self
            .publisher_counts
            .lock()
            .unwrap()
            .contains_key(&topic_hash)
        {
            self.publishers
                .lock()
                .unwrap()
                .insert(topic_hash, pubsub.clone());
        }
        let gid = make_gid("sub", self.node_id, topic_hash);
        self.graph_cache.register_subscription(
            topic_hash,
            topic_name,
            topic_type,
            self.node_id,
            *qos,
            gid,
        );
        let eventfd = pubsub.event_fd();
        let initial_seq = if qos.durability == crate::types::Durability::TransientLocal {
            // Deliver retained samples for latched topics, but never below the
            // current publisher generation: a reused (orphaned) SHM segment may
            // still hold the previous run's frames, which must not resurface.
            pubsub.oldest_available_seq().max(pubsub.generation_start())
        } else {
            pubsub.current_seq()
        };
        if let Some(ref qt) = self.quic_transport {
            let (depth, keep_all) = match qos.history {
                HistoryKind::KeepLast { .. } => (effective_depth, false),
                HistoryKind::KeepAll => (effective_depth, true),
            };
            // A session may contain several ROS subscriptions to the same
            // topic (the demo creates one graph subscription per knowledge
            // graph).  Keep one transport queue per topic and fan samples
            // out by cursor instead of replacing the queue/sender for every
            // new subscription.  Replacing it silently orphaned the earlier
            // subscribers and left their graphs permanently stale.
            let (queue, register_receiver) = {
                let mut queues = self.remote_recv_queues.lock().unwrap();
                if let Some(queue) = queues.get(&topic_hash) {
                    (queue.clone(), false)
                } else {
                    let queue =
                        Arc::new(crate::subscriber_queue::SubscriberQueue::with_seq_and_mode(
                            depth,
                            initial_seq,
                            keep_all,
                        ));
                    queues.insert(topic_hash, queue.clone());
                    (queue, true)
                }
            };
            if register_receiver {
                qt.register_recv_subscriber(topic_hash, pubsub.clone(), queue);
            }
        }
        let handle = SubscriptionHandle {
            topic_hash,
            shm_path: format!("/dev/shm/axon_{}", name),
            ring_buf: std::ptr::null_mut(),
            data_ptr: std::ptr::null_mut(),
            eventfd,
            initial_seq,
        };
        self.subscriptions
            .lock()
            .unwrap()
            .insert(topic_hash, pubsub);
        *self
            .subscription_counts
            .lock()
            .unwrap()
            .entry(topic_hash)
            .or_default() += 1;
        let mut subscribed_topics = self.subscribed_topics.write().unwrap();
        if !subscribed_topics.contains(&topic_hash) {
            subscribed_topics.push(topic_hash);
        }
        self.register_subscribed_topic_with_daemon(topic_hash, topic_name, topic_type, qos);
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

        self.signal_graph_eventfds();

        // Auto-register deadline/liveliness monitors if QoS specifies them
        if let Some(ref em) = self.event_monitor {
            if let Some(deadline) = qos.deadline {
                if !deadline.is_zero() {
                    let handle = em.create_event(EventKind::DeadlineMissed);
                    em.register_deadline_monitor(handle, topic_hash, 0, deadline);
                }
            }
            if let Some(liveliness_lease) = qos.liveliness_lease_duration {
                if !liveliness_lease.is_zero() {
                    let handle = em.create_event(EventKind::LivelinessLost);
                    em.register_liveliness_monitor(handle, self.node_id, liveliness_lease);
                }
            }
        }

        Ok(handle)
    }

    /// Destroy one subscription endpoint for a topic.
    pub fn destroy_subscription(&self, topic_hash: TopicHash) -> Result<(), String> {
        let mut counts = self.subscription_counts.lock().unwrap();
        let count = counts
            .get_mut(&topic_hash)
            .ok_or("subscription not found")?;
        *count -= 1;
        if *count > 0 {
            return Ok(());
        }
        counts.remove(&topic_hash);
        drop(counts);
        self.remote_recv_queues.lock().unwrap().remove(&topic_hash);
        if let Some(ref qt) = self.quic_transport {
            qt.recv_channels.lock().unwrap().remove(&topic_hash);
        }
        self.subscriptions.lock().unwrap().remove(&topic_hash);
        self.graph_cache
            .local_subscriptions
            .write()
            .unwrap()
            .remove(&topic_hash);
        self.subscribed_topics
            .write()
            .unwrap()
            .retain(|hash| *hash != topic_hash);
        if !self
            .publisher_counts
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

    /// Receive a message from the given topic by sequence number.
    ///
    /// # Arguments
    /// * `topic_hash` - Hashed topic identifier
    /// * `seq` - Message sequence number
    /// * `out` - Output buffer
    ///
    /// # Returns
    /// Number of bytes read on success, or an error if subscription not found.
    pub fn receive(
        &self,
        topic_hash: TopicHash,
        seq: u64,
        out: &mut [u8],
    ) -> Result<usize, String> {
        let queue = self
            .remote_recv_queues
            .lock()
            .unwrap()
            .get(&topic_hash)
            .cloned();
        // Check decompressed size before consuming from remote queue
        if let Some(ref q) = queue {
            if let Some((prefix, _)) = q.peek_prefix(seq) {
                let needed = decompressed_size_from_prefix(seq, q, &prefix);
                if let Some(n) = needed {
                    if n > out.len() {
                        return Ok(n);
                    }
                }
            }
        }
        let mut remote_data: Option<(usize, Option<Instant>)> = None;
        if let Some(ref q) = queue {
            if let Some((size, _)) = q.try_take(seq, out) {
                if size > out.len() {
                    return Ok(size);
                }
                let ts = q.timestamp_for(seq);
                remote_data = Some((size, ts));
            }
        }
        if let Some((size, ts)) = remote_data {
            let qos_cache = self.topic_qos_cache.read().unwrap();
            if let Some(rq) = qos_cache.get(&(self.node_id, topic_hash)) {
                let qos: QosProfile = (*rq).into();
                if let Some(lifespan) = qos.lifespan {
                    if !lifespan.is_zero() {
                        let now = Instant::now();
                        let effective_ts = ts.unwrap_or(now);
                        if now.duration_since(effective_ts) > lifespan {
                            return Err("message expired (lifespan exceeded)".into());
                        }
                    }
                }
            }
            if let Some(d) = crate::compress::decompress(&out[..size]) {
                let dlen = d.len().min(out.len());
                out[..dlen].copy_from_slice(&d[..dlen]);
                return Ok(dlen);
            }
            return Ok(size);
        }

        let subs = self.subscriptions.lock().unwrap();
        let pubsub = subs
            .get(&topic_hash)
            .ok_or("subscription not found")?
            .as_ref();

        {
            let local_pubs = self.graph_cache.local_publishers.read().unwrap();
            let local_subs = self.graph_cache.local_subscriptions.read().unwrap();
            if let (Some(pub_entity), Some(sub_entity)) =
                (local_pubs.get(&topic_hash), local_subs.get(&topic_hash))
            {
                if !crate::types::qos_profiles_compatible(&pub_entity.qos, &sub_entity.qos) {
                    return Err("QoS incompatible".into());
                }
            }
        }

        {
            let qos_cache = self.topic_qos_cache.read().unwrap();
            if let Some(remote_qos) = qos_cache.get(&(self.node_id, topic_hash)) {
                let qos: QosProfile = (*remote_qos).into();
                if let Some(lifespan) = qos.lifespan {
                    if !lifespan.is_zero() {
                        let ts_map = self.message_timestamps.lock().unwrap();
                        let timestamp = ts_map
                            .get(&(topic_hash, seq))
                            .copied()
                            .or_else(|| pubsub.timestamps.lock().unwrap().get(&seq).copied());
                        if let Some(ts) = timestamp {
                            if Instant::now().duration_since(ts) > lifespan {
                                return Err("message expired (lifespan exceeded)".into());
                            }
                        }
                    }
                }
            }
        }

        {
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

        let result = pubsub.receive(seq, out);
        if let (Ok(_), Some(ref em)) = (&result, &self.event_monitor) {
            let gid = pubsub
                .publisher_gids
                .lock()
                .unwrap()
                .get(&seq)
                .copied()
                .unwrap_or(0);
            em.update_deadline_publish_time(topic_hash, gid);
        }
        result.map_err(|e| e.to_string())
    }

    /// Peek at the message size for a given sequence number without consuming it.
    pub fn peek_message_size(&self, topic_hash: TopicHash, seq: u64) -> Result<usize, String> {
        if let Some(q) = self.remote_recv_queues.lock().unwrap().get(&topic_hash) {
            if let Some((prefix, _)) = q.peek_prefix(seq) {
                return Ok(decompressed_size_from_prefix(seq, q, &prefix).unwrap_or(0));
            }
        }
        let subs = self.subscriptions.lock().unwrap();
        let pubsub = subs
            .get(&topic_hash)
            .ok_or("subscription not found")?
            .as_ref();
        pubsub.message_size(seq).map_err(|e| e.to_string())
    }

    /// Resolve a consumer sequence to the oldest retained message and return
    /// that message's size.
    pub fn peek_next_message_size(
        &self,
        topic_hash: TopicHash,
        requested_seq: u64,
    ) -> Result<(usize, u64), String> {
        if let Some(q) = self.remote_recv_queues.lock().unwrap().get(&topic_hash) {
            if let Some((prefix, actual_seq)) = q.peek_prefix(requested_seq) {
                let size = decompressed_size_from_prefix(requested_seq, q, &prefix)
                    .ok_or_else(|| "subscription not found".to_string())?;
                return Ok((size, actual_seq));
            }
        }
        let subs = self.subscriptions.lock().unwrap();
        let pubsub = subs
            .get(&topic_hash)
            .ok_or("subscription not found")?
            .as_ref();
        let write_idx = pubsub.current_seq();
        if write_idx == 0 || requested_seq >= write_idx {
            return Err("no data at this sequence number".into());
        }
        let oldest = pubsub.oldest_available_seq();
        let actual_seq = if requested_seq >= oldest {
            requested_seq
        } else {
            write_idx.saturating_sub(1)
        };
        let size = match pubsub.message_size(actual_seq) {
            Ok(size) => size,
            Err("slot overwritten") => {
                let latest_seq = pubsub.current_seq().saturating_sub(1);
                let size = pubsub.message_size(latest_seq).map_err(|e| e.to_string())?;
                return Ok((size, latest_seq));
            }
            Err(e) => return Err(e.to_string()),
        };
        Ok((size, actual_seq))
    }

    /// Check whether data is available on the given topic subscription.
    ///
    /// # Arguments
    /// * `topic_hash` - Hashed topic identifier
    ///
    /// # Returns
    /// `true` if at least one message is available.
    pub fn data_available(&self, topic_hash: TopicHash) -> bool {
        let queue = self
            .remote_recv_queues
            .lock()
            .unwrap()
            .get(&topic_hash)
            .cloned();
        if let Some(ref q) = queue {
            if q.is_active() && q.data_available_from(0) {
                return true;
            }
        }
        self.subscriptions
            .lock()
            .unwrap()
            .get(&topic_hash)
            .map(|s| s.data_available())
            .unwrap_or(false)
    }

    /// Check whether a particular consumer sequence has data available.
    pub fn data_available_from(&self, topic_hash: TopicHash, sequence_number: u64) -> bool {
        let queue = self
            .remote_recv_queues
            .lock()
            .unwrap()
            .get(&topic_hash)
            .cloned();
        if let Some(ref q) = queue {
            if q.is_active() && q.data_available_from(sequence_number) {
                return true;
            }
        }
        self.subscriptions
            .lock()
            .unwrap()
            .get(&topic_hash)
            .map(|s| s.data_available_from(sequence_number))
            .unwrap_or(false)
    }

    /// Read the next available message for a consumer.
    ///
    /// If the consumer's requested sequence is still in the ring buffer, reads
    /// from there.  If the consumer fell behind (the slot was overwritten),
    /// skips to the latest written message — avoids replaying the entire
    /// ring buffer depth on a late-joining subscriber.
    pub fn receive_next(
        &self,
        topic_hash: TopicHash,
        requested_seq: u64,
        out: &mut [u8],
    ) -> Result<(usize, u64), String> {
        let queue = self
            .remote_recv_queues
            .lock()
            .unwrap()
            .get(&topic_hash)
            .cloned();
        // Peek decompressed size before consuming from remote queue.
        // This prevents consuming a message whose decompressed data would
        // overflow the caller's buffer — the caller can resize and retry.
        if let Some(ref q) = queue {
            if let Some((prefix, peek_seq)) = q.peek_prefix(requested_seq) {
                let needed = decompressed_size_from_prefix(requested_seq, q, &prefix);
                if let Some(n) = needed {
                    if n > out.len() {
                        return Ok((n, peek_seq));
                    }
                }
            }
        }
        let mut remote_data: Option<(usize, u64, Option<Instant>)> = None;
        if let Some(ref q) = queue {
            if let Some((size, actual_seq)) = q.read_at(requested_seq, out) {
                if size > out.len() {
                    // Buffer too small — don't decompress, pass size through so
                    // the caller can resize and retry without losing the message.
                    return Ok((size, actual_seq));
                }
                let ts = q.timestamp_for(actual_seq);
                remote_data = Some((size, actual_seq, ts));
            }
        }
        if let Some((size, actual_seq, ts)) = remote_data {
            let c = TRACE_RECV_NEXT.fetch_add(1, Ordering::Relaxed);
            if crate::trace::enabled() || c.is_multiple_of(30) {
                let queue_us = ts.map(|t| t.elapsed().as_micros() as u64).unwrap_or(0);
                tracing::info!(target: "axon_latency", topic_hash, size, seq = actual_seq, queue_wait_us = queue_us, "subscriber_took");
            }
            crate::axon_trace!(
                "event=quic_to_shm topic_hash={} seq={} bytes={} queue_wait_us={} transport=quic_to_shared_memory",
                topic_hash,
                actual_seq,
                size,
                ts.map(|t| t.elapsed().as_micros() as u64).unwrap_or(0)
            );
            let qos_cache = self.topic_qos_cache.read().unwrap();
            if let Some(rq) = qos_cache.get(&(self.node_id, topic_hash)) {
                let qos: QosProfile = (*rq).into();
                if let Some(lifespan) = qos.lifespan {
                    if !lifespan.is_zero() {
                        let now = Instant::now();
                        let effective_ts = ts.unwrap_or(now);
                        if now.duration_since(effective_ts) > lifespan {
                            return Err("message expired (lifespan exceeded)".into());
                        }
                    }
                }
            }
            if let Some(d) = crate::compress::decompress(&out[..size]) {
                let dlen = d.len().min(out.len());
                out[..dlen].copy_from_slice(&d[..dlen]);
                return Ok((dlen, actual_seq));
            }
            return Ok((size, actual_seq));
        }

        let subs = self.subscriptions.lock().unwrap();
        let pubsub = subs
            .get(&topic_hash)
            .ok_or("subscription not found")?
            .as_ref();
        let write_idx = pubsub.current_seq();
        let oldest = pubsub.oldest_available_seq();
        if write_idx == 0 || requested_seq >= write_idx {
            return Err("no data at this sequence number".into());
        }
        let initial_seq = if requested_seq >= oldest {
            requested_seq
        } else {
            write_idx.saturating_sub(1)
        };

        {
            let local_pubs = self.graph_cache.local_publishers.read().unwrap();
            let local_subs = self.graph_cache.local_subscriptions.read().unwrap();
            if let (Some(pub_entity), Some(sub_entity)) =
                (local_pubs.get(&topic_hash), local_subs.get(&topic_hash))
            {
                if !crate::types::qos_profiles_compatible(&pub_entity.qos, &sub_entity.qos) {
                    return Err("QoS incompatible".into());
                }
            }
        }

        // Clean up old timestamps and publisher_gids: remove entries for
        // sequences that have been overwritten by the ring buffer.
        {
            let oldest = pubsub.oldest_available_seq();
            let mut ts_map = self.message_timestamps.lock().unwrap();
            ts_map.retain(|(th, s), _| *th != topic_hash || *s >= oldest);
        }
        {
            let oldest = pubsub.oldest_available_seq();
            let mut ts_map = pubsub.timestamps.lock().unwrap();
            ts_map.retain(|&s, _| s >= oldest);
        }
        {
            let oldest = pubsub.oldest_available_seq();
            let mut gid_map = pubsub.publisher_gids.lock().unwrap();
            gid_map.retain(|&s, _| s >= oldest);
        }

        let mut actual_seq = initial_seq;
        let mut retries = 0;
        let size = loop {
            // `RingBuffer::read` only advances the producer watermark; it does
            // not remove or invalidate the slot.  Each ROS subscription keeps
            // its own cursor, so later subscriptions can still read the same
            // sample while the writer gets an accurate consumer watermark.
            match pubsub.receive(actual_seq, out) {
                Ok(size) => break size,
                Err("slot overwritten") if retries < 4 => {
                    let latest_seq = pubsub.current_seq().saturating_sub(1);
                    if latest_seq == actual_seq {
                        return Err(format!(
                            "slot overwritten (write_idx={} actual_seq={} requested_seq={} oldest={})",
                            pubsub.current_seq(),
                            actual_seq,
                            requested_seq,
                            pubsub.oldest_available_seq()
                        ));
                    }
                    actual_seq = latest_seq;
                    retries += 1;
                }
                Err("slot not yet written") if retries < 4 => {
                    let latest_seq = pubsub.current_seq().saturating_sub(1);
                    if latest_seq > actual_seq {
                        actual_seq = latest_seq;
                    } else {
                        std::thread::yield_now();
                    }
                    retries += 1;
                }
                Err("slot not yet written") => {
                    return Err("no data at this sequence number".into());
                }
                Err(e) => {
                    return Err(format!(
                        "{} (write_idx={} actual_seq={} requested_seq={} oldest={})",
                        e,
                        pubsub.current_seq(),
                        actual_seq,
                        requested_seq,
                        pubsub.oldest_available_seq()
                    ));
                }
            }
        };

        {
            let qos_cache = self.topic_qos_cache.read().unwrap();
            if let Some(remote_qos) = qos_cache.get(&(self.node_id, topic_hash)) {
                let qos: QosProfile = (*remote_qos).into();
                if let Some(lifespan) = qos.lifespan {
                    if !lifespan.is_zero() {
                        let ts_map = self.message_timestamps.lock().unwrap();
                        let timestamp =
                            ts_map.get(&(topic_hash, actual_seq)).copied().or_else(|| {
                                pubsub.timestamps.lock().unwrap().get(&actual_seq).copied()
                            });
                        if let Some(ts) = timestamp {
                            if Instant::now().duration_since(ts) > lifespan {
                                return Err("message expired (lifespan exceeded)".into());
                            }
                        }
                    }
                }
            }
        }

        // Update per-publisher deadline tracking on successful receive
        if let Some(ref em) = self.event_monitor {
            let gid = pubsub
                .publisher_gids
                .lock()
                .unwrap()
                .get(&actual_seq)
                .copied()
                .unwrap_or(0);
            em.update_deadline_publish_time(topic_hash, gid);
        }

        crate::axon_trace!(
            "event=shm_take topic_hash={} requested_seq={} seq={} bytes={} transport=shared_memory",
            topic_hash,
            requested_seq,
            actual_seq,
            size
        );
        Ok((size, actual_seq))
    }

    /// Take a loaned message from a subscription.
    pub fn take_loaned(&self, topic_hash: TopicHash, seq: u64) -> Option<(*const u8, usize)> {
        let subs = self.subscriptions.lock().unwrap();
        let pubsub = subs.get(&topic_hash)?;
        pubsub.take_loaned(seq)
    }

    /// Return a loaned message to a subscription.
    pub fn return_loaned(&self, topic_hash: TopicHash, ptr: *const u8, size: usize) {
        let subs = self.subscriptions.lock().unwrap();
        if let Some(pubsub) = subs.get(&topic_hash) {
            pubsub.return_loaned(ptr, size);
        }
    }

    /// Get actual QoS for a subscription.
    ///
    /// # Arguments
    /// * `topic_name` - Human-readable topic name
    ///
    /// # Returns
    /// The QoS profile if a subscription exists for the topic.
    pub fn subscription_actual_qos(&self, topic_name: &str) -> Option<QosProfile> {
        let topic_hash = fxhash(topic_name);
        let subs = self.graph_cache.local_subscriptions.read().unwrap();
        subs.values()
            .find(|e| e.topic_hash == topic_hash)
            .map(|e| e.qos)
    }

    /// Get the 16-byte GID for a subscription on the given topic.
    ///
    /// # Arguments
    /// * `topic_name` - Human-readable topic name
    ///
    /// # Returns
    /// `Some(gid)` if a subscription exists for the topic.
    pub fn subscription_gid(&self, topic_name: &str) -> Option<[u8; 16]> {
        let topic_hash = fxhash(topic_name);
        let subs = self.graph_cache.local_subscriptions.read().unwrap();
        subs.values()
            .find(|e| e.topic_hash == topic_hash)
            .map(|e| e.gid)
    }

    /// Count the number of subscriptions for a given topic (local only).
    ///
    /// # Arguments
    /// * `topic` - Topic name string
    ///
    /// # Returns
    /// Total subscription count.
    pub fn get_subscription_count(&self, topic: &str) -> usize {
        let mut count = 0;
        {
            let subs = self.graph_cache.local_subscriptions.read().unwrap();
            for entity in subs.values() {
                if entity.topic_name == topic {
                    count += 1;
                }
            }
        }
        count
    }

    /// Get the eventfd for a topic subscription.
    ///
    /// # Arguments
    /// * `topic_hash` - Hashed topic identifier
    ///
    /// # Returns
    /// `Some(fd)` if the subscription exists, `None` otherwise.
    pub fn subscription_eventfd(&self, topic_hash: TopicHash) -> Option<std::os::fd::RawFd> {
        self.subscriptions
            .lock()
            .unwrap()
            .get(&topic_hash)
            .map(|s| s.event_fd())
    }

    /// Get eventfds for all topic subscriptions.
    ///
    /// # Returns
    /// Vector of eventfd file descriptors.
    pub fn subscription_eventfds(&self) -> Vec<std::os::fd::RawFd> {
        self.subscriptions
            .lock()
            .unwrap()
            .values()
            .map(|s| s.event_fd())
            .collect()
    }

    /// Set a content filter for a subscription topic.
    ///
    /// # Arguments
    /// * `topic_name` - Topic name
    /// * `name` - Filter name
    /// * `expression` - SQL-like expression
    /// * `parameters` - Named parameters
    pub fn set_content_filter(
        &self,
        topic_name: &str,
        name: &str,
        expression: &str,
        parameters: HashMap<String, String>,
    ) {
        let topic_hash = fxhash(topic_name);
        let filter = ContentFilter::new(name, expression, parameters);
        self.content_filters
            .lock()
            .unwrap()
            .insert(topic_hash, filter);
    }

    /// Get the content filter for a subscription topic.
    ///
    /// # Arguments
    /// * `topic_name` - Topic name
    ///
    /// # Returns
    /// Reference to the ContentFilter if one exists.
    pub fn get_content_filter(&self, topic_name: &str) -> Option<ContentFilter> {
        let topic_hash = fxhash(topic_name);
        self.content_filters
            .lock()
            .unwrap()
            .get(&topic_hash)
            .cloned()
    }

    /// Get remote flow endpoints for a subscription.
    ///
    /// # Arguments
    /// * `topic_name` - Human-readable topic name
    ///
    /// # Returns
    /// Vector of remote socket addresses.
    pub fn subscription_flow_endpoints(&self, topic_name: &str) -> Vec<std::net::SocketAddr> {
        self.publisher_flow_endpoints(topic_name)
    }
}

/// Extract the decompressed message size from the compression prefix stored
/// in the remote subscriber queue.  Returns `None` when the prefix is
/// ambiguous or the queue has been emptied between the peek and the call.
fn decompressed_size_from_prefix(
    seq: u64,
    q: &crate::subscriber_queue::SubscriberQueue,
    prefix: &[u8; 5],
) -> Option<usize> {
    if prefix[0] == 1 && prefix[1..].iter().any(|&b| b != 0) {
        // Compressed: original size stored in bytes 1-4 (big-endian)
        Some(u32::from_be_bytes(prefix[1..5].try_into().unwrap()) as usize)
    } else if prefix[0] == 0 {
        // Uncompressed: stored size minus the 0x00 prefix byte
        q.message_size(seq).map(|s| s.saturating_sub(1))
    } else {
        q.message_size(seq)
    }
}
