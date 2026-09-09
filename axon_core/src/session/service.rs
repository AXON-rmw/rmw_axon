use super::Session;
use crate::local::LocalPubSub;
use crate::quic_transport::PeerId;
use crate::types::*;
use std::sync::atomic::Ordering;
use std::sync::Arc;

fn service_ring_depth(qos: &QosProfile) -> u32 {
    match qos.history {
        HistoryKind::KeepLast { depth } => (depth as u32).clamp(2, 16),
        HistoryKind::KeepAll => 16,
    }
}

const SERVICE_ENVELOPE_MAGIC: &[u8; 8] = b"AXSRV001";
const SERVICE_ENVELOPE_HEADER_LEN: usize = 40;

#[derive(Debug, Clone, Copy)]
struct ServiceEnvelopeHeader {
    kind: u8,
    client_gid: [u8; 16],
    request_sequence: i64,
}

/// Result of scanning the shared service response ring for a specific client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceResponseTake {
    Taken {
        size: usize,
        next_seq: u64,
        request_sequence: i64,
    },
    BufferTooSmall {
        required: usize,
    },
    NoMatch {
        next_seq: u64,
    },
}

fn encode_service_envelope(
    kind: u8,
    client_gid: [u8; 16],
    request_sequence: i64,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(SERVICE_ENVELOPE_HEADER_LEN + payload.len());
    out.extend_from_slice(SERVICE_ENVELOPE_MAGIC);
    out.push(kind);
    out.extend_from_slice(&[0u8; 7]);
    out.extend_from_slice(&client_gid);
    out.extend_from_slice(&request_sequence.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

fn decode_service_envelope(data: &[u8]) -> Option<(ServiceEnvelopeHeader, &[u8])> {
    if data.len() < SERVICE_ENVELOPE_HEADER_LEN {
        return None;
    }
    if &data[..8] != SERVICE_ENVELOPE_MAGIC {
        return None;
    }
    let kind = data[8];
    let client_gid: [u8; 16] = data[16..32].try_into().ok()?;
    let request_sequence = i64::from_le_bytes(data[32..40].try_into().ok()?);
    Some((
        ServiceEnvelopeHeader {
            kind,
            client_gid,
            request_sequence,
        },
        &data[SERVICE_ENVELOPE_HEADER_LEN..],
    ))
}

impl Session {
    /// Create a service server endpoint.
    ///
    /// # Arguments
    /// * `service_id` - Unique service identifier
    /// * `service_type` - Service type string
    /// * `qos` - Quality-of-service profile
    ///
    /// # Returns
    /// `Ok(())` on success, or an error string if SHM creation fails.
    pub fn create_service(
        &self,
        service_id: ServiceId,
        service_type: &str,
        qos: &QosProfile,
    ) -> Result<(), String> {
        self.create_named_service(service_id, &format!("{:x}", service_id), service_type, qos)
    }

    /// Create a named service server endpoint.
    pub fn create_named_service(
        &self,
        service_id: ServiceId,
        service_name: &str,
        service_type: &str,
        qos: &QosProfile,
    ) -> Result<(), String> {
        let depth = service_ring_depth(qos);
        let req_topic = service_request_topic(service_id);
        let res_topic = service_response_topic(service_id);

        let req_name = super::local_channel_name(self.domain_id, req_topic);
        let res_name = super::local_channel_name(self.domain_id, res_topic);
        let slot_size = qos
            .max_message_size
            .saturating_add(SERVICE_ENVELOPE_HEADER_LEN)
            .min(u32::MAX as usize) as u32;

        let existing_request_pub = self
            .service_request_pubs
            .lock()
            .unwrap()
            .get(&service_id)
            .cloned();
        let req_sub_arc = match existing_request_pub {
            Some(pubsub) => pubsub,
            None => Arc::new(
                LocalPubSub::create_or_open(&req_name, depth, slot_size, false)
                    .map_err(|e| format!("failed to create service request sub: {}", e))?,
            ),
        };
        self.service_request_subs
            .lock()
            .unwrap()
            .insert(service_id, req_sub_arc);
        *self
            .service_server_counts
            .lock()
            .unwrap()
            .entry(service_id)
            .or_default() += 1;

        let existing_response_sub = self
            .service_response_subs
            .lock()
            .unwrap()
            .get(&service_id)
            .cloned();
        let res_pub = match existing_response_sub {
            Some(pubsub) => pubsub,
            None => Arc::new(
                LocalPubSub::create_or_open(&res_name, depth, slot_size, false)
                    .map_err(|e| format!("failed to create service response pub: {}", e))?,
            ),
        };
        self.service_response_pubs
            .lock()
            .unwrap()
            .insert(service_id, res_pub);
        let res_topic = service_response_topic(service_id);
        self.add_published_topic(res_topic);
        self.add_subscribed_topic(req_topic);
        self.topic_name_cache.write().unwrap().insert(
            req_topic,
            format!("{}{}", super::SERVICE_REQUEST_PREFIX, service_name),
        );
        self.topic_name_cache.write().unwrap().insert(
            res_topic,
            format!("{}{}", super::SERVICE_RESPONSE_PREFIX, service_name),
        );
        self.topic_type_cache
            .write()
            .unwrap()
            .insert(req_topic, service_type.to_string());
        self.topic_type_cache
            .write()
            .unwrap()
            .insert(res_topic, service_type.to_string());
        self.topic_qos_cache
            .write()
            .unwrap()
            .insert((self.node_id, req_topic), RemoteQos::from_qos_profile(qos));
        self.topic_qos_cache
            .write()
            .unwrap()
            .insert((self.node_id, res_topic), RemoteQos::from_qos_profile(qos));
        self.graph_cache
            .register_service(service_id, service_name, service_type, self.node_id);
        let res_gid = make_gid("pub", self.node_id, res_topic);
        self.graph_cache.register_publisher(
            res_topic,
            &format!("{:x}", res_topic),
            "",
            self.node_id,
            *qos,
            res_gid,
        );
        let req_gid = make_gid("sub", self.node_id, req_topic);
        self.graph_cache.register_subscription(
            req_topic,
            &format!("{:x}", req_topic),
            "",
            self.node_id,
            *qos,
            req_gid,
        );
        self.register_published_topic_with_daemon(
            res_topic,
            &format!("{}{}", super::SERVICE_RESPONSE_PREFIX, service_name),
            service_type,
            qos,
        );
        self.register_subscribed_topic_with_daemon(
            req_topic,
            &format!("{}{}", super::SERVICE_REQUEST_PREFIX, service_name),
            service_type,
            qos,
        );

        self.signal_graph_eventfds();

        // If QUIC transport is available, register a service handler that bridges
        // incoming QUIC bi-stream requests into the service request sub.
        if let Some(ref qt) = self.quic_transport {
            let mut rx = qt.register_service_handler(req_topic);
            let pending = qt.pending_service_responses.clone();
            let req_sub = self
                .service_request_subs
                .lock()
                .unwrap()
                .get(&service_id)
                .cloned();
            qt.spawn(async move {
                while let Some((req_data, resp_tx)) = rx.recv().await {
                    // Correlate the response stream with the request that
                    // arrived on it: parse the client GID and request
                    // sequence from the request envelope so send_response
                    // completes exactly this stream, not merely the oldest.
                    let (client_gid, request_sequence) = decode_service_envelope(&req_data)
                        .map(|(header, _)| (header.client_gid, header.request_sequence))
                        .unwrap_or(([0u8; 16], 0));
                    // Store response oneshot BEFORE publishing to SHM to avoid a
                    // race: the server application may process the request and call
                    // send_response (which calls try_complete_pending_response)
                    // between the publish (which signals the eventfd) and the
                    // oneshot store. Storing first ensures the response channel
                    // is ready before the server can see the request.
                    pending
                        .lock()
                        .unwrap()
                        .entry(res_topic)
                        .or_insert_with(Vec::new)
                        .push(crate::quic_transport::PendingServiceResponse {
                            client_gid,
                            request_sequence,
                            tx: resp_tx,
                        });
                    // Publish request to the request sub
                    if let Some(ref pubsub) = req_sub {
                        let _ = pubsub.publish(&req_data);
                    }
                }
            });
        }

        Ok(())
    }

    /// Create a service client endpoint.
    ///
    /// # Arguments
    /// * `service_id` - Unique service identifier
    /// * `service_type` - Service type string
    /// * `qos` - Quality-of-service profile
    ///
    /// # Returns
    /// `Ok(())` on success, or an error string if SHM creation fails.
    pub fn create_client(
        &self,
        service_id: ServiceId,
        service_type: &str,
        qos: &QosProfile,
    ) -> Result<(), String> {
        self.create_named_client(service_id, &format!("{:x}", service_id), service_type, qos)
    }

    /// Create a named service client endpoint.
    pub fn create_named_client(
        &self,
        service_id: ServiceId,
        service_name: &str,
        service_type: &str,
        qos: &QosProfile,
    ) -> Result<(), String> {
        // Serialize endpoint creation with destroy_client.  Previously the
        // request publisher was inserted and the reference count incremented
        // before the response endpoint was ready.  A concurrent destruction
        // of the last existing client could therefore remove that publisher
        // between the two operations, leaving a positive count with no
        // request endpoint; the next service call then failed with
        // "service client not found".  Keep the count lock for the complete
        // local endpoint transaction and only publish the new count after
        // both SHM channels have been created successfully.
        let mut client_counts = self.service_client_counts.lock().unwrap();
        let depth = service_ring_depth(qos);
        let req_topic = service_request_topic(service_id);
        let res_topic = service_response_topic(service_id);

        let req_name = super::local_channel_name(self.domain_id, req_topic);
        let res_name = super::local_channel_name(self.domain_id, res_topic);
        let slot_size = qos
            .max_message_size
            .saturating_add(SERVICE_ENVELOPE_HEADER_LEN)
            .min(u32::MAX as usize) as u32;

        let existing_request_sub = self
            .service_request_subs
            .lock()
            .unwrap()
            .get(&service_id)
            .cloned();
        let req_pub = match existing_request_sub {
            Some(pubsub) => pubsub,
            None => Arc::new(
                LocalPubSub::create_or_open(&req_name, depth, slot_size, false)
                    .map_err(|e| format!("failed to create service request pub: {}", e))?,
            ),
        };
        let existing_response_pub = self
            .service_response_pubs
            .lock()
            .unwrap()
            .get(&service_id)
            .cloned();
        let res_sub_arc = match existing_response_pub {
            Some(pubsub) => pubsub,
            None => Arc::new(
                LocalPubSub::create_or_open(&res_name, depth, slot_size, false)
                    .map_err(|e| format!("failed to create service response sub: {}", e))?,
            ),
        };
        self.service_request_pubs
            .lock()
            .unwrap()
            .insert(service_id, req_pub);
        self.service_response_subs
            .lock()
            .unwrap()
            .insert(service_id, res_sub_arc);
        *client_counts.entry(service_id).or_default() += 1;
        let req_topic = service_request_topic(service_id);
        self.add_published_topic(req_topic);
        self.add_subscribed_topic(res_topic);
        self.topic_name_cache.write().unwrap().insert(
            req_topic,
            format!("{}{}", super::SERVICE_REQUEST_PREFIX, service_name),
        );
        self.topic_name_cache.write().unwrap().insert(
            res_topic,
            format!("{}{}", super::SERVICE_RESPONSE_PREFIX, service_name),
        );
        self.topic_type_cache
            .write()
            .unwrap()
            .insert(req_topic, service_type.to_string());
        self.topic_type_cache
            .write()
            .unwrap()
            .insert(res_topic, service_type.to_string());
        self.topic_qos_cache
            .write()
            .unwrap()
            .insert((self.node_id, req_topic), RemoteQos::from_qos_profile(qos));
        self.topic_qos_cache
            .write()
            .unwrap()
            .insert((self.node_id, res_topic), RemoteQos::from_qos_profile(qos));
        self.graph_cache
            .register_client(service_id, service_name, service_type, self.node_id);
        let req_gid = make_gid("pub", self.node_id, req_topic);
        self.graph_cache.register_publisher(
            req_topic,
            &format!("{:x}", req_topic),
            "",
            self.node_id,
            *qos,
            req_gid,
        );
        let res_gid = make_gid("sub", self.node_id, res_topic);
        self.graph_cache.register_subscription(
            res_topic,
            &format!("{:x}", res_topic),
            "",
            self.node_id,
            *qos,
            res_gid,
        );
        self.register_published_topic_with_daemon(
            req_topic,
            &format!("{}{}", super::SERVICE_REQUEST_PREFIX, service_name),
            service_type,
            qos,
        );
        self.register_subscribed_topic_with_daemon(
            res_topic,
            &format!("{}{}", super::SERVICE_RESPONSE_PREFIX, service_name),
            service_type,
            qos,
        );
        self.signal_graph_eventfds();
        Ok(())
    }

    /// Send a service request.
    ///
    /// # Arguments
    /// * `service_id` - Unique service identifier
    /// * `data` - Raw request bytes
    ///
    /// # Returns
    /// Sequence number on success, or an error if client not found or ACL denied.
    pub fn send_request(&self, service_id: ServiceId, data: &[u8]) -> Result<u64, String> {
        let client_gid = make_gid("pub", self.node_id, service_request_topic(service_id));
        self.send_request_with_gid(service_id, client_gid, data)
    }

    /// Send a service request with an endpoint-specific client GID. ROS can
    /// create several clients for the same service from one node (notably
    /// concurrent action clients), so a deterministic topic-only GID would
    /// make their response streams indistinguishable.
    pub fn send_request_with_gid(
        &self,
        service_id: ServiceId,
        client_gid: [u8; 16],
        data: &[u8],
    ) -> Result<u64, String> {
        let req_topic = service_request_topic(service_id);
        if !self.acl_allows(AclDirection::Publish, req_topic) {
            return Err("access denied".into());
        }
        let request_sequence = self
            .service_request_sequence
            .fetch_add(1, Ordering::Relaxed) as i64;
        let request_data = encode_service_envelope(1, client_gid, request_sequence, data);

        let pubs = self.service_request_pubs.lock().unwrap();
        let pubsub = pubs.get(&service_id).ok_or("service client not found")?;
        let _ring_seq = pubsub.publish(&request_data).map_err(|e| e.to_string())?;
        drop(pubs);

        // Fire-and-forget QUIC service calls for cross-host peers.  The
        // response is always delivered via SHM (from the server's send_response
        // → try_complete_pending_response → QUIC stream → our background task
        // → response SHM publish).  We don't block: rmw_wait picks up the
        // response from SHM through its eventfd + data_available polling.
        //
        // For same-host service calls (daemon_origin == 0), the SHM ring buffer
        // alone handles delivery — no QUIC needed.  We do a single fast sync
        // and bail early when no cross-host peers exist, matching the pattern
        // used by topic publish_with_gid.
        if let Some(ref qt) = self.quic_transport {
            self.sync_daemon_matches();
            let collect_found_peers = || -> Vec<PeerId> {
                let routes = self.remote_routes.lock().unwrap();
                let addrs = routes.get(&req_topic).cloned();
                drop(routes);
                let known = self.known_addrs.read().unwrap();
                addrs
                    .iter()
                    .flat_map(|addrs| addrs.iter())
                    .filter_map(|addr| known.iter().find(|(_, a)| **a == *addr).map(|(id, _)| *id))
                    .collect()
            };

            // Do not block same-host service clients while remote discovery is
            // converging. The request has already been published to the local
            // SHM ring, which is the delivery path used by dense Gazebo/Nav2
            // bringup. Waiting here can burn lifecycle/action timeouts before
            // the server has a chance to respond.
            let mut found_peers = collect_found_peers();
            if found_peers.is_empty() {
                self.seed_remote_service_route(req_topic);
                found_peers = collect_found_peers();
            }
            if found_peers.is_empty() {
                return Ok(request_sequence as u64);
            }
            let cross_host_peers: Vec<PeerId> = match self.daemon_shm.as_ref() {
                Some(shm) => {
                    let node_table = shm.node_table();
                    found_peers
                        .into_iter()
                        .filter(|peer_id| {
                            shm.find_slot_by_node_id(*peer_id)
                                .map(|idx| node_table[idx].daemon_origin != 0)
                                .unwrap_or(true)
                        })
                        .collect()
                }
                None => found_peers,
            };
            if cross_host_peers.is_empty() {
                return Ok(request_sequence as u64);
            }
            let res_sub = self
                .service_response_subs
                .lock()
                .unwrap()
                .get(&service_id)
                .cloned();
            for peer_id in cross_host_peers {
                let addr = self.known_addrs.read().unwrap().get(&peer_id).copied();
                let q = qt.clone();
                let data = request_data.clone();
                let sub = res_sub.clone();
                let q2 = q.clone();
                q.spawn(async move {
                    let mut attempts = 0usize;
                    let result = loop {
                        attempts += 1;
                        let result = q2.service_call(peer_id, req_topic, &data, addr).await;
                        match result {
                            Ok(response) => break Ok(response),
                            Err(e)
                                if attempts < 3
                                    && (e.contains("connect")
                                        || e.contains("handshake")
                                        || e.contains("not connected")
                                        || e.contains("open bi")
                                        || e.contains("write")) =>
                            {
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                                continue;
                            }
                            Err(e) => break Err(e),
                        }
                    };
                    match result {
                        Ok(response) => {
                            if let Some(pubsub) = &sub {
                                let _ = pubsub.publish(&response);
                            }
                        }
                        Err(e) => {
                            tracing::warn!("QUIC send_request service_call failed: {}", e);
                        }
                    }
                });
            }
        }

        Ok(request_sequence as u64)
    }

    pub(crate) fn ensure_request_sub(&self, service_id: ServiceId) {
        let mut subs = self.service_request_subs.lock().unwrap();
        if subs.get(&service_id).is_none() {
            if let Some(pubsub) = self
                .service_request_pubs
                .lock()
                .unwrap()
                .get(&service_id)
                .cloned()
            {
                subs.insert(service_id, pubsub);
            }
        }
    }

    pub(crate) fn ensure_response_sub(&self, service_id: ServiceId) {
        let mut subs = self.service_response_subs.lock().unwrap();
        if subs.get(&service_id).is_none() {
            if let Some(pubsub) = self
                .service_response_pubs
                .lock()
                .unwrap()
                .get(&service_id)
                .cloned()
            {
                subs.insert(service_id, pubsub);
            }
        }
    }

    pub fn service_initial_seq(&self, service_id: ServiceId) -> u64 {
        self.ensure_request_sub(service_id);
        self.service_request_subs
            .lock()
            .unwrap()
            .get(&service_id)
            .map(|s| s.current_seq())
            .unwrap_or(0)
    }

    pub fn client_initial_seq(&self, service_id: ServiceId) -> u64 {
        self.ensure_response_sub(service_id);
        self.service_response_subs
            .lock()
            .unwrap()
            .get(&service_id)
            .map(|s| s.current_seq())
            .unwrap_or(0)
    }

    pub fn service_request_data_available(&self, service_id: ServiceId, seq: u64) -> bool {
        self.ensure_request_sub(service_id);
        self.service_request_subs
            .lock()
            .unwrap()
            .get(&service_id)
            .map(|s| s.data_available_from(seq))
            .unwrap_or(false)
    }

    pub fn service_response_data_available(&self, service_id: ServiceId, seq: u64) -> bool {
        self.ensure_response_sub(service_id);
        self.service_response_subs
            .lock()
            .unwrap()
            .get(&service_id)
            .map(|s| s.data_available_from(seq))
            .unwrap_or(false)
    }

    /// Peek the size of a service request message without consuming it.
    pub fn request_message_size(&self, service_id: ServiceId, seq: u64) -> Result<usize, String> {
        self.ensure_request_sub(service_id);
        let subs = self.service_request_subs.lock().unwrap();
        let pubsub = subs
            .get(&service_id)
            .ok_or("service request sub not available")?;
        let msg_size = pubsub.message_size(seq).map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; msg_size];
        let n = pubsub.receive(seq, &mut buf).map_err(|e| e.to_string())?;
        Ok(decode_service_envelope(&buf[..n])
            .map(|(_, payload)| payload.len())
            .unwrap_or(n))
    }

    /// Peek the size of a service response message without consuming it.
    pub fn response_message_size(&self, service_id: ServiceId, seq: u64) -> Result<usize, String> {
        self.ensure_response_sub(service_id);
        let subs = self.service_response_subs.lock().unwrap();
        let pubsub = subs
            .get(&service_id)
            .ok_or("service response sub not available")?;
        let msg_size = pubsub.message_size(seq).map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; msg_size];
        let n = pubsub.receive(seq, &mut buf).map_err(|e| e.to_string())?;
        Ok(decode_service_envelope(&buf[..n])
            .map(|(_, payload)| payload.len())
            .unwrap_or(n))
    }

    /// Take a service request from the server-side request subscription.
    ///
    /// # Arguments
    /// * `service_id` - Unique service identifier
    /// * `seq` - Message sequence number
    /// * `out` - Output buffer
    ///
    /// # Returns
    /// Number of bytes read on success, or an error if subscription unavailable.
    pub fn take_request(
        &self,
        service_id: ServiceId,
        seq: u64,
        out: &mut [u8],
    ) -> Result<usize, String> {
        self.take_request_with_info(service_id, seq, out)
            .map(|(size, _, _)| size)
    }

    /// Take a service request and return the ROS request correlation metadata.
    pub fn take_request_with_info(
        &self,
        service_id: ServiceId,
        seq: u64,
        out: &mut [u8],
    ) -> Result<(usize, [u8; 16], i64), String> {
        self.ensure_request_sub(service_id);
        let subs = self.service_request_subs.lock().unwrap();
        let pubsub = subs
            .get(&service_id)
            .ok_or("service request sub not available")?
            .as_ref();
        let msg_size = pubsub.message_size(seq).map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; msg_size];
        let n = pubsub.receive(seq, &mut buf).map_err(|e| e.to_string())?;
        if let Some((header, payload)) = decode_service_envelope(&buf[..n]) {
            if header.kind != 1 {
                return Err("unexpected service envelope kind for request".into());
            }
            if payload.len() > out.len() {
                return Err("buffer too small".into());
            }
            out[..payload.len()].copy_from_slice(payload);
            return Ok((payload.len(), header.client_gid, header.request_sequence));
        }
        if n > out.len() {
            return Err("buffer too small".into());
        }
        out[..n].copy_from_slice(&buf[..n]);
        Ok((n, [0u8; 16], seq as i64))
    }

    /// Send a service response.
    ///
    /// # Arguments
    /// * `service_id` - Unique service identifier
    /// * `data` - Raw response bytes
    ///
    /// # Returns
    /// Sequence number on success, or an error if server not found or ACL denied.
    pub fn send_response(&self, service_id: ServiceId, data: &[u8]) -> Result<u64, String> {
        self.send_response_with_info(service_id, [0u8; 16], 0, data)
    }

    /// Send a service response tagged for the client/request that issued it.
    pub fn send_response_with_info(
        &self,
        service_id: ServiceId,
        client_gid: [u8; 16],
        request_sequence: i64,
        data: &[u8],
    ) -> Result<u64, String> {
        let res_topic = service_response_topic(service_id);
        if !self.acl_allows(AclDirection::Publish, res_topic) {
            return Err("access denied".into());
        }
        let pubs = self.service_response_pubs.lock().unwrap();
        let pubsub = pubs.get(&service_id).ok_or("service server not found")?;
        let response_data = if client_gid.iter().any(|byte| *byte != 0) {
            encode_service_envelope(2, client_gid, request_sequence, data)
        } else {
            data.to_vec()
        };
        let seq = pubsub.publish(&response_data).map_err(|e| e.to_string())?;
        drop(pubs);
        if let Some(ref qt) = self.quic_transport {
            let _ = qt.try_complete_pending_response(
                res_topic,
                client_gid,
                request_sequence,
                response_data,
            );
        }
        Ok(seq)
    }

    /// Destroy a service server endpoint, cleaning up SHM and graph entries.
    ///
    /// # Arguments
    /// * `service_id` - Unique service identifier
    ///
    /// # Returns
    /// `Ok(())` on success.
    pub fn destroy_service(&self, service_id: ServiceId) -> Result<(), String> {
        let req_topic = service_request_topic(service_id);
        let res_topic = service_response_topic(service_id);
        let mut counts = self.service_server_counts.lock().unwrap();
        let count = counts
            .get_mut(&service_id)
            .ok_or("service server not found")?;
        *count -= 1;
        if *count > 0 {
            return Ok(());
        }
        counts.remove(&service_id);
        drop(counts);
        self.service_request_subs
            .lock()
            .unwrap()
            .remove(&service_id);
        self.service_response_pubs
            .lock()
            .unwrap()
            .remove(&service_id);
        self.graph_cache
            .local_services
            .write()
            .unwrap()
            .remove(&service_id);
        self.graph_cache
            .local_publishers
            .write()
            .unwrap()
            .remove(&res_topic);
        self.graph_cache
            .local_subscriptions
            .write()
            .unwrap()
            .remove(&req_topic);
        self.published_topics
            .write()
            .unwrap()
            .retain(|hash| *hash != res_topic);
        self.subscribed_topics
            .write()
            .unwrap()
            .retain(|hash| *hash != req_topic);
        if !self
            .graph_cache
            .local_clients
            .read()
            .unwrap()
            .contains_key(&service_id)
        {
            self.topic_name_cache.write().unwrap().remove(&req_topic);
            self.topic_name_cache.write().unwrap().remove(&res_topic);
            self.topic_type_cache.write().unwrap().remove(&req_topic);
            self.topic_type_cache.write().unwrap().remove(&res_topic);
            self.topic_qos_cache
                .write()
                .unwrap()
                .remove(&(self.node_id, req_topic));
            self.topic_qos_cache
                .write()
                .unwrap()
                .remove(&(self.node_id, res_topic));
        }
        // Clean up QUIC service handler so the handler task can exit and
        // orphaned pending responses don't accumulate.
        if let Some(ref qt) = self.quic_transport {
            qt.service_request_channels
                .lock()
                .unwrap()
                .remove(&req_topic);
            qt.pending_service_responses
                .lock()
                .unwrap()
                .remove(&res_topic);
        }
        self.signal_graph_eventfds();
        Ok(())
    }

    /// Destroy a service client endpoint, cleaning up SHM and graph entries.
    ///
    /// # Arguments
    /// * `service_id` - Unique service identifier
    ///
    /// # Returns
    /// `Ok(())` on success.
    pub fn destroy_client(&self, service_id: ServiceId) -> Result<(), String> {
        let req_topic = service_request_topic(service_id);
        let res_topic = service_response_topic(service_id);
        let mut counts = self.service_client_counts.lock().unwrap();
        let count = counts
            .get_mut(&service_id)
            .ok_or("service client not found")?;
        *count -= 1;
        if *count > 0 {
            return Ok(());
        }
        counts.remove(&service_id);
        drop(counts);
        self.service_response_subs
            .lock()
            .unwrap()
            .remove(&service_id);
        self.service_request_pubs
            .lock()
            .unwrap()
            .remove(&service_id);
        self.graph_cache
            .local_clients
            .write()
            .unwrap()
            .remove(&service_id);
        self.graph_cache
            .local_publishers
            .write()
            .unwrap()
            .remove(&req_topic);
        self.graph_cache
            .local_subscriptions
            .write()
            .unwrap()
            .remove(&res_topic);
        self.published_topics
            .write()
            .unwrap()
            .retain(|hash| *hash != req_topic);
        self.subscribed_topics
            .write()
            .unwrap()
            .retain(|hash| *hash != res_topic);
        if !self
            .graph_cache
            .local_services
            .read()
            .unwrap()
            .contains_key(&service_id)
        {
            self.topic_name_cache.write().unwrap().remove(&req_topic);
            self.topic_name_cache.write().unwrap().remove(&res_topic);
            self.topic_type_cache.write().unwrap().remove(&req_topic);
            self.topic_type_cache.write().unwrap().remove(&res_topic);
            self.topic_qos_cache
                .write()
                .unwrap()
                .remove(&(self.node_id, req_topic));
            self.topic_qos_cache
                .write()
                .unwrap()
                .remove(&(self.node_id, res_topic));
        }
        self.signal_graph_eventfds();
        Ok(())
    }

    /// Take a service response from the client-side response subscription.
    ///
    /// # Arguments
    /// * `service_id` - Unique service identifier
    /// * `seq` - Message sequence number
    /// * `out` - Output buffer
    ///
    /// # Returns
    /// Number of bytes read on success, or an error if subscription unavailable.
    pub fn take_response(
        &self,
        service_id: ServiceId,
        seq: u64,
        out: &mut [u8],
    ) -> Result<usize, String> {
        self.ensure_response_sub(service_id);
        let subs = self.service_response_subs.lock().unwrap();
        let pubsub = subs
            .get(&service_id)
            .ok_or("service response sub not available")?
            .as_ref();
        let msg_size = pubsub.message_size(seq).map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; msg_size];
        let n = pubsub.receive(seq, &mut buf).map_err(|e| e.to_string())?;
        if let Some((header, payload)) = decode_service_envelope(&buf[..n]) {
            if header.kind != 2 {
                return Err("unexpected service envelope kind for response".into());
            }
            if payload.len() > out.len() {
                return Err("buffer too small".into());
            }
            out[..payload.len()].copy_from_slice(payload);
            return Ok(payload.len());
        }
        if n > out.len() {
            return Err("buffer too small".into());
        }
        out[..n].copy_from_slice(&buf[..n]);
        Ok(n)
    }

    /// Scan shared service responses and return only responses addressed to one client.
    pub fn take_response_for_client(
        &self,
        service_id: ServiceId,
        seq: u64,
        client_gid: [u8; 16],
        out: &mut [u8],
    ) -> Result<ServiceResponseTake, String> {
        self.ensure_response_sub(service_id);
        let subs = self.service_response_subs.lock().unwrap();
        let pubsub = subs
            .get(&service_id)
            .ok_or("service response sub not available")?
            .as_ref();

        let mut scan_seq = seq.max(pubsub.oldest_available_seq());
        let current = pubsub.current_seq();
        let legacy_client = client_gid.iter().all(|byte| *byte == 0);

        while scan_seq < current {
            let msg_size = match pubsub.message_size(scan_seq) {
                Ok(size) if size > 0 => size,
                Err("slot not yet written") => {
                    return Ok(ServiceResponseTake::NoMatch { next_seq: scan_seq });
                }
                _ => {
                    scan_seq += 1;
                    continue;
                }
            };
            let mut buf = vec![0u8; msg_size];
            // Service responses are multiplexed by client GID in one shared
            // ring. Do not advance the ring's global read watermark while
            // scanning: another ROS client may need to inspect this same
            // response before its own cursor reaches it.
            let n = match pubsub.receive_peek(scan_seq, &mut buf) {
                Ok(n) => n,
                Err("slot not yet written") => {
                    return Ok(ServiceResponseTake::NoMatch { next_seq: scan_seq });
                }
                Err(_) => {
                    scan_seq += 1;
                    continue;
                }
            };

            if let Some((header, payload)) = decode_service_envelope(&buf[..n]) {
                if header.kind == 2 && header.client_gid == client_gid {
                    if payload.len() > out.len() {
                        return Ok(ServiceResponseTake::BufferTooSmall {
                            required: payload.len(),
                        });
                    }
                    out[..payload.len()].copy_from_slice(payload);
                    return Ok(ServiceResponseTake::Taken {
                        size: payload.len(),
                        next_seq: scan_seq + 1,
                        request_sequence: header.request_sequence,
                    });
                }
            } else if legacy_client {
                if n > out.len() {
                    return Ok(ServiceResponseTake::BufferTooSmall { required: n });
                }
                out[..n].copy_from_slice(&buf[..n]);
                return Ok(ServiceResponseTake::Taken {
                    size: n,
                    next_seq: scan_seq + 1,
                    request_sequence: scan_seq as i64,
                });
            }

            scan_seq += 1;
        }

        Ok(ServiceResponseTake::NoMatch { next_seq: current })
    }

    pub fn service_request_eventfd(&self, service_id: ServiceId) -> Option<std::os::fd::RawFd> {
        self.service_request_subs
            .lock()
            .unwrap()
            .get(&service_id)
            .map(|s| s.event_fd())
    }

    pub fn service_response_eventfd(&self, service_id: ServiceId) -> Option<std::os::fd::RawFd> {
        self.service_response_subs
            .lock()
            .unwrap()
            .get(&service_id)
            .map(|s| s.event_fd())
    }
}
