use super::{Session, TopicEndpointInfo};
use crate::types::*;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

const DEFAULT_GRAPH_DISCOVERY_WAIT_MS: u64 = 3000;
const GRAPH_DISCOVERY_POLL_MS: u64 = 50;
const NODE_SERVICE_SUFFIXES: &[&str] = &[
    "change_state",
    "describe_parameters",
    "get_available_states",
    "get_available_transitions",
    "get_parameter_types",
    "get_parameters",
    "get_state",
    "get_transition_graph",
    "list_parameters",
    "set_parameters",
    "set_parameters_atomically",
];

fn node_name_from_service_name(service_name: &str) -> Option<(String, String)> {
    let service_path = service_name.strip_prefix('/').unwrap_or(service_name);
    for suffix in NODE_SERVICE_SUFFIXES {
        let suffix_with_sep = format!("/{}", suffix);
        let Some(node_path) = service_path.strip_suffix(&suffix_with_sep) else {
            continue;
        };
        if node_path.is_empty() {
            return None;
        }
        let (namespace, name) = match node_path.rsplit_once('/') {
            Some((ns, name)) if !name.is_empty() => (format!("/{}", ns), name.to_string()),
            None => ("/".to_string(), node_path.to_string()),
            _ => return None,
        };
        return Some((name, namespace));
    }
    None
}

fn fixed_cstr(buf: &[u8], default: &str) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let value = std::str::from_utf8(&buf[..end]).unwrap_or(default);
    if value.is_empty() {
        default.to_string()
    } else {
        value.to_string()
    }
}

fn insert_topic_type(topics: &mut HashMap<String, String>, topic_name: String, topic_type: String) {
    let candidate_is_known =
        !topic_type.is_empty() && topic_type != "unknown" && topic_type != "unknown/msg/Unknown";
    match topics.entry(topic_name) {
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(topic_type);
        }
        std::collections::hash_map::Entry::Occupied(mut entry) => {
            let current = entry.get();
            let current_is_unknown =
                current.is_empty() || current == "unknown" || current == "unknown/msg/Unknown";
            if current_is_unknown && candidate_is_known {
                entry.insert(topic_type);
            }
        }
    }
}

impl Session {
    fn is_builtin_graph_topic_name(name: &str) -> bool {
        name == "/parameter_events" || name == "/rosout" || super::is_service_topic_metadata(name)
    }

    fn has_remote_user_graph_topic(&self) -> bool {
        let Some(ref shm) = self.open_daemon_shm() else {
            return false;
        };
        use crate::daemon::discovery_shm::MAX_TOPIC_NAME_LEN;
        let _gen = shm.header().generation.load(Ordering::Acquire);
        for entry in shm.node_table() {
            if entry.state.load(Ordering::Acquire) != 2 {
                continue;
            }
            if entry.domain_id != self.domain_id && !self.include_all_domains {
                continue;
            }
            if entry.node_id == self.node_id || entry.daemon_origin == 0 {
                continue;
            }
            if !crate::daemon::discovery_shm::is_daemon_node_alive(entry) {
                continue;
            }
            for topic_entry in &entry.published_topics[..entry.pub_count as usize] {
                let name_end = topic_entry
                    .topic_name
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(MAX_TOPIC_NAME_LEN);
                let name = std::str::from_utf8(&topic_entry.topic_name[..name_end]).unwrap_or("");
                if !name.is_empty() && !Self::is_builtin_graph_topic_name(name) {
                    return true;
                }
            }
            for topic_entry in &entry.subscribed_topics[..entry.sub_count as usize] {
                let name_end = topic_entry
                    .topic_name
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(MAX_TOPIC_NAME_LEN);
                let name = std::str::from_utf8(&topic_entry.topic_name[..name_end]).unwrap_or("");
                if !name.is_empty() && !Self::is_builtin_graph_topic_name(name) {
                    return true;
                }
            }
        }
        false
    }

    /// On the first graph query when remote transport is present, sleep for
    /// a bounded interval to give the daemon time to receive remote HELLOs and
    /// sync peer graph data. Short-lived CLI processes such as `ros2 topic info`
    /// otherwise often query before the first remote heartbeat arrives.
    fn wait_for_discovery(&self) {
        self.sync_daemon_matches();
        if self.quic_transport.is_none() || !self.first_graph_query.swap(false, Ordering::AcqRel) {
            return;
        }

        let wait_ms = std::env::var("AXON_GRAPH_DISCOVERY_WAIT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_GRAPH_DISCOVERY_WAIT_MS);
        if wait_ms == 0 {
            return;
        }

        let deadline = Instant::now() + Duration::from_millis(wait_ms);
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(GRAPH_DISCOVERY_POLL_MS));
            self.sync_daemon_matches();
            if self.has_remote_user_graph_topic() {
                break;
            }
        }
    }

    /// Return sorted list of all known node names (local + remote).
    ///
    /// # Returns
    /// Deduplicated, sorted vector of node name strings.
    pub fn get_node_names(&self) -> Vec<String> {
        self.get_node_names_and_namespaces()
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    }

    /// Return sorted node names paired with their namespaces.
    pub fn get_node_names_and_namespaces(&self) -> Vec<(String, String)> {
        self.wait_for_discovery();
        let mut names = vec![(
            self.graph_cache.node_name.read().unwrap().clone(),
            self.graph_cache.node_namespace.read().unwrap().clone(),
        )];
        {
            if let Some(ref shm) = self.open_daemon_shm() {
                use crate::daemon::discovery_shm::{
                    MAX_NODE_NAME_LEN, MAX_NODE_NS_LEN, MAX_TOPIC_NAME_LEN,
                };
                let _gen = shm.header().generation.load(Ordering::Acquire);
                for entry in shm.node_table() {
                    if entry.state.load(Ordering::Acquire) != 2 {
                        continue;
                    }
                    if entry.domain_id != self.domain_id && !self.include_all_domains {
                        continue;
                    }
                    if entry.node_id == self.node_id {
                        continue;
                    }
                    if !crate::daemon::discovery_shm::is_daemon_node_alive(entry) {
                        continue;
                    }
                    let name_end = entry
                        .node_name
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(MAX_NODE_NAME_LEN);
                    let name = std::str::from_utf8(&entry.node_name[..name_end]).unwrap_or("");
                    let ns_end = entry
                        .node_namespace
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(MAX_NODE_NS_LEN);
                    let ns = std::str::from_utf8(&entry.node_namespace[..ns_end]).unwrap_or("/");
                    if name.is_empty() {
                        continue;
                    }
                    let entry_name = (name.to_string(), ns.to_string());
                    if !names.contains(&entry_name) {
                        names.push(entry_name);
                    }
                    for topic_entry in &entry.published_topics[..entry.pub_count as usize] {
                        let endpoint_name = fixed_cstr(&topic_entry.node_name, "");
                        if !endpoint_name.is_empty() {
                            let endpoint_ns = fixed_cstr(&topic_entry.node_namespace, "/");
                            let endpoint_node = (endpoint_name, endpoint_ns);
                            if !names.contains(&endpoint_node) {
                                names.push(endpoint_node);
                            }
                        }
                        let topic_end = topic_entry
                            .topic_name
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(MAX_TOPIC_NAME_LEN);
                        let topic =
                            std::str::from_utf8(&topic_entry.topic_name[..topic_end]).unwrap_or("");
                        let Some(service_name) = topic.strip_prefix(super::SERVICE_RESPONSE_PREFIX)
                        else {
                            continue;
                        };
                        let Some(node_from_service) = node_name_from_service_name(service_name)
                        else {
                            continue;
                        };
                        if !names.contains(&node_from_service) {
                            names.push(node_from_service);
                        }
                    }
                    for topic_entry in &entry.subscribed_topics[..entry.sub_count as usize] {
                        let endpoint_name = fixed_cstr(&topic_entry.node_name, "");
                        if endpoint_name.is_empty() {
                            continue;
                        }
                        let endpoint_ns = fixed_cstr(&topic_entry.node_namespace, "/");
                        let endpoint_node = (endpoint_name, endpoint_ns);
                        if !names.contains(&endpoint_node) {
                            names.push(endpoint_node);
                        }
                    }
                }
            }
        }
        names.sort();
        names.dedup();
        names
    }

    fn is_internal_service_topic(&self, topic_hash: TopicHash) -> bool {
        let services = self.graph_cache.local_services.read().unwrap();
        if services.values().any(|service| {
            service_request_topic(service.service_id) == topic_hash
                || service_response_topic(service.service_id) == topic_hash
        }) {
            return true;
        }
        drop(services);
        let clients = self.graph_cache.local_clients.read().unwrap();
        clients.values().any(|client| {
            service_request_topic(client.client_id) == topic_hash
                || service_response_topic(client.client_id) == topic_hash
        })
    }

    /// Return sorted list of all known topic names (local + cached remote).
    ///
    /// # Returns
    /// Deduplicated, sorted vector of topic name strings.
    pub fn get_topic_names(&self) -> Vec<String> {
        self.wait_for_discovery();
        let mut names = Vec::new();
        {
            let pubs = self.graph_cache.local_publishers.read().unwrap();
            for entity in pubs.values() {
                if !self.is_internal_service_topic(entity.topic_hash) {
                    names.push(entity.topic_name.clone());
                }
            }
        }
        {
            let subs = self.graph_cache.local_subscriptions.read().unwrap();
            for entity in subs.values() {
                if !self.is_internal_service_topic(entity.topic_hash)
                    && !names.contains(&entity.topic_name)
                {
                    names.push(entity.topic_name.clone());
                }
            }
        }
        {
            let cache = self.topic_name_cache.read().unwrap();
            for (_hash, name) in cache.iter() {
                if !super::is_service_topic_metadata(name) && !names.contains(name) {
                    names.push(name.clone());
                }
            }
        }
        {
            if let Some(ref shm) = self.open_daemon_shm() {
                use crate::daemon::discovery_shm::MAX_TOPIC_NAME_LEN;
                let _gen = shm.header().generation.load(Ordering::Acquire);
                let node_table = shm.node_table();
                for entry in node_table {
                    if entry.state.load(Ordering::Acquire) != 2 {
                        continue;
                    }
                    if entry.domain_id != self.domain_id && !self.include_all_domains {
                        continue;
                    }
                    for topic_entry in &entry.published_topics[..entry.pub_count as usize] {
                        let name_end = topic_entry
                            .topic_name
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(MAX_TOPIC_NAME_LEN);
                        let name = std::str::from_utf8(&topic_entry.topic_name[..name_end])
                            .unwrap_or("")
                            .to_string();
                        if !name.is_empty()
                            && !super::is_service_topic_metadata(&name)
                            && !names.contains(&name)
                        {
                            names.push(name);
                        }
                    }
                    for topic_entry in &entry.subscribed_topics[..entry.sub_count as usize] {
                        let name_end = topic_entry
                            .topic_name
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(MAX_TOPIC_NAME_LEN);
                        let name = std::str::from_utf8(&topic_entry.topic_name[..name_end])
                            .unwrap_or("")
                            .to_string();
                        if !name.is_empty()
                            && !super::is_service_topic_metadata(&name)
                            && !names.contains(&name)
                        {
                            names.push(name);
                        }
                    }
                }
            }
        }
        names.sort();
        names
    }

    /// Return topic names paired with their type strings.
    ///
    /// # Returns
    /// Vector of `(name, type)` tuples.
    pub fn get_topic_names_and_types(&self) -> Vec<(String, String)> {
        self.wait_for_discovery();
        let mut result: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let pubs = self.graph_cache.local_publishers.read().unwrap();
        for p in pubs.values() {
            if !self.is_internal_service_topic(p.topic_hash) {
                result.insert(p.topic_name.clone(), p.topic_type.clone());
            }
        }
        let subs = self.graph_cache.local_subscriptions.read().unwrap();
        for s in subs.values() {
            if !self.is_internal_service_topic(s.topic_hash) {
                result
                    .entry(s.topic_name.clone())
                    .or_insert_with(|| s.topic_type.clone());
            }
        }
        let cache = self.topic_name_cache.read().unwrap();
        let type_cache = self.topic_type_cache.read().unwrap();
        for (hash, name) in cache.iter() {
            if !super::is_service_topic_metadata(name) {
                let type_str = type_cache
                    .get(hash)
                    .cloned()
                    .unwrap_or_else(|| "unknown/msg/Unknown".to_string());
                insert_topic_type(&mut result, name.clone(), type_str);
            }
        }
        {
            if let Some(ref shm) = self.open_daemon_shm() {
                use crate::daemon::discovery_shm::{MAX_TOPIC_NAME_LEN, MAX_TOPIC_TYPE_LEN};
                let _gen = shm.header().generation.load(Ordering::Acquire);
                let node_table = shm.node_table();
                for entry in node_table {
                    if entry.state.load(Ordering::Acquire) != 2 {
                        continue;
                    }
                    if entry.domain_id != self.domain_id && !self.include_all_domains {
                        continue;
                    }
                    if !crate::daemon::discovery_shm::is_daemon_node_alive(entry) {
                        continue;
                    }
                    for topic_entry in entry.published_topics[..entry.pub_count as usize]
                        .iter()
                        .chain(entry.subscribed_topics[..entry.sub_count as usize].iter())
                    {
                        let name_end = topic_entry
                            .topic_name
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(MAX_TOPIC_NAME_LEN);
                        let type_end = topic_entry
                            .topic_type
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(MAX_TOPIC_TYPE_LEN);
                        let name = std::str::from_utf8(&topic_entry.topic_name[..name_end])
                            .unwrap_or("")
                            .to_string();
                        let typ = std::str::from_utf8(&topic_entry.topic_type[..type_end])
                            .unwrap_or("")
                            .to_string();
                        if !name.is_empty() && !super::is_service_topic_metadata(&name) {
                            insert_topic_type(&mut result, name, typ);
                        }
                    }
                }
            }
        }
        result.into_iter().collect()
    }

    /// Return service names paired with their type strings.
    ///
    /// # Returns
    /// Vector of `(name, type)` tuples for all registered services.
    pub fn get_service_names_and_types(&self) -> Vec<(String, String)> {
        self.wait_for_discovery();
        let mut result: HashMap<String, String> = self
            .graph_cache
            .local_services
            .read()
            .unwrap()
            .values()
            .map(|e| (e.service_name.clone(), e.service_type.clone()))
            .collect();
        {
            if let Some(ref shm) = self.open_daemon_shm() {
                use crate::daemon::discovery_shm::MAX_TOPIC_NAME_LEN;
                let _gen = shm.header().generation.load(Ordering::Acquire);
                for entry in shm.node_table() {
                    if entry.state.load(Ordering::Acquire) != 2 {
                        continue;
                    }
                    if entry.domain_id != self.domain_id && !self.include_all_domains {
                        continue;
                    }
                    for te in &entry.published_topics[..entry.pub_count as usize] {
                        let name_end = te
                            .topic_name
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(MAX_TOPIC_NAME_LEN);
                        let name = std::str::from_utf8(&te.topic_name[..name_end]).unwrap_or("");
                        let service_name = match name.strip_prefix(super::SERVICE_RESPONSE_PREFIX) {
                            Some(s) => s,
                            None => continue,
                        };
                        if !result.contains_key(service_name) {
                            let type_end = te
                                .topic_type
                                .iter()
                                .position(|&b| b == 0)
                                .unwrap_or(MAX_TOPIC_NAME_LEN);
                            let type_str = std::str::from_utf8(&te.topic_type[..type_end])
                                .unwrap_or("unknown");
                            result.insert(service_name.to_string(), type_str.to_string());
                        }
                    }
                }
            }
        }
        result.into_iter().collect()
    }

    /// Count the number of publishers on a given topic (local + remote).
    ///
    /// # Arguments
    /// * `topic_name` - Human-readable topic name
    ///
    /// # Returns
    /// Total number of publishers publishing to the topic.
    pub fn count_publishers(&self, topic_name: &str) -> usize {
        let topic_hash = fxhash(topic_name);
        let local_count = self
            .publisher_counts
            .lock()
            .unwrap()
            .get(&topic_hash)
            .copied()
            .unwrap_or_else(|| {
                self.graph_cache
                    .local_publishers
                    .read()
                    .unwrap()
                    .values()
                    .filter(|entity| entity.topic_hash == topic_hash)
                    .count()
            });
        let remote_count = 0usize;
        let mut daemon_count = 0usize;
        if let Some(ref shm) = self.open_daemon_shm() {
            let _gen = shm.header().generation.load(Ordering::Acquire);
            for entry in shm.node_table() {
                if entry.state.load(Ordering::Acquire) != 2 {
                    continue;
                }
                if entry.domain_id != self.domain_id && !self.include_all_domains {
                    continue;
                }
                if entry.node_id == self.node_id {
                    continue;
                }
                if !crate::daemon::discovery_shm::is_daemon_node_alive(entry) {
                    continue;
                }
                for te in &entry.published_topics[..entry.pub_count as usize] {
                    if te.hash == topic_hash {
                        daemon_count += 1;
                    }
                }
            }
        }
        local_count + remote_count + daemon_count
    }

    /// Count the number of subscribers on a given topic (local).
    ///
    /// # Arguments
    /// * `topic_name` - Human-readable topic name
    ///
    /// # Returns
    /// Total number of subscribers to the topic.
    pub fn count_subscribers(&self, topic_name: &str) -> usize {
        let topic_hash = fxhash(topic_name);
        let local_count = self
            .subscription_counts
            .lock()
            .unwrap()
            .get(&topic_hash)
            .copied()
            .unwrap_or_else(|| {
                self.graph_cache
                    .local_subscriptions
                    .read()
                    .unwrap()
                    .values()
                    .filter(|entity| entity.topic_hash == topic_hash)
                    .count()
            });
        let remote_count = 0usize;
        let mut daemon_count = 0usize;
        if let Some(ref shm) = self.open_daemon_shm() {
            let _gen = shm.header().generation.load(Ordering::Acquire);
            for entry in shm.node_table() {
                if entry.state.load(Ordering::Acquire) != 2 {
                    continue;
                }
                if entry.domain_id != self.domain_id && !self.include_all_domains {
                    continue;
                }
                if entry.node_id == self.node_id {
                    continue;
                }
                if !crate::daemon::discovery_shm::is_daemon_node_alive(entry) {
                    continue;
                }
                for te in &entry.subscribed_topics[..entry.sub_count as usize] {
                    if te.hash == topic_hash {
                        daemon_count += 1;
                    }
                }
            }
        }
        local_count + remote_count + daemon_count
    }

    /// Count the number of services with a given name (local).
    ///
    /// # Arguments
    /// * `service_name` - Human-readable service name
    ///
    /// # Returns
    /// Total number of services with the given name.
    pub fn count_services(&self, service_name: &str) -> usize {
        let svcs = self.graph_cache.local_services.read().unwrap();
        let local_count = svcs
            .values()
            .filter(|e| e.service_name == service_name)
            .count();
        let svc_topic_name = format!("{}{}", super::SERVICE_RESPONSE_PREFIX, service_name);
        let mut daemon_count = 0usize;
        if let Some(ref shm) = self.open_daemon_shm() {
            use crate::daemon::discovery_shm::MAX_TOPIC_NAME_LEN;
            let _gen = shm.header().generation.load(Ordering::Acquire);
            for entry in shm.node_table() {
                if entry.state.load(Ordering::Acquire) != 2 {
                    continue;
                }
                if entry.domain_id != self.domain_id && !self.include_all_domains {
                    continue;
                }
                if entry.node_id == self.node_id {
                    continue;
                }
                if !crate::daemon::discovery_shm::is_daemon_node_alive(entry) {
                    continue;
                }
                for te in &entry.published_topics[..entry.pub_count as usize] {
                    let name_end = te
                        .topic_name
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(MAX_TOPIC_NAME_LEN);
                    let name = std::str::from_utf8(&te.topic_name[..name_end]).unwrap_or("");
                    if name == svc_topic_name {
                        daemon_count += 1;
                    }
                }
            }
        }
        local_count + daemon_count
    }

    /// Count the number of clients with a given service name (local).
    ///
    /// # Arguments
    /// * `service_name` - Human-readable service name
    ///
    /// # Returns
    /// Total number of clients for the given service name.
    pub fn count_clients(&self, service_name: &str) -> usize {
        let clients = self.graph_cache.local_clients.read().unwrap();
        let local_count = clients
            .values()
            .filter(|e| e.service_name == service_name)
            .count();
        let svc_topic_name = format!("{}{}", super::SERVICE_REQUEST_PREFIX, service_name);
        let mut daemon_count = 0usize;
        if let Some(ref shm) = self.open_daemon_shm() {
            use crate::daemon::discovery_shm::MAX_TOPIC_NAME_LEN;
            let _gen = shm.header().generation.load(Ordering::Acquire);
            for entry in shm.node_table() {
                if entry.state.load(Ordering::Acquire) != 2 {
                    continue;
                }
                if entry.domain_id != self.domain_id && !self.include_all_domains {
                    continue;
                }
                if entry.node_id == self.node_id {
                    continue;
                }
                if !crate::daemon::discovery_shm::is_daemon_node_alive(entry) {
                    continue;
                }
                for te in &entry.published_topics[..entry.pub_count as usize] {
                    let name_end = te
                        .topic_name
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(MAX_TOPIC_NAME_LEN);
                    let name = std::str::from_utf8(&te.topic_name[..name_end]).unwrap_or("");
                    if name == svc_topic_name {
                        daemon_count += 1;
                    }
                }
            }
        }
        local_count + daemon_count
    }

    /// Count matched subscriptions for a publisher on a topic.
    ///
    /// # Arguments
    /// * `topic_name` - Human-readable topic name
    ///
    /// # Returns
    /// Number of subscribers matched to the topic.
    pub fn count_matched_subscriptions(&self, topic_name: &str) -> usize {
        self.count_subscribers(topic_name)
    }

    /// Count matched publishers for a subscription on a topic.
    ///
    /// # Arguments
    /// * `topic_name` - Human-readable topic name
    ///
    /// # Returns
    /// Number of publishers matched to the topic.
    pub fn count_matched_publishers(&self, topic_name: &str) -> usize {
        self.count_publishers(topic_name)
    }

    /// Check whether a service is available (has a server).
    ///
    /// # Arguments
    /// * `service_name` - Human-readable service name
    ///
    /// # Returns
    /// `true` if a service server exists for the given name.
    pub fn service_available(&self, service_name: &str) -> bool {
        let svcs = self.graph_cache.local_services.read().unwrap();
        if svcs.values().any(|e| e.service_name == service_name) {
            return true;
        }
        drop(svcs);
        let svc_topic_name = format!("{}{}", super::SERVICE_RESPONSE_PREFIX, service_name);
        if let Some(ref shm) = self.open_daemon_shm() {
            use crate::daemon::discovery_shm::MAX_TOPIC_NAME_LEN;
            let _gen = shm.header().generation.load(Ordering::Acquire);
            for entry in shm.node_table() {
                if entry.state.load(Ordering::Acquire) != 2 {
                    continue;
                }
                if entry.domain_id != self.domain_id && !self.include_all_domains {
                    continue;
                }
                for te in &entry.published_topics[..entry.pub_count as usize] {
                    let name_end = te
                        .topic_name
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(MAX_TOPIC_NAME_LEN);
                    let name = std::str::from_utf8(&te.topic_name[..name_end]).unwrap_or("");
                    if name == svc_topic_name {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Resolve a node name to a NodeId.
    ///
    /// # Arguments
    /// * `node_name` - Human-readable node name
    /// * `node_ns` - Node namespace
    ///
    /// # Returns
    /// The NodeId if found, 0 otherwise.
    fn resolve_node_id(&self, node_name: &str, node_ns: &str) -> NodeId {
        let ns = if node_ns.is_empty() { "/" } else { node_ns };
        let full_name = if ns == "/" {
            node_name.to_string()
        } else {
            format!("{}/{}", ns.trim_end_matches('/'), node_name)
        };
        let local_name = self.graph_cache.node_name.read().unwrap().clone();
        let local_namespace = self.graph_cache.node_namespace.read().unwrap().clone();
        let local_full_name = if local_namespace == "/" {
            local_name
        } else {
            format!("{}/{}", local_namespace.trim_end_matches('/'), local_name)
        };
        if local_full_name == full_name {
            return self.node_id;
        }
        {
            if let Some(ref shm) = self.open_daemon_shm() {
                use crate::daemon::discovery_shm::{MAX_NODE_NAME_LEN, MAX_NODE_NS_LEN};
                let _gen = shm.header().generation.load(Ordering::Acquire);
                for entry in shm.node_table() {
                    if entry.state.load(Ordering::Acquire) != 2 {
                        continue;
                    }
                    if entry.domain_id != self.domain_id && !self.include_all_domains {
                        continue;
                    }
                    if entry.node_id == self.node_id {
                        continue;
                    }
                    let name_end = entry
                        .node_name
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(MAX_NODE_NAME_LEN);
                    let shm_name = std::str::from_utf8(&entry.node_name[..name_end]).unwrap_or("");
                    let ns_end = entry
                        .node_namespace
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(MAX_NODE_NS_LEN);
                    let shm_ns =
                        std::str::from_utf8(&entry.node_namespace[..ns_end]).unwrap_or("/");
                    let shm_full = if shm_ns == "/" {
                        shm_name.to_string()
                    } else {
                        format!("{}/{}", shm_ns.trim_end_matches('/'), shm_name)
                    };
                    if shm_full == full_name {
                        return entry.node_id;
                    }
                }
            }
        }
        0
    }

    /// Get publishers by node name.
    ///
    /// # Arguments
    /// * `node_name` - Human-readable node name
    /// * `node_ns` - Node namespace
    ///
    /// # Returns
    /// Vector of (topic_name, vec of type strings) tuples.
    pub fn get_publishers_by_node(
        &self,
        node_name: &str,
        node_ns: &str,
    ) -> Vec<(String, Vec<String>)> {
        self.wait_for_discovery();
        let target_id = self.resolve_node_id(node_name, node_ns);
        let pubs = self.graph_cache.local_publishers.read().unwrap();
        let mut result: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for p in pubs.values() {
            if p.node_id == target_id && !self.is_internal_service_topic(p.topic_hash) {
                result
                    .entry(p.topic_name.clone())
                    .or_insert_with(|| vec![p.topic_type.clone()]);
            }
        }
        if target_id != 0 {
            if let Some(ref shm) = self.open_daemon_shm() {
                use crate::daemon::discovery_shm::MAX_TOPIC_NAME_LEN;
                let _gen = shm.header().generation.load(Ordering::Acquire);
                for entry in shm.node_table() {
                    if entry.state.load(Ordering::Acquire) != 2 {
                        continue;
                    }
                    if entry.node_id != target_id {
                        continue;
                    }
                    for te in &entry.published_topics[..entry.pub_count as usize] {
                        let name_end = te
                            .topic_name
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(MAX_TOPIC_NAME_LEN);
                        let name = std::str::from_utf8(&te.topic_name[..name_end]).unwrap_or("");
                        if name.is_empty() || super::is_service_topic_metadata(name) {
                            continue;
                        }
                        let type_end = te
                            .topic_type
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(MAX_TOPIC_NAME_LEN);
                        let type_str =
                            std::str::from_utf8(&te.topic_type[..type_end]).unwrap_or("unknown");
                        result
                            .entry(name.to_string())
                            .or_insert_with(|| vec![type_str.to_string()]);
                    }
                }
            }
        }
        result.into_iter().collect()
    }

    /// Get subscribers by node name.
    ///
    /// # Arguments
    /// * `node_name` - Human-readable node name
    /// * `node_ns` - Node namespace
    ///
    /// # Returns
    /// Vector of (topic_name, vec of type strings) tuples.
    pub fn get_subscribers_by_node(
        &self,
        node_name: &str,
        node_ns: &str,
    ) -> Vec<(String, Vec<String>)> {
        self.wait_for_discovery();
        let target_id = self.resolve_node_id(node_name, node_ns);
        let subs = self.graph_cache.local_subscriptions.read().unwrap();
        let mut result: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for s in subs.values() {
            if s.node_id == target_id && !self.is_internal_service_topic(s.topic_hash) {
                result
                    .entry(s.topic_name.clone())
                    .or_insert_with(|| vec![s.topic_type.clone()]);
            }
        }
        if target_id != 0 {
            if let Some(ref shm) = self.open_daemon_shm() {
                use crate::daemon::discovery_shm::MAX_TOPIC_NAME_LEN;
                let _gen = shm.header().generation.load(Ordering::Acquire);
                for entry in shm.node_table() {
                    if entry.state.load(Ordering::Acquire) != 2 {
                        continue;
                    }
                    if entry.node_id != target_id {
                        continue;
                    }
                    for te in &entry.subscribed_topics[..entry.sub_count as usize] {
                        let name_end = te
                            .topic_name
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(MAX_TOPIC_NAME_LEN);
                        let name = std::str::from_utf8(&te.topic_name[..name_end]).unwrap_or("");
                        if name.is_empty() || super::is_service_topic_metadata(name) {
                            continue;
                        }
                        let type_end = te
                            .topic_type
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(MAX_TOPIC_NAME_LEN);
                        let type_str =
                            std::str::from_utf8(&te.topic_type[..type_end]).unwrap_or("unknown");
                        result
                            .entry(name.to_string())
                            .or_insert_with(|| vec![type_str.to_string()]);
                    }
                }
            }
        }
        result.into_iter().collect()
    }

    /// Get services by node name.
    ///
    /// # Arguments
    /// * `node_name` - Human-readable node name
    /// * `node_ns` - Node namespace
    ///
    /// # Returns
    /// Vector of (service_name, vec of type strings) tuples.
    pub fn get_services_by_node(
        &self,
        node_name: &str,
        node_ns: &str,
    ) -> Vec<(String, Vec<String>)> {
        self.wait_for_discovery();
        let target_id = self.resolve_node_id(node_name, node_ns);
        let svcs = self.graph_cache.local_services.read().unwrap();
        let mut result: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for s in svcs.values() {
            if s.node_id == target_id {
                result
                    .entry(s.service_name.clone())
                    .or_insert_with(|| vec![s.service_type.clone()]);
            }
        }
        // Remote services: handled via daemon SHM below
        if target_id != 0 {
            if let Some(ref shm) = self.open_daemon_shm() {
                use crate::daemon::discovery_shm::MAX_TOPIC_NAME_LEN;
                let _gen = shm.header().generation.load(Ordering::Acquire);
                for entry in shm.node_table() {
                    if entry.state.load(Ordering::Acquire) != 2 {
                        continue;
                    }
                    if entry.node_id != target_id {
                        continue;
                    }
                    for te in &entry.subscribed_topics[..entry.sub_count as usize] {
                        let name_end = te
                            .topic_name
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(MAX_TOPIC_NAME_LEN);
                        let name = std::str::from_utf8(&te.topic_name[..name_end]).unwrap_or("");
                        let service_name = match name.strip_prefix(super::SERVICE_REQUEST_PREFIX) {
                            Some(s) => s,
                            None => continue,
                        };
                        if !result.contains_key(service_name) {
                            let type_end = te
                                .topic_type
                                .iter()
                                .position(|&b| b == 0)
                                .unwrap_or(MAX_TOPIC_NAME_LEN);
                            let type_str = std::str::from_utf8(&te.topic_type[..type_end])
                                .unwrap_or("unknown");
                            result.insert(service_name.to_string(), vec![type_str.to_string()]);
                        }
                    }
                }
            }
        }
        result.into_iter().collect()
    }

    /// Get clients by node name.
    ///
    /// # Arguments
    /// * `node_name` - Human-readable node name
    /// * `node_ns` - Node namespace
    ///
    /// # Returns
    /// Vector of (service_name, vec of type strings) tuples.
    pub fn get_clients_by_node(
        &self,
        node_name: &str,
        node_ns: &str,
    ) -> Vec<(String, Vec<String>)> {
        self.wait_for_discovery();
        let target_id = self.resolve_node_id(node_name, node_ns);
        let clients = self.graph_cache.local_clients.read().unwrap();
        let mut result: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for c in clients.values() {
            if c.node_id == target_id {
                result
                    .entry(c.service_name.clone())
                    .or_insert_with(|| vec![c.service_type.clone()]);
            }
        }
        // Remote clients: handled via daemon SHM below
        if target_id != 0 {
            if let Some(ref shm) = self.open_daemon_shm() {
                use crate::daemon::discovery_shm::MAX_TOPIC_NAME_LEN;
                let _gen = shm.header().generation.load(Ordering::Acquire);
                for entry in shm.node_table() {
                    if entry.state.load(Ordering::Acquire) != 2 {
                        continue;
                    }
                    if entry.node_id != target_id {
                        continue;
                    }
                    for te in &entry.published_topics[..entry.pub_count as usize] {
                        let name_end = te
                            .topic_name
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(MAX_TOPIC_NAME_LEN);
                        let name = std::str::from_utf8(&te.topic_name[..name_end]).unwrap_or("");
                        let service_name = match name.strip_prefix(super::SERVICE_REQUEST_PREFIX) {
                            Some(s) => s,
                            None => continue,
                        };
                        if !result.contains_key(service_name) {
                            let type_end = te
                                .topic_type
                                .iter()
                                .position(|&b| b == 0)
                                .unwrap_or(MAX_TOPIC_NAME_LEN);
                            let type_str = std::str::from_utf8(&te.topic_type[..type_end])
                                .unwrap_or("unknown");
                            result.insert(service_name.to_string(), vec![type_str.to_string()]);
                        }
                    }
                }
            }
        }
        result.into_iter().collect()
    }

    /// Get publisher info for a topic.
    ///
    /// # Arguments
    /// * `topic_name` - Human-readable topic name
    ///
    /// # Returns
    /// Vector of endpoint info for matching publishers.
    pub fn get_publishers_info(&self, topic_name: &str) -> Vec<TopicEndpointInfo> {
        self.wait_for_discovery();
        let topic_hash = fxhash(topic_name);
        let mut result: Vec<TopicEndpointInfo> = Vec::new();
        // Local publishers
        let pubs = self.graph_cache.local_publishers.read().unwrap();
        for e in pubs.values().filter(|e| e.topic_hash == topic_hash) {
            result.push(TopicEndpointInfo {
                node_name: e.node_name.clone(),
                node_namespace: e.node_namespace.clone(),
                topic_type: e.topic_type.clone(),
                topic_name: e.topic_name.clone(),
                gid: e.gid,
                qos: e.qos,
                transport_kind: "axon".to_string(),
            });
        }
        drop(pubs);
        {
            if let Some(ref shm) = self.open_daemon_shm() {
                use std::sync::atomic::Ordering;
                let _gen = shm.header().generation.load(Ordering::Acquire);
                for entry in shm.node_table() {
                    if entry.state.load(Ordering::Acquire) != 2 {
                        continue;
                    }
                    if entry.domain_id != self.domain_id && !self.include_all_domains {
                        continue;
                    }
                    if entry.node_id == self.node_id {
                        continue;
                    }
                    if !crate::daemon::discovery_shm::is_daemon_node_alive(entry) {
                        continue;
                    }
                    let mut matching_te: Option<&crate::daemon::discovery_shm::TopicEntry> = None;
                    for te in &entry.published_topics[..entry.pub_count as usize] {
                        if te.hash == topic_hash {
                            matching_te = Some(te);
                            break;
                        }
                    }
                    let te = match matching_te {
                        Some(t) => t,
                        None => continue,
                    };
                    let shm_node_name = {
                        use crate::daemon::discovery_shm::MAX_NODE_NAME_LEN;
                        let name_end = entry
                            .node_name
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(MAX_NODE_NAME_LEN);
                        std::str::from_utf8(&entry.node_name[..name_end])
                            .unwrap_or("")
                            .to_string()
                    };
                    let shm_node_ns = {
                        use crate::daemon::discovery_shm::MAX_NODE_NS_LEN;
                        let ns_end = entry
                            .node_namespace
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(MAX_NODE_NS_LEN);
                        std::str::from_utf8(&entry.node_namespace[..ns_end])
                            .unwrap_or("/")
                            .to_string()
                    };
                    let shm_topic_type = {
                        use crate::daemon::discovery_shm::MAX_TOPIC_TYPE_LEN;
                        let type_end = te
                            .topic_type
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(MAX_TOPIC_TYPE_LEN);
                        let t = std::str::from_utf8(&te.topic_type[..type_end]).unwrap_or("");
                        if t.is_empty() {
                            "unknown/msg/Unknown".to_string()
                        } else {
                            t.to_string()
                        }
                    };
                    let endpoint_node_name = fixed_cstr(&te.node_name, "");
                    let endpoint_node_ns = fixed_cstr(&te.node_namespace, "");
                    let proper_node_name = if !endpoint_node_name.is_empty() {
                        endpoint_node_name
                    } else if shm_node_name.is_empty() {
                        format!("node_{}", entry.node_id)
                    } else {
                        shm_node_name
                    };
                    let proper_node_ns = if endpoint_node_ns.is_empty() {
                        shm_node_ns
                    } else {
                        endpoint_node_ns
                    };
                    let gid = make_gid("pub", entry.node_id, topic_hash);
                    let pub_qos = Self::entry_fields_to_qos(
                        te.qos_reliability,
                        te.qos_durability,
                        te.qos_history_kind,
                        te.qos_history_depth,
                        te.qos_deadline_sec,
                        te.qos_deadline_nsec,
                        te.qos_lifespan_sec,
                        te.qos_lifespan_nsec,
                        te.qos_liveliness,
                        te.qos_liveliness_lease_sec,
                        te.qos_liveliness_lease_nsec,
                    );
                    result.push(TopicEndpointInfo {
                        node_name: proper_node_name,
                        node_namespace: proper_node_ns,
                        topic_type: shm_topic_type,
                        topic_name: topic_name.to_string(),
                        gid,
                        qos: pub_qos,
                        transport_kind: "axon".to_string(),
                    });
                }
            }
        }
        result
    }

    /// Get subscription info for a topic.
    ///
    /// # Arguments
    /// * `topic_name` - Human-readable topic name
    ///
    /// # Returns
    /// Vector of endpoint info for matching subscriptions.
    pub fn get_subscriptions_info(&self, topic_name: &str) -> Vec<TopicEndpointInfo> {
        self.wait_for_discovery();
        let topic_hash = fxhash(topic_name);
        let mut result: Vec<TopicEndpointInfo> = Vec::new();
        // Local subscriptions
        let subs = self.graph_cache.local_subscriptions.read().unwrap();
        for e in subs.values().filter(|e| e.topic_hash == topic_hash) {
            result.push(TopicEndpointInfo {
                node_name: e.node_name.clone(),
                node_namespace: e.node_namespace.clone(),
                topic_type: e.topic_type.clone(),
                topic_name: e.topic_name.clone(),
                gid: e.gid,
                qos: e.qos,
                transport_kind: "axon".to_string(),
            });
        }
        drop(subs);
        {
            if let Some(ref shm) = self.open_daemon_shm() {
                use crate::daemon::discovery_shm::{
                    MAX_NODE_NAME_LEN, MAX_NODE_NS_LEN, MAX_TOPIC_TYPE_LEN,
                };
                use std::sync::atomic::Ordering;
                let _gen = shm.header().generation.load(Ordering::Acquire);
                for entry in shm.node_table() {
                    if entry.state.load(Ordering::Acquire) != 2 {
                        continue;
                    }
                    if entry.domain_id != self.domain_id && !self.include_all_domains {
                        continue;
                    }
                    if entry.node_id == self.node_id {
                        continue;
                    }
                    if !crate::daemon::discovery_shm::is_daemon_node_alive(entry) {
                        continue;
                    }
                    let mut matching_te: Option<&crate::daemon::discovery_shm::TopicEntry> = None;
                    for te in &entry.subscribed_topics[..entry.sub_count as usize] {
                        if te.hash == topic_hash {
                            matching_te = Some(te);
                            break;
                        }
                    }
                    let te = match matching_te {
                        Some(t) => t,
                        None => continue,
                    };
                    let shm_node_name = {
                        let name_end = entry
                            .node_name
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(MAX_NODE_NAME_LEN);
                        std::str::from_utf8(&entry.node_name[..name_end])
                            .unwrap_or("")
                            .to_string()
                    };
                    let shm_node_ns = {
                        let ns_end = entry
                            .node_namespace
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(MAX_NODE_NS_LEN);
                        std::str::from_utf8(&entry.node_namespace[..ns_end])
                            .unwrap_or("/")
                            .to_string()
                    };
                    let shm_topic_type = {
                        let type_end = te
                            .topic_type
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(MAX_TOPIC_TYPE_LEN);
                        let t = std::str::from_utf8(&te.topic_type[..type_end]).unwrap_or("");
                        if t.is_empty() {
                            "unknown/msg/Unknown".to_string()
                        } else {
                            t.to_string()
                        }
                    };
                    let endpoint_node_name = fixed_cstr(&te.node_name, "");
                    let endpoint_node_ns = fixed_cstr(&te.node_namespace, "");
                    let proper_node_name = if !endpoint_node_name.is_empty() {
                        endpoint_node_name
                    } else if shm_node_name.is_empty() {
                        format!("node_{}", entry.node_id)
                    } else {
                        shm_node_name
                    };
                    let proper_node_ns = if endpoint_node_ns.is_empty() {
                        shm_node_ns
                    } else {
                        endpoint_node_ns
                    };
                    let gid = make_gid("sub", entry.node_id, topic_hash);
                    let sub_qos = Self::entry_fields_to_qos(
                        te.qos_reliability,
                        te.qos_durability,
                        te.qos_history_kind,
                        te.qos_history_depth,
                        te.qos_deadline_sec,
                        te.qos_deadline_nsec,
                        te.qos_lifespan_sec,
                        te.qos_lifespan_nsec,
                        te.qos_liveliness,
                        te.qos_liveliness_lease_sec,
                        te.qos_liveliness_lease_nsec,
                    );
                    result.push(TopicEndpointInfo {
                        node_name: proper_node_name,
                        node_namespace: proper_node_ns,
                        topic_type: shm_topic_type,
                        topic_name: topic_name.to_string(),
                        gid,
                        qos: sub_qos,
                        transport_kind: "axon".to_string(),
                    });
                }
            }
        }
        result
    }

    /// Get actual QoS for a service endpoint.
    ///
    /// role: 0=request-reader, 1=response-sender, 2=request-sender, 3=response-reader
    pub fn service_actual_qos(&self, service_name: &str, role: u8) -> Option<QosProfile> {
        let service_id = fxhash(service_name);
        let topic_hash = match role {
            0 => service_request_topic(service_id),
            1 => service_response_topic(service_id),
            2 => service_request_topic(service_id),
            3 => service_response_topic(service_id),
            _ => return None,
        };
        match role {
            0 | 3 => self
                .graph_cache
                .local_subscriptions
                .read()
                .unwrap()
                .get(&topic_hash)
                .map(|e| e.qos),
            1 | 2 => self
                .graph_cache
                .local_publishers
                .read()
                .unwrap()
                .get(&topic_hash)
                .map(|e| e.qos),
            _ => None,
        }
    }

    /// Get the local node's human-readable name.
    pub fn get_node_name(&self) -> String {
        self.graph_cache.node_name.read().unwrap().clone()
    }

    /// Get the local node's namespace.
    pub fn get_node_namespace(&self) -> String {
        self.graph_cache.node_namespace.read().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::{insert_topic_type, node_name_from_service_name};
    use std::collections::HashMap;

    #[test]
    fn test_node_name_from_standard_service_name() {
        assert_eq!(
            node_name_from_service_name("/controller_server/get_state"),
            Some(("controller_server".to_string(), "/".to_string()))
        );
        assert_eq!(
            node_name_from_service_name("/local_costmap/local_costmap/get_parameters"),
            Some(("local_costmap".to_string(), "/local_costmap".to_string()))
        );
        assert_eq!(
            node_name_from_service_name("/navigate_to_pose/_action/send_goal"),
            None
        );
    }

    #[test]
    fn test_known_subscription_type_replaces_unknown_cached_type() {
        let mut topics = HashMap::new();
        insert_topic_type(
            &mut topics,
            "/subscriber_only".to_string(),
            "unknown/msg/Unknown".to_string(),
        );
        insert_topic_type(
            &mut topics,
            "/subscriber_only".to_string(),
            "std_msgs/msg/String".to_string(),
        );

        assert_eq!(
            topics.get("/subscriber_only").map(String::as_str),
            Some("std_msgs/msg/String")
        );
    }
}
