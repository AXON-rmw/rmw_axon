use std::collections::HashMap;
use std::sync::RwLock;

use crate::types::{
    ClientEntity, NodeId, PublisherEntity, QosProfile, ServiceEntity, ServiceId,
    SubscriptionEntity, TopicHash,
};

pub struct GraphCache {
    pub local_publishers: RwLock<HashMap<TopicHash, PublisherEntity>>,
    pub local_subscriptions: RwLock<HashMap<TopicHash, SubscriptionEntity>>,
    pub local_services: RwLock<HashMap<ServiceId, ServiceEntity>>,
    pub local_clients: RwLock<HashMap<u64, ClientEntity>>,
    pub node_name: RwLock<String>,
    pub node_namespace: RwLock<String>,
}

impl GraphCache {
    pub fn new(node_name: &str) -> Self {
        Self {
            local_publishers: RwLock::new(HashMap::new()),
            local_subscriptions: RwLock::new(HashMap::new()),
            local_services: RwLock::new(HashMap::new()),
            local_clients: RwLock::new(HashMap::new()),
            node_name: RwLock::new(node_name.to_string()),
            node_namespace: RwLock::new("/".to_string()),
        }
    }

    pub fn register_publisher(
        &self,
        topic_hash: TopicHash,
        topic_name: &str,
        topic_type: &str,
        node_id: NodeId,
        qos: QosProfile,
        gid: [u8; 16],
    ) {
        self.local_publishers.write().unwrap().insert(
            topic_hash,
            PublisherEntity {
                topic_name: topic_name.to_string(),
                topic_type: topic_type.to_string(),
                topic_hash,
                node_id,
                node_name: self.node_name.read().unwrap().clone(),
                node_namespace: self.node_namespace.read().unwrap().clone(),
                qos,
                gid,
            },
        );
    }

    pub fn register_subscription(
        &self,
        topic_hash: TopicHash,
        topic_name: &str,
        topic_type: &str,
        node_id: NodeId,
        qos: QosProfile,
        gid: [u8; 16],
    ) {
        self.local_subscriptions.write().unwrap().insert(
            topic_hash,
            SubscriptionEntity {
                topic_name: topic_name.to_string(),
                topic_type: topic_type.to_string(),
                topic_hash,
                node_id,
                node_name: self.node_name.read().unwrap().clone(),
                node_namespace: self.node_namespace.read().unwrap().clone(),
                qos,
                gid,
            },
        );
    }

    pub fn register_service(
        &self,
        service_id: ServiceId,
        service_name: &str,
        service_type: &str,
        node_id: NodeId,
    ) {
        self.local_services.write().unwrap().insert(
            service_id,
            ServiceEntity {
                service_name: service_name.to_string(),
                service_type: service_type.to_string(),
                service_id,
                node_id,
            },
        );
    }

    pub fn register_client(
        &self,
        client_id: u64,
        service_name: &str,
        service_type: &str,
        node_id: NodeId,
    ) {
        self.local_clients.write().unwrap().insert(
            client_id,
            ClientEntity {
                service_name: service_name.to_string(),
                service_type: service_type.to_string(),
                client_id,
                node_id,
            },
        );
    }
}
