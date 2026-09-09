use std::sync::atomic::AtomicU64;

pub use crate::qos::*;

pub type NodeId = u64;
pub type TopicHash = u64;
pub type SequenceNumber = u64;
pub type ServiceId = u64;

pub fn service_request_topic(service_id: ServiceId) -> TopicHash {
    service_id ^ 0x52655100
}

pub fn service_response_topic(service_id: ServiceId) -> TopicHash {
    service_id ^ 0x52657300
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclDirection {
    Publish,
    Subscribe,
}

pub fn fxhash(s: &str) -> u64 {
    let mut h: u64 = 0;
    for b in s.bytes() {
        h = h.rotate_left(5) ^ h.rotate_right(7);
        h = h.wrapping_add(b as u64);
    }
    h
}

pub fn make_gid(prefix: &str, node_id: u64, topic_hash: u64) -> [u8; 16] {
    let low = fxhash(&format!("{}_{:x}_{:x}", prefix, node_id, topic_hash));
    let high = fxhash(&format!("{}_{:x}_{:x}_high", prefix, node_id, topic_hash));
    ((high as u128) << 64 | low as u128).to_le_bytes()
}

#[derive(Debug, Clone)]
pub struct PublisherEntity {
    pub topic_name: String,
    pub topic_type: String,
    pub topic_hash: TopicHash,
    pub node_id: NodeId,
    pub node_name: String,
    pub node_namespace: String,
    pub qos: QosProfile,
    pub gid: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct SubscriptionEntity {
    pub topic_name: String,
    pub topic_type: String,
    pub topic_hash: TopicHash,
    pub node_id: NodeId,
    pub node_name: String,
    pub node_namespace: String,
    pub qos: QosProfile,
    pub gid: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct ServiceEntity {
    pub service_name: String,
    pub service_type: String,
    pub service_id: ServiceId,
    pub node_id: NodeId,
}

#[derive(Debug, Clone)]
pub struct ClientEntity {
    pub service_name: String,
    pub service_type: String,
    pub client_id: u64,
    pub node_id: NodeId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditDirection {
    Send,
    Recv,
}

#[derive(Debug)]
#[repr(C)]
pub struct RingBufferHeader {
    pub capacity: u32,
    pub slot_size: u32,
    pub write_index: AtomicU64,
    pub read_index: AtomicU64,
    pub epoch: AtomicU64,
}

#[derive(Debug, Clone)]
pub struct SubscriptionHandle {
    pub topic_hash: TopicHash,
    pub shm_path: String,
    pub ring_buf: *mut RingBufferHeader,
    pub data_ptr: *mut u8,
    pub eventfd: std::os::fd::RawFd,
    pub initial_seq: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entity_types() {
        let pub_entity = PublisherEntity {
            topic_name: "/cmd_vel".to_string(),
            topic_type: "geometry_msgs/msg/Twist".to_string(),
            topic_hash: 0xdeadbeef,
            node_id: 42,
            node_name: "cmd_node".to_string(),
            node_namespace: "/".to_string(),
            qos: QosProfile::default_sensor(),
            gid: [0u8; 16],
        };
        assert_eq!(pub_entity.topic_name, "/cmd_vel");
        assert_eq!(pub_entity.topic_type, "geometry_msgs/msg/Twist");
        assert_eq!(pub_entity.topic_hash, 0xdeadbeef);

        let sub_entity = SubscriptionEntity {
            topic_name: "/odom".to_string(),
            topic_type: "nav_msgs/msg/Odometry".to_string(),
            topic_hash: 0xcafe,
            node_id: 43,
            node_name: "odom_node".to_string(),
            node_namespace: "/nav".to_string(),
            qos: QosProfile::default_sensor(),
            gid: [0u8; 16],
        };
        assert_eq!(sub_entity.node_id, 43);
        assert_eq!(sub_entity.node_name, "odom_node");
        assert_eq!(sub_entity.topic_type, "nav_msgs/msg/Odometry");

        let svc_entity = ServiceEntity {
            service_name: "/spawn".to_string(),
            service_type: "std_srvs/srv/Empty".to_string(),
            service_id: 0x5e51563,
            node_id: 44,
        };
        assert_eq!(svc_entity.service_name, "/spawn");

        assert_eq!(AuditDirection::Send, AuditDirection::Send);
        assert_ne!(AuditDirection::Send, AuditDirection::Recv);
    }
}
