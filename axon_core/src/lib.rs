#![allow(clippy::not_unsafe_ptr_arg_deref)]

/// Multi-session C bridge with explicit session IDs.
pub mod c_bridge;
/// Message compression for remote transport.
pub mod compress;
/// AXON daemon — persistent graph cache with XML-RPC server.
pub mod daemon;
/// Event monitoring for deadline and liveliness.
pub mod events;
/// Content filtering for subscription messages.
pub mod filter;
/// Graph cache for topic/service/node registry.
pub mod graph_cache;
/// Local shared-memory pub/sub transport.
pub mod local;
/// ETSI GS QKD 014 clients, bootstrap session store, and message-key rotation.
pub mod qkd;
/// QoS profiles, policies, and compatibility checking.
pub mod qos;
/// QUIC transport for peer-to-peer communication.
pub mod quic_transport;
/// Rate-limiting and resource management.
pub mod resource;
/// SCM_RIGHTS eventfd passing for cross-process SHM signaling.
pub mod scm;
/// ACL engine, audit logging, and crypto.
pub mod security;
pub mod security_mode;
/// Message serialization utilities.
pub mod serialize;
/// Session management, routing, and graph introspection.
pub mod session;
/// Per-subscriber queue for remote data delivery.
pub mod subscriber_queue;
/// Opt-in exhaustive metadata tracing for integration runs.
pub mod trace;
/// Core types, QoS profiles, and entity metadata.
pub mod types;
/// Wait-set for multiplexing eventfd notifications.
pub mod wait;

pub use local::*;
pub use types::*;
