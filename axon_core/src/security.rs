//! Application-level authorization and audit support.
//!
//! Remote payload protection belongs to QUIC. In QKD mode QUIC still uses a
//! bootstrap external PSK for the connection, and every application message
//! carries a second AEAD envelope sealed with an ETSI QKD key. The key rotates
//! after ten outgoing messages and every message uses a fresh nonce. The KME
//! key identifier and the sender SAE are metadata; the key bytes never cross
//! the wire. Classic mode keeps the payload unchanged because QUIC already
//! provides its transport encryption.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use glob::Pattern;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};

use crate::qkd::{EtsiQkdClient, QkdConfig, QkdKeyStore, QkdMessageKeyLookup};
use crate::security_mode::{QuicCipher, SecurityMode};
use crate::types::{AclDirection, AuditDirection};

const QKD_WIRE_MAGIC: &[u8; 8] = b"AXQKD001";
const QKD_WIRE_HEADER_LEN: usize = 36;
const QKD_NONCE_BYTES: usize = 12;
const QKD_MAX_WIRE_FIELD: usize = 192;
const QKD_REPLAY_CACHE_SIZE: usize = 4096;
const QKD_TOPIC_SEAL_CACHE_SIZE: usize = 256;
const QKD_MESSAGES_PER_KEY: u64 = 10;

type TopicSealKey = (u64, u64, u64);
type TopicSealCell = Arc<tokio::sync::OnceCell<Vec<u8>>>;

#[derive(Default)]
struct TopicSealCache {
    entries: HashMap<TopicSealKey, TopicSealCell>,
    order: VecDeque<TopicSealKey>,
}

struct CachedOutboundKey {
    material: crate::qkd::QkdKeyMaterial,
    uses: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum WireKind {
    Topic = 1,
    ServiceRequest = 2,
    ServiceResponse = 3,
    Control = 4,
}

#[derive(Clone, Copy, Debug)]
pub struct WireContext {
    pub kind: WireKind,
    pub topic_hash: u64,
}

impl WireContext {
    pub const fn topic(topic_hash: u64) -> Self {
        Self {
            kind: WireKind::Topic,
            topic_hash,
        }
    }

    pub const fn service_request(topic_hash: u64) -> Self {
        Self {
            kind: WireKind::ServiceRequest,
            topic_hash,
        }
    }

    pub const fn service_response(topic_hash: u64) -> Self {
        Self {
            kind: WireKind::ServiceResponse,
            topic_hash,
        }
    }

    pub const fn control(channel: u64) -> Self {
        Self {
            kind: WireKind::Control,
            topic_hash: channel,
        }
    }
}

#[derive(Clone, Debug)]
pub struct QkdReplyToken {
    /// SAE ID of the peer that sent the request. A response obtains a new
    /// encryption key for this SAE rather than reusing the request key.
    pub(crate) remote_sae_id: String,
}

#[derive(Debug)]
pub struct OpenedPayload {
    pub data: Vec<u8>,
    pub qkd_reply: Option<QkdReplyToken>,
}

/// Per-message QKD application protection used by the QUIC data paths.
///
/// The daemon remains responsible for the long-lived TLS bootstrap key. ROS
/// processes use this small client for message protection. An outgoing KME key
/// is rotated after ten messages; every envelope receives an independent
/// nonce. Receivers retrieve each key ID once and coordinate that lookup
/// through the QKD shared-memory store.
#[derive(Clone)]
pub struct QkdMessageCrypto {
    client: EtsiQkdClient,
    local_sae_id: String,
    seen_message_keys: Arc<Mutex<HashSet<Vec<u8>>>>,
    topic_seals: Arc<Mutex<TopicSealCache>>,
    outbound_keys: Arc<tokio::sync::Mutex<HashMap<String, CachedOutboundKey>>>,
}

impl QkdMessageCrypto {
    pub fn from_env() -> Result<Self, String> {
        let config = QkdConfig::from_env()?;
        let client = EtsiQkdClient::new(&config)?;
        Ok(Self {
            client,
            local_sae_id: config.local_sae_id,
            seen_message_keys: Arc::new(Mutex::new(HashSet::new())),
            topic_seals: Arc::new(Mutex::new(TopicSealCache::default())),
            outbound_keys: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        })
    }

    async fn encryption_key(
        &self,
        remote_sae_id: &str,
    ) -> Result<(crate::qkd::QkdKeyMaterial, bool), String> {
        let mut cache = self.outbound_keys.lock().await;
        if let Some(cached) = cache.get_mut(remote_sae_id) {
            if cached.uses < QKD_MESSAGES_PER_KEY {
                cached.uses += 1;
                return Ok((cached.material.clone(), false));
            }
        }

        let material = self.client.get_encryption_key(remote_sae_id).await?;
        cache.insert(
            remote_sae_id.to_string(),
            CachedOutboundKey {
                material: material.clone(),
                uses: 1,
            },
        );
        Ok((material, true))
    }

    fn context_aad(context: WireContext, sender_sae_id: &str, key_id: &str) -> Vec<u8> {
        let mut aad = Vec::with_capacity(1 + 8 + sender_sae_id.len() + key_id.len());
        aad.push(context.kind as u8);
        aad.extend_from_slice(&context.topic_hash.to_be_bytes());
        aad.extend_from_slice(sender_sae_id.as_bytes());
        aad.extend_from_slice(key_id.as_bytes());
        aad
    }

    fn encode_header(
        context: WireContext,
        nonce: &[u8; QKD_NONCE_BYTES],
        sender_sae_id: &str,
        key_id: &str,
    ) -> Result<Vec<u8>, String> {
        if sender_sae_id.is_empty() || sender_sae_id.len() > QKD_MAX_WIRE_FIELD {
            return Err("QKD sender SAE ID is too long".into());
        }
        if key_id.is_empty() || key_id.len() > QKD_MAX_WIRE_FIELD {
            return Err("QKD message key ID is too long".into());
        }
        let mut out = Vec::with_capacity(QKD_WIRE_HEADER_LEN + sender_sae_id.len() + key_id.len());
        out.extend_from_slice(QKD_WIRE_MAGIC);
        out.push(context.kind as u8);
        out.extend_from_slice(&[0u8; 3]);
        out.extend_from_slice(&context.topic_hash.to_be_bytes());
        out.extend_from_slice(nonce);
        out.extend_from_slice(&(sender_sae_id.len() as u16).to_be_bytes());
        out.extend_from_slice(&(key_id.len() as u16).to_be_bytes());
        out.extend_from_slice(sender_sae_id.as_bytes());
        out.extend_from_slice(key_id.as_bytes());
        Ok(out)
    }

    /// Seal one outgoing application message with the current QKD key.
    pub async fn seal_for_daemon(
        &self,
        remote_daemon_id: u64,
        context: WireContext,
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        let store = QkdKeyStore::open().map_err(|error| format!("open QKD key store: {error}"))?;
        let session = store
            .find_for_daemon(remote_daemon_id, true)
            .ok_or_else(|| format!("no active QKD session for daemon {remote_daemon_id}"))?;
        let (material, fetched_from_kme) = self.encryption_key(&session.remote_sae_id).await?;
        crate::axon_trace!(
            "event=qkd_key_received direction=encrypt source={} remote_sae={} key_id={} payload_bytes={}",
            if fetched_from_kme { "kme" } else { "reuse" },
            session.remote_sae_id,
            material.key_id,
            payload.len()
        );
        let result = Self::seal_with_material(
            &self.local_sae_id,
            context,
            &material.key,
            &material.key_id,
            payload,
        );
        crate::axon_trace!(
            "event=qkd_message_sealed direction=encrypt remote_daemon={} key_id={} kind={:?} topic_hash={} payload_bytes={} result={}",
            remote_daemon_id,
            material.key_id,
            context.kind,
            context.topic_hash,
            payload.len(),
            if result.is_ok() { "ok" } else { "error" }
        );
        result
    }

    /// Seal one logical topic publication once per remote daemon.
    ///
    /// A remote host can expose several matching ROS processes. They all
    /// receive the same publication, so reusing its already-sealed envelope is
    /// still one logical message. The receivers coordinate the matching
    /// `dec_keys` lookup through the shared message-key cache.
    pub async fn seal_topic_for_daemon(
        &self,
        remote_daemon_id: u64,
        topic_hash: u64,
        publication_id: u64,
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        let cache_key = (remote_daemon_id, topic_hash, publication_id);
        let cell = {
            let mut cache = self.topic_seals.lock().unwrap();
            if let Some(cell) = cache.entries.get(&cache_key) {
                cell.clone()
            } else {
                while cache.entries.len() >= QKD_TOPIC_SEAL_CACHE_SIZE {
                    if let Some(oldest) = cache.order.pop_front() {
                        cache.entries.remove(&oldest);
                    } else {
                        break;
                    }
                }
                let cell = Arc::new(tokio::sync::OnceCell::new());
                cache.entries.insert(cache_key, cell.clone());
                cache.order.push_back(cache_key);
                cell
            }
        };

        let result = cell
            .get_or_try_init(|| async {
                self.seal_for_daemon(remote_daemon_id, WireContext::topic(topic_hash), payload)
                    .await
            })
            .await;
        match result {
            Ok(wire) => Ok(wire.clone()),
            Err(error) => {
                let mut cache = self.topic_seals.lock().unwrap();
                if cache
                    .entries
                    .get(&cache_key)
                    .is_some_and(|current| Arc::ptr_eq(current, &cell))
                {
                    cache.entries.remove(&cache_key);
                    cache.order.retain(|key| *key != cache_key);
                }
                Err(error)
            }
        }
    }

    /// Seal a service response with the current QKD key for the requesting SAE.
    pub async fn seal_for_reply(
        &self,
        token: &QkdReplyToken,
        context: WireContext,
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        let (material, fetched_from_kme) = self.encryption_key(&token.remote_sae_id).await?;
        crate::axon_trace!(
            "event=qkd_key_received direction=encrypt_reply source={} remote_sae={} key_id={} payload_bytes={}",
            if fetched_from_kme { "kme" } else { "reuse" },
            token.remote_sae_id,
            material.key_id,
            payload.len()
        );
        let result = Self::seal_with_material(
            &self.local_sae_id,
            context,
            &material.key,
            &material.key_id,
            payload,
        );
        crate::axon_trace!(
            "event=qkd_message_sealed direction=encrypt_reply remote_sae={} key_id={} kind={:?} topic_hash={} payload_bytes={} result={}",
            token.remote_sae_id,
            material.key_id,
            context.kind,
            context.topic_hash,
            payload.len(),
            if result.is_ok() { "ok" } else { "error" }
        );
        result
    }

    fn seal_with_material(
        local_sae_id: &str,
        context: WireContext,
        key: &[u8; 32],
        key_id: &str,
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        let mut nonce_bytes = [0u8; QKD_NONCE_BYTES];
        SystemRandom::new()
            .fill(&mut nonce_bytes)
            .map_err(|_| "QKD message nonce generation failed".to_string())?;
        let mut wire = Self::encode_header(context, &nonce_bytes, local_sae_id, key_id)?;
        let aad = Self::context_aad(context, local_sae_id, key_id);
        let unbound = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| "invalid QKD message key material".to_string())?;
        let key = LessSafeKey::new(unbound);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut ciphertext = payload.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::from(aad.as_slice()), &mut ciphertext)
            .map_err(|_| "QKD message encryption failed".to_string())?;
        wire.extend_from_slice(&ciphertext);
        Ok(wire)
    }

    /// Open one incoming application message and consume its matching KME key.
    pub async fn open_wire(
        &self,
        wire: Vec<u8>,
        context: WireContext,
    ) -> Result<OpenedPayload, String> {
        if wire.len() < QKD_WIRE_HEADER_LEN + aead::AES_256_GCM.tag_len() {
            return Err("QKD message envelope is truncated".into());
        }
        if &wire[..8] != QKD_WIRE_MAGIC {
            return Err("QKD message is missing its QKD envelope".into());
        }
        let kind = wire[8];
        let wire_topic = u64::from_be_bytes(wire[12..20].try_into().unwrap());
        if kind != context.kind as u8 || wire_topic != context.topic_hash {
            return Err("QKD message context mismatch".into());
        }
        let mut nonce_bytes = [0u8; QKD_NONCE_BYTES];
        nonce_bytes.copy_from_slice(&wire[20..32]);
        let sender_len = u16::from_be_bytes([wire[32], wire[33]]) as usize;
        let key_len = u16::from_be_bytes([wire[34], wire[35]]) as usize;
        let fields_end = QKD_WIRE_HEADER_LEN
            .checked_add(sender_len)
            .and_then(|n| n.checked_add(key_len))
            .ok_or_else(|| "QKD message envelope length overflow".to_string())?;
        if sender_len == 0
            || sender_len > QKD_MAX_WIRE_FIELD
            || key_len == 0
            || key_len > QKD_MAX_WIRE_FIELD
            || fields_end > wire.len()
        {
            return Err("invalid QKD message envelope lengths".into());
        }
        let sender_sae_id =
            std::str::from_utf8(&wire[QKD_WIRE_HEADER_LEN..QKD_WIRE_HEADER_LEN + sender_len])
                .map_err(|_| "QKD sender SAE ID is not UTF-8".to_string())?;
        let key_id = std::str::from_utf8(&wire[QKD_WIRE_HEADER_LEN + sender_len..fields_end])
            .map_err(|_| "QKD message key ID is not UTF-8".to_string())?;
        let store = QkdKeyStore::open().map_err(|error| format!("open QKD key store: {error}"))?;
        let mut replay_key = Vec::with_capacity(sender_sae_id.len() + key_id.len() + 14);
        replay_key.extend_from_slice(sender_sae_id.as_bytes());
        replay_key.push(0);
        replay_key.extend_from_slice(key_id.as_bytes());
        replay_key.push(0);
        replay_key.extend_from_slice(&nonce_bytes);
        {
            let mut seen = self.seen_message_keys.lock().unwrap();
            if seen.contains(&replay_key) {
                return Err("QKD message key ID was already used".into());
            }
            if seen.len() >= QKD_REPLAY_CACHE_SIZE {
                if let Some(oldest) = seen.iter().next().cloned() {
                    seen.remove(&oldest);
                }
            }
            seen.insert(replay_key.clone());
        }
        let (material, fetched_from_kme) = loop {
            let lookup = match store.claim_message_key(sender_sae_id, key_id) {
                Ok(lookup) => lookup,
                Err(error) => {
                    self.seen_message_keys.lock().unwrap().remove(&replay_key);
                    return Err(error);
                }
            };
            match lookup {
                QkdMessageKeyLookup::Ready(material) => break (material, false),
                QkdMessageKeyLookup::Claimed => {
                    crate::axon_trace!(
                        "event=qkd_key_request direction=decrypt sender_sae={} key_id={} kind={:?} topic_hash={} wire_bytes={}",
                        sender_sae_id,
                        key_id,
                        context.kind,
                        context.topic_hash,
                        wire.len()
                    );
                    match self.client.get_decryption_key(sender_sae_id, key_id).await {
                        Ok(material) => break (material, true),
                        Err(error) => {
                            store.abandon_message_key(sender_sae_id, key_id);
                            self.seen_message_keys.lock().unwrap().remove(&replay_key);
                            return Err(error);
                        }
                    }
                }
                QkdMessageKeyLookup::Pending => {
                    // The shared store recovers a pending entry only when its
                    // claimant process has exited. A live request may spend
                    // longer than one HTTP timeout queued behind the process
                    // KME limiter and must never be stolen by another process.
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
        };
        crate::axon_trace!(
            "event=qkd_key_received direction=decrypt source={} sender_sae={} key_id={} wire_bytes={}",
            if fetched_from_kme { "kme" } else { "shared_cache" },
            sender_sae_id,
            key_id,
            wire.len()
        );
        let aad = Self::context_aad(context, sender_sae_id, key_id);
        let unbound = UnboundKey::new(&AES_256_GCM, &material.key)
            .map_err(|_| "invalid QKD message key material".to_string())?;
        let key = LessSafeKey::new(unbound);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut ciphertext = wire[fields_end..].to_vec();
        let plaintext = match key.open_in_place(nonce, Aad::from(aad.as_slice()), &mut ciphertext) {
            Ok(plaintext) => plaintext,
            Err(_) => {
                if fetched_from_kme {
                    store.abandon_message_key(sender_sae_id, key_id);
                }
                self.seen_message_keys.lock().unwrap().remove(&replay_key);
                return Err("QKD message authentication failed".into());
            }
        };
        if fetched_from_kme {
            if let Err(error) = store.publish_message_key(sender_sae_id, &material) {
                self.seen_message_keys.lock().unwrap().remove(&replay_key);
                return Err(error);
            }
        }
        let opened = OpenedPayload {
            data: plaintext.to_vec(),
            qkd_reply: (context.kind == WireKind::ServiceRequest).then(|| QkdReplyToken {
                remote_sae_id: sender_sae_id.to_string(),
            }),
        };
        crate::axon_trace!(
            "event=qkd_message_opened direction=decrypt sender_sae={} key_id={} kind={:?} topic_hash={} payload_bytes={} result=ok",
            sender_sae_id,
            key_id,
            context.kind,
            context.topic_hash,
            opened.data.len()
        );
        Ok(opened)
    }
}

/// Validate the complete security configuration before the daemon starts.
pub fn validate_runtime() -> Result<(SecurityMode, QuicCipher), String> {
    let mode = SecurityMode::from_env()?;
    let cipher = QuicCipher::from_env()?;
    if mode == SecurityMode::Qkd {
        crate::qkd::QkdConfig::from_env()?;
    }
    for obsolete in [
        "AXON_SECURITY_PROFILE",
        "AXON_ENCRYPTION_MODE",
        "AXON_ENCRYPTION_KEY",
    ] {
        if std::env::var_os(obsolete).is_some() {
            return Err(format!(
                "{obsolete} is obsolete; use AXON_SECURITY_MODE=classic|qkd"
            ));
        }
    }
    Ok((mode, cipher))
}

pub fn validate_pre_daemon_runtime() -> Result<(SecurityMode, QuicCipher), String> {
    validate_runtime()
}

/// QUIC already authenticates and encrypts this payload.
pub fn seal_for_daemon(
    _remote_daemon_id: u64,
    _context: WireContext,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    Ok(payload.to_vec())
}

/// QUIC already authenticates and encrypts this response.
pub fn seal_for_reply(
    _token: &QkdReplyToken,
    _context: WireContext,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    Ok(payload.to_vec())
}

pub fn open_wire(wire: Vec<u8>, _context: WireContext) -> Result<OpenedPayload, String> {
    Ok(OpenedPayload {
        data: wire,
        qkd_reply: None,
    })
}

/// Access-control list engine with glob pattern matching.
pub struct AclEngine {
    allow_publish: Vec<Pattern>,
    allow_subscribe: Vec<Pattern>,
}

impl AclEngine {
    pub fn new() -> Self {
        Self {
            allow_publish: Vec::new(),
            allow_subscribe: Vec::new(),
        }
    }

    pub fn from_env() -> Self {
        let mut engine = Self::new();
        for (var, dir) in [
            ("AXON_ACL_PUBLISH", AclDirection::Publish),
            ("AXON_ACL_SUBSCRIBE", AclDirection::Subscribe),
        ] {
            if let Ok(rules) = std::env::var(var) {
                for pattern in rules.split(',').map(str::trim).filter(|v| !v.is_empty()) {
                    engine.add_rule(dir, pattern);
                }
            }
        }
        engine
    }

    pub fn add_rule(&mut self, direction: AclDirection, pattern: &str) -> bool {
        let Ok(pattern) = Pattern::new(pattern) else {
            return false;
        };
        match direction {
            AclDirection::Publish => self.allow_publish.push(pattern),
            AclDirection::Subscribe => self.allow_subscribe.push(pattern),
        }
        true
    }

    pub fn check(&self, direction: AclDirection, topic: &str) -> bool {
        let patterns = match direction {
            AclDirection::Publish => &self.allow_publish,
            AclDirection::Subscribe => &self.allow_subscribe,
        };
        patterns.is_empty() || patterns.iter().any(|pattern| pattern.matches(topic))
    }
}

impl Default for AclEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Bounded audit log with topic filtering.
pub struct AuditLog {
    entries: Mutex<VecDeque<(Instant, AuditDirection, String, usize)>>,
    max_entries: usize,
}

impl AuditLog {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(max_entries.min(4096))),
            max_entries,
        }
    }

    pub fn log(&self, direction: AuditDirection, topic_hash: &str, size: usize) {
        let mut entries = self.entries.lock().unwrap();
        if entries.len() >= self.max_entries {
            entries.pop_front();
        }
        entries.push_back((Instant::now(), direction, topic_hash.to_string(), size));
    }

    pub fn recent(&self) -> Vec<(AuditDirection, String, usize)> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .map(|(_, direction, topic, size)| (*direction, topic.clone(), *size))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_is_not_double_encrypted() {
        let payload = b"camera frame";
        let wire = seal_for_daemon(7, WireContext::topic(42), payload).unwrap();
        assert_eq!(wire, payload);
        assert_eq!(
            open_wire(wire, WireContext::topic(42)).unwrap().data,
            payload
        );
    }

    #[test]
    fn qkd_message_envelope_uses_a_fresh_nonce() {
        let key = [0x42u8; 32];
        let context = WireContext::topic(7);
        let first = QkdMessageCrypto::seal_with_material(
            "sae-test",
            context,
            &key,
            "key-1",
            b"same payload",
        )
        .unwrap();
        let second = QkdMessageCrypto::seal_with_material(
            "sae-test",
            context,
            &key,
            "key-1",
            b"same payload",
        )
        .unwrap();

        assert_ne!(first, second);
        assert_eq!(&first[..8], QKD_WIRE_MAGIC);
        assert_eq!(&second[..8], QKD_WIRE_MAGIC);
        assert_ne!(&first[20..32], &second[20..32]);
    }
}
