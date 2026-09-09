use std::collections::HashMap;
use std::future::Future;
use std::net::{SocketAddr, UdpSocket};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

static TRACE_COMPRESS: AtomicU64 = AtomicU64::new(0);
static TRACE_SEND: AtomicU64 = AtomicU64::new(0);
static TRACE_RECV: AtomicU64 = AtomicU64::new(0);

use futures_util::stream::{FuturesOrdered, StreamExt};
use quinn::congestion::{Controller, ControllerFactory};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, EndpointConfig, ServerConfig, TokioRuntime, TransportConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

use crate::local::LocalPubSub;
use crate::qkd::{QkdKeyStore, QkdSessionKey};
use crate::security::QkdMessageCrypto;
use crate::security_mode::{QuicCipher, SecurityMode};
use crate::types::TopicHash;

const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(5);
const SERVICE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const TOPIC_PREPARE_DEPTH: usize = 4;

pub type PeerId = u64;

/// Install the default TLS crypto provider for rustls.
/// Must be called once before any QUIC transport operations.
pub fn install_quic_crypto() {
    static INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INIT.get_or_init(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

pub fn generate_self_signed_certs() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    use rcgen::PKCS_ECDSA_P256_SHA256;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
    let key_pair =
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("failed to generate ECDSA keypair");
    let mut params = CertificateParams::new(vec!["axon".to_string()]).expect("invalid cert params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    let cert = params
        .self_signed(&key_pair)
        .expect("failed to self-sign cert");
    let cert_der = cert.der().clone();
    let key_der = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
    (cert_der, key_der.into())
}

pub fn configure_server(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> ServerConfig {
    let mode = SecurityMode::from_env().expect("invalid AXON_SECURITY_MODE");
    let provider = transport_provider(mode).expect("invalid AXON_QUIC_CIPHER");
    let mut crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 is unavailable")
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("bad server cert");
    if mode == SecurityMode::Qkd {
        crypto.external_psk_resolver =
            Some(Arc::new(QkdPskResolver::open().unwrap_or_else(|error| {
                panic!("QKD TLS key store is unavailable: {error}")
            })));
        crypto.send_tls13_tickets = 0;
    }
    let mut config = ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::with_initial(Arc::new(crypto), quic_initial_suite())
            .expect("invalid AXON QUIC server config"),
    ));
    config.transport_config(Arc::new(quic_transport_config()));
    config
}

pub fn configure_client() -> ClientConfig {
    configure_client_for_daemon(None).expect("invalid AXON QUIC client config")
}

pub fn configure_client_for_daemon(remote_daemon_id: Option<u64>) -> Result<ClientConfig, String> {
    let mode = SecurityMode::from_env()?;
    let provider = transport_provider(mode)?;
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| format!("TLS 1.3 is unavailable: {error}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification::new()))
        .with_no_client_auth();
    if mode == SecurityMode::Qkd {
        let remote_daemon_id =
            remote_daemon_id.ok_or_else(|| "QKD connection has no remote daemon ID".to_string())?;
        let store =
            QkdKeyStore::open().map_err(|error| format!("open QKD TLS key store: {error}"))?;
        let session = store
            .find_for_daemon(remote_daemon_id, false)
            .ok_or_else(|| format!("no QKD key for daemon {remote_daemon_id}"))?;
        crypto.external_psk = Some(qkd_external_psk(&session)?);
        crypto.resumption = rustls::client::Resumption::disabled();
    }
    let mut config = ClientConfig::new(Arc::new(
        QuicClientConfig::with_initial(Arc::new(crypto), quic_initial_suite())
            .expect("invalid AXON QUIC client config"),
    ));
    config.transport_config(Arc::new(quic_transport_config()));
    Ok(config)
}

fn transport_provider(mode: SecurityMode) -> Result<Arc<rustls::crypto::CryptoProvider>, String> {
    Ok(transport_provider_with_cipher(
        mode,
        QuicCipher::from_env()?,
    ))
}

fn transport_provider_with_cipher(
    mode: SecurityMode,
    cipher: QuicCipher,
) -> Arc<rustls::crypto::CryptoProvider> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites = vec![match cipher {
        QuicCipher::ChaCha20Poly1305 => {
            rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256
        }
        QuicCipher::Aes256Gcm => rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
    }];
    provider.kx_groups = match mode {
        SecurityMode::Classic => {
            vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768]
        }
        SecurityMode::Qkd => Vec::new(),
    };
    Arc::new(provider)
}

fn quic_initial_suite() -> rustls::quic::Suite {
    rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .and_then(|suite| suite.quic_suite())
        .expect("AWS-LC provider does not support mandatory QUIC Initial protection")
}

struct QkdPskResolver {
    store: QkdKeyStore,
}

impl std::fmt::Debug for QkdPskResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("QkdPskResolver")
    }
}

impl QkdPskResolver {
    fn open() -> Result<Self, String> {
        Ok(Self {
            store: QkdKeyStore::open().map_err(|error| error.to_string())?,
        })
    }
}

impl rustls::external_psk::ResolvesExternalPsk for QkdPskResolver {
    fn resolve(&self, identity: &[u8]) -> Option<rustls::external_psk::ExternalPsk> {
        let key_id = qkd_identity_key_id(identity)?;
        let session = self.store.find_by_key_id_for_tls(key_id)?;
        qkd_external_psk(&session).ok()
    }
}

struct TlsPskLength;

impl ring::hkdf::KeyType for TlsPskLength {
    fn len(&self) -> usize {
        32
    }
}

fn qkd_identity(key_id: &str) -> Vec<u8> {
    let mut identity = b"AXON-QKD-TLS13-v1:".to_vec();
    identity.extend_from_slice(key_id.as_bytes());
    identity
}

fn qkd_identity_key_id(identity: &[u8]) -> Option<&str> {
    const PREFIX: &[u8] = b"AXON-QKD-TLS13-v1:";
    std::str::from_utf8(identity.strip_prefix(PREFIX)?).ok()
}

fn qkd_external_psk(session: &QkdSessionKey) -> Result<rustls::external_psk::ExternalPsk, String> {
    let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, b"AXON-QKD-TLS13-EXTERNAL-PSK-v1");
    let prk = salt.extract(&session.key);
    let info = [session.key_id.as_bytes()];
    let okm = prk
        .expand(&info, TlsPskLength)
        .map_err(|_| "QKD TLS HKDF expansion failed".to_string())?;
    let mut secret = vec![0u8; 32];
    okm.fill(&mut secret)
        .map_err(|_| "QKD TLS HKDF output failed".to_string())?;
    rustls::external_psk::ExternalPsk::new(qkd_identity(&session.key_id), secret)
        .map_err(str::to_string)
}

fn quic_stream_window() -> quinn::VarInt {
    let default: u64 = 64 * 1024 * 1024;
    let val = std::env::var("AXON_QUIC_STREAM_WINDOW")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default);
    quinn::VarInt::from_u64(val.clamp(1024 * 1024, u64::MAX))
        .unwrap_or(quinn::VarInt::from_u32(64 * 1024 * 1024))
}

fn quic_send_window() -> u64 {
    // Keep enough connection-level room for one large sensor frame plus
    // small control/time streams. A 2 MiB window makes a single PointCloud2
    // stream block /clock and image streams over WiFi.
    // Set AXON_QUIC_SEND_WINDOW to override (minimum 1 MiB).
    let default: u64 = 16 * 1024 * 1024;
    std::env::var("AXON_QUIC_SEND_WINDOW")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
        .max(1024 * 1024)
}

fn quic_max_udp_payload_size() -> u16 {
    // QUIC works best when packets fit the path MTU. The previous 65527-byte
    // datagrams relied on IP fragmentation; on WiFi, losing one fragment drops
    // the whole packet and large camera/pointcloud streams collapse.
    let default: u16 = 1200;
    std::env::var("AXON_QUIC_MAX_UDP_PAYLOAD")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .map(|v| v.clamp(1200, 65527))
        .unwrap_or(default)
}

/// A congestion controller that never limits throughput.
/// On lossy WiFi, standard QUIC congestion controllers (NewReno, Cubic, BBR)
/// throttle the send rate based on packet loss. For real-time image streaming
/// on a local network, no congestion control is needed — retransmission of
/// lost frames adds unacceptable latency.
struct NoCongestion;

impl Controller for NoCongestion {
    fn on_sent(&mut self, _now: Instant, _bytes: u64, _seq: u64) {}
    fn on_ack(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _bytes: u64,
        _ce: bool,
        _rtt: &quinn_proto::RttEstimator,
    ) {
    }
    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_loss: bool,
        _lost_bytes: u64,
    ) {
    }
    fn on_mtu_update(&mut self, _mtu: u16) {}
    fn window(&self) -> u64 {
        u64::MAX
    }
    fn initial_window(&self) -> u64 {
        u64::MAX
    }
    fn clone_box(&self) -> Box<dyn Controller + 'static> {
        Box::new(NoCongestion)
    }
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any + 'static> {
        self
    }
}

struct NoCongestionFactory;

impl ControllerFactory for NoCongestionFactory {
    fn build(self: Arc<Self>, _now: Instant, _current_mtu: u16) -> Box<dyn Controller> {
        Box::new(NoCongestion)
    }
}

fn quic_transport_config() -> TransportConfig {
    let mut config = TransportConfig::default();
    config.max_idle_timeout(Some(IDLE_TIMEOUT.try_into().unwrap()));
    config.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
    config.stream_receive_window(quic_stream_window());
    config.send_window(quic_send_window());
    config.congestion_controller_factory(Arc::new(NoCongestionFactory));
    config
}

#[derive(Debug)]
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Self {
        Self
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

type ServiceRequest = (Vec<u8>, oneshot::Sender<Vec<u8>>);
type ServiceRequestChannels = Arc<Mutex<HashMap<TopicHash, mpsc::UnboundedSender<ServiceRequest>>>>;
type RawStreamSenders = Arc<Mutex<HashMap<(PeerId, TopicHash), Arc<RawDataSlot>>>>;

/// QUIC transport managing connections and streams per peer.
pub struct QuicTransport {
    endpoint: Endpoint,
    runtime: Arc<Mutex<Option<Runtime>>>,
    handle: tokio::runtime::Handle,
    connections: Arc<Mutex<HashMap<PeerId, quinn::Connection>>>,
    /// Signal to stop the incoming handler thread.
    running: Arc<AtomicBool>,
    /// Wakes the accept loop immediately during shutdown. Closing a QUIC
    /// endpoint does not reliably wake an already-pending `accept()` future.
    shutdown_notify: Arc<tokio::sync::Notify>,
    /// Join handle for the background accept + stream dispatch thread.
    thread_handle: Arc<Mutex<Option<thread::JoinHandle<()>>>>,
    /// Per-topic receiver channels for dispatching incoming messages.
    pub recv_channels: Arc<Mutex<HashMap<TopicHash, mpsc::Sender<Vec<u8>>>>>,
    /// Service request dispatch channels: topic_hash -> sender of (request_data, response_tx)
    pub service_request_channels: ServiceRequestChannels,
    /// Pending service responses: response topic_hash -> waiting request streams.
    /// Entries carry the requesting client's GID and request sequence so a
    /// response is written back on the stream of the request it answers,
    /// even when the server responds out of order or also serves local
    /// (SHM-only) clients.
    pub pending_service_responses: Arc<Mutex<HashMap<TopicHash, Vec<PendingServiceResponse>>>>,
    /// Per (peer, topic) push handles for raw data.  Each handle points into a
    /// shared slot that feeds N parallel compressor workers.
    stream_senders: RawStreamSenders,
    /// All discovered socket addresses for each peer, ordered by daemon preference.
    peer_addrs: Arc<Mutex<HashMap<PeerId, Vec<SocketAddr>>>>,
    /// Remote ROS node id to its owning daemon id. The stored daemon-pair key
    /// authenticates the QUIC bootstrap; application messages use rotating QKD
    /// material through `qkd_message_crypto`.
    peer_daemons: Arc<Mutex<HashMap<PeerId, u64>>>,
    /// Per-message QKD client. It is present only in QKD mode and is shared by
    /// all stream tasks belonging to this ROS process.
    qkd_message_crypto: Option<Arc<QkdMessageCrypto>>,
}

/// A remote service request stream waiting for its response.
pub struct PendingServiceResponse {
    /// Client GID parsed from the request envelope (all zero when the
    /// request carried no envelope).
    pub client_gid: [u8; 16],
    /// Request sequence parsed from the request envelope (0 when unknown).
    pub request_sequence: i64,
    /// Completing this sender writes the response back on the QUIC
    /// bi-stream that delivered the request.
    pub tx: oneshot::Sender<Vec<u8>>,
}

/// Shared slot for the latest raw frame, with a Notify to wake compressors.
struct RawDataSlot {
    data: Mutex<std::collections::VecDeque<PendingTopicSend>>,
    notify: tokio::sync::Notify,
}

struct PendingTopicSend {
    data: Vec<u8>,
    publication_id: u64,
}

struct PreparedTopicSend {
    compressed: Vec<u8>,
    wire: Vec<u8>,
}

type TopicPrepareFuture = Pin<Box<dyn Future<Output = PreparedTopicSend> + Send + 'static>>;

const RECV_CHANNEL_CAPACITY: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QkdKeyMode {
    Session,
    Messages10,
}

impl QkdKeyMode {
    fn from_env() -> Result<Self, String> {
        let value = std::env::var("AXON_QKD_KEY_MODE").unwrap_or_else(|_| "messages10".to_string());
        Self::parse(&value)
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "session" => Ok(Self::Session),
            "messages10" => Ok(Self::Messages10),
            value => Err(format!(
                "invalid AXON_QKD_KEY_MODE '{value}'; expected session or messages10"
            )),
        }
    }
}

impl QuicTransport {
    pub fn new(port: u16) -> std::io::Result<Self> {
        install_quic_crypto();
        let mode = SecurityMode::from_env().map_err(std::io::Error::other)?;
        let qkd_message_crypto = if mode == SecurityMode::Qkd {
            match QkdKeyMode::from_env().map_err(std::io::Error::other)? {
                QkdKeyMode::Session => None,
                QkdKeyMode::Messages10 => Some(Arc::new(
                    QkdMessageCrypto::from_env().map_err(std::io::Error::other)?,
                )),
            }
        } else {
            None
        };
        let (cert, key) = generate_self_signed_certs();
        let server_config = configure_server(cert, key);

        let bind_addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
        let socket = UdpSocket::bind(bind_addr)?;

        let runtime = Runtime::new()?;
        let _guard = runtime.enter();
        let mut endpoint_config = EndpointConfig::default();
        endpoint_config
            .max_udp_payload_size(quic_max_udp_payload_size())
            .unwrap();
        let mut endpoint = Endpoint::new(
            endpoint_config,
            Some(server_config),
            socket,
            Arc::new(TokioRuntime),
        )?;
        if SecurityMode::from_env().map_err(std::io::Error::other)? == SecurityMode::Classic {
            endpoint.set_default_client_config(configure_client());
        }
        drop(_guard);

        Ok(Self {
            handle: runtime.handle().clone(),
            endpoint,
            runtime: Arc::new(Mutex::new(Some(runtime))),
            connections: Arc::new(Mutex::new(HashMap::new())),
            running: Arc::new(AtomicBool::new(true)),
            shutdown_notify: Arc::new(tokio::sync::Notify::new()),
            thread_handle: Arc::new(Mutex::new(None)),
            recv_channels: Arc::new(Mutex::new(HashMap::new())),
            service_request_channels: Arc::new(Mutex::new(HashMap::new())),
            pending_service_responses: Arc::new(Mutex::new(HashMap::new())),
            stream_senders: Arc::new(Mutex::new(HashMap::new())),
            peer_addrs: Arc::new(Mutex::new(HashMap::new())),
            peer_daemons: Arc::new(Mutex::new(HashMap::new())),
            qkd_message_crypto,
        })
    }

    /// Start background threads for accepting incoming connections and streams.
    pub fn start(&self) {
        let running = self.running.clone();
        let connections = self.connections.clone();
        let endpoint = self.endpoint.clone();
        let shutdown_notify = self.shutdown_notify.clone();
        let rt = self.runtime.clone();
        let recv_channels = self.recv_channels.clone();
        let service_request_channels = self.service_request_channels.clone();
        let qkd_message_crypto = self.qkd_message_crypto.clone();

        let handle = thread::spawn(move || {
            let runtime = rt
                .lock()
                .unwrap()
                .take()
                .expect("start called more than once");
            runtime.block_on(async move {
                while running.load(Ordering::Acquire) {
                    tokio::select! {
                        _ = shutdown_notify.notified() => {
                            break;
                        }
                        incoming = endpoint.accept() => {
                            match incoming {
                                Some(incoming) => {
                                    // `Incoming::await` can remain pending while a
                                    // peer disappears mid-handshake. Keep shutdown
                                    // in the same select so destroying a short-lived
                                    // ROS CLI context cannot block on that peer.
                                    let accepted = tokio::select! {
                                        _ = shutdown_notify.notified() => {
                                            break;
                                        }
                                        accepted = incoming => accepted,
                                    };
                                    match accepted {
                                        Ok(connection) => {
                                            let peer_id = connection.stable_id() as PeerId;
                                            connections.lock().unwrap().insert(peer_id, connection.clone());
                                            // Spawn per-connection stream reader
                                            tokio::spawn(Self::handle_connection(
                                                connection, peer_id,
                                                recv_channels.clone(),
                                                service_request_channels.clone(),
                                                connections.clone(),
                                                qkd_message_crypto.clone(),
                                            ));
                                        }
                                        Err(e) => {
                                            tracing::warn!("QUIC accept failed: {}", e);
                                        }
                                    }
                                }
                                None => {
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                }
                            }
                        }
                    }
                }
            });
            runtime.shutdown_timeout(Duration::from_millis(200));
        });
        // Replace thread_handle: if start() was called before, the old thread is
        // leaked (defensive; calling start() twice is already a logic error).
        let _ = self.thread_handle.lock().unwrap().replace(handle);
    }

    /// Connect to a discovered peer asynchronously (spawned on transport's runtime).
    /// Skips if a healthy entry already exists to avoid racing multiple connection
    /// attempts to the same peer (which would close the previous connection
    /// and interrupt in-flight service calls).  Stale connections (closed by
    /// the peer or timed out) are detected via `close_reason()` and replaced
    /// with a fresh connection.
    pub fn connect_async(&self, peer_id: PeerId, addr: SocketAddr) {
        let connections = self.connections.clone();
        let endpoint = self.endpoint.clone();
        let peer_addrs = self.peer_addrs.clone();
        let peer_daemons = self.peer_daemons.clone();
        Self::remember_peer_addr(&peer_addrs, peer_id, addr);
        self.handle.spawn(async move {
            {
                let map = connections.lock().unwrap();
                if let Some(conn) = map.get(&peer_id) {
                    if conn.close_reason().is_none() {
                        return; // healthy connection exists
                    }
                }
            }
            connections.lock().unwrap().remove(&peer_id);
            if let Err(e) = Self::connect_peer_from_candidates(
                &endpoint,
                &connections,
                &peer_addrs,
                &peer_daemons,
                peer_id,
                Some(addr),
            )
            .await
            {
                tracing::warn!("QUIC connect failed for {}: {}", peer_id, e);
            }
        });
    }

    /// Connect to a discovered peer.
    pub async fn connect(&self, peer_id: PeerId, addr: SocketAddr) -> Result<(), String> {
        Self::remember_peer_addr(&self.peer_addrs, peer_id, addr);
        self.connect_any(peer_id, Some(addr)).await?;
        Ok(())
    }

    pub fn set_peer_addrs(&self, peer_id: PeerId, addrs: Vec<SocketAddr>) {
        let mut unique = Vec::new();
        for addr in addrs {
            if addr.port() != 0 && !addr.ip().is_unspecified() && !unique.contains(&addr) {
                unique.push(addr);
            }
        }
        if !unique.is_empty() {
            self.peer_addrs.lock().unwrap().insert(peer_id, unique);
        }
    }

    pub fn set_peer_daemon(&self, peer_id: PeerId, daemon_id: u64) {
        if daemon_id != 0 {
            self.peer_daemons.lock().unwrap().insert(peer_id, daemon_id);
        }
    }

    async fn connect_any(
        &self,
        peer_id: PeerId,
        preferred: Option<SocketAddr>,
    ) -> Result<quinn::Connection, String> {
        Self::connect_peer_from_candidates(
            &self.endpoint,
            &self.connections,
            &self.peer_addrs,
            &self.peer_daemons,
            peer_id,
            preferred,
        )
        .await
    }

    fn remember_peer_addr(
        peer_addrs: &Arc<Mutex<HashMap<PeerId, Vec<SocketAddr>>>>,
        peer_id: PeerId,
        addr: SocketAddr,
    ) {
        if addr.port() == 0 || addr.ip().is_unspecified() {
            return;
        }
        let mut map = peer_addrs.lock().unwrap();
        let addrs = map.entry(peer_id).or_default();
        if !addrs.contains(&addr) {
            addrs.push(addr);
        }
    }

    fn candidate_addrs_from(
        peer_addrs: &Arc<Mutex<HashMap<PeerId, Vec<SocketAddr>>>>,
        peer_id: PeerId,
        preferred: Option<SocketAddr>,
    ) -> Vec<SocketAddr> {
        let mut candidates = Vec::new();
        if let Some(addr) = preferred {
            if addr.port() != 0 && !addr.ip().is_unspecified() {
                candidates.push(addr);
            }
        }
        if let Some(addrs) = peer_addrs.lock().unwrap().get(&peer_id) {
            for addr in addrs {
                if addr.port() != 0 && !addr.ip().is_unspecified() && !candidates.contains(addr) {
                    candidates.push(*addr);
                }
            }
        }
        candidates
    }

    fn candidate_addrs(&self, peer_id: PeerId, preferred: Option<SocketAddr>) -> Vec<SocketAddr> {
        Self::candidate_addrs_from(&self.peer_addrs, peer_id, preferred)
    }

    async fn connect_peer_from_candidates(
        endpoint: &Endpoint,
        connections: &Arc<Mutex<HashMap<PeerId, quinn::Connection>>>,
        peer_addrs: &Arc<Mutex<HashMap<PeerId, Vec<SocketAddr>>>>,
        peer_daemons: &Arc<Mutex<HashMap<PeerId, u64>>>,
        peer_id: PeerId,
        preferred: Option<SocketAddr>,
    ) -> Result<quinn::Connection, String> {
        {
            let map = connections.lock().unwrap();
            if let Some(conn) = map.get(&peer_id) {
                if conn.close_reason().is_none() {
                    return Ok(conn.clone());
                }
            }
        }
        connections.lock().unwrap().remove(&peer_id);

        let candidates = Self::candidate_addrs_from(peer_addrs, peer_id, preferred);
        if candidates.is_empty() {
            return Err("no peer address".into());
        }

        let mut last_error = String::from("no peer address");
        let remote_daemon_id = peer_daemons.lock().unwrap().get(&peer_id).copied();
        let client_config = configure_client_for_daemon(remote_daemon_id)?;
        for addr in candidates {
            match endpoint.connect_with(client_config.clone(), addr, "axon") {
                Ok(connecting) => match tokio::time::timeout(CONNECT_TIMEOUT, connecting).await {
                    Ok(Ok(connection)) => {
                        connections
                            .lock()
                            .unwrap()
                            .insert(peer_id, connection.clone());
                        return Ok(connection);
                    }
                    Ok(Err(e)) => {
                        last_error = format!("handshake failed via {}: {}", addr, e);
                    }
                    Err(_) => {
                        last_error = format!("handshake timed out via {}", addr);
                    }
                },
                Err(e) => {
                    last_error = format!("connect failed via {}: {}", addr, e);
                }
            }
        }
        Err(last_error)
    }

    /// Open a unidirectional stream to a peer for a topic.
    pub async fn open_send_stream(&self, peer_id: PeerId) -> Result<quinn::SendStream, String> {
        let conn = self
            .connections
            .lock()
            .unwrap()
            .get(&peer_id)
            .ok_or("not connected")?
            .clone();
        let send = conn
            .open_uni()
            .await
            .map_err(|e| format!("open stream failed: {}", e))?;
        Ok(send)
    }

    async fn write_wire(stream: &mut quinn::SendStream, wire: &[u8]) -> Result<(), String> {
        stream
            .write_all(&(wire.len() as u32).to_be_bytes())
            .await
            .map_err(|e| format!("write length failed: {}", e))?;
        stream
            .write_all(wire)
            .await
            .map_err(|e| format!("write data failed: {}", e))?;
        Ok(())
    }

    async fn write_sealed(
        stream: &mut quinn::SendStream,
        remote_daemon_id: u64,
        context: crate::security::WireContext,
        data: &[u8],
        topic_publication_id: Option<u64>,
        qkd_message_crypto: Option<Arc<QkdMessageCrypto>>,
    ) -> Result<(), String> {
        let qkd_enabled = qkd_message_crypto.is_some();
        crate::axon_trace!(
            "event=wire_seal_start remote_daemon={} kind={:?} topic_hash={} payload_bytes={} security={}",
            remote_daemon_id,
            context.kind,
            context.topic_hash,
            data.len(),
            if qkd_enabled { "qkd" } else { "classic" }
        );
        let wire = match qkd_message_crypto {
            Some(crypto) => match topic_publication_id {
                Some(publication_id) => {
                    crypto
                        .seal_topic_for_daemon(
                            remote_daemon_id,
                            context.topic_hash,
                            publication_id,
                            data,
                        )
                        .await?
                }
                None => {
                    crypto
                        .seal_for_daemon(remote_daemon_id, context, data)
                        .await?
                }
            },
            None => crate::security::seal_for_daemon(remote_daemon_id, context, data)?,
        };
        let result = Self::write_wire(stream, &wire).await;
        crate::axon_trace!(
            "event=wire_seal_written remote_daemon={} kind={:?} topic_hash={} payload_bytes={} wire_bytes={} security={} result={}",
            remote_daemon_id,
            context.kind,
            context.topic_hash,
            data.len(),
            wire.len(),
            if qkd_enabled { "qkd" } else { "classic" },
            if result.is_ok() { "ok" } else { "error" }
        );
        result
    }

    async fn prepare_topic_send(
        remote_daemon_id: u64,
        topic_hash: TopicHash,
        pending: PendingTopicSend,
        qkd_message_crypto: Option<Arc<QkdMessageCrypto>>,
    ) -> PreparedTopicSend {
        let publication_id = pending.publication_id;
        let raw = Arc::new(pending.data);
        let fallback = raw.clone();
        let raw_len = raw.len();
        let started = Instant::now();
        let compressed = tokio::task::spawn_blocking(move || crate::compress::compress(&raw))
            .await
            .unwrap_or_else(|_| {
                let mut out = Vec::with_capacity(fallback.len() + 1);
                out.push(0);
                out.extend_from_slice(&fallback);
                out
            });
        let count = TRACE_COMPRESS.fetch_add(1, Ordering::Relaxed);
        if crate::trace::enabled() || count.is_multiple_of(30) {
            tracing::info!(
                target: "axon_latency",
                raw = raw_len,
                compressed = compressed.len(),
                compress_us = started.elapsed().as_micros() as u64,
                "compress_done"
            );
        }

        let context = crate::security::WireContext::topic(topic_hash);
        loop {
            crate::axon_trace!(
                "event=wire_seal_start remote_daemon={} kind={:?} topic_hash={} payload_bytes={} security={}",
                remote_daemon_id,
                context.kind,
                topic_hash,
                compressed.len(),
                if qkd_message_crypto.is_some() {
                    "qkd"
                } else {
                    "classic"
                }
            );
            let result = match qkd_message_crypto.as_ref() {
                Some(crypto) => {
                    crypto
                        .seal_topic_for_daemon(
                            remote_daemon_id,
                            topic_hash,
                            publication_id,
                            &compressed,
                        )
                        .await
                }
                None => crate::security::seal_for_daemon(remote_daemon_id, context, &compressed),
            };
            match result {
                Ok(wire) => return PreparedTopicSend { compressed, wire },
                Err(error) => {
                    tracing::warn!(
                        "topic security preparation blocked for daemon {remote_daemon_id}: {error}"
                    );
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    async fn read_sealed(
        recv: &mut quinn::RecvStream,
        context: crate::security::WireContext,
        qkd_message_crypto: Option<Arc<QkdMessageCrypto>>,
    ) -> Result<crate::security::OpenedPayload, String> {
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf)
            .await
            .map_err(|e| format!("read length failed: {e}"))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut data = vec![0u8; len];
        recv.read_exact(&mut data)
            .await
            .map_err(|e| format!("read data failed: {e}"))?;
        let qkd_enabled = qkd_message_crypto.is_some();
        crate::axon_trace!(
            "event=wire_read security={} kind={:?} topic_hash={} wire_bytes={}",
            if qkd_enabled { "qkd" } else { "classic" },
            context.kind,
            context.topic_hash,
            data.len()
        );
        let result = match qkd_message_crypto {
            Some(crypto) => crypto.open_wire(data, context).await,
            None => crate::security::open_wire(data, context),
        };
        if let Ok(ref opened) = result {
            crate::axon_trace!(
                "event=wire_opened security={} kind={:?} topic_hash={} payload_bytes={} result=ok",
                if qkd_enabled { "qkd" } else { "classic" },
                context.kind,
                context.topic_hash,
                opened.data.len()
            );
        } else {
            crate::axon_trace!(
                "event=wire_opened security={} kind={:?} topic_hash={} result=error",
                if qkd_enabled { "qkd" } else { "classic" },
                context.kind,
                context.topic_hash
            );
        }
        result
    }

    /// Send a message over a QUIC stream (length-prefixed).
    ///
    /// Opens a fresh stream per message. QUIC streams are lightweight and
    /// multiplexed — no connection overhead. Finishing the stream signals
    /// completion to the receiver without closing the connection.
    pub async fn send_message(
        &self,
        peer_id: PeerId,
        topic_hash: TopicHash,
        data: &[u8],
    ) -> Result<(), String> {
        let mut stream = self.open_send_stream(peer_id).await?;
        // Write topic_hash first so receiver can demux by topic
        stream
            .write_all(&topic_hash.to_be_bytes())
            .await
            .map_err(|e| format!("write hash failed: {}", e))?;
        let remote_daemon_id = self
            .peer_daemons
            .lock()
            .unwrap()
            .get(&peer_id)
            .copied()
            .unwrap_or(0);
        Self::write_sealed(
            &mut stream,
            remote_daemon_id,
            crate::security::WireContext::topic(topic_hash),
            data,
            None,
            self.qkd_message_crypto.clone(),
        )
        .await?;
        stream
            .finish()
            .map_err(|e| format!("finish failed: {}", e))?;
        Ok(())
    }

    /// Get the local socket address of the QUIC endpoint.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Release);
        // Unlike `notify_waiters`, `notify_one` stores a permit when the accept
        // loop is between await points, closing the shutdown race.
        self.shutdown_notify.notify_one();
    }

    /// Stop accepting traffic and close every active QUIC connection.
    ///
    /// This is separate from `Drop` so an RMW context can quiesce callbacks
    /// as soon as `rmw_shutdown()` is called, before ROS destroys entities.
    pub fn shutdown(&self) {
        self.stop();
        if let Ok(mut connections) = self.connections.lock() {
            for (_, connection) in connections.drain() {
                connection.close(0u32.into(), b"shutdown");
            }
        }
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.endpoint.close(0u32.into(), b"shutdown");
        }));
    }

    /// Set up a receiver channel for a topic. Called when subscribing to a remote topic.
    pub fn register_recv_topic(&self, topic_hash: TopicHash) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(RECV_CHANNEL_CAPACITY);
        self.recv_channels.lock().unwrap().insert(topic_hash, tx);
        rx
    }

    /// Register a subscriber (LocalPubSub) for a topic hash.
    ///
    /// Creates a receive channel and spawns an async task on the QUIC transport's
    /// runtime that forwards incoming messages directly into the pub/sub ring buffer.
    /// Mirrors the UDP path where `RemoteTransport::register_receiver` stores the
    /// `Arc<LocalPubSub>` directly.
    pub fn register_recv_subscriber(
        &self,
        topic_hash: TopicHash,
        subscriber: Arc<LocalPubSub>,
        queue: Arc<crate::subscriber_queue::SubscriberQueue>,
    ) {
        let cap = queue.capacity().max(1);
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(cap);
        self.recv_channels.lock().unwrap().insert(topic_hash, tx);
        self.handle.spawn(async move {
            while let Some(data) = rx.recv().await {
                if queue.push(data).is_some() {
                    subscriber.signal();
                }
            }
        });
    }

    /// Open a bidirectional stream for service calls.
    ///
    /// Retries up to ~5s if the QUIC connection has not been established yet.
    /// Removes stale connections from the map on failure and triggers
    /// synchronous reconnection when the peer's socket address is known
    /// (the `addr` parameter).  Using synchronous `connect()` (instead of
    /// fire-and-forget `connect_async`) ensures the fresh connection is
    /// available before the next retry iteration.
    pub async fn open_bi_stream(
        &self,
        peer_id: PeerId,
        addr: Option<SocketAddr>,
    ) -> Result<(quinn::SendStream, quinn::RecvStream), String> {
        let mut last_connect_attempt = Instant::now() - Duration::from_secs(1);
        for _ in 0..50 {
            let conn = self.connections.lock().unwrap().get(&peer_id).cloned();
            if let Some(c) = conn {
                match tokio::time::timeout(CONNECT_TIMEOUT, c.open_bi()).await {
                    Ok(Ok(streams)) => return Ok(streams),
                    Ok(Err(e)) => {
                        self.connections.lock().unwrap().remove(&peer_id);
                        tracing::warn!(
                            "open bi stream failed for peer {}, removing stale connection: {}",
                            peer_id,
                            e
                        );
                        // Synchronous reconnection so the retry loop can pick
                        // up the fresh connection immediately.
                        if let Err(e) = self.connect_any(peer_id, addr).await {
                            tracing::warn!("reconnect failed for peer {}: {}", peer_id, e);
                        }
                        continue;
                    }
                    Err(_) => {
                        self.connections.lock().unwrap().remove(&peer_id);
                        tracing::warn!(
                            "open bi stream timed out for peer {}, removing stale connection",
                            peer_id
                        );
                        if let Err(e) = self.connect_any(peer_id, addr).await {
                            tracing::warn!("reconnect failed for peer {}: {}", peer_id, e);
                        }
                        continue;
                    }
                }
            } else if (addr.is_some() || !self.candidate_addrs(peer_id, None).is_empty())
                && last_connect_attempt.elapsed() >= Duration::from_millis(500)
            {
                last_connect_attempt = Instant::now();
                if let Err(e) = self.connect_any(peer_id, addr).await {
                    tracing::warn!(
                        "connect before bi stream failed for peer {}: {}",
                        peer_id,
                        e
                    );
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err("not connected after timeout".into())
    }

    /// Send a service request and wait for response over a bidirectional stream.
    ///
    /// Protocol: writes topic_hash (8 bytes) + request_length (4 bytes BE) + request_data,
    /// then reads response_length (4 bytes BE) + response_data.
    /// The optional `addr` is used to trigger reconnection if the QUIC
    /// connection is stale.
    pub async fn service_call(
        &self,
        peer_id: PeerId,
        topic_hash: TopicHash,
        request_data: &[u8],
        addr: Option<SocketAddr>,
    ) -> Result<Vec<u8>, String> {
        let fresh_connection;
        let candidates = self.candidate_addrs(peer_id, addr);
        let (mut send, mut recv) = if !candidates.is_empty() {
            let mut last_error = String::from("no peer address");
            let mut opened = None;
            for sock_addr in candidates {
                let remote_daemon_id = self.peer_daemons.lock().unwrap().get(&peer_id).copied();
                let client_config = configure_client_for_daemon(remote_daemon_id)?;
                let connection = match self.endpoint.connect_with(client_config, sock_addr, "axon")
                {
                    Ok(connecting) => match tokio::time::timeout(CONNECT_TIMEOUT, connecting).await
                    {
                        Ok(Ok(connection)) => connection,
                        Ok(Err(e)) => {
                            last_error = format!("handshake failed via {}: {}", sock_addr, e);
                            continue;
                        }
                        Err(_) => {
                            last_error = format!("handshake timeout via {}", sock_addr);
                            continue;
                        }
                    },
                    Err(e) => {
                        last_error = format!("connect failed via {}: {}", sock_addr, e);
                        continue;
                    }
                };
                match tokio::time::timeout(CONNECT_TIMEOUT, connection.open_bi()).await {
                    Ok(Ok(streams)) => {
                        opened = Some((connection, streams));
                        break;
                    }
                    Ok(Err(e)) => {
                        last_error = format!("open bi failed via {}: {}", sock_addr, e);
                    }
                    Err(_) => {
                        last_error = format!("open bi timeout via {}", sock_addr);
                    }
                }
            }
            match opened {
                Some((connection, streams)) => {
                    fresh_connection = Some(connection);
                    streams
                }
                None => return Err(last_error),
            }
        } else {
            fresh_connection = None;
            self.open_bi_stream(peer_id, addr).await?
        };

        // If any I/O fails after open_bi_stream succeeds, the connection
        // may be stale (e.g. half-dead WiFi link where open_bi() returns
        // a stream but writes fail).  Remove the connection so the next
        // call triggers a fresh connect instead of hitting the same stale
        // entry.
        let cleanup = |e: String| -> String {
            self.connections.lock().unwrap().remove(&peer_id);
            if let Some(sock_addr) = self.candidate_addrs(peer_id, addr).first().copied() {
                self.connect_async(peer_id, sock_addr);
            }
            e
        };

        // Write topic_hash
        tokio::time::timeout(CONNECT_TIMEOUT, send.write_all(&topic_hash.to_be_bytes()))
            .await
            .map_err(|_| cleanup("write topic hash timeout".into()))?
            .map_err(|e| cleanup(format!("write topic hash failed: {}", e)))?;
        let remote_daemon_id = self
            .peer_daemons
            .lock()
            .unwrap()
            .get(&peer_id)
            .copied()
            .unwrap_or(0);
        crate::axon_trace!(
            "event=service_request_start peer_id={} remote_daemon={} topic_hash={} payload_bytes={} security={}",
            peer_id,
            remote_daemon_id,
            topic_hash,
            request_data.len(),
            if self.qkd_message_crypto.is_some() { "qkd" } else { "classic" }
        );
        let req_context = crate::security::WireContext::service_request(topic_hash);
        let req_wire = match self.qkd_message_crypto.clone() {
            Some(crypto) => {
                crypto
                    .seal_for_daemon(remote_daemon_id, req_context, request_data)
                    .await
            }
            None => crate::security::seal_for_daemon(remote_daemon_id, req_context, request_data),
        }
        .map_err(cleanup)?;
        let len = req_wire.len() as u32;
        tokio::time::timeout(CONNECT_TIMEOUT, send.write_all(&len.to_be_bytes()))
            .await
            .map_err(|_| cleanup("write req len timeout".into()))?
            .map_err(|e| cleanup(format!("write req len failed: {}", e)))?;
        tokio::time::timeout(CONNECT_TIMEOUT, send.write_all(&req_wire))
            .await
            .map_err(|_| cleanup("write req data timeout".into()))?
            .map_err(|e| cleanup(format!("write req data failed: {}", e)))?;
        send.finish()
            .map_err(|e| cleanup(format!("finish failed: {}", e)))?;

        // Read response with timeout to prevent indefinite blocking
        // when the server drops the connection after receiving the request.
        let mut len_buf = [0u8; 4];
        tokio::time::timeout(SERVICE_RESPONSE_TIMEOUT, recv.read_exact(&mut len_buf))
            .await
            .map_err(|_| cleanup("read resp len timeout".into()))?
            .map_err(|e| cleanup(format!("read resp len failed: {}", e)))?;
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        let mut resp_data = vec![0u8; resp_len];
        tokio::time::timeout(SERVICE_RESPONSE_TIMEOUT, recv.read_exact(&mut resp_data))
            .await
            .map_err(|_| cleanup("read resp data timeout".into()))?
            .map_err(|e| cleanup(format!("read resp data failed: {}", e)))?;
        let resp_context = crate::security::WireContext::service_response(topic_hash);
        let opened = match self.qkd_message_crypto.clone() {
            Some(crypto) => crypto.open_wire(resp_data, resp_context).await,
            None => crate::security::open_wire(resp_data, resp_context),
        }
        .map_err(cleanup)?;
        let resp_data = opened.data;
        crate::axon_trace!(
            "event=service_response_complete peer_id={} topic_hash={} payload_bytes={} security={} result=ok",
            peer_id,
            topic_hash,
            resp_data.len(),
            if self.qkd_message_crypto.is_some() { "qkd" } else { "classic" }
        );
        if let Some(connection) = fresh_connection {
            connection.close(0u32.into(), b"service complete");
        }
        Ok(resp_data)
    }

    /// Spawn an async task on the transport's runtime.
    pub fn spawn<F>(&self, f: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        self.handle.spawn(f);
    }

    /// Register a handler for incoming service requests on a given topic.
    /// Returns an mpsc receiver that the session can poll for incoming requests.
    pub fn register_service_handler(
        &self,
        topic_hash: TopicHash,
    ) -> mpsc::UnboundedReceiver<(Vec<u8>, oneshot::Sender<Vec<u8>>)> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.service_request_channels
            .lock()
            .unwrap()
            .insert(topic_hash, tx);
        rx
    }

    /// Try to complete a pending QUIC service response.
    /// Returns true if a pending request stream was found and completed.
    ///
    /// Matching order:
    /// 1. Exact (client_gid, request_sequence) match — the stream that
    ///    carried exactly this request.
    /// 2. When the response has no correlation info (all-zero GID, legacy
    ///    envelope-less path), fall back to FIFO.
    ///
    /// A response addressed to a specific client never completes another
    /// client's stream; without this, a response to a *local* (SHM-only)
    /// client would consume a remote request's stream and the remote client
    /// would never receive its response.
    pub fn try_complete_pending_response(
        &self,
        topic_hash: TopicHash,
        client_gid: [u8; 16],
        request_sequence: i64,
        data: Vec<u8>,
    ) -> bool {
        let mut map = self.pending_service_responses.lock().unwrap();
        let Some(senders) = map.get_mut(&topic_hash) else {
            return false;
        };
        // Drop entries whose bi-stream handler already timed out or vanished.
        senders.retain(|p| !p.tx.is_closed());

        let addressed = client_gid.iter().any(|b| *b != 0);
        let idx = if addressed {
            senders
                .iter()
                .position(|p| p.client_gid == client_gid && p.request_sequence == request_sequence)
        } else if senders.is_empty() {
            None
        } else {
            Some(0)
        };
        match idx {
            Some(i) => {
                let pending = senders.remove(i);
                let _ = pending.tx.send(data);
                true
            }
            None => false,
        }
    }

    /// Deliver retained TRANSIENT_LOCAL history to a newly matched peer.
    ///
    /// This uses a dedicated ordered stream instead of the normal latest-frame
    /// pipeline so a late subscriber can receive every retained sample.
    pub fn send_retained_history(
        &self,
        peer_id: PeerId,
        topic_hash: TopicHash,
        samples: Vec<(u64, Vec<u8>)>,
    ) -> oneshot::Receiver<Result<(), String>> {
        let (completion_tx, completion_rx) = oneshot::channel();
        // Startup history and subsequent live traffic must share the same
        // per-writer pipeline. Separate QUIC streams can overtake one another,
        // which violates reliable writer ordering during route establishment.
        // Enqueue synchronously so a publish that triggered route discovery
        // cannot place its live sample ahead of its own retained history.
        for (publication_id, sample) in samples {
            self.send_message_reuse(peer_id, topic_hash, sample, publication_id, usize::MAX);
        }
        let _ = completion_tx.send(Ok(()));
        completion_rx
    }

    /// Send a message asynchronously using a persistent per-(peer,topic) pipeline.
    ///
    /// One background task preserves publication order while compressing and
    /// writing to a persistent QUIC stream:
    ///
    /// ```text
    /// publisher thread ──queue──▶ [compressor + sender] ──▶ QUIC
    /// ```
    ///
    /// Reliable publishers use an ordered, lossless queue. Best-effort
    /// publishers keep only their configured history depth under backpressure.
    pub fn send_message_reuse(
        &self,
        peer_id: PeerId,
        topic_hash: TopicHash,
        data: Vec<u8>,
        publication_id: u64,
        send_depth: usize,
    ) {
        let key = (peer_id, topic_hash);
        let push = {
            let mut senders = self.stream_senders.lock().unwrap();
            if let Some(p) = senders.get(&key) {
                p.clone()
            } else {
                let raw_slot = Arc::new(RawDataSlot {
                    data: Mutex::new(std::collections::VecDeque::new()),
                    notify: tokio::sync::Notify::new(),
                });
                let push_handle = raw_slot.clone();
                senders.insert(key, push_handle);
                drop(senders);
                let connections = self.connections.clone();
                let endpoint = self.endpoint.clone();
                let peer_addrs = self.peer_addrs.clone();
                let peer_daemons = self.peer_daemons.clone();
                let qkd_message_crypto = self.qkd_message_crypto.clone();

                // A single worker is intentional: parallel compression can
                // complete out of order. Preparation is pipelined below, but
                // FuturesOrdered keeps QUIC writes in publication order.
                let queue = raw_slot.clone();
                self.handle.spawn(async move {
                    let mut stream = None;
                    let mut preparing = FuturesOrdered::<TopicPrepareFuture>::new();
                    loop {
                        while preparing.len() < TOPIC_PREPARE_DEPTH {
                            let pending = queue.data.lock().unwrap().pop_front();
                            let Some(pending) = pending else {
                                break;
                            };
                            let remote_daemon_id = peer_daemons
                                .lock()
                                .unwrap()
                                .get(&peer_id)
                                .copied()
                                .unwrap_or(0);
                            let crypto = qkd_message_crypto.clone();
                            preparing.push_back(Box::pin(Self::prepare_topic_send(
                                remote_daemon_id,
                                topic_hash,
                                pending,
                                crypto,
                            )));
                        }

                        if preparing.is_empty() {
                            queue.notify.notified().await;
                            continue;
                        }

                        let prepared = tokio::select! {
                            ready = preparing.next() => ready.expect("preparation queue is not empty"),
                            _ = queue.notify.notified(), if preparing.len() < TOPIC_PREPARE_DEPTH => {
                                continue;
                            }
                        };

                        loop {
                            if stream.is_none() {
                                let existing_connection =
                                    { connections.lock().unwrap().get(&peer_id).cloned() };
                                let connection = match existing_connection {
                                    Some(connection) => connection,
                                    None => match Self::connect_peer_from_candidates(
                                        &endpoint,
                                        &connections,
                                        &peer_addrs,
                                        &peer_daemons,
                                        peer_id,
                                        None,
                                    )
                                    .await
                                    {
                                        Ok(connection) => connection,
                                        Err(_) => {
                                            tokio::time::sleep(Duration::from_millis(100)).await;
                                            continue;
                                        }
                                    },
                                };
                                match connection.open_uni().await {
                                    Ok(new_stream) => stream = Some(new_stream),
                                    Err(_) => {
                                        connections.lock().unwrap().remove(&peer_id);
                                        tokio::time::sleep(Duration::from_millis(100)).await;
                                        continue;
                                    }
                                }
                            }
                            let send = stream.as_mut().expect("stream initialized");
                            let send_size = prepared.compressed.len();
                            let t0 = Instant::now();
                            if send.write_all(&topic_hash.to_be_bytes()).await.is_err() {
                                stream = None;
                                connections.lock().unwrap().remove(&peer_id);
                                continue;
                            }
                            if let Err(error) = Self::write_wire(send, &prepared.wire).await {
                                tracing::warn!(
                                    "QUIC send blocked for peer {peer_id}: {error}"
                                );
                                stream = None;
                                connections.lock().unwrap().remove(&peer_id);
                                continue;
                            }
                            crate::axon_trace!(
                                "event=wire_seal_written kind={:?} topic_hash={} payload_bytes={} wire_bytes={} security={} result=ok",
                                crate::security::WireKind::Topic,
                                topic_hash,
                                prepared.compressed.len(),
                                prepared.wire.len(),
                                if qkd_message_crypto.is_some() {
                                    "qkd"
                                } else {
                                    "classic"
                                }
                            );
                            let c = TRACE_SEND.fetch_add(1, Ordering::Relaxed);
                            if crate::trace::enabled() || c.is_multiple_of(30) {
                                tracing::info!(target: "axon_latency", bytes = send_size, send_us = t0.elapsed().as_micros() as u64, "quic_sent");
                            }
                            break;
                        }
                    }
                });

                raw_slot
            }
        };
        // Reliable queues are lossless. Best-effort queues retain only the
        // requested history depth and discard the oldest pending sample.
        {
            let mut queue = push.data.lock().unwrap();
            if send_depth != usize::MAX {
                let capacity = send_depth.max(1);
                while queue.len() >= capacity {
                    queue.pop_front();
                }
            }
            queue.push_back(PendingTopicSend {
                data,
                publication_id,
            });
        }
        push.notify.notify_one();
    }
    /// Spawn per-connection stream reading. Called from start() for each accepted connection.
    /// Handles both unidirectional (pub/sub) and bidirectional (service) streams.
    /// On connection close, removes the entry from the connections map.
    async fn handle_connection(
        connection: quinn::Connection,
        peer_id: PeerId,
        recv_channels: Arc<Mutex<HashMap<TopicHash, mpsc::Sender<Vec<u8>>>>>,
        service_request_channels: ServiceRequestChannels,
        connections: Arc<Mutex<HashMap<PeerId, quinn::Connection>>>,
        qkd_message_crypto: Option<Arc<QkdMessageCrypto>>,
    ) {
        loop {
            tokio::select! {
                stream = connection.accept_uni() => {
                    match stream {
                        Ok(stream) => {
                            tokio::spawn(Self::read_stream_loop(
                                stream,
                                recv_channels.clone(),
                                qkd_message_crypto.clone(),
                            ));
                        }
                        Err(quinn::ConnectionError::ApplicationClosed { .. }) |
                        Err(quinn::ConnectionError::Reset) |
                        Err(quinn::ConnectionError::ConnectionClosed { .. }) |
                        Err(quinn::ConnectionError::TransportError { .. }) |
                        Err(quinn::ConnectionError::TimedOut) => {
                            break;
                        }
                        Err(e) => {
                            tracing::warn!(?e, "accept_uni failed for peer {}, continuing", peer_id);
                            continue;
                        }
                    }
                }
                bi = connection.accept_bi() => {
                    match bi {
                        Ok((send, recv)) => {
                            tokio::spawn(Self::handle_bi_stream(
                                send,
                                recv,
                                service_request_channels.clone(),
                                qkd_message_crypto.clone(),
                            ));
                        }
                        Err(quinn::ConnectionError::ApplicationClosed { .. }) |
                        Err(quinn::ConnectionError::Reset) |
                        Err(quinn::ConnectionError::ConnectionClosed { .. }) |
                        Err(quinn::ConnectionError::TransportError { .. }) |
                        Err(quinn::ConnectionError::TimedOut) => {
                            break;
                        }
                        Err(e) => {
                            tracing::warn!(?e, "accept_bi failed for peer {}, continuing", peer_id);
                            continue;
                        }
                    }
                }
            }
        }
        // Remove the connection from the map on exit to prevent stale entries
        // from blocking reconnection attempts.
        connections.lock().unwrap().remove(&peer_id);
    }

    /// Handle an incoming bidirectional stream (service call).
    /// Reads topic_hash + request, dispatches via service_request_channels,
    /// waits for response, and writes it back.
    async fn handle_bi_stream(
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        service_request_channels: ServiceRequestChannels,
        qkd_message_crypto: Option<Arc<QkdMessageCrypto>>,
    ) {
        // Read topic_hash
        let mut hash_buf = [0u8; 8];
        if recv.read_exact(&mut hash_buf).await.is_err() {
            return;
        }
        let topic_hash = u64::from_be_bytes(hash_buf);

        // Read length-prefixed request, unsealing it when encryption is enabled
        let opened = match Self::read_sealed(
            &mut recv,
            crate::security::WireContext::service_request(topic_hash),
            qkd_message_crypto.clone(),
        )
        .await
        {
            Ok(opened) => opened,
            Err(error) => {
                tracing::warn!("service request security check failed: {error}");
                return;
            }
        };
        let req_data = opened.data;
        let qkd_reply = opened.qkd_reply;
        let qkd_enabled = qkd_reply.is_some();
        crate::axon_trace!(
            "event=service_request_received topic_hash={} payload_bytes={} security={}",
            topic_hash,
            req_data.len(),
            if qkd_enabled { "qkd" } else { "classic" }
        );

        // Create oneshot for the response
        let (resp_tx, resp_rx) = oneshot::channel();

        // Dispatch to registered handler
        {
            let channels = service_request_channels.lock().unwrap();
            if let Some(tx) = channels.get(&topic_hash) {
                if tx.send((req_data, resp_tx)).is_err() {
                    return;
                }
            } else {
                tracing::warn!("no service handler for topic_hash {}", topic_hash);
                return;
            }
        }

        // Wait for response with timeout to prevent indefinite blocking
        // when the server-side service handler never calls send_response.
        let resp_data = match tokio::time::timeout(SERVICE_RESPONSE_TIMEOUT, resp_rx).await {
            Ok(Ok(data)) => data,
            Ok(Err(_)) => {
                tracing::warn!("service response sender dropped");
                return;
            }
            Err(_) => {
                tracing::warn!("service response timeout for topic_hash {}", topic_hash);
                return;
            }
        };

        // Write response: length prefix + (optionally sealed) data, then finish
        // the stream so the client can read it without getting a RESET_STREAM.
        let response_context = crate::security::WireContext::service_response(topic_hash);
        let response_wire = match qkd_reply {
            Some(ref token) => match qkd_message_crypto {
                Some(ref crypto) => {
                    crypto
                        .seal_for_reply(token, response_context, &resp_data)
                        .await
                }
                None => crate::security::seal_for_reply(token, response_context, &resp_data),
            },
            None => crate::security::seal_for_daemon(0, response_context, &resp_data),
        };
        let response_wire = match response_wire {
            Ok(wire) => wire,
            Err(error) => {
                tracing::warn!("service response security setup failed: {error}");
                return;
            }
        };
        if Self::write_wire(&mut send, &response_wire).await.is_err() {
            return;
        }
        crate::axon_trace!(
            "event=service_response_written topic_hash={} payload_bytes={} wire_bytes={} security={} result=ok",
            topic_hash,
            resp_data.len(),
            response_wire.len(),
            if qkd_enabled { "qkd" } else { "classic" }
        );
        let _ = send.finish();
    }

    async fn read_stream_loop(
        mut recv: quinn::RecvStream,
        recv_channels: Arc<Mutex<HashMap<TopicHash, mpsc::Sender<Vec<u8>>>>>,
        qkd_message_crypto: Option<Arc<QkdMessageCrypto>>,
    ) {
        loop {
            let mut hash_buf = [0u8; 8];
            if recv.read_exact(&mut hash_buf).await.is_err() {
                return;
            }
            let topic_hash = u64::from_be_bytes(hash_buf);

            // Reads the length-prefixed payload and unseals it when encryption
            // is enabled; a wrong key fails AEAD here and drops the stream.
            let data = match Self::read_sealed(
                &mut recv,
                crate::security::WireContext::topic(topic_hash),
                qkd_message_crypto.clone(),
            )
            .await
            {
                Ok(opened) => opened.data,
                Err(error) => {
                    tracing::warn!("topic security check failed: {error}");
                    return;
                }
            };
            let len = data.len();

            let c = TRACE_RECV.fetch_add(1, Ordering::Relaxed);
            if crate::trace::enabled() || c.is_multiple_of(30) {
                tracing::info!(target: "axon_latency", topic_hash, bytes = len, "quic_recvd");
            }

            let tx = {
                let channels = recv_channels.lock().unwrap();
                channels.get(&topic_hash).cloned()
            };
            if let Some(tx) = tx {
                use mpsc::error::TrySendError;
                if let Err(TrySendError::Closed(_)) = tx.try_send(data) {
                    return;
                }
            }
        }
    }
}

impl Drop for QuicTransport {
    fn drop(&mut self) {
        self.shutdown();
        // Normal shutdown finishes in a few milliseconds. Do not let an
        // operating-system or QUIC edge case hold rmw_context_fini forever:
        // after the bounded grace period, dropping the handle detaches the
        // already-cancelled thread and lets ROS finish destroying the context.
        if let Some(handle) = self.thread_handle.lock().ok().and_then(|mut g| g.take()) {
            let deadline = Instant::now() + Duration::from_millis(500);
            while !handle.is_finished() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(5));
            }
            if handle.is_finished() {
                let _ = handle.join();
            } else {
                tracing::warn!("QUIC accept thread did not stop within 500 ms; detaching it");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert_generation() {
        let (cert, key) = generate_self_signed_certs();
        assert!(!cert.is_empty());
        assert!(!key.secret_der().is_empty());
    }

    #[test]
    fn classic_provider_requires_ml_kem_and_a_256_bit_cipher() {
        for (cipher, expected_suite) in [
            (
                QuicCipher::ChaCha20Poly1305,
                rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            ),
            (
                QuicCipher::Aes256Gcm,
                rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
            ),
        ] {
            let provider = transport_provider_with_cipher(SecurityMode::Classic, cipher);
            assert_eq!(provider.kx_groups.len(), 1);
            assert_eq!(
                provider.kx_groups[0].name(),
                rustls::NamedGroup::X25519MLKEM768
            );
            assert_eq!(provider.cipher_suites.len(), 1);
            assert_eq!(provider.cipher_suites[0].suite(), expected_suite);
        }
    }

    #[test]
    fn qkd_provider_has_no_key_exchange_group() {
        let provider = transport_provider(SecurityMode::Qkd).unwrap();
        assert!(provider.kx_groups.is_empty());
    }

    #[test]
    fn qkd_key_mode_accepts_only_the_two_supported_strategies() {
        assert_eq!(QkdKeyMode::parse("session").unwrap(), QkdKeyMode::Session);
        assert_eq!(
            QkdKeyMode::parse("messages10").unwrap(),
            QkdKeyMode::Messages10
        );
        assert!(QkdKeyMode::parse("fake").is_err());
        assert!(QkdKeyMode::parse("realtime").is_err());
    }

    #[test]
    fn shutdown_wakes_pending_accept() {
        let transport = QuicTransport::new(0).unwrap();
        transport.start();
        std::thread::sleep(Duration::from_millis(20));

        let started = std::time::Instant::now();
        drop(transport);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "QUIC transport shutdown blocked for {:?}",
            started.elapsed()
        );
    }
}
