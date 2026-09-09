//! Native ETSI GS QKD 014 key delivery support.
//!
//! The AXON daemon owns the KME client used for the QUIC bootstrap and stores
//! one 256-bit session key per remote daemon in a user-only POSIX shared-memory
//! segment. ROS processes map that store for TLS and use their own QKD client
//! for the application-message key rotation used by remote traffic.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use nix::fcntl::OFlag;
use nix::sys::mman::{mmap, munmap, shm_open, shm_unlink, MapFlags, ProtFlags};
use nix::unistd::{close, ftruncate};
use reqwest::{Certificate, Client, Identity, Url};
use serde::Deserialize;
use std::ffi::CString;
use std::mem::ManuallyDrop;
use std::num::NonZeroUsize;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

pub const QKD_SHM_NAME: &str = "/axon_qkd_keys";
// Bump the magic whenever the shared-memory layout changes. This prevents an
// older process from interpreting a newer mapping (and vice versa).
const QKD_SHM_MAGIC: u32 = 0x4158_514c;
const QKD_KEY_BYTES: usize = 32;
const MAX_QKD_SESSIONS: usize = 32;
const MAX_QKD_MESSAGE_KEYS: usize = 4096;
const MAX_SAE_ID_LEN: usize = 128;
const MAX_KEY_ID_LEN: usize = 192;
const EXPLICIT_QKD_ENV: [&str; 5] = [
    "AXON_QKD_KME_BASE_URL",
    "AXON_QKD_LOCAL_SAE_ID",
    "AXON_QKD_CA_CERT",
    "AXON_QKD_CLIENT_CERT",
    "AXON_QKD_CLIENT_KEY",
];

const ENTRY_EMPTY: u8 = 0;
const ENTRY_PENDING: u8 = 1;
const ENTRY_ACTIVE: u8 = 2;

const MESSAGE_ENTRY_EMPTY: u8 = 0;
const MESSAGE_ENTRY_WRITING: u8 = 1;
const MESSAGE_ENTRY_PENDING: u8 = 2;
const MESSAGE_ENTRY_READY: u8 = 3;

pub const MSG_QKD_KEY_ANNOUNCE: u8 = 0x51;
pub const MSG_QKD_KEY_ACK: u8 = 0x52;
pub const MSG_QKD_KEY_ERROR: u8 = 0x53;

#[derive(Debug, Clone)]
pub struct QkdConfig {
    pub kme_base_url: Url,
    pub local_sae_id: String,
    pub ca_certificate: Option<PathBuf>,
    pub client_certificate: Option<PathBuf>,
    pub client_private_key: Option<PathBuf>,
    pub request_timeout: Duration,
    pub allow_insecure_http: bool,
}

impl QkdConfig {
    pub fn from_env() -> Result<Self, String> {
        if EXPLICIT_QKD_ENV
            .iter()
            .any(|name| std::env::var_os(name).is_some())
        {
            Self::from_explicit_env()
        } else {
            Self::from_beta_profile()
        }
    }

    fn from_explicit_env() -> Result<Self, String> {
        let base = required_env("AXON_QKD_KME_BASE_URL")?;
        let kme_base_url =
            Url::parse(&base).map_err(|e| format!("invalid AXON_QKD_KME_BASE_URL: {e}"))?;
        let local_sae_id = required_env("AXON_QKD_LOCAL_SAE_ID")?;
        validate_identifier("AXON_QKD_LOCAL_SAE_ID", &local_sae_id, MAX_SAE_ID_LEN)?;

        let allow_insecure_http = env_bool("AXON_QKD_ALLOW_INSECURE_HTTP", false);
        if kme_base_url.scheme() != "https" && !allow_insecure_http {
            return Err(
                "AXON_QKD_KME_BASE_URL must use https (set AXON_QKD_ALLOW_INSECURE_HTTP=1 only for local tests)"
                    .into(),
            );
        }

        let ca_certificate = optional_path("AXON_QKD_CA_CERT");
        let client_certificate = optional_path("AXON_QKD_CLIENT_CERT");
        let client_private_key = optional_path("AXON_QKD_CLIENT_KEY");

        if kme_base_url.scheme() == "https"
            && (ca_certificate.is_none()
                || client_certificate.is_none()
                || client_private_key.is_none())
        {
            return Err(
                "QKD HTTPS requires AXON_QKD_CA_CERT, AXON_QKD_CLIENT_CERT, and AXON_QKD_CLIENT_KEY"
                    .into(),
            );
        }

        Ok(Self {
            kme_base_url,
            local_sae_id,
            ca_certificate,
            client_certificate,
            client_private_key,
            request_timeout: qkd_request_timeout(),
            allow_insecure_http,
        })
    }

    fn from_beta_profile() -> Result<Self, String> {
        let profile_dirs = beta_profile_dirs();
        for profile_dir in &profile_dirs {
            if profile_dir.join("profile").is_file() {
                return Self::from_beta_profile_dir(profile_dir);
            }
        }
        let searched = profile_dirs
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        Err(format!(
            "QKD configuration is missing: set the AXON_QKD_* variables or install a beta profile (searched: {searched})"
        ))
    }

    fn from_beta_profile_dir(profile_dir: &Path) -> Result<Self, String> {
        let profile_path = profile_dir.join("profile");
        let profile_text = std::fs::read_to_string(&profile_path).map_err(|error| {
            format!(
                "QKD configuration is missing: set the AXON_QKD_* variables or install {} ({error})",
                profile_path.display()
            )
        })?;
        let profile = BetaProfile::parse(&profile_text)?;
        let sae_id = format!("sae-{}", profile.role);
        let kme_base_url = Url::parse(&format!(
            "https://kme-{}.acct-{}.etsi-qkd-api.qukaydee.com/api/v1/keys",
            profile.role, profile.account_id
        ))
        .map_err(|error| format!("invalid beta QKD profile URL: {error}"))?;
        let ca_certificate = profile_dir.join(format!(
            "account-{}-server-ca-qukaydee-com.crt",
            profile.account_id
        ));
        let client_certificate = profile_dir.join(format!("{sae_id}.crt"));
        let client_private_key = profile_dir.join(format!("{sae_id}.key"));
        for (label, path) in [
            ("server CA certificate", &ca_certificate),
            ("SAE certificate", &client_certificate),
            ("SAE private key", &client_private_key),
        ] {
            if !path.is_file() {
                return Err(format!(
                    "beta QKD profile {label} is missing: {}",
                    path.display()
                ));
            }
        }

        Ok(Self {
            kme_base_url,
            local_sae_id: sae_id,
            ca_certificate: Some(ca_certificate),
            client_certificate: Some(client_certificate),
            client_private_key: Some(client_private_key),
            request_timeout: qkd_request_timeout(),
            allow_insecure_http: false,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
struct BetaProfile {
    account_id: String,
    role: u8,
}

impl BetaProfile {
    fn parse(contents: &str) -> Result<Self, String> {
        let mut account_id = None;
        let mut role = None;
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (name, value) = line
                .split_once('=')
                .ok_or_else(|| format!("invalid beta QKD profile line: {line}"))?;
            match name.trim() {
                "account_id" => account_id = Some(value.trim().to_string()),
                "role" => {
                    role = Some(
                        value
                            .trim()
                            .parse::<u8>()
                            .map_err(|_| "beta QKD profile role must be 1 or 2".to_string())?,
                    )
                }
                other => return Err(format!("unknown beta QKD profile field: {other}")),
            }
        }
        let account_id =
            account_id.ok_or_else(|| "beta QKD profile requires account_id".to_string())?;
        if account_id.is_empty() || !account_id.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("beta QKD profile account_id must contain only digits".into());
        }
        let role = role.ok_or_else(|| "beta QKD profile requires role".to_string())?;
        if !matches!(role, 1 | 2) {
            return Err("beta QKD profile role must be 1 or 2".into());
        }
        Ok(Self { account_id, role })
    }
}

fn required_env(name: &str) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} is required in QKD mode"))
}

fn optional_path(name: &str) -> Option<PathBuf> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn beta_profile_dirs() -> Vec<PathBuf> {
    if let Some(profile_dir) = optional_path("AXON_QKD_PROFILE_DIR") {
        return vec![profile_dir];
    }

    let mut profile_dirs = Vec::with_capacity(8);
    if let Some(home_dir) = std::env::var_os("HOME").map(PathBuf::from) {
        push_unique_profile_dir(&mut profile_dirs, home_dir.join(".config/axon/qkd"));
    }
    if let Some(daemon_path) = optional_path("AXON_DAEMON_PATH") {
        if let Some(profile_dir) = installed_profile_dir(&daemon_path) {
            push_unique_profile_dir(&mut profile_dirs, profile_dir);
        }
    }
    for prefix_var in ["AMENT_PREFIX_PATH", "COLCON_PREFIX_PATH"] {
        if let Some(prefixes) = std::env::var_os(prefix_var) {
            for prefix in std::env::split_paths(&prefixes) {
                push_unique_profile_dir(&mut profile_dirs, prefix.join("share/rmw_axon/qkd"));
            }
        }
    }
    if let Ok(executable) = std::env::current_exe() {
        if let Some(profile_dir) = installed_profile_dir(&executable) {
            push_unique_profile_dir(&mut profile_dirs, profile_dir);
        }
    }
    profile_dirs
}

fn installed_profile_dir(executable: &Path) -> Option<PathBuf> {
    executable
        .parent()
        .and_then(Path::parent)
        .map(|prefix| prefix.join("share/rmw_axon/qkd"))
}

fn push_unique_profile_dir(profile_dirs: &mut Vec<PathBuf>, profile_dir: PathBuf) {
    if !profile_dirs.contains(&profile_dir) {
        profile_dirs.push(profile_dir);
    }
}

fn env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(default)
}

fn qkd_request_timeout() -> Duration {
    let timeout_ms = std::env::var("AXON_QKD_REQUEST_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(3000)
        .clamp(100, 60_000);
    Duration::from_millis(timeout_ms)
}

fn qkd_max_in_flight() -> usize {
    std::env::var("AXON_QKD_MAX_IN_FLIGHT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(4)
        .clamp(1, 32)
}

fn validate_identifier(name: &str, value: &str, max_len: usize) -> Result<(), String> {
    if value.is_empty() || value.len() >= max_len {
        return Err(format!("{name} must contain 1..{} bytes", max_len - 1));
    }
    if value
        .bytes()
        .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(format!("{name} contains an invalid character"));
    }
    Ok(())
}

#[derive(Debug)]
pub struct QkdKeyMaterial {
    pub key_id: String,
    pub key: [u8; QKD_KEY_BYTES],
}

impl Clone for QkdKeyMaterial {
    fn clone(&self) -> Self {
        Self {
            key_id: self.key_id.clone(),
            key: self.key,
        }
    }
}

impl Drop for QkdKeyMaterial {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Debug, Deserialize)]
struct KeyResponse {
    keys: Vec<KeyRecord>,
}

#[derive(Debug, Deserialize)]
struct KeyRecord {
    #[serde(rename = "key_ID")]
    key_id: String,
    key: String,
}

#[derive(Clone)]
pub struct EtsiQkdClient {
    client: Client,
    base_url: Url,
    request_gate: Arc<tokio::sync::Semaphore>,
}

impl EtsiQkdClient {
    pub fn new(config: &QkdConfig) -> Result<Self, String> {
        match config.kme_base_url.scheme() {
            "https" => {
                if config.ca_certificate.is_none()
                    || config.client_certificate.is_none()
                    || config.client_private_key.is_none()
                {
                    return Err(
                        "QKD HTTPS requires a CA certificate and a client certificate/private key"
                            .into(),
                    );
                }
            }
            "http" if config.allow_insecure_http => {}
            "http" => {
                return Err(
                    "unencrypted QKD KME access is disabled; HTTP is only allowed for local tests"
                        .into(),
                )
            }
            scheme => return Err(format!("unsupported QKD KME URL scheme: {scheme}")),
        }
        let mut builder = Client::builder().timeout(config.request_timeout);

        if let Some(path) = &config.ca_certificate {
            let pem = read_secret_file(path, "QKD CA certificate")?;
            let certificate = Certificate::from_pem(&pem)
                .map_err(|e| format!("invalid QKD CA certificate: {e}"))?;
            builder = builder.add_root_certificate(certificate);
        }

        match (&config.client_certificate, &config.client_private_key) {
            (Some(cert_path), Some(key_path)) => {
                let mut identity_pem = read_secret_file(cert_path, "QKD client certificate")?;
                if !identity_pem.ends_with(b"\n") {
                    identity_pem.push(b'\n');
                }
                let mut private_key = read_secret_file(key_path, "QKD client private key")?;
                identity_pem.extend_from_slice(&private_key);
                private_key.zeroize();
                let identity = Identity::from_pem(&identity_pem)
                    .map_err(|e| format!("invalid QKD client identity: {e}"));
                identity_pem.zeroize();
                let identity = identity?;
                builder = builder.identity(identity);
            }
            (None, None) => {}
            _ => return Err("both QKD client certificate and private key are required".into()),
        }

        let client = builder
            .build()
            .map_err(|e| format!("create QKD HTTPS client: {e}"))?;
        Ok(Self {
            client,
            base_url: config.kme_base_url.clone(),
            request_gate: Arc::new(tokio::sync::Semaphore::new(qkd_max_in_flight())),
        })
    }

    pub async fn get_encryption_key(&self, peer_sae_id: &str) -> Result<QkdKeyMaterial, String> {
        let _request_permit = self
            .request_gate
            .acquire()
            .await
            .map_err(|_| "QKD request limiter closed".to_string())?;
        let mut url = self.operation_url(peer_sae_id, "enc_keys")?;
        url.query_pairs_mut()
            .append_pair("number", "1")
            .append_pair("size", "256");
        let response = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|error| {
                crate::axon_trace!(
                    "event=qkd_kme_request_failed operation=enc_keys peer_sae={} error={}",
                    peer_sae_id,
                    error
                );
                format!("QKD enc_keys request failed: {error}")
            })?
            .error_for_status()
            .map_err(|error| {
                crate::axon_trace!(
                    "event=qkd_kme_request_failed operation=enc_keys peer_sae={} error={}",
                    peer_sae_id,
                    error
                );
                format!("QKD enc_keys rejected: {error}")
            })?;
        decode_single_key(
            response
                .json::<KeyResponse>()
                .await
                .map_err(|e| format!("invalid QKD enc_keys JSON: {e}"))?,
            None,
        )
    }

    pub async fn get_decryption_key(
        &self,
        peer_sae_id: &str,
        key_id: &str,
    ) -> Result<QkdKeyMaterial, String> {
        let _request_permit = self
            .request_gate
            .acquire()
            .await
            .map_err(|_| "QKD request limiter closed".to_string())?;
        validate_identifier("QKD key_ID", key_id, MAX_KEY_ID_LEN)?;
        let mut url = self.operation_url(peer_sae_id, "dec_keys")?;
        url.query_pairs_mut().append_pair("key_ID", key_id);
        let response = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|error| {
                crate::axon_trace!(
                    "event=qkd_kme_request_failed operation=dec_keys peer_sae={} key_id={} error={}",
                    peer_sae_id,
                    key_id,
                    error
                );
                format!("QKD dec_keys request failed: {error}")
            })?
            .error_for_status()
            .map_err(|error| {
                crate::axon_trace!(
                    "event=qkd_kme_request_failed operation=dec_keys peer_sae={} key_id={} error={}",
                    peer_sae_id,
                    key_id,
                    error
                );
                format!("QKD dec_keys rejected: {error}")
            })?;
        decode_single_key(
            response
                .json::<KeyResponse>()
                .await
                .map_err(|e| format!("invalid QKD dec_keys JSON: {e}"))?,
            Some(key_id),
        )
    }

    fn operation_url(&self, peer_sae_id: &str, operation: &str) -> Result<Url, String> {
        validate_identifier("peer SAE ID", peer_sae_id, MAX_SAE_ID_LEN)?;
        let mut url = self.base_url.clone();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| "AXON_QKD_KME_BASE_URL cannot be used as a path base".to_string())?;
            segments.pop_if_empty();
            segments.push(peer_sae_id);
            segments.push(operation);
        }
        Ok(url)
    }
}

fn read_secret_file(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("read {label} {}: {e}", path.display()))
}

fn decode_single_key(
    response: KeyResponse,
    expected_key_id: Option<&str>,
) -> Result<QkdKeyMaterial, String> {
    let record = response
        .keys
        .into_iter()
        .next()
        .ok_or_else(|| "QKD response contained no keys".to_string())?;
    validate_identifier("QKD key_ID", &record.key_id, MAX_KEY_ID_LEN)?;
    if expected_key_id.is_some_and(|expected| expected != record.key_id) {
        return Err("QKD response key_ID does not match the requested key".into());
    }
    let mut decoded = BASE64
        .decode(record.key)
        .map_err(|e| format!("invalid base64 QKD key: {e}"))?;
    if decoded.len() != QKD_KEY_BYTES {
        decoded.zeroize();
        return Err(format!(
            "QKD key must be 256 bits, received {} bits",
            decoded.len() * 8
        ));
    }
    let mut key = [0u8; QKD_KEY_BYTES];
    key.copy_from_slice(&decoded);
    decoded.zeroize();
    Ok(QkdKeyMaterial {
        key_id: record.key_id,
        key,
    })
}

#[repr(C)]
struct QkdShmHeader {
    magic: AtomicU32,
    daemon_pid: AtomicU32,
    generation: AtomicU64,
    local_sae_len: AtomicU16,
    local_sae_id: [AtomicU8; MAX_SAE_ID_LEN],
}

#[repr(C)]
struct QkdShmEntry {
    state: AtomicU8,
    remote_daemon_id: AtomicU64,
    key_id_len: AtomicU16,
    remote_sae_len: AtomicU16,
    key: [AtomicU8; QKD_KEY_BYTES],
    key_id: [AtomicU8; MAX_KEY_ID_LEN],
    remote_sae_id: [AtomicU8; MAX_SAE_ID_LEN],
}

#[repr(C)]
struct QkdMessageShmEntry {
    state: AtomicU8,
    writer_pid: AtomicU32,
    generation: AtomicU64,
    key_id_len: AtomicU16,
    sender_sae_len: AtomicU16,
    key: [AtomicU8; QKD_KEY_BYTES],
    key_id: [AtomicU8; MAX_KEY_ID_LEN],
    sender_sae_id: [AtomicU8; MAX_SAE_ID_LEN],
}

pub(crate) enum QkdMessageKeyLookup {
    Ready(QkdKeyMaterial),
    Claimed,
    Pending,
}

pub struct QkdSessionKey {
    pub remote_daemon_id: u64,
    pub local_sae_id: String,
    pub remote_sae_id: String,
    pub key_id: String,
    pub key: [u8; QKD_KEY_BYTES],
    pub active: bool,
}

impl Clone for QkdSessionKey {
    fn clone(&self) -> Self {
        Self {
            remote_daemon_id: self.remote_daemon_id,
            local_sae_id: self.local_sae_id.clone(),
            remote_sae_id: self.remote_sae_id.clone(),
            key_id: self.key_id.clone(),
            key: self.key,
            active: self.active,
        }
    }
}

impl Drop for QkdSessionKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

pub struct QkdKeyStore {
    fd: ManuallyDrop<OwnedFd>,
    header: NonNull<QkdShmHeader>,
    entries: NonNull<QkdShmEntry>,
    message_entries: NonNull<QkdMessageShmEntry>,
    size: usize,
}

fn qkd_shm_size() -> usize {
    let raw = std::mem::size_of::<QkdShmHeader>()
        + std::mem::size_of::<QkdShmEntry>() * MAX_QKD_SESSIONS
        + std::mem::size_of::<QkdMessageShmEntry>() * MAX_QKD_MESSAGE_KEYS;
    (raw + 4095) & !4095
}

fn nix_to_io(error: nix::Error) -> std::io::Error {
    let kind = match error {
        nix::Error::ENOENT => std::io::ErrorKind::NotFound,
        nix::Error::EEXIST => std::io::ErrorKind::AlreadyExists,
        nix::Error::EACCES | nix::Error::EPERM => std::io::ErrorKind::PermissionDenied,
        _ => std::io::ErrorKind::Other,
    };
    std::io::Error::new(kind, error.to_string())
}

impl QkdKeyStore {
    pub fn create(local_sae_id: &str) -> std::io::Result<Self> {
        Self::create_named(QKD_SHM_NAME, local_sae_id)
    }

    pub(crate) fn create_named(name: &str, local_sae_id: &str) -> std::io::Result<Self> {
        validate_identifier("local SAE ID", local_sae_id, MAX_SAE_ID_LEN)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let name = CString::new(name).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "QKD SHM name contains a null byte",
            )
        })?;
        let fd = shm_open(
            name.as_c_str(),
            OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_RDWR,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .map_err(nix_to_io)?;
        let size = qkd_shm_size();
        ftruncate(&fd, size as i64).map_err(nix_to_io)?;
        let ptr = unsafe {
            mmap(
                None,
                NonZeroUsize::new(size).unwrap(),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED,
                &fd,
                0,
            )
        }
        .map_err(nix_to_io)?;
        unsafe {
            std::ptr::write_bytes(ptr.as_ptr() as *mut u8, 0, size);
        }
        let header = NonNull::new(ptr.as_ptr() as *mut QkdShmHeader).unwrap();
        let entries = NonNull::new(unsafe { header.as_ptr().add(1) as *mut QkdShmEntry }).unwrap();
        let message_entries = NonNull::new(unsafe {
            entries.as_ptr().add(MAX_QKD_SESSIONS) as *mut QkdMessageShmEntry
        })
        .unwrap();
        unsafe {
            (*header.as_ptr())
                .daemon_pid
                .store(std::process::id(), Ordering::Relaxed);
            (*header.as_ptr()).generation.store(0, Ordering::Relaxed);
            store_atomic_bytes(&(*header.as_ptr()).local_sae_id, local_sae_id.as_bytes());
            (*header.as_ptr())
                .local_sae_len
                .store(local_sae_id.len() as u16, Ordering::Relaxed);
            std::sync::atomic::fence(Ordering::Release);
            (*header.as_ptr())
                .magic
                .store(QKD_SHM_MAGIC, Ordering::Release);
        }
        Ok(Self {
            fd: ManuallyDrop::new(fd),
            header,
            entries,
            message_entries,
            size,
        })
    }

    pub fn open() -> std::io::Result<Self> {
        Self::open_named(QKD_SHM_NAME)
    }

    fn open_named(name: &str) -> std::io::Result<Self> {
        let name = CString::new(name).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "QKD SHM name contains a null byte",
            )
        })?;
        let fd = shm_open(
            name.as_c_str(),
            OFlag::O_RDWR,
            nix::sys::stat::Mode::empty(),
        )
        .map_err(nix_to_io)?;
        let size = qkd_shm_size();
        let stat = nix::sys::stat::fstat(fd.as_raw_fd()).map_err(nix_to_io)?;
        let current_uid = unsafe { libc::geteuid() };
        if stat.st_uid != current_uid || stat.st_mode & 0o077 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "QKD SHM must be owned by the current user and inaccessible to group/other",
            ));
        }
        if stat.st_size < size as i64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "QKD SHM is smaller than expected",
            ));
        }
        let ptr = unsafe {
            mmap(
                None,
                NonZeroUsize::new(size).unwrap(),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED,
                &fd,
                0,
            )
        }
        .map_err(nix_to_io)?;
        let header = NonNull::new(ptr.as_ptr() as *mut QkdShmHeader).unwrap();
        if unsafe { header.as_ref() }.magic.load(Ordering::Acquire) != QKD_SHM_MAGIC {
            unsafe {
                let _ = munmap(ptr, size);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid QKD SHM magic",
            ));
        }
        let entries = NonNull::new(unsafe { header.as_ptr().add(1) as *mut QkdShmEntry }).unwrap();
        let message_entries = NonNull::new(unsafe {
            entries.as_ptr().add(MAX_QKD_SESSIONS) as *mut QkdMessageShmEntry
        })
        .unwrap();
        Ok(Self {
            fd: ManuallyDrop::new(fd),
            header,
            entries,
            message_entries,
            size,
        })
    }

    pub fn destroy() -> std::io::Result<()> {
        Self::destroy_named(QKD_SHM_NAME)
    }

    pub fn purge() -> std::io::Result<()> {
        if let Ok(store) = Self::open() {
            store.clear();
        }
        Self::destroy()
    }

    pub(crate) fn destroy_named(name: &str) -> std::io::Result<()> {
        let name = CString::new(name).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "QKD SHM name contains a null byte",
            )
        })?;
        shm_unlink(name.as_c_str()).map_err(nix_to_io)
    }

    pub fn reset(&self, local_sae_id: &str) -> Result<(), String> {
        validate_identifier("local SAE ID", local_sae_id, MAX_SAE_ID_LEN)?;
        self.clear_entries();
        self.clear_message_entries();
        let header = unsafe { &mut *self.header.as_ptr() };
        header.magic.store(0, Ordering::Release);
        header
            .daemon_pid
            .store(std::process::id(), Ordering::Relaxed);
        store_atomic_bytes(&header.local_sae_id, local_sae_id.as_bytes());
        header
            .local_sae_len
            .store(local_sae_id.len() as u16, Ordering::Release);
        header.generation.fetch_add(1, Ordering::Release);
        header.magic.store(QKD_SHM_MAGIC, Ordering::Release);
        Ok(())
    }

    pub fn clear(&self) {
        self.clear_entries();
        self.clear_message_entries();
        let header = unsafe { &mut *self.header.as_ptr() };
        header.daemon_pid.store(0, Ordering::Release);
        header.generation.fetch_add(1, Ordering::Release);
    }

    pub fn local_sae_id(&self) -> Result<String, String> {
        let header = unsafe { self.header.as_ref() };
        let len = header.local_sae_len.load(Ordering::Acquire) as usize;
        if len == 0 || len >= MAX_SAE_ID_LEN {
            return Err("invalid local SAE ID in QKD SHM".into());
        }
        atomic_string(&header.local_sae_id, len)
            .ok_or_else(|| "QKD SHM local SAE ID is not UTF-8".into())
    }

    pub fn put(
        &self,
        remote_daemon_id: u64,
        remote_sae_id: &str,
        material: &QkdKeyMaterial,
        active: bool,
    ) -> Result<(), String> {
        validate_identifier("remote SAE ID", remote_sae_id, MAX_SAE_ID_LEN)?;
        validate_identifier("QKD key_ID", &material.key_id, MAX_KEY_ID_LEN)?;
        let entries = self.entries_mut();
        let index = entries
            .iter()
            .position(|entry| {
                entry.state.load(Ordering::Acquire) != ENTRY_EMPTY
                    && entry.remote_daemon_id.load(Ordering::Relaxed) == remote_daemon_id
            })
            .or_else(|| {
                entries
                    .iter()
                    .position(|entry| entry.state.load(Ordering::Acquire) == ENTRY_EMPTY)
            })
            .unwrap_or(0);
        let entry = &mut entries[index];
        entry.state.store(ENTRY_EMPTY, Ordering::Release);
        clear_atomic_bytes(&entry.key);
        clear_atomic_bytes(&entry.key_id);
        clear_atomic_bytes(&entry.remote_sae_id);
        entry
            .remote_daemon_id
            .store(remote_daemon_id, Ordering::Relaxed);
        store_atomic_bytes(&entry.key, &material.key);
        store_atomic_bytes(&entry.key_id, material.key_id.as_bytes());
        store_atomic_bytes(&entry.remote_sae_id, remote_sae_id.as_bytes());
        entry
            .key_id_len
            .store(material.key_id.len() as u16, Ordering::Relaxed);
        entry
            .remote_sae_len
            .store(remote_sae_id.len() as u16, Ordering::Relaxed);
        entry.state.store(
            if active { ENTRY_ACTIVE } else { ENTRY_PENDING },
            Ordering::Release,
        );
        unsafe {
            self.header
                .as_ref()
                .generation
                .fetch_add(1, Ordering::Release);
        }
        Ok(())
    }

    pub fn activate(&self, remote_daemon_id: u64, key_id: &str) -> bool {
        for entry in self.entries_mut() {
            let state = entry.state.load(Ordering::Acquire);
            if (state == ENTRY_PENDING || state == ENTRY_ACTIVE)
                && entry.remote_daemon_id.load(Ordering::Relaxed) == remote_daemon_id
                && atomic_string(
                    &entry.key_id,
                    entry.key_id_len.load(Ordering::Relaxed) as usize,
                )
                .as_deref()
                    == Some(key_id)
            {
                if state == ENTRY_ACTIVE {
                    return true;
                }
                entry.state.store(ENTRY_ACTIVE, Ordering::Release);
                unsafe {
                    self.header
                        .as_ref()
                        .generation
                        .fetch_add(1, Ordering::Release);
                }
                return true;
            }
        }
        false
    }

    pub fn remove(&self, remote_daemon_id: u64) {
        for entry in self.entries_mut() {
            if entry.state.load(Ordering::Acquire) != ENTRY_EMPTY
                && entry.remote_daemon_id.load(Ordering::Relaxed) == remote_daemon_id
            {
                entry.state.store(ENTRY_EMPTY, Ordering::Release);
                clear_atomic_bytes(&entry.key);
                clear_atomic_bytes(&entry.key_id);
                clear_atomic_bytes(&entry.remote_sae_id);
                entry.remote_daemon_id.store(0, Ordering::Relaxed);
                entry.key_id_len.store(0, Ordering::Relaxed);
                entry.remote_sae_len.store(0, Ordering::Relaxed);
                unsafe {
                    self.header
                        .as_ref()
                        .generation
                        .fetch_add(1, Ordering::Release);
                }
            }
        }
    }

    fn clear_entries(&self) {
        for entry in self.entries_mut() {
            entry.state.store(ENTRY_EMPTY, Ordering::Release);
            clear_atomic_bytes(&entry.key);
            clear_atomic_bytes(&entry.key_id);
            clear_atomic_bytes(&entry.remote_sae_id);
            entry.remote_daemon_id.store(0, Ordering::Relaxed);
            entry.key_id_len.store(0, Ordering::Relaxed);
            entry.remote_sae_len.store(0, Ordering::Relaxed);
        }
    }

    /// Return a cached application-message key or atomically claim the KME
    /// retrieval for this process. Other local ROS processes wait for the
    /// claimant and then reuse the key only for their copy of the same logical
    /// message; different messages still have different QKD key IDs.
    pub(crate) fn claim_message_key(
        &self,
        sender_sae_id: &str,
        key_id: &str,
    ) -> Result<QkdMessageKeyLookup, String> {
        validate_identifier("QKD sender SAE ID", sender_sae_id, MAX_SAE_ID_LEN)?;
        validate_identifier("QKD message key_ID", key_id, MAX_KEY_ID_LEN)?;

        let entries = self.message_entries();
        let start = message_key_hash(sender_sae_id, key_id) as usize % entries.len();
        'scan: loop {
            let mut oldest_ready: Option<(usize, u64)> = None;

            for offset in 0..entries.len() {
                let index = (start + offset) % entries.len();
                let entry = &entries[index];
                let mut state = entry.state.load(Ordering::Acquire);
                if state == MESSAGE_ENTRY_WRITING {
                    let writing_since = Instant::now();
                    while state == MESSAGE_ENTRY_WRITING
                        && writing_since.elapsed() < Duration::from_millis(10)
                    {
                        std::thread::yield_now();
                        state = entry.state.load(Ordering::Acquire);
                    }
                    if state == MESSAGE_ENTRY_WRITING {
                        let writer_pid = entry.writer_pid.load(Ordering::Acquire);
                        if writer_pid == 0 || !process_is_alive(writer_pid) {
                            // Recover the tiny claim/write window if its owner
                            // exited before publishing the metadata.
                            let _ = entry.state.compare_exchange(
                                MESSAGE_ENTRY_WRITING,
                                MESSAGE_ENTRY_EMPTY,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            );
                        }
                    }
                    continue 'scan;
                }

                if state == MESSAGE_ENTRY_EMPTY {
                    if entry
                        .state
                        .compare_exchange(
                            MESSAGE_ENTRY_EMPTY,
                            MESSAGE_ENTRY_WRITING,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        self.initialize_message_entry(entry, sender_sae_id, key_id);
                        return Ok(QkdMessageKeyLookup::Claimed);
                    }
                    continue 'scan;
                }

                if state == MESSAGE_ENTRY_PENDING || state == MESSAGE_ENTRY_READY {
                    if message_entry_matches(entry, sender_sae_id, key_id) {
                        if state == MESSAGE_ENTRY_PENDING {
                            let writer_pid = entry.writer_pid.load(Ordering::Acquire);
                            if (writer_pid == 0 || !process_is_alive(writer_pid))
                                && entry
                                    .state
                                    .compare_exchange(
                                        MESSAGE_ENTRY_PENDING,
                                        MESSAGE_ENTRY_WRITING,
                                        Ordering::AcqRel,
                                        Ordering::Acquire,
                                    )
                                    .is_ok()
                            {
                                clear_message_entry(entry);
                                continue 'scan;
                            }
                        }
                        return if state == MESSAGE_ENTRY_READY {
                            self.copy_message_key(entry)
                                .map(QkdMessageKeyLookup::Ready)
                                .ok_or_else(|| "QKD message key cache changed while reading".into())
                        } else {
                            Ok(QkdMessageKeyLookup::Pending)
                        };
                    }
                    if state == MESSAGE_ENTRY_READY {
                        let generation = entry.generation.load(Ordering::Relaxed);
                        if match oldest_ready {
                            Some((_, oldest)) => generation < oldest,
                            None => true,
                        } {
                            oldest_ready = Some((index, generation));
                        }
                    }
                }
            }

            if let Some((index, _)) = oldest_ready {
                let entry = &entries[index];
                if entry
                    .state
                    .compare_exchange(
                        MESSAGE_ENTRY_READY,
                        MESSAGE_ENTRY_WRITING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    self.initialize_message_entry(entry, sender_sae_id, key_id);
                    return Ok(QkdMessageKeyLookup::Claimed);
                }
                continue 'scan;
            }

            return Err("QKD message key cache has no available entries".into());
        }
    }

    pub(crate) fn publish_message_key(
        &self,
        sender_sae_id: &str,
        material: &QkdKeyMaterial,
    ) -> Result<(), String> {
        let entry = self
            .find_message_entry(sender_sae_id, &material.key_id, MESSAGE_ENTRY_PENDING)
            .ok_or_else(|| "QKD message key cache claim was lost".to_string())?;
        store_atomic_bytes(&entry.key, &material.key);
        entry.state.store(MESSAGE_ENTRY_READY, Ordering::Release);
        Ok(())
    }

    pub(crate) fn abandon_message_key(&self, sender_sae_id: &str, key_id: &str) {
        if let Some(entry) = self.find_message_entry(sender_sae_id, key_id, MESSAGE_ENTRY_PENDING) {
            if entry
                .state
                .compare_exchange(
                    MESSAGE_ENTRY_PENDING,
                    MESSAGE_ENTRY_WRITING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                clear_message_entry(entry);
            }
        }
    }

    fn initialize_message_entry(
        &self,
        entry: &QkdMessageShmEntry,
        sender_sae_id: &str,
        key_id: &str,
    ) {
        entry
            .writer_pid
            .store(std::process::id(), Ordering::Release);
        clear_atomic_bytes(&entry.key);
        clear_atomic_bytes(&entry.key_id);
        clear_atomic_bytes(&entry.sender_sae_id);
        store_atomic_bytes(&entry.key_id, key_id.as_bytes());
        store_atomic_bytes(&entry.sender_sae_id, sender_sae_id.as_bytes());
        entry
            .key_id_len
            .store(key_id.len() as u16, Ordering::Relaxed);
        entry
            .sender_sae_len
            .store(sender_sae_id.len() as u16, Ordering::Relaxed);
        let generation = unsafe {
            self.header
                .as_ref()
                .generation
                .fetch_add(1, Ordering::Relaxed)
                + 1
        };
        entry.generation.store(generation, Ordering::Relaxed);
        entry.state.store(MESSAGE_ENTRY_PENDING, Ordering::Release);
    }

    fn find_message_entry(
        &self,
        sender_sae_id: &str,
        key_id: &str,
        expected_state: u8,
    ) -> Option<&QkdMessageShmEntry> {
        self.message_entries().iter().find(|entry| {
            entry.state.load(Ordering::Acquire) == expected_state
                && message_entry_matches(entry, sender_sae_id, key_id)
        })
    }

    fn copy_message_key(&self, entry: &QkdMessageShmEntry) -> Option<QkdKeyMaterial> {
        if entry.state.load(Ordering::Acquire) != MESSAGE_ENTRY_READY {
            return None;
        }
        let key_id = atomic_string(
            &entry.key_id,
            entry.key_id_len.load(Ordering::Relaxed) as usize,
        )?;
        let mut key = [0u8; QKD_KEY_BYTES];
        load_atomic_bytes(&entry.key, &mut key);
        if entry.state.load(Ordering::Acquire) != MESSAGE_ENTRY_READY {
            key.zeroize();
            return None;
        }
        Some(QkdKeyMaterial { key_id, key })
    }

    fn clear_message_entries(&self) {
        for entry in self.message_entries() {
            entry.state.store(MESSAGE_ENTRY_WRITING, Ordering::Release);
            clear_message_entry(entry);
        }
    }

    pub fn find_for_daemon(
        &self,
        remote_daemon_id: u64,
        require_active: bool,
    ) -> Option<QkdSessionKey> {
        self.entries().iter().find_map(|entry| {
            let state = entry.state.load(Ordering::Acquire);
            if state == ENTRY_EMPTY
                || (require_active && state != ENTRY_ACTIVE)
                || entry.remote_daemon_id.load(Ordering::Relaxed) != remote_daemon_id
            {
                return None;
            }
            self.copy_entry(entry, state == ENTRY_ACTIVE)
        })
    }

    pub fn find_active_by_key_id(&self, key_id: &str) -> Option<QkdSessionKey> {
        self.find_active_by_key_id_and_sae(key_id, None)
    }

    /// Find a key during TLS bootstrap. The initiator keeps its freshly
    /// fetched key pending until the peer proves possession in the handshake.
    pub fn find_by_key_id_for_tls(&self, key_id: &str) -> Option<QkdSessionKey> {
        self.entries().iter().find_map(|entry| {
            let state = entry.state.load(Ordering::Acquire);
            if state != ENTRY_ACTIVE && state != ENTRY_PENDING {
                return None;
            }
            let stored = atomic_string(
                &entry.key_id,
                entry.key_id_len.load(Ordering::Relaxed) as usize,
            )?;
            if stored != key_id {
                return None;
            }
            self.copy_entry(entry, state == ENTRY_ACTIVE)
        })
    }

    pub fn find_active_by_key_id_and_remote_sae(
        &self,
        key_id: &str,
        remote_sae_id: &str,
    ) -> Option<QkdSessionKey> {
        self.find_active_by_key_id_and_sae(key_id, Some(remote_sae_id))
    }

    fn find_active_by_key_id_and_sae(
        &self,
        key_id: &str,
        remote_sae_id: Option<&str>,
    ) -> Option<QkdSessionKey> {
        self.entries().iter().find_map(|entry| {
            if entry.state.load(Ordering::Acquire) != ENTRY_ACTIVE {
                return None;
            }
            let stored = atomic_string(
                &entry.key_id,
                entry.key_id_len.load(Ordering::Relaxed) as usize,
            )?;
            if stored != key_id {
                return None;
            }
            if let Some(expected_sae) = remote_sae_id {
                let stored_sae = atomic_string(
                    &entry.remote_sae_id,
                    entry.remote_sae_len.load(Ordering::Relaxed) as usize,
                )?;
                if stored_sae != expected_sae {
                    return None;
                }
            }
            self.copy_entry(entry, true)
        })
    }

    fn copy_entry(&self, entry: &QkdShmEntry, active: bool) -> Option<QkdSessionKey> {
        let expected_state = if active { ENTRY_ACTIVE } else { ENTRY_PENDING };
        let local_sae_id = self.local_sae_id().ok()?;
        let remote_sae_id = atomic_string(
            &entry.remote_sae_id,
            entry.remote_sae_len.load(Ordering::Relaxed) as usize,
        )?;
        let key_id = atomic_string(
            &entry.key_id,
            entry.key_id_len.load(Ordering::Relaxed) as usize,
        )?;
        let mut key = [0u8; QKD_KEY_BYTES];
        load_atomic_bytes(&entry.key, &mut key);
        let remote_daemon_id = entry.remote_daemon_id.load(Ordering::Relaxed);
        if entry.state.load(Ordering::Acquire) != expected_state {
            key.zeroize();
            return None;
        }
        Some(QkdSessionKey {
            remote_daemon_id,
            local_sae_id,
            remote_sae_id,
            key_id,
            key,
            active,
        })
    }

    fn entries(&self) -> &[QkdShmEntry] {
        unsafe { std::slice::from_raw_parts(self.entries.as_ptr(), MAX_QKD_SESSIONS) }
    }

    fn message_entries(&self) -> &[QkdMessageShmEntry] {
        unsafe { std::slice::from_raw_parts(self.message_entries.as_ptr(), MAX_QKD_MESSAGE_KEYS) }
    }

    #[allow(clippy::mut_from_ref)]
    fn entries_mut(&self) -> &mut [QkdShmEntry] {
        unsafe { std::slice::from_raw_parts_mut(self.entries.as_ptr(), MAX_QKD_SESSIONS) }
    }
}

fn message_key_hash(sender_sae_id: &str, key_id: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in sender_sae_id
        .bytes()
        .chain(std::iter::once(0))
        .chain(key_id.bytes())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    hash
}

fn message_entry_matches(entry: &QkdMessageShmEntry, sender_sae_id: &str, key_id: &str) -> bool {
    atomic_string(
        &entry.sender_sae_id,
        entry.sender_sae_len.load(Ordering::Relaxed) as usize,
    )
    .as_deref()
        == Some(sender_sae_id)
        && atomic_string(
            &entry.key_id,
            entry.key_id_len.load(Ordering::Relaxed) as usize,
        )
        .as_deref()
            == Some(key_id)
}

fn clear_message_entry(entry: &QkdMessageShmEntry) {
    clear_atomic_bytes(&entry.key);
    clear_atomic_bytes(&entry.key_id);
    clear_atomic_bytes(&entry.sender_sae_id);
    entry.writer_pid.store(0, Ordering::Relaxed);
    entry.generation.store(0, Ordering::Relaxed);
    entry.key_id_len.store(0, Ordering::Relaxed);
    entry.sender_sae_len.store(0, Ordering::Relaxed);
    entry.state.store(MESSAGE_ENTRY_EMPTY, Ordering::Release);
}

fn process_is_alive(pid: u32) -> bool {
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn store_atomic_bytes(destination: &[AtomicU8], source: &[u8]) {
    for (index, byte) in destination.iter().enumerate() {
        byte.store(source.get(index).copied().unwrap_or(0), Ordering::Relaxed);
    }
}

fn clear_atomic_bytes(destination: &[AtomicU8]) {
    for byte in destination {
        byte.store(0, Ordering::Relaxed);
    }
}

fn load_atomic_bytes(source: &[AtomicU8], destination: &mut [u8]) {
    for (source, destination) in source.iter().zip(destination) {
        *destination = source.load(Ordering::Relaxed);
    }
}

fn atomic_string(bytes: &[AtomicU8], len: usize) -> Option<String> {
    if len == 0 || len > bytes.len() {
        return None;
    }
    let mut value = vec![0u8; len];
    load_atomic_bytes(&bytes[..len], &mut value);
    String::from_utf8(value).ok()
}

unsafe impl Send for QkdKeyStore {}
unsafe impl Sync for QkdKeyStore {}

impl Drop for QkdKeyStore {
    fn drop(&mut self) {
        unsafe {
            let _ = munmap(
                NonNull::new(self.header.as_ptr() as *mut libc::c_void).unwrap(),
                self.size,
            );
        }
        let _ = close(self.fd.as_raw_fd());
    }
}

pub struct QkdDaemonManager {
    client: EtsiQkdClient,
    store: QkdKeyStore,
    local_sae_id: String,
    write_lock: Mutex<()>,
}

impl QkdDaemonManager {
    pub fn from_env() -> Result<Self, String> {
        let config = QkdConfig::from_env()?;
        let client = EtsiQkdClient::new(&config)?;
        let store = match QkdKeyStore::open() {
            Ok(store) => {
                store
                    .reset(&config.local_sae_id)
                    .map_err(|e| format!("reset QKD key store: {e}"))?;
                store
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                QkdKeyStore::create(&config.local_sae_id)
                    .map_err(|e| format!("create QKD key store: {e}"))?
            }
            Err(_) => {
                let _ = QkdKeyStore::destroy();
                QkdKeyStore::create(&config.local_sae_id)
                    .map_err(|e| format!("replace invalid QKD key store: {e}"))?
            }
        };
        Ok(Self {
            client,
            store,
            local_sae_id: config.local_sae_id,
            write_lock: Mutex::new(()),
        })
    }

    pub fn local_sae_id(&self) -> &str {
        &self.local_sae_id
    }

    pub async fn prepare_outbound(
        &self,
        remote_daemon_id: u64,
        remote_sae_id: &str,
    ) -> Result<QkdSessionKey, String> {
        if let Some(existing) = self.store.find_for_daemon(remote_daemon_id, false) {
            if existing.remote_sae_id == remote_sae_id {
                return Ok(existing);
            }
        }
        let material = self.client.get_encryption_key(remote_sae_id).await?;
        let _guard = self.write_lock.lock().unwrap();
        self.store
            .put(remote_daemon_id, remote_sae_id, &material, false)?;
        self.store
            .find_for_daemon(remote_daemon_id, false)
            .ok_or_else(|| "QKD key disappeared after storing it".into())
    }

    pub fn activate_outbound(&self, remote_daemon_id: u64, key_id: &str) -> bool {
        let _guard = self.write_lock.lock().unwrap();
        self.store.activate(remote_daemon_id, key_id)
    }

    pub fn activate_outbound_by_key_id(&self, key_id: &str) -> Option<u64> {
        let session = self.store.find_by_key_id_for_tls(key_id)?;
        if session.active || self.activate_outbound(session.remote_daemon_id, key_id) {
            Some(session.remote_daemon_id)
        } else {
            None
        }
    }

    pub fn has_active_session(&self, remote_daemon_id: u64) -> bool {
        self.store.find_for_daemon(remote_daemon_id, true).is_some()
    }

    pub async fn accept_inbound(
        &self,
        remote_daemon_id: u64,
        remote_sae_id: &str,
        key_id: &str,
    ) -> Result<(), String> {
        if let Some(existing) = self.store.find_for_daemon(remote_daemon_id, false) {
            if existing.remote_sae_id == remote_sae_id && existing.key_id == key_id {
                let _guard = self.write_lock.lock().unwrap();
                if existing.active || self.store.activate(remote_daemon_id, key_id) {
                    return Ok(());
                }
            }
        }
        let material = self
            .client
            .get_decryption_key(remote_sae_id, key_id)
            .await?;
        let _guard = self.write_lock.lock().unwrap();
        self.store
            .put(remote_daemon_id, remote_sae_id, &material, true)
    }

    pub fn remove_session(&self, remote_daemon_id: u64) {
        let _guard = self.write_lock.lock().unwrap();
        self.store.remove(remote_daemon_id);
    }

    pub fn clear_sessions(&self) {
        let _guard = self.write_lock.lock().unwrap();
        self.store.clear();
    }
}

impl Drop for QkdDaemonManager {
    fn drop(&mut self) {
        self.store.clear();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QkdKeyAnnouncement {
    pub daemon_id: u64,
    pub sae_id: String,
    pub key_id: String,
}

pub fn encode_key_announcement(announcement: &QkdKeyAnnouncement) -> Result<Vec<u8>, String> {
    validate_identifier("QKD SAE ID", &announcement.sae_id, MAX_SAE_ID_LEN)?;
    validate_identifier("QKD key_ID", &announcement.key_id, MAX_KEY_ID_LEN)?;
    let mut out = Vec::with_capacity(13 + announcement.sae_id.len() + announcement.key_id.len());
    out.push(MSG_QKD_KEY_ANNOUNCE);
    out.extend_from_slice(&announcement.daemon_id.to_be_bytes());
    out.extend_from_slice(&(announcement.sae_id.len() as u16).to_be_bytes());
    out.extend_from_slice(&(announcement.key_id.len() as u16).to_be_bytes());
    out.extend_from_slice(announcement.sae_id.as_bytes());
    out.extend_from_slice(announcement.key_id.as_bytes());
    Ok(out)
}

pub fn decode_key_announcement(data: &[u8]) -> Result<QkdKeyAnnouncement, String> {
    if data.len() < 13 || data[0] != MSG_QKD_KEY_ANNOUNCE {
        return Err("invalid QKD key announcement".into());
    }
    let daemon_id = u64::from_be_bytes(data[1..9].try_into().map_err(|_| "invalid QKD daemon id")?);
    let sae_len = u16::from_be_bytes([data[9], data[10]]) as usize;
    let key_len = u16::from_be_bytes([data[11], data[12]]) as usize;
    if sae_len == 0
        || sae_len >= MAX_SAE_ID_LEN
        || key_len == 0
        || key_len >= MAX_KEY_ID_LEN
        || data.len() != 13 + sae_len + key_len
    {
        return Err("invalid QKD key announcement lengths".into());
    }
    let sae_id = std::str::from_utf8(&data[13..13 + sae_len])
        .map_err(|_| "QKD SAE ID is not UTF-8")?
        .to_string();
    let key_id = std::str::from_utf8(&data[13 + sae_len..])
        .map_err(|_| "QKD key_ID is not UTF-8")?
        .to_string();
    Ok(QkdKeyAnnouncement {
        daemon_id,
        sae_id,
        key_id,
    })
}

pub fn encode_key_ack(key_id: &str) -> Result<Vec<u8>, String> {
    validate_identifier("QKD key_ID", key_id, MAX_KEY_ID_LEN)?;
    let mut out = Vec::with_capacity(3 + key_id.len());
    out.push(MSG_QKD_KEY_ACK);
    out.extend_from_slice(&(key_id.len() as u16).to_be_bytes());
    out.extend_from_slice(key_id.as_bytes());
    Ok(out)
}

pub fn decode_key_ack(data: &[u8]) -> Result<String, String> {
    if data.len() < 3 || data[0] != MSG_QKD_KEY_ACK {
        return Err(decode_key_error(data).unwrap_or_else(|| "invalid QKD key ACK".into()));
    }
    let len = u16::from_be_bytes([data[1], data[2]]) as usize;
    if len == 0 || len >= MAX_KEY_ID_LEN || data.len() != 3 + len {
        return Err("invalid QKD key ACK length".into());
    }
    std::str::from_utf8(&data[3..])
        .map(str::to_owned)
        .map_err(|_| "QKD ACK key_ID is not UTF-8".into())
}

pub fn encode_key_error(message: &str) -> Vec<u8> {
    let bytes = message.as_bytes();
    let len = bytes.len().min(1024);
    let mut out = Vec::with_capacity(3 + len);
    out.push(MSG_QKD_KEY_ERROR);
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.extend_from_slice(&bytes[..len]);
    out
}

fn decode_key_error(data: &[u8]) -> Option<String> {
    if data.len() < 3 || data[0] != MSG_QKD_KEY_ERROR {
        return None;
    }
    let len = u16::from_be_bytes([data[1], data[2]]) as usize;
    if data.len() != 3 + len {
        return Some("malformed QKD peer error".into());
    }
    Some(format!(
        "remote QKD setup failed: {}",
        String::from_utf8_lossy(&data[3..])
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    #[test]
    fn beta_profile_accepts_two_fixed_roles() {
        assert_eq!(
            BetaProfile::parse("account_id=4624\nrole=1\n").unwrap(),
            BetaProfile {
                account_id: "4624".into(),
                role: 1,
            }
        );
        assert_eq!(
            BetaProfile::parse("# second host\naccount_id = 4624\nrole = 2\n").unwrap(),
            BetaProfile {
                account_id: "4624".into(),
                role: 2,
            }
        );
    }

    #[test]
    fn beta_profile_rejects_invalid_or_ambiguous_values() {
        assert!(BetaProfile::parse("account_id=acct-4624\nrole=1\n").is_err());
        assert!(BetaProfile::parse("account_id=4624\nrole=3\n").is_err());
        assert!(BetaProfile::parse("account_id=4624\n").is_err());
        assert!(BetaProfile::parse("account_id=4624\nrole=1\nextra=x\n").is_err());
    }

    #[test]
    fn beta_profile_builds_complete_qkd_configuration() {
        let profile_dir =
            std::env::temp_dir().join(format!("axon-qkd-profile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&profile_dir);
        std::fs::create_dir_all(&profile_dir).unwrap();
        std::fs::write(profile_dir.join("profile"), "account_id=4624\nrole=2\n").unwrap();
        for file_name in [
            "account-4624-server-ca-qukaydee-com.crt",
            "sae-2.crt",
            "sae-2.key",
        ] {
            std::fs::write(profile_dir.join(file_name), b"test fixture").unwrap();
        }

        let config = QkdConfig::from_beta_profile_dir(&profile_dir).unwrap();
        assert_eq!(config.local_sae_id, "sae-2");
        assert_eq!(
            config.kme_base_url.as_str(),
            "https://kme-2.acct-4624.etsi-qkd-api.qukaydee.com/api/v1/keys"
        );
        assert_eq!(
            config.client_private_key.as_deref(),
            Some(profile_dir.join("sae-2.key").as_path())
        );

        std::fs::remove_dir_all(profile_dir).unwrap();
    }

    #[test]
    fn installed_profile_is_derived_from_the_daemon_prefix() {
        let daemon = Path::new("/tmp/axon_ws/install/rmw_axon/lib/axon_daemon");
        assert_eq!(
            installed_profile_dir(daemon).as_deref(),
            Some(Path::new(
                "/tmp/axon_ws/install/rmw_axon/share/rmw_axon/qkd"
            ))
        );
    }

    fn unique_store() -> (String, QkdKeyStore) {
        let name = format!("/axon_qkd_test_{}", std::process::id());
        let _ = QkdKeyStore::destroy_named(&name);
        let store = QkdKeyStore::create_named(&name, "sae-local").unwrap();
        (name, store)
    }

    #[test]
    fn shared_store_pending_activation_and_lookup() {
        let (name, store) = unique_store();
        let material = QkdKeyMaterial {
            key_id: "key-42".into(),
            key: [0x42; QKD_KEY_BYTES],
        };
        store.put(77, "sae-remote", &material, false).unwrap();
        assert!(store.find_for_daemon(77, true).is_none());
        assert!(!store.find_for_daemon(77, false).unwrap().active);
        assert!(store.activate(77, "key-42"));
        assert!(
            store.activate(77, "key-42"),
            "activating the negotiated key again must remain successful"
        );
        let active = store.find_active_by_key_id("key-42").unwrap();
        assert_eq!(active.remote_daemon_id, 77);
        assert_eq!(active.local_sae_id, "sae-local");
        assert_eq!(active.remote_sae_id, "sae-remote");
        assert_eq!(active.key, [0x42; QKD_KEY_BYTES]);
        drop(store);
        let _ = QkdKeyStore::destroy_named(&name);
    }

    #[test]
    fn shared_store_reset_is_visible_to_existing_process_mappings() {
        let name = format!("/axon_qkd_restart_test_{}", std::process::id());
        let _ = QkdKeyStore::destroy_named(&name);
        let daemon_store = QkdKeyStore::create_named(&name, "sae-before").unwrap();
        let process_store = QkdKeyStore::open_named(&name).unwrap();
        let old = QkdKeyMaterial {
            key_id: "old-key".into(),
            key: [0x11; QKD_KEY_BYTES],
        };
        daemon_store.put(10, "remote-before", &old, true).unwrap();
        assert!(process_store.find_for_daemon(10, true).is_some());

        daemon_store.reset("sae-after").unwrap();
        assert!(process_store.find_for_daemon(10, true).is_none());
        assert_eq!(process_store.local_sae_id().unwrap(), "sae-after");
        let new = QkdKeyMaterial {
            key_id: "new-key".into(),
            key: [0x22; QKD_KEY_BYTES],
        };
        daemon_store.put(11, "remote-after", &new, true).unwrap();
        assert_eq!(
            process_store.find_for_daemon(11, true).unwrap().key_id,
            "new-key"
        );

        drop(process_store);
        drop(daemon_store);
        let _ = QkdKeyStore::destroy_named(&name);
    }

    #[test]
    fn shared_message_cache_coordinates_one_retrieval_across_process_mappings() {
        let name = format!("/axon_qkd_message_test_{}", std::process::id());
        let _ = QkdKeyStore::destroy_named(&name);
        let first_process = QkdKeyStore::create_named(&name, "sae-local").unwrap();
        let second_process = QkdKeyStore::open_named(&name).unwrap();

        assert!(matches!(
            first_process
                .claim_message_key("sae-remote", "message-key-1")
                .unwrap(),
            QkdMessageKeyLookup::Claimed
        ));
        assert!(matches!(
            second_process
                .claim_message_key("sae-remote", "message-key-1")
                .unwrap(),
            QkdMessageKeyLookup::Pending
        ));

        let material = QkdKeyMaterial {
            key_id: "message-key-1".into(),
            key: [0x7a; QKD_KEY_BYTES],
        };
        first_process
            .publish_message_key("sae-remote", &material)
            .unwrap();
        let cached = match second_process
            .claim_message_key("sae-remote", "message-key-1")
            .unwrap()
        {
            QkdMessageKeyLookup::Ready(material) => material,
            _ => panic!("the second process did not receive the shared message key"),
        };
        assert_eq!(cached.key_id, "message-key-1");
        assert_eq!(cached.key, [0x7a; QKD_KEY_BYTES]);

        drop(second_process);
        drop(first_process);
        let _ = QkdKeyStore::destroy_named(&name);
    }

    #[test]
    fn key_response_rejects_wrong_size_and_id() {
        let wrong_size = KeyResponse {
            keys: vec![KeyRecord {
                key_id: "key-a".into(),
                key: BASE64.encode([0u8; 16]),
            }],
        };
        assert!(decode_single_key(wrong_size, None)
            .unwrap_err()
            .contains("256 bits"));

        let wrong_id = KeyResponse {
            keys: vec![KeyRecord {
                key_id: "key-b".into(),
                key: BASE64.encode([0u8; 32]),
            }],
        };
        assert!(decode_single_key(wrong_id, Some("key-a"))
            .unwrap_err()
            .contains("does not match"));
    }

    #[test]
    fn key_announcement_and_ack_roundtrip() {
        let announcement = QkdKeyAnnouncement {
            daemon_id: 123,
            sae_id: "sae-a".into(),
            key_id: "key-123".into(),
        };
        let encoded = encode_key_announcement(&announcement).unwrap();
        assert_eq!(decode_key_announcement(&encoded).unwrap(), announcement);
        let ack = encode_key_ack("key-123").unwrap();
        assert_eq!(decode_key_ack(&ack).unwrap(), "key-123");
        assert!(decode_key_ack(&encode_key_error("KME unavailable"))
            .unwrap_err()
            .contains("KME unavailable"));
    }

    fn spawn_mock_kme(
        expected_requests: usize,
    ) -> (Url, Arc<Mutex<Vec<String>>>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let handle = std::thread::spawn(move || {
            for _ in 0..expected_requests {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = [0u8; 4096];
                let count = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..count]);
                let first_line = request.lines().next().unwrap_or_default().to_string();
                captured.lock().unwrap().push(first_line.clone());
                let key_id = if first_line.contains("dec_keys") {
                    "key-dec"
                } else {
                    "key-enc"
                };
                let body = format!(
                    "{{\"keys\":[{{\"key_ID\":\"{key_id}\",\"key\":\"{}\"}}]}}",
                    BASE64.encode([0x5au8; QKD_KEY_BYTES])
                );
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
                stream.flush().unwrap();
            }
        });
        (
            Url::parse(&format!("http://{addr}/api/v1/keys")).unwrap(),
            requests,
            handle,
        )
    }

    fn spawn_fixed_mock_kme(
        expected_requests: usize,
        key_id: &'static str,
        key_byte: u8,
    ) -> (Url, Arc<Mutex<Vec<String>>>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let handle = std::thread::spawn(move || {
            for _ in 0..expected_requests {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = [0u8; 4096];
                let count = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..count]);
                captured
                    .lock()
                    .unwrap()
                    .push(request.lines().next().unwrap_or_default().to_string());
                let body = format!(
                    "{{\"keys\":[{{\"key_ID\":\"{key_id}\",\"key\":\"{}\"}}]}}",
                    BASE64.encode([key_byte; QKD_KEY_BYTES])
                );
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
                stream.flush().unwrap();
            }
        });
        (
            Url::parse(&format!("http://{addr}/api/v1/keys")).unwrap(),
            requests,
            handle,
        )
    }

    fn test_client(base_url: Url) -> EtsiQkdClient {
        EtsiQkdClient::new(&QkdConfig {
            kme_base_url: base_url,
            local_sae_id: "sae-local".into(),
            ca_certificate: None,
            client_certificate: None,
            client_private_key: None,
            request_timeout: Duration::from_secs(2),
            allow_insecure_http: true,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn etsi_client_uses_expected_enc_and_dec_endpoints() {
        let (base_url, requests, server) = spawn_mock_kme(2);
        let client = test_client(base_url);
        let encryption = client.get_encryption_key("sae-remote").await.unwrap();
        let decryption = client
            .get_decryption_key("sae-remote", "key-dec")
            .await
            .unwrap();
        server.join().unwrap();

        assert_eq!(encryption.key_id, "key-enc");
        assert_eq!(decryption.key_id, "key-dec");
        assert_eq!(encryption.key, [0x5a; QKD_KEY_BYTES]);
        let requests = requests.lock().unwrap();
        assert!(requests[0].starts_with("GET /api/v1/keys/sae-remote/enc_keys?number=1&size=256 "));
        assert!(requests[1].starts_with("GET /api/v1/keys/sae-remote/dec_keys?key_ID=key-dec "));
    }

    #[tokio::test]
    async fn daemon_manager_fetches_only_one_key_per_peer_session() {
        let (base_url, requests, server) = spawn_mock_kme(1);
        let name = format!("/axon_qkd_manager_test_{}", std::process::id());
        let _ = QkdKeyStore::destroy_named(&name);
        let manager = QkdDaemonManager {
            client: test_client(base_url),
            store: QkdKeyStore::create_named(&name, "sae-local").unwrap(),
            local_sae_id: "sae-local".into(),
            write_lock: Mutex::new(()),
        };

        let first = manager.prepare_outbound(88, "sae-remote").await.unwrap();
        let second = manager.prepare_outbound(88, "sae-remote").await.unwrap();
        assert_eq!(first.key_id, second.key_id);
        assert!(manager.activate_outbound(88, &first.key_id));
        assert!(manager.has_active_session(88));
        server.join().unwrap();
        assert_eq!(requests.lock().unwrap().len(), 1);

        drop(manager);
        let _ = QkdKeyStore::destroy_named(&name);
    }

    #[tokio::test]
    async fn two_daemons_negotiate_the_same_qkd_session_key() {
        let (alice_url, alice_requests, alice_server) =
            spawn_fixed_mock_kme(1, "shared-key-1", 0xa5);
        let (bob_url, bob_requests, bob_server) = spawn_fixed_mock_kme(1, "shared-key-1", 0xa5);
        let alice_name = format!("/axon_qkd_alice_test_{}", std::process::id());
        let bob_name = format!("/axon_qkd_bob_test_{}", std::process::id());
        let _ = QkdKeyStore::destroy_named(&alice_name);
        let _ = QkdKeyStore::destroy_named(&bob_name);
        let alice = QkdDaemonManager {
            client: test_client(alice_url),
            store: QkdKeyStore::create_named(&alice_name, "sae-alice").unwrap(),
            local_sae_id: "sae-alice".into(),
            write_lock: Mutex::new(()),
        };
        let bob = QkdDaemonManager {
            client: test_client(bob_url),
            store: QkdKeyStore::create_named(&bob_name, "sae-bob").unwrap(),
            local_sae_id: "sae-bob".into(),
            write_lock: Mutex::new(()),
        };

        let alice_key = alice.prepare_outbound(22, "sae-bob").await.unwrap();
        let announcement_wire = encode_key_announcement(&QkdKeyAnnouncement {
            daemon_id: 11,
            sae_id: "sae-alice".into(),
            key_id: alice_key.key_id.clone(),
        })
        .unwrap();
        let announcement = decode_key_announcement(&announcement_wire).unwrap();
        bob.accept_inbound(
            announcement.daemon_id,
            &announcement.sae_id,
            &announcement.key_id,
        )
        .await
        .unwrap();
        let ack_key_id = decode_key_ack(&encode_key_ack(&announcement.key_id).unwrap()).unwrap();
        assert!(alice.activate_outbound(22, &ack_key_id));

        let alice_active = alice.store.find_for_daemon(22, true).unwrap();
        let bob_active = bob.store.find_for_daemon(11, true).unwrap();
        assert_eq!(alice_active.key_id, bob_active.key_id);
        assert_eq!(alice_active.key, bob_active.key);
        alice_server.join().unwrap();
        bob_server.join().unwrap();
        assert_eq!(alice_requests.lock().unwrap().len(), 1);
        assert_eq!(bob_requests.lock().unwrap().len(), 1);

        drop(alice);
        drop(bob);
        let _ = QkdKeyStore::destroy_named(&alice_name);
        let _ = QkdKeyStore::destroy_named(&bob_name);
    }

    #[tokio::test]
    async fn missing_kme_fails_without_installing_a_session_key() {
        let unavailable = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = unavailable.local_addr().unwrap();
        drop(unavailable);
        let name = format!("/axon_qkd_offline_test_{}", std::process::id());
        let _ = QkdKeyStore::destroy_named(&name);
        let manager = QkdDaemonManager {
            client: test_client(Url::parse(&format!("http://{addr}/api/v1/keys")).unwrap()),
            store: QkdKeyStore::create_named(&name, "sae-local").unwrap(),
            local_sae_id: "sae-local".into(),
            write_lock: Mutex::new(()),
        };

        assert!(manager.prepare_outbound(99, "sae-remote").await.is_err());
        assert!(!manager.has_active_session(99));

        drop(manager);
        let _ = QkdKeyStore::destroy_named(&name);
    }
}
