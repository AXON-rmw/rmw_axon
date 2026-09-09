//! TLS 1.3 external pre-shared keys.
//!
//! This small API lets AXON import a QKD-derived secret into the TLS 1.3
//! key schedule. It uses RFC 8446 `psk_ke`, without an additional key share.

use alloc::vec::Vec;
use core::fmt;

use zeroize::Zeroizing;

/// A TLS 1.3 external pre-shared key and its public identity.
#[derive(Clone)]
pub struct ExternalPsk {
    identity: Vec<u8>,
    secret: Zeroizing<Vec<u8>>,
}

impl ExternalPsk {
    /// Construct an external PSK from a public identity and secret bytes.
    pub fn new(identity: Vec<u8>, secret: Vec<u8>) -> Result<Self, &'static str> {
        if identity.is_empty() || identity.len() > u16::MAX as usize {
            return Err("external PSK identity must contain 1..65535 bytes");
        }
        if secret.len() < 32 {
            return Err("external PSK secret must contain at least 32 bytes");
        }
        Ok(Self {
            identity,
            secret: Zeroizing::new(secret),
        })
    }

    pub(crate) fn identity(&self) -> &[u8] {
        &self.identity
    }

    pub(crate) fn secret(&self) -> &[u8] {
        &self.secret
    }
}

impl fmt::Debug for ExternalPsk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternalPsk")
            .field("identity", &self.identity)
            .field("secret", &"[redacted]")
            .finish()
    }
}

/// Resolves a server-side external PSK from its public identity.
pub trait ResolvesExternalPsk: fmt::Debug + Send + Sync {
    /// Return the PSK matching `identity`, or `None` to reject it.
    fn resolve(&self, identity: &[u8]) -> Option<ExternalPsk>;
}
