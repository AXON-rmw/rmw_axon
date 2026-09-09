//! AXON transport-security configuration.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum SecurityMode {
    /// TLS 1.3 with mandatory hybrid X25519 + ML-KEM-768 key exchange.
    #[default]
    Classic = 0,
    /// TLS 1.3 with a QKD key imported as an external PSK.
    Qkd = 1,
}

impl SecurityMode {
    pub fn from_env() -> Result<Self, String> {
        Self::from_value(std::env::var("AXON_SECURITY_MODE").ok().as_deref())
    }

    pub fn from_value(value: Option<&str>) -> Result<Self, String> {
        match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
            None | Some("") | Some("classic") => Ok(Self::Classic),
            Some("qkd") => Ok(Self::Qkd),
            Some(other) => Err(format!(
                "invalid AXON_SECURITY_MODE={other}; expected classic or qkd"
            )),
        }
    }

    pub const fn wire_value(self) -> u8 {
        self as u8
    }

    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Classic),
            1 => Some(Self::Qkd),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Classic => "classic",
            Self::Qkd => "qkd",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum QuicCipher {
    #[default]
    ChaCha20Poly1305,
    Aes256Gcm,
}

impl QuicCipher {
    pub fn from_env() -> Result<Self, String> {
        Self::from_value(std::env::var("AXON_QUIC_CIPHER").ok().as_deref())
    }

    pub fn from_value(value: Option<&str>) -> Result<Self, String> {
        match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
            None | Some("") | Some("chacha20") | Some("chacha20-poly1305") | Some("chacha") => {
                Ok(Self::ChaCha20Poly1305)
            }
            Some("aes256") | Some("aes-256-gcm") | Some("aes256-gcm") => Ok(Self::Aes256Gcm),
            Some(other) => Err(format!(
                "invalid AXON_QUIC_CIPHER={other}; expected chacha20 or aes256"
            )),
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            Self::Aes256Gcm => "AES-256-GCM",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_are_strict_and_classic_is_default() {
        assert_eq!(
            SecurityMode::from_value(None).unwrap(),
            SecurityMode::Classic
        );
        assert_eq!(
            SecurityMode::from_value(Some("qkd")).unwrap(),
            SecurityMode::Qkd
        );
        assert!(SecurityMode::from_value(Some("post-quantum")).is_err());
        assert!(SecurityMode::from_value(Some("off")).is_err());
    }

    #[test]
    fn only_256_bit_quic_ciphers_are_accepted() {
        assert_eq!(
            QuicCipher::from_value(None).unwrap(),
            QuicCipher::ChaCha20Poly1305
        );
        assert_eq!(
            QuicCipher::from_value(Some("aes256")).unwrap(),
            QuicCipher::Aes256Gcm
        );
        assert!(QuicCipher::from_value(Some("aes128")).is_err());
    }
}
