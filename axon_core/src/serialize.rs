//! CDR (Common Data Representation) serialization utilities.
//!
//! Wraps the `cdr_encoding` crate with little-endian byte order for
//! DDS-compatible message serialization.

use byteorder::LittleEndian;
use cdr_encoding::{from_bytes, to_vec};

/// Serialize a value to CDR bytes using little-endian encoding.
///
/// # Arguments
/// * `msg` - Any `serde::Serialize` value
pub fn serialize<T: serde::Serialize>(msg: &T) -> Result<Vec<u8>, String> {
    to_vec::<T, LittleEndian>(msg).map_err(|e| format!("serialization error: {}", e))
}

/// Deserialize a value from CDR bytes using little-endian encoding.
///
/// # Arguments
/// * `bytes` - CDR-encoded byte slice
pub fn deserialize<'a, T: serde::Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, String> {
    from_bytes::<T, LittleEndian>(bytes)
        .map(|(v, _)| v)
        .map_err(|e| format!("deserialization error: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Point {
        x: f64,
        y: f64,
        z: f64,
    }

    #[test]
    fn test_cdr_roundtrip() {
        let p = Point {
            x: 1.0,
            y: 2.0,
            z: 3.0,
        };
        let bytes = serialize(&p).unwrap();
        let p2: Point = deserialize(&bytes).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn test_cdr_serialize_non_zero() {
        let p = Point {
            x: -1.5,
            y: 0.0,
            z: 42.5,
        };
        let bytes = serialize(&p).unwrap();
        assert!(!bytes.is_empty());
        let p2: Point = deserialize(&bytes).unwrap();
        assert_eq!(p, p2);
    }
}
