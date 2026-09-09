const COMPRESSION_THRESHOLD: usize = 1024;

fn compression_level() -> i32 {
    std::env::var("AXON_COMPRESSION_LEVEL")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(1)
}

pub fn compression_enabled() -> bool {
    let val = std::env::var("AXON_COMPRESSION").ok();
    match val.as_deref() {
        None | Some("1") | Some("true") | Some("yes") | Some("on") => true,
        Some("0") | Some("false") | Some("no") | Some("off") => false,
        _ => true,
    }
}

pub fn compress(data: &[u8]) -> Vec<u8> {
    if data.len() <= COMPRESSION_THRESHOLD || !compression_enabled() {
        let mut out = Vec::with_capacity(data.len() + 1);
        out.push(0);
        out.extend_from_slice(data);
        return out;
    }
    let level = compression_level();
    match zstd::bulk::compress(data, level) {
        Ok(compressed) if compressed.len() + 5 < data.len() + 1 => {
            let mut out = Vec::with_capacity(5 + compressed.len());
            out.push(1);
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            out.extend_from_slice(&compressed);
            out
        }
        _ => {
            let mut out = Vec::with_capacity(data.len() + 1);
            out.push(0);
            out.extend_from_slice(data);
            out
        }
    }
}

pub fn decompress(data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() {
        return None;
    }
    if data[0] == 0 {
        return Some(data[1..].to_vec());
    }
    if data.len() < 5 {
        return None;
    }
    let original_len = u32::from_be_bytes(data[1..5].try_into().ok()?) as usize;
    zstd::bulk::decompress(&data[5..], original_len).ok()
}

/// Decompress data directly into the output buffer, avoiding an intermediate
/// Vec allocation.  Returns the number of decompressed bytes on success.
///
/// When `data` aliases `out` (e.g. after `try_take` wrote compressed data
/// into the output buffer), the compressed payload is first moved to the
/// end of `out` to guarantee non-overlapping source and destination for the
/// zstd decoder.  If there is not enough room at the end, falls back to a
/// temporary allocation.
pub fn decompress_into(data: &[u8], out: &mut [u8]) -> Option<usize> {
    if data.is_empty() || out.is_empty() {
        return None;
    }
    if data[0] == 0 {
        let payload = &data[1..];
        let len = payload.len().min(out.len());
        out[..len].copy_from_slice(&payload[..len]);
        return Some(len);
    }
    if data.len() < 5 {
        return None;
    }
    let original_len = u32::from_be_bytes(data[1..5].try_into().ok()?) as usize;
    if original_len > out.len() {
        return None;
    }
    let payload = &data[5..];
    let payload_len = payload.len();

    let aliased = std::ptr::eq(data.as_ptr(), out.as_ptr());
    if aliased && payload_len > 0 && out.len() >= original_len + payload_len {
        // Move payload to end so source and destination don't overlap.
        let dst = out.len() - payload_len;
        out.copy_within(5..5 + payload_len, dst);
        let (dest, src) = out.split_at_mut(original_len);
        let src_offset = dst - original_len;
        zstd::bulk::decompress_to_buffer(&src[src_offset..src_offset + payload_len], dest).ok()
    } else if !aliased || payload_len == 0 {
        zstd::bulk::decompress_to_buffer(payload, &mut out[..original_len]).ok()
    } else {
        // Not enough room for non-overlapping layout — use a temp Vec.
        let d = zstd::bulk::decompress(payload, original_len).ok()?;
        out[..original_len].copy_from_slice(&d);
        Some(original_len)
    }
}

pub fn decompressed_size(data: &[u8]) -> Option<usize> {
    if data.is_empty() {
        return None;
    }
    if data[0] == 0 {
        return Some(data.len().saturating_sub(1));
    }
    if data.len() < 5 {
        return None;
    }
    Some(u32::from_be_bytes(data[1..5].try_into().ok()?) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_small() {
        let input = vec![42u8; 512];
        let compressed = compress(&input);
        assert_eq!(compressed[0], 0); // uncompressed flag
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, input);
    }

    #[test]
    fn test_decompress_uncompressed() {
        let input = vec![10u8, 20, 30];
        let mut data = vec![0u8];
        data.extend_from_slice(&input);
        let result = decompress(&data).unwrap();
        assert_eq!(result, input);
    }

    #[test]
    fn test_compression_disabled() {
        std::env::set_var("AXON_COMPRESSION", "0");
        let input = vec![0u8; 8192];
        let compressed = compress(&input);
        assert_eq!(compressed[0], 0);
        std::env::remove_var("AXON_COMPRESSION");
    }
}
