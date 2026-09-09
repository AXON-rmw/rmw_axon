//! Opt-in, lossless middleware tracing for integration testing.
//!
//! The normal Axon logs intentionally stay quiet.  Setting `AXON_TRACE=1`
//! enables one line per middleware event on stderr.  Events contain routing
//! metadata, sequence numbers, sizes and timings, but never message contents
//! or cryptographic key material. This makes a split-process ROS 2 deployment
//! auditable without turning tracing on for production deployments.

use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// Whether exhaustive tracing was requested for this process.
pub fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("AXON_TRACE")
            .map(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on" | "all"
                )
            })
            .unwrap_or(false)
    })
}

/// Emit one machine-readable-ish trace line.  The payload is deliberately
/// supplied by callers as metadata only; callers must not include plaintext
/// or key bytes.
pub fn emit(message: String) {
    if !enabled() {
        return;
    }
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    eprintln!(
        "[axon_trace] ts_ms={} pid={} {}",
        timestamp_ms,
        std::process::id(),
        message
    );
}

/// Convenience macro for metadata-only events.
#[macro_export]
macro_rules! axon_trace {
    ($($arg:tt)*) => {
        if $crate::trace::enabled() {
            $crate::trace::emit(format!($($arg)*));
        }
    };
}
