//! Timing Normalization — Layer 5, §5.2.3
//!
//! Prevents timing side-channels by normalizing response latency.
//! Modes: FixedFloor (Dark), Bucket (Island/Vault), None (Light).

use std::time::{Duration, Instant};
use tokio::time::sleep;

use crate::config::{TimingMode, TimingNormalizationConfig};

/// Timing normalizer
pub struct TimingNormalizer {
    config: TimingNormalizationConfig,
}

impl TimingNormalizer {
    /// Create a new timing normalizer
    pub fn new(config: TimingNormalizationConfig) -> Self {
        Self { config }
    }

    /// Wait until the next timing boundary.
    ///
    /// Call this with the time the request started processing.
    /// This function will sleep until the next allowed response time.
    pub async fn normalize(&self, started_at: Instant) {
        if !self.config.enabled {
            return;
        }

        let elapsed_ms = started_at.elapsed().as_millis() as u64;

        let target_ms = match self.config.mode {
            TimingMode::None => return,

            TimingMode::FixedFloor => {
                // Never respond faster than the fixed floor
                if elapsed_ms >= self.config.fixed_floor_ms {
                    return;
                }
                self.config.fixed_floor_ms
            }

            TimingMode::Bucket => {
                // Round up to the next bucket boundary
                let bucket = self.config.bucket_ms;
                if bucket == 0 {
                    return;
                }
                let next_bucket = ((elapsed_ms / bucket) + 1) * bucket;
                if elapsed_ms >= next_bucket {
                    // Already at or past bucket boundary — no wait needed
                    return;
                }
                next_bucket
            }
        };

        let wait_ms = target_ms.saturating_sub(elapsed_ms);
        if wait_ms > 0 {
            sleep(Duration::from_millis(wait_ms)).await;
        }
    }

    /// Compute the target response time in ms for a given elapsed time
    pub fn target_ms(&self, elapsed_ms: u64) -> u64 {
        if !self.config.enabled {
            return elapsed_ms;
        }
        match self.config.mode {
            TimingMode::None => elapsed_ms,
            TimingMode::FixedFloor => elapsed_ms.max(self.config.fixed_floor_ms),
            TimingMode::Bucket => {
                let bucket = self.config.bucket_ms;
                if bucket == 0 {
                    return elapsed_ms;
                }
                let next_bucket = ((elapsed_ms / bucket) + 1) * bucket;
                next_bucket
            }
        }
    }

    /// Whether timing normalization is active
    pub fn is_active(&self) -> bool {
        self.config.enabled && !matches!(self.config.mode, TimingMode::None)
    }

    /// Get the configured bucket size (for metrics/reporting)
    pub fn bucket_ms(&self) -> Option<u64> {
        if !self.config.enabled {
            return None;
        }
        match self.config.mode {
            TimingMode::Bucket => Some(self.config.bucket_ms),
            TimingMode::FixedFloor => Some(self.config.fixed_floor_ms),
            TimingMode::None => None,
        }
    }
}

/// Pad a response body to a consistent size (prevents length-based side-channels)
///
/// In high-assurance modes, responses are padded to the next power-of-two
/// length. The padding is stripped by the client SDK.
pub fn pad_response(response: &str, enabled: bool) -> (String, usize) {
    if !enabled {
        return (response.to_string(), 0);
    }

    let len = response.len();
    if len == 0 {
        return (response.to_string(), 0);
    }

    // Next power of 2 at least 64 bytes apart
    let target = next_padded_length(len);
    let padding_len = target - len;

    // Use space + null padding marker (stripped by client)
    let mut padded = response.to_string();
    // Padding marker: \x00 repeated to fill to target length
    // Client strips everything after the first \x00
    padded.push('\x00');
    padded.extend(std::iter::repeat(' ').take(padding_len.saturating_sub(1)));

    (padded, padding_len)
}

/// Compute the next padded length (nearest multiple of 256, at least target)
fn next_padded_length(len: usize) -> usize {
    let step = 256;
    ((len / step) + 1) * step
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{TimingNormalizationConfig, TimingMode};

    #[test]
    fn test_bucket_target() {
        let config = TimingNormalizationConfig {
            enabled: true,
            mode: TimingMode::Bucket,
            bucket_ms: 100,
            fixed_floor_ms: 0,
        };
        let normalizer = TimingNormalizer::new(config);
        assert_eq!(normalizer.target_ms(0), 100);
        assert_eq!(normalizer.target_ms(50), 100);
        assert_eq!(normalizer.target_ms(100), 200);
        assert_eq!(normalizer.target_ms(150), 200);
        assert_eq!(normalizer.target_ms(200), 300);
    }

    #[test]
    fn test_fixed_floor_target() {
        let config = TimingNormalizationConfig {
            enabled: true,
            mode: TimingMode::FixedFloor,
            bucket_ms: 0,
            fixed_floor_ms: 500,
        };
        let normalizer = TimingNormalizer::new(config);
        assert_eq!(normalizer.target_ms(0), 500);
        assert_eq!(normalizer.target_ms(200), 500);
        assert_eq!(normalizer.target_ms(600), 600); // Already past floor
    }

    #[test]
    fn test_none_passthrough() {
        let config = TimingNormalizationConfig {
            enabled: false,
            mode: TimingMode::None,
            bucket_ms: 100,
            fixed_floor_ms: 500,
        };
        let normalizer = TimingNormalizer::new(config);
        assert_eq!(normalizer.target_ms(123), 123);
    }

    #[test]
    fn test_pad_response() {
        let (padded, padding) = pad_response("Hello", true);
        assert!(padded.len() >= 256);
        assert!(padding > 0);
        // Original content preserved at start
        assert!(padded.starts_with("Hello\x00"));
    }
}
