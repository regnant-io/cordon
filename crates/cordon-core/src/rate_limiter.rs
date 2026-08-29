//! Rate Limiter — §4.2 Layer 1
//!
//! Token bucket rate limiting per client_id.
//! Burst allowance configurable per client.
//! Sustained violations trigger anomaly alerts.

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

use crate::error::{CordonError, CordonResult};
use crate::identity::ClientPolicy;

/// Token bucket state for a single client
struct ClientBucket {
    /// Tokens available for requests (refilled at rate)
    request_tokens: f64,
    /// Tokens available for output (refilled at rate)
    output_tokens: f64,
    /// Last refill time
    last_refill: DateTime<Utc>,
    /// Max requests/min for this client
    max_requests_per_minute: f64,
    /// Max tokens/min for this client
    max_tokens_per_minute: f64,
    /// Burst multiplier (default 2x)
    burst_multiplier: f64,
    /// Count of violations in current window
    violations_this_minute: u32,
    /// Window start for violation counting
    violation_window_start: DateTime<Utc>,
}

impl ClientBucket {
    fn new(policy: &ClientPolicy) -> Self {
        let max_req = policy.max_requests_per_minute as f64;
        let max_tok = policy.max_tokens_per_minute as f64;
        Self {
            // Start at the configured steady-state capacity, NOT the burst ceiling.
            // Idle time can refill up to `burst_multiplier` × capacity, so bursts are
            // still allowed — but a freshly seen client cannot immediately exceed its
            // configured per-minute limit (previously it could, by 2×).
            request_tokens: max_req,
            output_tokens: max_tok,
            last_refill: Utc::now(),
            max_requests_per_minute: max_req,
            max_tokens_per_minute: max_tok,
            burst_multiplier: 2.0,
            violations_this_minute: 0,
            violation_window_start: Utc::now(),
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = Utc::now();
        let elapsed_secs = (now - self.last_refill).num_milliseconds() as f64 / 1000.0;
        self.last_refill = now;

        let req_refill = self.max_requests_per_minute * elapsed_secs / 60.0;
        let tok_refill = self.max_tokens_per_minute * elapsed_secs / 60.0;

        let max_req_bucket = self.max_requests_per_minute * self.burst_multiplier;
        let max_tok_bucket = self.max_tokens_per_minute * self.burst_multiplier;

        self.request_tokens = (self.request_tokens + req_refill).min(max_req_bucket);
        self.output_tokens = (self.output_tokens + tok_refill).min(max_tok_bucket);

        // Reset violation window each minute
        if (now - self.violation_window_start).num_seconds() >= 60 {
            self.violations_this_minute = 0;
            self.violation_window_start = now;
        }
    }

    /// Try to consume one request token and **reserve** `max_output_tokens`
    /// output tokens. The reservation is settled after inference via `settle`,
    /// crediting back whatever was not actually generated.
    fn try_consume(&mut self, max_output_tokens: u32) -> RateLimitResult {
        self.refill();

        if self.request_tokens < 1.0 {
            self.violations_this_minute += 1;
            return RateLimitResult::RequestLimitExceeded {
                violations_this_minute: self.violations_this_minute,
            };
        }

        let tokens_needed = max_output_tokens as f64;
        if self.output_tokens < tokens_needed {
            // Not enough budget to cover this request's maximum output.
            self.violations_this_minute += 1;
            return RateLimitResult::TokenLimitExceeded {
                available: self.output_tokens as u32,
                violations_this_minute: self.violations_this_minute,
            };
        }

        self.request_tokens -= 1.0;
        self.output_tokens -= tokens_needed; // reserve up-front
        RateLimitResult::Allowed
    }

    /// Settle a reservation once actual usage is known: refund the difference
    /// between the reserved maximum and what was actually generated.
    fn settle(&mut self, reserved: u32, actual: u32) {
        let refund = reserved.saturating_sub(actual) as f64;
        if refund <= 0.0 {
            return;
        }
        let max_bucket = self.max_tokens_per_minute * self.burst_multiplier;
        self.output_tokens = (self.output_tokens + refund).min(max_bucket);
    }
}

/// Result of a rate limit check
#[derive(Debug, Clone)]
pub enum RateLimitResult {
    /// Request is allowed
    Allowed,
    /// Request rate limit exceeded
    RequestLimitExceeded {
        /// Number of violations in the current minute
        violations_this_minute: u32,
    },
    /// Token limit exceeded
    TokenLimitExceeded {
        /// Tokens currently available
        available: u32,
        /// Number of violations in the current minute
        violations_this_minute: u32,
    },
}

/// Per-client rate limiter
pub struct RateLimiter {
    buckets: Arc<Mutex<HashMap<String, ClientBucket>>>,
    /// Threshold for sustained violation alerts
    violation_alert_threshold: u32,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(violation_alert_threshold: u32) -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            violation_alert_threshold,
        }
    }

    /// Check rate limit for a client request
    pub fn check(
        &self,
        client_id: &str,
        max_output_tokens: u32,
        policy: &ClientPolicy,
    ) -> CordonResult<()> {
        let mut buckets = self.buckets.lock();
        let bucket = buckets
            .entry(client_id.to_string())
            .or_insert_with(|| ClientBucket::new(policy));

        match bucket.try_consume(max_output_tokens) {
            RateLimitResult::Allowed => Ok(()),
            RateLimitResult::RequestLimitExceeded {
                violations_this_minute,
            } => {
                if violations_this_minute >= self.violation_alert_threshold {
                    tracing::warn!(
                        client_id = client_id,
                        violations = violations_this_minute,
                        "Sustained rate limit violations — possible attack"
                    );
                }
                Err(CordonError::RateLimitExceeded {
                    client_id: client_id.to_string(),
                })
            }
            RateLimitResult::TokenLimitExceeded {
                available,
                violations_this_minute,
            } => {
                tracing::debug!(
                    client_id = client_id,
                    available_tokens = available,
                    "Token rate limit exceeded"
                );
                if violations_this_minute >= self.violation_alert_threshold {
                    tracing::warn!(
                        client_id = client_id,
                        violations = violations_this_minute,
                        "Sustained token rate limit violations"
                    );
                }
                Err(CordonError::RateLimitExceeded {
                    client_id: client_id.to_string(),
                })
            }
        }
    }

    /// Settle a client's output-token reservation once the actual number of
    /// generated tokens is known (called after inference completes).
    pub fn settle(&self, client_id: &str, reserved: u32, actual: u32) {
        if let Some(bucket) = self.buckets.lock().get_mut(client_id) {
            bucket.settle(reserved, actual);
        }
    }

    /// Update bucket parameters when a policy changes
    pub fn update_policy(&self, policy: &ClientPolicy) {
        let mut buckets = self.buckets.lock();
        if let Some(bucket) = buckets.get_mut(&policy.client_id) {
            bucket.max_requests_per_minute = policy.max_requests_per_minute as f64;
            bucket.max_tokens_per_minute = policy.max_tokens_per_minute as f64;
        }
    }

    /// Remove a client's bucket (on suspension or removal)
    pub fn remove_client(&self, client_id: &str) {
        self.buckets.lock().remove(client_id);
    }

    /// Get violation count for a client in the current window
    pub fn violations_this_minute(&self, client_id: &str) -> u32 {
        self.buckets
            .lock()
            .get(client_id)
            .map(|b| b.violations_this_minute)
            .unwrap_or(0)
    }

    /// Prune buckets for clients that haven't made requests recently
    pub fn prune_stale_buckets(&self, stale_after_secs: i64) {
        let cutoff = Utc::now() - chrono::Duration::seconds(stale_after_secs);
        self.buckets.lock().retain(|_, b| b.last_refill > cutoff);
    }
}
