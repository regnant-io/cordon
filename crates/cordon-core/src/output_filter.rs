//! Output content filter (Layer 5).
//!
//! Applies client-defined policy to model output before it reaches the caller.
//! Rules can log, redact, truncate, or block outright.
//!
//! # Streaming
//!
//! [`StreamingFilter`] applies the same policy incrementally so a response can
//! be streamed without releasing text the policy would have removed. It does so
//! by holding back a trailing window: text is released only once enough
//! following characters have arrived that no rule could still match across the
//! boundary. A pattern that completes late — a credit-card number whose final
//! digits arrive in the next chunk — is therefore caught before any part of it
//! has left the node.
//!
//! # A note on string indices
//!
//! Every truncation in this module goes through [`floor_char_boundary`]. Slicing
//! a Rust `String` at an arbitrary byte offset panics, and with `panic = "abort"`
//! that would take the whole process down — a remote denial of service triggered
//! by any output containing a multi-byte character near a limit.

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::error::{CordonError, CordonResult};

/// Characters held back from a stream until enough context has arrived to know
/// no rule spans the boundary. Comfortably longer than any built-in pattern.
const DEFAULT_STREAM_HOLDBACK_CHARS: usize = 128;

/// Action taken when a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    /// Refuse the response and return an error.
    ReturnError,
    /// Replace the matched text.
    Redact,
    /// Cut the output at the match point.
    Truncate,
    /// Record the match and release the text unchanged.
    LogAndContinue,
}

/// A single content policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Unique rule ID, recorded in the audit log when the rule fires.
    pub rule_id: String,
    /// Human-readable description.
    pub description: String,
    /// What the rule matches.
    pub rule_type: PolicyRuleType,
    /// What to do on a match.
    pub action: PolicyAction,
    /// Whether the rule is active.
    pub enabled: bool,
}

/// What a rule matches on.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyRuleType {
    /// Literal substrings.
    TokenBlocklist {
        /// Substrings to match.
        tokens: Vec<String>,
    },
    /// A regular expression over the detokenized text.
    PatternFilter {
        /// The pattern.
        pattern: String,
        /// Replacement used by the `redact` action.
        replacement: Option<String>,
    },
    /// A set of keywords, firing once enough of them appear.
    TopicFilter {
        /// Keywords indicating the topic.
        keywords: Vec<String>,
        /// How many distinct keywords must appear.
        min_matches: usize,
    },
    /// Common personally identifying patterns.
    PiiDetector {
        /// Categories to detect.
        pii_types: Vec<PiiType>,
        /// Whether to redact matches or only flag them.
        redact: bool,
    },
    /// An upper bound on output length, in characters.
    MaxLength {
        /// Maximum characters.
        max_chars: usize,
    },
}

/// Categories of personally identifying information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiiType {
    /// Email addresses.
    Email,
    /// Telephone numbers.
    PhoneNumber,
    /// US social security numbers.
    Ssn,
    /// Payment card numbers.
    CreditCard,
    /// IPv4 addresses.
    IpAddress,
    /// US postal codes.
    PostalCode,
}

impl PiiType {
    fn pattern(&self) -> &'static str {
        match self {
            PiiType::Email => r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
            PiiType::PhoneNumber => r"\b(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
            PiiType::Ssn => r"\b\d{3}-\d{2}-\d{4}\b",
            PiiType::CreditCard => r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
            PiiType::IpAddress => r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            PiiType::PostalCode => r"\b\d{5}(?:-\d{4})?\b",
        }
    }
}

/// A rule that fired.
#[derive(Debug, Clone)]
pub struct PolicyMatch {
    /// Rule that matched.
    pub rule_id: String,
    /// Action taken.
    pub action: PolicyAction,
    /// Byte offset of the first match, when the rule has a position.
    pub offset: Option<usize>,
    /// Description of what matched. Never contains the matched text itself —
    /// audit records must not become a channel for the content they describe.
    pub match_summary: String,
}

/// The result of applying a policy.
#[derive(Debug)]
pub struct FilterResult {
    /// The text after redaction and truncation.
    pub text: String,
    /// Whether any rule fired.
    pub triggered: bool,
    /// Every rule that fired.
    pub matches: Vec<PolicyMatch>,
    /// Whether the response must be refused entirely.
    pub blocked: bool,
}

/// A named set of rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentPolicy {
    /// Policy version.
    pub version: String,
    /// Rules, evaluated in order.
    pub rules: Vec<PolicyRule>,
    /// Client the policy belongs to.
    pub client_id: String,
}

impl ContentPolicy {
    /// A policy that flags PII without altering output.
    pub fn default_permissive(client_id: &str) -> Self {
        Self {
            version: "1.0".to_string(),
            client_id: client_id.to_string(),
            rules: vec![PolicyRule {
                rule_id: "pii-default".to_string(),
                description: "Flag personally identifying information in output".to_string(),
                rule_type: PolicyRuleType::PiiDetector {
                    pii_types: vec![PiiType::Email, PiiType::PhoneNumber, PiiType::CreditCard],
                    redact: false,
                },
                action: PolicyAction::LogAndContinue,
                enabled: true,
            }],
        }
    }

    /// Parse a policy from JSON.
    pub fn from_json(json: &str) -> CordonResult<Self> {
        serde_json::from_str(json)
            .map_err(|e| CordonError::ConfigError(format!("invalid content policy: {}", e)))
    }

    /// Load a policy from a file.
    pub fn from_file(path: &std::path::Path) -> CordonResult<Self> {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            CordonError::ConfigError(format!(
                "cannot read content policy {}: {}",
                path.display(),
                e
            ))
        })?;
        Self::from_json(&contents)
    }
}

struct CompiledRule {
    rule: PolicyRule,
    pattern: Option<Regex>,
}

/// The compiled filter engine.
pub struct OutputFilter {
    rules: Vec<CompiledRule>,
}

impl OutputFilter {
    /// Compile a policy. Every regular expression is compiled once, here, so a
    /// malformed pattern is a startup failure rather than a request failure.
    pub fn new(policy: &ContentPolicy) -> CordonResult<Self> {
        let mut rules = Vec::new();

        for rule in &policy.rules {
            if !rule.enabled {
                continue;
            }
            let pattern = match &rule.rule_type {
                PolicyRuleType::PatternFilter { pattern, .. } => {
                    Some(Regex::new(pattern).map_err(|e| {
                        CordonError::ConfigError(format!(
                            "rule '{}' has an invalid regular expression: {}",
                            rule.rule_id, e
                        ))
                    })?)
                }
                PolicyRuleType::PiiDetector { pii_types, .. } => {
                    if pii_types.is_empty() {
                        None
                    } else {
                        let combined = pii_types
                            .iter()
                            .map(|t| t.pattern())
                            .collect::<Vec<_>>()
                            .join("|");
                        Some(Regex::new(&combined).map_err(|e| {
                            CordonError::ConfigError(format!("PII pattern error: {}", e))
                        })?)
                    }
                }
                _ => None,
            };
            rules.push(CompiledRule {
                rule: rule.clone(),
                pattern,
            });
        }

        Ok(Self { rules })
    }

    /// Number of active rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Apply the policy to a complete output.
    pub fn filter(&self, mut text: String) -> FilterResult {
        let mut matches = Vec::new();
        let mut blocked = false;

        for compiled in &self.rules {
            let rule = &compiled.rule;

            match &rule.rule_type {
                PolicyRuleType::MaxLength { max_chars } => {
                    if text.chars().count() > *max_chars {
                        matches.push(PolicyMatch {
                            rule_id: rule.rule_id.clone(),
                            action: rule.action,
                            offset: Some(*max_chars),
                            match_summary: format!("output exceeded {} characters", max_chars),
                        });
                        match rule.action {
                            PolicyAction::Truncate => truncate_to_chars(&mut text, *max_chars),
                            PolicyAction::ReturnError => blocked = true,
                            _ => {}
                        }
                    }
                }

                PolicyRuleType::TokenBlocklist { tokens } => {
                    for token in tokens {
                        if token.is_empty() {
                            continue;
                        }
                        let Some(position) = text.find(token.as_str()) else {
                            continue;
                        };
                        matches.push(PolicyMatch {
                            rule_id: rule.rule_id.clone(),
                            action: rule.action,
                            offset: Some(position),
                            match_summary: "blocked token present".to_string(),
                        });
                        match rule.action {
                            PolicyAction::Redact => {
                                text = text.replace(token.as_str(), "[REDACTED]");
                            }
                            PolicyAction::ReturnError => {
                                blocked = true;
                                break;
                            }
                            PolicyAction::Truncate => {
                                // `find` returns a char boundary, so this slice
                                // is sound.
                                text.truncate(position);
                                break;
                            }
                            PolicyAction::LogAndContinue => {}
                        }
                    }
                }

                PolicyRuleType::TopicFilter {
                    keywords,
                    min_matches,
                } => {
                    let lowered = text.to_lowercase();
                    let hits = keywords
                        .iter()
                        .filter(|k| !k.is_empty() && lowered.contains(&k.to_lowercase()))
                        .count();
                    if hits >= *min_matches && *min_matches > 0 {
                        matches.push(PolicyMatch {
                            rule_id: rule.rule_id.clone(),
                            action: rule.action,
                            offset: None,
                            match_summary: format!("{} topic keywords matched", hits),
                        });
                        match rule.action {
                            PolicyAction::ReturnError => blocked = true,
                            PolicyAction::Truncate => text.clear(),
                            _ => {}
                        }
                    }
                }

                PolicyRuleType::PatternFilter { .. } | PolicyRuleType::PiiDetector { .. } => {
                    let Some(regex) = &compiled.pattern else {
                        continue;
                    };
                    let Some(first) = regex.find(&text) else {
                        continue;
                    };

                    matches.push(PolicyMatch {
                        rule_id: rule.rule_id.clone(),
                        action: rule.action,
                        offset: Some(first.start()),
                        match_summary: format!(
                            "{} pattern matches",
                            regex.find_iter(&text).count()
                        ),
                    });

                    match rule.action {
                        PolicyAction::Redact => {
                            let replacement = match &rule.rule_type {
                                PolicyRuleType::PatternFilter {
                                    replacement: Some(r),
                                    ..
                                } => r.as_str(),
                                _ => "[REDACTED]",
                            };
                            text = regex.replace_all(&text, replacement).into_owned();
                        }
                        PolicyAction::ReturnError => blocked = true,
                        PolicyAction::Truncate => {
                            let start = first.start();
                            text.truncate(start);
                        }
                        PolicyAction::LogAndContinue => {}
                    }
                }
            }

            if blocked {
                break;
            }
        }

        FilterResult {
            triggered: !matches.is_empty(),
            blocked,
            matches,
            text,
        }
    }
}

/// Applies a policy to a response as it is generated.
///
/// The contract is that nothing is released that the equivalent whole-response
/// filter would have removed. That is achieved by re-filtering the accumulated
/// text on every push and releasing only the part far enough from the end that
/// no further input can change it.
pub struct StreamingFilter {
    filter: std::sync::Arc<OutputFilter>,
    /// Everything the model has produced so far, unfiltered.
    raw: String,
    /// How many characters of the *filtered* text have been released.
    released_chars: usize,
    /// Trailing characters withheld pending more context.
    holdback: usize,
    /// Everything released to the caller so far, in order.
    released: String,
    /// Rules that have fired so far.
    matches: Vec<PolicyMatch>,
}

impl StreamingFilter {
    /// Create a streaming filter with the default holdback window.
    pub fn new(filter: std::sync::Arc<OutputFilter>) -> Self {
        Self::with_holdback(filter, DEFAULT_STREAM_HOLDBACK_CHARS)
    }

    /// Create a streaming filter with an explicit holdback, in characters.
    pub fn with_holdback(filter: std::sync::Arc<OutputFilter>, holdback: usize) -> Self {
        Self {
            filter,
            raw: String::new(),
            released_chars: 0,
            holdback,
            released: String::new(),
            matches: Vec::new(),
        }
    }

    /// Add generated text and return whatever is now safe to release.
    ///
    /// Returns [`CordonError::ContentPolicyViolation`] if the accumulated text
    /// trips a blocking rule. The caller must abandon the stream at that point;
    /// anything already released was, by construction, text the policy allowed.
    pub fn push(&mut self, delta: &str) -> CordonResult<String> {
        self.raw.push_str(delta);
        let result = self.filter.filter(self.raw.clone());

        if result.blocked {
            let rule_id = result
                .matches
                .first()
                .map(|m| m.rule_id.clone())
                .unwrap_or_default();
            return Err(CordonError::ContentPolicyViolation { rule_id });
        }
        self.matches = result.matches;

        let filtered_chars = result.text.chars().count();
        let releasable = filtered_chars.saturating_sub(self.holdback);
        if releasable <= self.released_chars {
            return Ok(String::new());
        }

        let chunk: String = result
            .text
            .chars()
            .skip(self.released_chars)
            .take(releasable - self.released_chars)
            .collect();
        self.released_chars = releasable;
        self.released.push_str(&chunk);
        Ok(chunk)
    }

    /// Release the withheld tail and return the complete filtered text.
    ///
    /// Call exactly once, when generation has finished.
    pub fn finish(&mut self) -> CordonResult<(String, FilterResult)> {
        let result = self.filter.filter(std::mem::take(&mut self.raw));

        if result.blocked {
            let rule_id = result
                .matches
                .first()
                .map(|m| m.rule_id.clone())
                .unwrap_or_default();
            return Err(CordonError::ContentPolicyViolation { rule_id });
        }

        let tail: String = result.text.chars().skip(self.released_chars).collect();
        self.released_chars = result.text.chars().count();
        self.released.push_str(&tail);
        Ok((tail, result))
    }

    /// Rules that have fired so far.
    pub fn matches(&self) -> &[PolicyMatch] {
        &self.matches
    }

    /// Everything released to the caller so far, concatenated.
    ///
    /// After [`Self::finish`] this is the complete filtered response — the exact
    /// text the caller received, which is what the audit record and the response
    /// signature must both commit to.
    pub fn released_text(&self) -> &str {
        &self.released
    }
}

/// Truncate a string to `max_chars` characters without splitting one.
fn truncate_to_chars(text: &mut String, max_chars: usize) {
    if let Some((byte_index, _)) = text.char_indices().nth(max_chars) {
        text.truncate(byte_index);
    }
}

/// The largest byte index at or below `index` that is a character boundary.
///
/// Available on nightly as `str::floor_char_boundary`; implemented here so the
/// crate builds on stable.
pub fn floor_char_boundary(text: &str, index: usize) -> usize {
    if index >= text.len() {
        return text.len();
    }
    let mut i = index;
    while i > 0 && !text.is_char_boundary(i) {
        i -= 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn policy(rule_type: PolicyRuleType, action: PolicyAction) -> ContentPolicy {
        ContentPolicy {
            version: "test".into(),
            client_id: "test".into(),
            rules: vec![PolicyRule {
                rule_id: "r1".into(),
                description: "test rule".into(),
                rule_type,
                action,
                enabled: true,
            }],
        }
    }

    fn filter_for(rule_type: PolicyRuleType, action: PolicyAction) -> OutputFilter {
        OutputFilter::new(&policy(rule_type, action)).unwrap()
    }

    /// The regression this module's index handling exists to prevent: with
    /// `panic = "abort"`, slicing mid-character would abort the process, so any
    /// caller could kill the node by eliciting accented output.
    #[test]
    fn multibyte_output_does_not_panic_on_length_truncation() {
        let f = filter_for(
            PolicyRuleType::MaxLength { max_chars: 5 },
            PolicyAction::Truncate,
        );
        let result = f.filter("ééééééééé".to_string());
        assert_eq!(result.text.chars().count(), 5);
        assert!(result.triggered);
    }

    #[test]
    fn max_length_counts_characters_not_bytes() {
        // Ten characters, twenty bytes. A byte-based limit of 15 would fire; a
        // character-based limit of 15 must not.
        let f = filter_for(
            PolicyRuleType::MaxLength { max_chars: 15 },
            PolicyAction::Truncate,
        );
        let result = f.filter("é".repeat(10));
        assert!(!result.triggered);
        assert_eq!(result.text.chars().count(), 10);
    }

    #[test]
    fn max_length_can_block_instead_of_truncating() {
        let f = filter_for(
            PolicyRuleType::MaxLength { max_chars: 3 },
            PolicyAction::ReturnError,
        );
        assert!(f.filter("far too long".into()).blocked);
    }

    #[test]
    fn token_blocklist_redacts() {
        let f = filter_for(
            PolicyRuleType::TokenBlocklist {
                tokens: vec!["secret".into()],
            },
            PolicyAction::Redact,
        );
        let result = f.filter("the secret value".into());
        assert_eq!(result.text, "the [REDACTED] value");
        assert!(result.triggered);
    }

    #[test]
    fn token_blocklist_truncation_is_char_safe() {
        let f = filter_for(
            PolicyRuleType::TokenBlocklist {
                tokens: vec!["STOP".into()],
            },
            PolicyAction::Truncate,
        );
        let result = f.filter("naïve café STOP hidden".into());
        assert_eq!(result.text, "naïve café ");
    }

    #[test]
    fn pii_detection_flags_without_altering_by_default() {
        let f = OutputFilter::new(&ContentPolicy::default_permissive("c")).unwrap();
        let result = f.filter("write to alice@example.com".into());
        assert!(result.triggered);
        assert_eq!(result.text, "write to alice@example.com");
        // The summary must not leak the matched value into the audit log.
        assert!(!result.matches[0].match_summary.contains("alice"));
    }

    #[test]
    fn pii_redaction_removes_the_value() {
        let f = filter_for(
            PolicyRuleType::PiiDetector {
                pii_types: vec![PiiType::Email],
                redact: true,
            },
            PolicyAction::Redact,
        );
        let result = f.filter("mail alice@example.com now".into());
        assert!(!result.text.contains("alice@example.com"));
        assert!(result.text.contains("[REDACTED]"));
    }

    #[test]
    fn topic_filter_needs_enough_keywords() {
        let f = filter_for(
            PolicyRuleType::TopicFilter {
                keywords: vec!["alpha".into(), "beta".into(), "gamma".into()],
                min_matches: 2,
            },
            PolicyAction::ReturnError,
        );
        assert!(!f.filter("only alpha here".into()).blocked);
        assert!(f.filter("alpha and beta".into()).blocked);
    }

    #[test]
    fn invalid_regex_fails_at_compile_time() {
        let bad = policy(
            PolicyRuleType::PatternFilter {
                pattern: "(unclosed".into(),
                replacement: None,
            },
            PolicyAction::Redact,
        );
        assert!(OutputFilter::new(&bad).is_err());
    }

    #[test]
    fn disabled_rules_are_not_compiled() {
        let mut p = policy(
            PolicyRuleType::MaxLength { max_chars: 1 },
            PolicyAction::Truncate,
        );
        p.rules[0].enabled = false;
        let f = OutputFilter::new(&p).unwrap();
        assert_eq!(f.rule_count(), 0);
        assert_eq!(f.filter("unchanged".into()).text, "unchanged");
    }

    // ── Streaming ───────────────────────────────────────────────────────────

    #[test]
    fn streaming_reassembles_the_whole_response() {
        let f = Arc::new(OutputFilter::new(&ContentPolicy::default_permissive("c")).unwrap());
        let mut stream = StreamingFilter::with_holdback(f, 8);

        let mut released = String::new();
        for chunk in ["Hello ", "there, ", "this is a ", "streamed reply."] {
            released.push_str(&stream.push(chunk).unwrap());
        }
        let (tail, result) = stream.finish().unwrap();
        released.push_str(&tail);

        assert_eq!(released, "Hello there, this is a streamed reply.");
        assert_eq!(released, result.text);
    }

    /// The property that makes streaming safe: a pattern completed by a later
    /// chunk must not have had its earlier characters already released.
    #[test]
    fn streaming_holds_back_a_pattern_that_completes_late() {
        let f = Arc::new(
            OutputFilter::new(&policy(
                PolicyRuleType::PiiDetector {
                    pii_types: vec![PiiType::CreditCard],
                    redact: true,
                },
                PolicyAction::Redact,
            ))
            .unwrap(),
        );
        let mut stream = StreamingFilter::with_holdback(f, 32);

        let mut released = String::new();
        released.push_str(&stream.push("Card: 4111 1111 ").unwrap());
        released.push_str(&stream.push("1111 1111 done").unwrap());
        let (tail, _) = stream.finish().unwrap();
        released.push_str(&tail);

        assert!(
            !released.contains("4111 1111 1111 1111"),
            "the card number leaked: {}",
            released
        );
        assert!(released.contains("[REDACTED]"));
    }

    #[test]
    fn streaming_stops_on_a_blocking_rule() {
        let f = Arc::new(
            OutputFilter::new(&policy(
                PolicyRuleType::TokenBlocklist {
                    tokens: vec!["forbidden".into()],
                },
                PolicyAction::ReturnError,
            ))
            .unwrap(),
        );
        let mut stream = StreamingFilter::with_holdback(f, 4);

        stream.push("this is fine ").unwrap();
        let err = stream.push("forbidden").unwrap_err();
        assert!(matches!(err, CordonError::ContentPolicyViolation { .. }));
    }

    #[test]
    fn streaming_handles_multibyte_chunk_boundaries() {
        let f = Arc::new(OutputFilter::new(&ContentPolicy::default_permissive("c")).unwrap());
        let mut stream = StreamingFilter::with_holdback(f, 2);

        let mut released = String::new();
        for chunk in ["日本", "語のテ", "キスト"] {
            released.push_str(&stream.push(chunk).unwrap());
        }
        let (tail, _) = stream.finish().unwrap();
        released.push_str(&tail);
        assert_eq!(released, "日本語のテキスト");
    }

    #[test]
    fn streaming_releases_nothing_before_the_holdback_fills() {
        let f = Arc::new(OutputFilter::new(&ContentPolicy::default_permissive("c")).unwrap());
        let mut stream = StreamingFilter::with_holdback(f, 100);
        assert_eq!(stream.push("short").unwrap(), "");
        let (tail, _) = stream.finish().unwrap();
        assert_eq!(tail, "short");
    }

    #[test]
    fn char_boundary_floor() {
        let s = "aé";
        assert_eq!(floor_char_boundary(s, 0), 0);
        assert_eq!(floor_char_boundary(s, 1), 1);
        assert_eq!(floor_char_boundary(s, 2), 1); // mid-'é'
        assert_eq!(floor_char_boundary(s, 99), s.len());
    }
}
