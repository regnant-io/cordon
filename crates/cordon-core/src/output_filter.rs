//! Output Filter — Layer 5, §8.1
//!
//! Applies client-defined content policies to raw model output.
//! Policy is loaded from signed output_policy.json — vendor cannot modify
//! without client re-signature.

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::error::{CordonError, CordonResult};

/// Action to take when a policy rule is triggered
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    /// Return an error to the caller
    ReturnError,
    /// Redact the matched text
    Redact,
    /// Truncate output at the match point
    Truncate,
    /// Log the match and continue
    LogAndContinue,
}

/// A single content policy rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Unique rule ID
    pub rule_id: String,
    /// Human-readable description
    pub description: String,
    /// Rule type
    pub rule_type: PolicyRuleType,
    /// Action to take when triggered
    pub action: PolicyAction,
    /// Whether this rule is enabled
    pub enabled: bool,
}

/// Type of policy rule
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyRuleType {
    /// Exact token-level blocklist
    TokenBlocklist {
        /// Token strings to block
        tokens: Vec<String>,
    },
    /// Regex pattern match on detokenized text
    PatternFilter {
        /// Regex pattern
        pattern: String,
        /// Replacement string (for Redact action)
        replacement: Option<String>,
    },
    /// Keyword-based topic filter
    TopicFilter {
        /// Keywords that indicate a blocked topic
        keywords: Vec<String>,
        /// Minimum number of keywords to trigger
        min_matches: usize,
    },
    /// PII detector — flags or redacts common PII patterns
    PiiDetector {
        /// PII types to detect
        pii_types: Vec<PiiType>,
        /// Whether to redact or just flag
        redact: bool,
    },
    /// Maximum output length
    MaxLength {
        /// Maximum characters allowed
        max_chars: usize,
    },
}

/// Types of PII to detect
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiiType {
    /// Email addresses
    Email,
    /// Phone numbers
    PhoneNumber,
    /// Social security numbers
    Ssn,
    /// Credit card numbers
    CreditCard,
    /// IP addresses
    IpAddress,
    /// US postal codes
    PostalCode,
}

/// Output of a policy rule evaluation
#[derive(Debug, Clone)]
pub struct PolicyMatch {
    /// Rule that triggered
    pub rule_id: String,
    /// Action taken
    pub action: PolicyAction,
    /// Offset in the text where the match occurred (if applicable)
    pub offset: Option<usize>,
    /// Summary of what was matched (not the actual content)
    pub match_summary: String,
}

/// Result of output filtering
#[derive(Debug)]
pub struct FilterResult {
    /// Filtered (possibly modified) text
    pub text: String,
    /// Whether any policy was triggered
    pub triggered: bool,
    /// All policy matches
    pub matches: Vec<PolicyMatch>,
    /// Whether inference was blocked entirely
    pub blocked: bool,
}

/// Content policy — loaded from signed output_policy.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentPolicy {
    /// Policy version
    pub version: String,
    /// Rules in evaluation order
    pub rules: Vec<PolicyRule>,
    /// Client ID this policy belongs to
    pub client_id: String,
}

impl ContentPolicy {
    /// Default permissive policy
    pub fn default_permissive(client_id: &str) -> Self {
        Self {
            version: "1.0".to_string(),
            client_id: client_id.to_string(),
            rules: vec![
                PolicyRule {
                    rule_id: "pii-default".to_string(),
                    description: "Flag PII in outputs".to_string(),
                    rule_type: PolicyRuleType::PiiDetector {
                        pii_types: vec![PiiType::Email, PiiType::PhoneNumber, PiiType::CreditCard],
                        redact: false,
                    },
                    action: PolicyAction::LogAndContinue,
                    enabled: true,
                },
            ],
        }
    }

    /// Load from a JSON string
    pub fn from_json(json: &str) -> CordonResult<Self> {
        serde_json::from_str(json)
            .map_err(|e| CordonError::Internal(format!("Invalid policy JSON: {}", e)))
    }
}

/// Compiled policy rule with pre-compiled regexes
struct CompiledRule {
    rule: PolicyRule,
    compiled_pattern: Option<Regex>,
}

/// Output filter engine
pub struct OutputFilter {
    compiled_rules: Vec<CompiledRule>,
}

impl OutputFilter {
    /// Create a new output filter from a content policy
    pub fn new(policy: &ContentPolicy) -> CordonResult<Self> {
        let mut compiled = Vec::new();
        for rule in &policy.rules {
            if !rule.enabled {
                continue;
            }
            let pattern = match &rule.rule_type {
                PolicyRuleType::PatternFilter { pattern, .. } => {
                    Some(Regex::new(pattern)
                        .map_err(|e| CordonError::Internal(
                            format!("Invalid regex in rule {}: {}", rule.rule_id, e)
                        ))?)
                }
                PolicyRuleType::PiiDetector { pii_types, .. } => {
                    // Build combined PII regex
                    let patterns: Vec<&str> = pii_types.iter().map(|t| match t {
                        PiiType::Email => r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
                        PiiType::PhoneNumber => r"\b(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
                        PiiType::Ssn => r"\b\d{3}-\d{2}-\d{4}\b",
                        PiiType::CreditCard => r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
                        PiiType::IpAddress => r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                        PiiType::PostalCode => r"\b\d{5}(?:-\d{4})?\b",
                    }).collect();
                    let combined = patterns.join("|");
                    Some(Regex::new(&combined)
                        .map_err(|e| CordonError::Internal(format!("PII regex error: {}", e)))?)
                }
                _ => None,
            };
            compiled.push(CompiledRule {
                rule: rule.clone(),
                compiled_pattern: pattern,
            });
        }
        Ok(Self { compiled_rules: compiled })
    }

    /// Apply the policy to raw output text
    pub fn filter(&self, mut text: String) -> FilterResult {
        let mut matches = Vec::new();
        let mut blocked = false;

        for compiled in &self.compiled_rules {
            let rule = &compiled.rule;

            match &rule.rule_type {
                PolicyRuleType::MaxLength { max_chars } => {
                    if text.len() > *max_chars {
                        matches.push(PolicyMatch {
                            rule_id: rule.rule_id.clone(),
                            action: rule.action.clone(),
                            offset: Some(*max_chars),
                            match_summary: format!("Output exceeded {} chars", max_chars),
                        });
                        match &rule.action {
                            PolicyAction::Truncate => {
                                text = text[..*max_chars].to_string();
                            }
                            PolicyAction::ReturnError => {
                                blocked = true;
                            }
                            _ => {}
                        }
                    }
                }

                PolicyRuleType::TokenBlocklist { tokens } => {
                    for token in tokens {
                        if text.contains(token.as_str()) {
                            matches.push(PolicyMatch {
                                rule_id: rule.rule_id.clone(),
                                action: rule.action.clone(),
                                offset: text.find(token.as_str()),
                                match_summary: format!("Blocked token detected"),
                            });
                            match &rule.action {
                                PolicyAction::Redact => {
                                    text = text.replace(token.as_str(), "[REDACTED]");
                                }
                                PolicyAction::ReturnError => {
                                    blocked = true;
                                    break;
                                }
                                PolicyAction::Truncate => {
                                    if let Some(pos) = text.find(token.as_str()) {
                                        text = text[..pos].to_string();
                                    }
                                    break;
                                }
                                PolicyAction::LogAndContinue => {}
                            }
                        }
                    }
                }

                PolicyRuleType::TopicFilter { keywords, min_matches } => {
                    let lower = text.to_lowercase();
                    let count = keywords.iter()
                        .filter(|k| lower.contains(k.to_lowercase().as_str()))
                        .count();
                    if count >= *min_matches {
                        matches.push(PolicyMatch {
                            rule_id: rule.rule_id.clone(),
                            action: rule.action.clone(),
                            offset: None,
                            match_summary: format!("{} topic keywords matched", count),
                        });
                        if matches!(rule.action, PolicyAction::ReturnError) {
                            blocked = true;
                        }
                    }
                }

                PolicyRuleType::PatternFilter { .. }
                | PolicyRuleType::PiiDetector { .. } => {
                    if let Some(re) = &compiled.compiled_pattern {
                        if re.is_match(&text) {
                            let match_count = re.find_iter(&text).count();
                            matches.push(PolicyMatch {
                                rule_id: rule.rule_id.clone(),
                                action: rule.action.clone(),
                                offset: re.find(&text).map(|m| m.start()),
                                match_summary: format!("{} pattern matches found", match_count),
                            });
                            match &rule.action {
                                PolicyAction::Redact => {
                                    let repl = match &rule.rule_type {
                                        PolicyRuleType::PatternFilter { replacement: Some(r), .. } => r.as_str(),
                                        _ => "[REDACTED]",
                                    };
                                    text = re.replace_all(&text, repl).to_string();
                                }
                                PolicyAction::ReturnError => {
                                    blocked = true;
                                }
                                PolicyAction::Truncate => {
                                    if let Some(m) = re.find(&text) {
                                        text = text[..m.start()].to_string();
                                    }
                                }
                                PolicyAction::LogAndContinue => {}
                            }
                        }
                    }
                }
            }

            if blocked {
                break;
            }
        }

        let triggered = !matches.is_empty();
        FilterResult { text, triggered, matches, blocked }
    }
}
