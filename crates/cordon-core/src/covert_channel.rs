//! Covert Channel Detector — Layer 5, §8.1
#![allow(missing_docs)] // analysis score fields are self-describing
//!
//! Detects anomalous output patterns that may encode sensitive data.
//! Threats: steganography, encoding, systematic patterns in output.

use serde::{Deserialize, Serialize};

/// Result of covert channel analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CovertChannelAnalysis {
    /// Overall anomaly score (0.0 = clean, 1.0 = highly suspicious)
    pub anomaly_score: f32,
    /// Whether a covert channel was detected (score > threshold)
    pub detected: bool,
    /// Individual detection scores
    pub entropy_score: f32,
    pub pattern_score: f32,
    pub length_score: f32,
    pub whitespace_score: f32,
    /// Human-readable findings
    pub findings: Vec<String>,
}

/// Covert channel detector configuration
#[derive(Debug, Clone)]
pub struct CovertChannelConfig {
    /// Score threshold to trigger a detection
    pub detection_threshold: f32,
    /// Expected entropy range for normal text
    pub normal_entropy_min: f32,
    pub normal_entropy_max: f32,
    /// Base64-density threshold (fraction of output that looks like base64)
    pub base64_density_threshold: f32,
    /// Hex-density threshold
    pub hex_density_threshold: f32,
    /// Unusual whitespace fraction threshold
    pub whitespace_anomaly_threshold: f32,
}

impl Default for CovertChannelConfig {
    fn default() -> Self {
        Self {
            detection_threshold: 0.6,
            normal_entropy_min: 3.5,
            normal_entropy_max: 5.5,
            base64_density_threshold: 0.25,
            hex_density_threshold: 0.20,
            whitespace_anomaly_threshold: 0.15,
        }
    }
}

/// Covert channel detector
pub struct CovertChannelDetector {
    config: CovertChannelConfig,
}

impl CovertChannelDetector {
    /// Create a new detector
    pub fn new(config: CovertChannelConfig) -> Self {
        Self { config }
    }

    /// Analyze output for covert channel signals
    pub fn analyze(&self, text: &str) -> CovertChannelAnalysis {
        if text.is_empty() {
            return CovertChannelAnalysis {
                anomaly_score: 0.0,
                detected: false,
                entropy_score: 0.0,
                pattern_score: 0.0,
                length_score: 0.0,
                whitespace_score: 0.0,
                findings: vec![],
            };
        }

        let mut findings = Vec::new();

        // A. Entropy analysis
        let entropy = self.compute_char_entropy(text);
        let entropy_score = self.score_entropy(entropy);
        if entropy_score > 0.5 {
            findings.push(format!(
                "High character entropy ({:.2} bits/char, expected {:.1}–{:.1})",
                entropy, self.config.normal_entropy_min, self.config.normal_entropy_max
            ));
        }

        // B. Pattern analysis
        let pattern_score = self.score_patterns(text, &mut findings);

        // C. Length anomaly (very short inputs generating very long outputs)
        let length_score = 0.0; // Requires input context — set by caller if available

        // D. Whitespace/punctuation pattern
        let whitespace_score = self.score_whitespace_patterns(text, &mut findings);

        // Combine scores with weights
        let anomaly_score = (entropy_score * 0.35
            + pattern_score * 0.40
            + length_score * 0.15
            + whitespace_score * 0.10)
            .min(1.0);

        let detected = anomaly_score >= self.config.detection_threshold;

        if detected {
            tracing::warn!(
                anomaly_score = anomaly_score,
                findings = ?findings,
                "Covert channel detection triggered"
            );
        }

        CovertChannelAnalysis {
            anomaly_score,
            detected,
            entropy_score,
            pattern_score,
            length_score,
            whitespace_score,
            findings,
        }
    }

    /// Compute Shannon entropy of character distribution
    fn compute_char_entropy(&self, text: &str) -> f32 {
        let mut counts = [0u32; 256];
        let mut total = 0u32;
        for b in text.bytes() {
            counts[b as usize] += 1;
            total += 1;
        }
        if total == 0 {
            return 0.0;
        }
        let mut entropy = 0.0f64;
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / total as f64;
                entropy -= p * p.log2();
            }
        }
        entropy as f32
    }

    /// Score based on entropy deviation from normal text
    fn score_entropy(&self, entropy: f32) -> f32 {
        let min = self.config.normal_entropy_min;
        let max = self.config.normal_entropy_max;
        if entropy >= min && entropy <= max {
            return 0.0; // Normal range
        }
        if entropy > max {
            // Anomalously high entropy (random-looking data)
            let excess = entropy - max;
            (excess / 2.0).min(1.0)
        } else {
            // Anomalously low entropy (repetitive patterns)
            let deficit = min - entropy;
            (deficit / 2.0).min(0.5)
        }
    }

    /// Score based on structural patterns (base64, hex, numeric density)
    fn score_patterns(&self, text: &str, findings: &mut Vec<String>) -> f32 {
        let total_chars = text.len() as f32;
        if total_chars == 0.0 {
            return 0.0;
        }

        let mut max_score = 0.0f32;

        // Check base64 density
        let _base64_chars = text
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
            .count() as f32;
        // Only suspicious in contiguous runs — approximate with window analysis
        let b64_density = self.compute_contiguous_density(text, |c| {
            c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
        });
        if b64_density > self.config.base64_density_threshold {
            findings.push(format!(
                "Base64-like content density: {:.1}%",
                b64_density * 100.0
            ));
            max_score = max_score.max(b64_density.min(1.0));
        }

        // Check hex density
        let hex_density = self.compute_contiguous_density(text, |c| c.is_ascii_hexdigit());
        if hex_density > self.config.hex_density_threshold {
            findings.push(format!(
                "Hex-like content density: {:.1}%",
                hex_density * 100.0
            ));
            max_score = max_score.max(hex_density.min(1.0));
        }

        // Check for numeric-dense patterns (potential encoded data)
        let digit_fraction =
            text.chars().filter(|c| c.is_ascii_digit()).count() as f32 / total_chars;
        if digit_fraction > 0.30 {
            findings.push(format!(
                "High numeric density: {:.1}%",
                digit_fraction * 100.0
            ));
            max_score = max_score.max((digit_fraction - 0.30) * 3.0);
        }

        // Detect repeated structural patterns (e.g., JSON/array-like patterns)
        if self.has_suspicious_repeated_structure(text) {
            findings.push("Suspicious repeated structural pattern detected".to_string());
            max_score = max_score.max(0.6);
        }

        max_score.min(1.0)
    }

    /// Compute density of characters satisfying a predicate in contiguous runs
    fn compute_contiguous_density<F>(&self, text: &str, pred: F) -> f32
    where
        F: Fn(char) -> bool,
    {
        let mut max_run = 0usize;
        let mut current_run = 0usize;
        for c in text.chars() {
            if pred(c) {
                current_run += 1;
                max_run = max_run.max(current_run);
            } else {
                current_run = 0;
            }
        }
        let total = text.chars().count().max(1);
        (max_run as f32 / total as f32).min(1.0)
    }

    /// Detect suspicious repeated structural patterns
    fn has_suspicious_repeated_structure(&self, text: &str) -> bool {
        // Look for patterns like: repeated comma-separated numbers, repeated JSON keys, etc.
        // Simple heuristic: check if text contains 5+ consecutive tokens with identical delimiters
        let bytes = text.as_bytes();
        if bytes.len() < 40 {
            return false;
        }
        // Count delimiter characters (comma, semicolon, pipe)
        let delimiters = bytes
            .iter()
            .filter(|&&b| b == b',' || b == b';' || b == b'|')
            .count();
        // If >15% of text is delimiters, suspicious
        delimiters as f32 / bytes.len() as f32 > 0.15
    }

    /// Score whitespace and non-printing character patterns
    fn score_whitespace_patterns(&self, text: &str, findings: &mut Vec<String>) -> f32 {
        let total = text.chars().count() as f32;
        if total == 0.0 {
            return 0.0;
        }

        // Count non-standard whitespace / zero-width characters
        let suspicious_whitespace = text
            .chars()
            .filter(|c| {
                matches!(
                    c,
                    '\u{200B}'
                        | '\u{200C}'
                        | '\u{200D}'
                        | '\u{FEFF}'
                        | '\u{00A0}'
                        | '\u{2009}'
                        | '\u{200A}'
                        | '\u{202F}'
                )
            })
            .count() as f32;

        let fraction = suspicious_whitespace / total;
        if fraction > self.config.whitespace_anomaly_threshold {
            findings.push(format!(
                "Suspicious zero-width/non-standard whitespace: {:.1}% of output",
                fraction * 100.0
            ));
            return (fraction * 5.0).min(1.0);
        }

        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_text_low_score() {
        let detector = CovertChannelDetector::new(CovertChannelConfig::default());
        let normal = "This is a perfectly normal response about machine learning and AI systems. \
            The model was trained on diverse data and can answer questions about many topics.";
        let result = detector.analyze(normal);
        assert!(!result.detected, "Normal text should not trigger detection");
        assert!(
            result.anomaly_score < 0.4,
            "Normal text anomaly score too high: {}",
            result.anomaly_score
        );
    }

    #[test]
    fn test_base64_heavy_text_triggers() {
        let detector = CovertChannelDetector::new(CovertChannelConfig::default());
        // Simulated base64-encoded data in output
        let suspicious = "Here is your result: dGhpcyBpcyBhIHNlY3JldCBtZXNzYWdlIGVuY29kZWQgaW4gYmFzZTY0 and more: \
            aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3QgZm9yIGNvdmVydCBjaGFubmVsIGRldGVjdGlvbg==";
        let result = detector.analyze(suspicious);
        // Should have elevated score
        assert!(
            result.pattern_score > 0.1,
            "Base64-heavy content should elevate pattern score"
        );
    }

    #[test]
    fn test_entropy_computation() {
        let detector = CovertChannelDetector::new(CovertChannelConfig::default());
        // Uniform random bytes → high entropy
        let random_text: String = (0..200).map(|i| (b'A' + (i % 26)) as char).collect();
        let entropy = detector.compute_char_entropy(&random_text);
        assert!(entropy > 3.0, "Random text should have high entropy");
    }
}
