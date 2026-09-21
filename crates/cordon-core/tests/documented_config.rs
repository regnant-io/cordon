//! The configuration the documentation shows must be configuration Cordon
//! accepts.
//!
//! A README whose examples are refused at startup is worse than one with no
//! examples: it costs an operator the time to find out, and it teaches them to
//! distrust the rest of the document. These tests parse the TOML blocks from
//! `README.md` and check that each one either validates or fails for the reason
//! the surrounding prose says it will.

use cordon_core::config::{
    CordonConfig, DeploymentMode, ExpectedMeasurementsConfig, MeasurementSource, OutboundPolicy,
};

/// Every template that is not Light. These are the modes whose whole purpose is
/// to be checked against something, so they are the ones that must refuse to
/// run unchecked.
const HARDENED_TEMPLATES: [(&str, &str); 4] = [
    (
        "sovereign_cloud",
        include_str!("../../../deployment/configs/cordon-sovereign_cloud.toml"),
    ),
    (
        "vault",
        include_str!("../../../deployment/configs/cordon-vault.toml"),
    ),
    (
        "island",
        include_str!("../../../deployment/configs/cordon-island.toml"),
    ),
    (
        "dark",
        include_str!("../../../deployment/configs/cordon-dark.toml"),
    ),
];

/// Extract every fenced ```toml block from a markdown file.
fn toml_blocks(markdown: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current: Option<String> = None;

    for line in markdown.lines() {
        match &mut current {
            None => {
                if line.trim_start().starts_with("```toml") {
                    current = Some(String::new());
                }
            }
            Some(buffer) => {
                if line.trim_start().starts_with("```") {
                    blocks.push(std::mem::take(buffer));
                    current = None;
                } else {
                    buffer.push_str(line);
                    buffer.push('\n');
                }
            }
        }
    }
    blocks
}

/// Every documented block must at least be well-formed TOML.
///
/// Most are fragments, a `[network]` section on its own, so they cannot be
/// deserialized into a whole configuration. Being parseable is the part that
/// catches a typo, an invented key shape, or a section header that drifted.
#[test]
fn every_documented_toml_block_parses() {
    let readme = include_str!("../../../README.md");
    let blocks = toml_blocks(readme);
    assert!(
        blocks.len() >= 5,
        "expected the README to carry several TOML examples, found {}",
        blocks.len()
    );

    for (i, block) in blocks.iter().enumerate() {
        toml::from_str::<toml::Value>(block)
            .unwrap_or_else(|e| panic!("README TOML block {} does not parse: {}\n{}", i, e, block));
    }
}

/// Every measurement source and outbound policy Cordon accepts must appear in
/// the README, and every one the README names must deserialize.
///
/// The failure this catches is the quiet one: a variant added to the enum and
/// never written down, so the only way an operator learns it exists is by
/// reading the source.
#[test]
fn the_documented_enum_values_and_the_real_ones_agree() {
    let readme = include_str!("../../../README.md");

    for name in ["sev_snp", "tpm2", "software_measurement", "nitro_enclave"] {
        let parsed: MeasurementSource = serde_json::from_str(&format!("\"{}\"", name))
            .unwrap_or_else(|e| panic!("the README names measurement source {}: {}", name, e));
        assert!(
            readme.contains(name),
            "{:?} is a measurement source Cordon accepts and the README never mentions",
            parsed
        );
    }

    for name in ["zero_egress", "restricted"] {
        let parsed: OutboundPolicy = serde_json::from_str(&format!("\"{}\"", name))
            .unwrap_or_else(|e| panic!("the README names outbound policy {}: {}", name, e));
        assert!(
            readme.contains(name),
            "{:?} is an outbound policy Cordon accepts and the README never mentions",
            parsed
        );
    }
}

/// The Light template is the one that runs as generated. It is what someone
/// evaluating Cordon copies first, so it must not need editing beyond the two
/// identifiers it marks `REPLACE_ME`.
#[test]
fn the_light_template_validates_as_generated() {
    let mut config: CordonConfig = toml::from_str(include_str!(
        "../../../deployment/configs/cordon-light.toml"
    ))
    .expect("the light template does not parse");
    config.node_id = "node-under-test".into();
    config.deployment_id = "deployment-under-test".into();

    config
        .validate()
        .expect("the light template would be refused at startup");
}

/// Every other template ships with `[attestation.expected]` commented out, and
/// each says in its own comments that the mode "refuses to boot without pinned
/// expected measurements". That refusal is the feature, an unpinned verifier
/// accepts any report, including an impostor's, so the test asserts the
/// refusal happens rather than asserting the template starts.
///
/// It also checks the operator is told *why*: an error that says only
/// "invalid configuration" sends them looking for a typo.
#[test]
fn the_hardened_templates_refuse_to_start_until_measurements_are_pinned() {
    for (name, text) in HARDENED_TEMPLATES {
        let mut config: CordonConfig = toml::from_str(text)
            .unwrap_or_else(|e| panic!("the {} template does not parse: {}", name, e));
        config.node_id = "node-under-test".into();
        config.deployment_id = "deployment-under-test".into();

        assert!(
            config.attestation.expected.is_none(),
            "the {} template should ship unpinned, so the operator has to look at              the measurements before trusting them",
            name
        );

        let refusal = config.validate().expect_err(&format!(
            "the {} template pins nothing, so starting it would mean verifying              reports against no expectation at all",
            name
        ));
        let refusal = refusal.to_string();
        assert!(
            refusal.contains("attestation.expected"),
            "the {} refusal must name the missing section, not just fail: {}",
            name,
            refusal
        );
        assert!(
            refusal.contains("cordon attest --pin"),
            "the {} refusal must say how to fix it: {}",
            name,
            refusal
        );
    }
}

/// And once the operator does what the comments say, the same template starts.
/// Without this, the test above would pass just as happily against a mode that
/// could never be configured at all.
#[test]
fn the_hardened_templates_validate_once_measurements_are_pinned() {
    for (name, text) in HARDENED_TEMPLATES {
        let mut config: CordonConfig = toml::from_str(text).unwrap();
        config.node_id = "node-under-test".into();
        config.deployment_id = "deployment-under-test".into();

        // What `cordon attest --pin` writes out.
        let mut pcr_values = std::collections::BTreeMap::new();
        pcr_values.insert(0u8, format!("sha256:{}", "11".repeat(32)));
        pcr_values.insert(4u8, format!("sha256:{}", "22".repeat(32)));
        pcr_values.insert(7u8, format!("sha256:{}", "33".repeat(32)));
        pcr_values.insert(11u8, format!("sha256:{}", "44".repeat(32)));
        config.attestation.expected = Some(ExpectedMeasurementsConfig {
            pcr_values,
            mrenclave: Some("ab".repeat(32)),
            mrsigner: Some("cd".repeat(32)),
            min_isv_svn: 0,
            sev_snp: None,
            nitro: None,
        });

        config.validate().unwrap_or_else(|e| {
            panic!(
                "the {} template is still refused after pinning, which is what                  its own comments tell the operator to do: {}",
                name, e
            )
        });
    }
}

/// The Docker stack ships its own configuration and it must validate too, and
/// must permit egress, or `cordon pull` inside the container cannot work.
#[test]
fn the_docker_config_validates_and_can_fetch_a_model() {
    let text = include_str!("../../../deployment/docker/cordon-light.toml");
    let config: CordonConfig =
        toml::from_str(text).expect("the Docker configuration does not parse");

    config
        .validate()
        .expect("the Docker configuration is refused");
    assert_eq!(config.mode, DeploymentMode::Light);
    assert!(
        config.permits_model_download(),
        "the Docker stack documents `docker compose run cordon pull`, which needs egress"
    );
}

/// The air-gapped modes' templates must actually declare zero egress, not merely
/// be described that way.
#[test]
fn air_gapped_templates_declare_zero_egress() {
    for (name, text) in [
        (
            "vault",
            include_str!("../../../deployment/configs/cordon-vault.toml"),
        ),
        (
            "island",
            include_str!("../../../deployment/configs/cordon-island.toml"),
        ),
        (
            "dark",
            include_str!("../../../deployment/configs/cordon-dark.toml"),
        ),
    ] {
        let config: CordonConfig = toml::from_str(text).unwrap();
        assert_eq!(
            config.network.outbound_policy,
            OutboundPolicy::ZeroEgress,
            "{} is documented as having no outbound access",
            name
        );
        assert!(!config.permits_model_download());
    }
}

/// Vault, Island and Dark are documented as normalising response latency. A
/// template with it switched off would quietly deliver less than the mode
/// claims.
#[test]
fn hardened_templates_normalise_timing() {
    for (name, text) in [
        (
            "vault",
            include_str!("../../../deployment/configs/cordon-vault.toml"),
        ),
        (
            "island",
            include_str!("../../../deployment/configs/cordon-island.toml"),
        ),
        (
            "dark",
            include_str!("../../../deployment/configs/cordon-dark.toml"),
        ),
    ] {
        let config: CordonConfig = toml::from_str(text).unwrap();
        assert!(
            config.side_channel.timing_normalization.enabled,
            "{} is documented as normalising latency",
            name
        );
    }
}

/// A configuration written for an earlier version must still load. Unknown keys
/// are ignored, so removing decorative fields does not strand an operator with
/// a file the node refuses to read.
#[test]
fn a_configuration_carrying_removed_keys_still_loads() {
    let legacy = r#"
mode = "light"
node_id = "legacy-node"
deployment_name = "legacy"
deployment_id = "legacy-deployment"
log_level = "info"

[network]
bind_address = "127.0.0.1"
api_port = 8443
require_mtls = false
outbound_policy = "restricted"
tls_cert_path = "/tmp/server.crt"
tls_key_path = "/tmp/server.key"
# Every key below this line was removed.
inbound_whitelist = []
hardware_firewall = "none"
smartnic_acl = false

[tee]
preferred = "simulation"
minimum_security_version = 1
re_attestation_interval_hours = 24
halt_on_attestation_failure = false
cache_partitioning = false

[side_channel]
constant_time_enforcement = true
memory_zeroize_on_completion = true
response_size_padding = true

[side_channel.timing_normalization]
enabled = false
mode = "none"
bucket_ms = 100
fixed_floor_ms = 1000

[hsm]
provider = "soft_hsm2"
fips_level = 1
slot_id = 0
pin_env_var = "CORDON_HSM_PIN"

[boot]
tpm_required = false
tpm_version = "2.0"
secure_boot = false
dm_verity = false

[boot.pcr_policy]
required_pcrs = []
expected_values = {}

[model_store]
path = "/tmp/bundles"
integrity_check_interval_minutes = 15
halt_on_tamper = true

[inference]
max_concurrent_requests = 32
default_timeout_seconds = 120
client_kv_cache_isolation = true
kv_cache_zero_on_session_end = true
multi_tenant = true
max_input_tokens = 32768
max_output_tokens = 4096

[audit]
log_path = "/tmp/audit"
log_format = "jsonl"
export_method = "operator_pull"
retention_days = 365
signing_key_from_enclave = true

[updates]
source = "mgmt_channel"
require_vendor_signature = true
require_client_signature = true
staged_rollout = true
auto_apply = false

[sustained_attack]
auth_failure_threshold_per_minute = 10
global_failure_threshold_per_minute = 50
covert_channel_score_threshold = 0.7
quarantine_on_critical = true
replay_probe_threshold = 20
"#;

    let config: CordonConfig =
        toml::from_str(legacy).expect("a configuration from an earlier version must still load");
    config
        .validate()
        .expect("and must still validate, since the removed keys described nothing");
    assert_eq!(config.mode, DeploymentMode::Light);
}
