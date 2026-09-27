//! Remote access, over the wire: a node behind mutual TLS with the private CA
//! from `cordon_api::pki` and a pinned client registry, as the desktop app
//! runs it when remote access is on.
//!
//! What must hold: an enrolled client is served; a certificate the same CA
//! issued but that is not enrolled (a revoked one) is refused; a caller with
//! no certificate never completes the handshake; and a header naming another
//! client changes nothing, because identity comes from the certificate.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use cordon_api::pki::Pki;
use cordon_api::server::ApiServer;
use cordon_api::tls::{TlsConfig, TlsMode};
use cordon_core::{
    config::{CordonConfig, MeasurementSource, RuntimeBackend},
    identity::ClientPolicy,
    node::CordonNode,
};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn client(ca_pem: &str, identity: Option<(&str, &str)>) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        .timeout(Duration::from_secs(20))
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap());
    if let Some((cert, key)) = identity {
        let pem = format!("{}{}", cert, key);
        builder = builder.identity(reqwest::Identity::from_pem(pem.as_bytes()).unwrap());
    }
    builder.build().unwrap()
}

#[tokio::test]
async fn remote_access_admits_only_enrolled_certificates() {
    let tmp = tempfile::tempdir().unwrap();
    let pki = Pki::new(tmp.path().join("pki"));
    pki.ensure_server(&["localhost".into(), "127.0.0.1".into()])
        .unwrap();
    let enrolled = pki.issue_client("laptop", 30).unwrap();
    let revoked = pki.issue_client("old-phone", 30).unwrap();

    // The registry the app writes: live clients pinned to their certificate,
    // and the console. The revoked client is simply absent.
    let registry = tmp.path().join("clients.json");
    let policies = vec![
        ClientPolicy {
            cert_pins: vec![enrolled.fingerprint.clone()],
            ..ClientPolicy::default_for("laptop")
        },
        ClientPolicy::default_for("console"),
    ];
    std::fs::write(&registry, serde_json::to_vec(&policies).unwrap()).unwrap();

    let mut config = CordonConfig::default_light("mtls-node".into(), "mtls-deployment".into());
    config.audit.log_path = tmp.path().join("audit");
    config.model_store.path = tmp.path().join("bundles");
    config.runtime.backend = RuntimeBackend::None;
    config.attestation.measurement_source = MeasurementSource::SoftwareMeasurement;
    config.client_registry_path = Some(registry);
    std::fs::create_dir_all(&config.audit.log_path).unwrap();
    std::fs::create_dir_all(&config.model_store.path).unwrap();

    let node = Arc::new(CordonNode::build(config).await.unwrap());
    node.go_operational().unwrap();

    let port = free_port();
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let tls = TlsConfig {
        cert_path: pki.server_cert_path(),
        key_path: pki.server_key_path(),
        client_ca_path: Some(pki.ca_cert_path()),
        mode: TlsMode::Mutual,
    };
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = ApiServer::new(node.clone(), addr, Some(tls));
    let serving = tokio::spawn(async move {
        server
            .run(async {
                let _ = stop_rx.await;
            })
            .await
    });

    let base = format!("https://127.0.0.1:{}", port);
    let ca = enrolled.ca_pem.clone();
    let laptop = client(&ca, Some((&enrolled.cert_pem, &enrolled.key_pem)));
    let phone = client(&ca, Some((&revoked.cert_pem, &revoked.key_pem)));
    let anonymous = client(&ca, None);

    for attempt in 0..100 {
        if laptop
            .get(format!("{}/v1/health", base))
            .send()
            .await
            .is_ok()
        {
            break;
        }
        assert!(attempt < 99, "the server never came up");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let infer = |c: &reqwest::Client, spoof: Option<&str>| {
        let mut request = c
            .post(format!("{}/v1/inference", base))
            .json(&serde_json::json!({
                "model_id": "default",
                "messages": [{ "role": "user", "content": "hello" }],
                "max_tokens": 8
            }));
        if let Some(id) = spoof {
            request = request.header("x-client-id", id);
        }
        request.send()
    };

    // An enrolled certificate is served, as itself.
    let response = infer(&laptop, None).await.unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());

    // A header claiming another identity is ignored: the certificate decides.
    let response = infer(&laptop, Some("console")).await.unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(
        body["client_id"], "laptop",
        "identity must come from the certificate: {}",
        body
    );

    // Issued by the same CA but no longer enrolled: refused.
    let response = infer(&phone, None).await.unwrap();
    assert!(
        response.status() == 401 || response.status() == 403,
        "a revoked client must be refused, got {}",
        response.status()
    );

    // No certificate at all: the handshake fails before any HTTP.
    assert!(
        anonymous
            .get(format!("{}/v1/health", base))
            .send()
            .await
            .is_err(),
        "a caller without a certificate must not complete the handshake"
    );

    let _ = stop_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(15), serving).await;
}
