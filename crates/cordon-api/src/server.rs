//! API server startup — binds the Axum router to a TCP listener.
//!
//! Two serving paths:
//!   * `--no-tls` (dev): plain HTTP via `axum::serve`.
//!   * TLS present: real TLS 1.3 termination via `tokio-rustls`, optionally
//!     requiring + verifying client certificates (mTLS). When mTLS is on, the
//!     verified client certificate is turned into a `VerifiedIdentity` and
//!     injected into request extensions, so handlers authenticate against the
//!     certificate — NOT the spoofable `x-client-id` header.

use std::net::SocketAddr;
use std::sync::Arc;
use std::io::BufReader;
use anyhow::{anyhow, Context, Result};

use axum::http::Request;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use hyper_util::service::TowerToHyperService;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{ServerConfig, RootCertStore};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tower::ServiceExt; // for `oneshot`

use cordon_core::identity::parse_client_identity_from_cert;
use cordon_core::node::CordonNode;
use crate::{
    handlers::AppState,
    middleware::VerifiedIdentity,
    router::build_router,
    tls::{TlsConfig, TlsMode, ensure_tls_certs},
};

/// The API server
pub struct ApiServer {
    node: Arc<CordonNode>,
    bind_addr: SocketAddr,
    tls_config: Option<TlsConfig>,
}

impl ApiServer {
    /// Create a new API server
    pub fn new(
        node: Arc<CordonNode>,
        bind_addr: SocketAddr,
        tls_config: Option<TlsConfig>,
    ) -> Self {
        Self { node, bind_addr, tls_config }
    }

    /// Start the server (blocking)
    pub async fn run(self) -> Result<()> {
        let state = AppState { node: self.node.clone() };
        let router = build_router(state);

        let listener = tokio::net::TcpListener::bind(&self.bind_addr)
            .await
            .context(format!("Cannot bind to {}", self.bind_addr))?;

        match self.tls_config {
            None => {
                tracing::warn!("TLS disabled — serving plain HTTP (dev only) on {}", self.bind_addr);
                axum::serve(listener, router).await.context("Server error")?;
            }
            Some(tls) => {
                ensure_tls_certs(&tls).context("TLS setup failed")?;
                let require_mtls = matches!(tls.mode, TlsMode::Mutual);
                let server_config = build_rustls_server_config(&tls)
                    .context("Failed to build rustls server config")?;
                let acceptor = TlsAcceptor::from(server_config);

                tracing::info!(
                    "Cordon API listening on https://{} (TLS 1.3{})",
                    self.bind_addr,
                    if require_mtls { ", mTLS required" } else { "" },
                );

                loop {
                    let (tcp, peer) = match listener.accept().await {
                        Ok(x) => x,
                        Err(e) => { tracing::warn!("accept error: {}", e); continue; }
                    };
                    let acceptor = acceptor.clone();
                    let router = router.clone();
                    tokio::spawn(async move {
                        serve_tls_connection(acceptor, tcp, peer, router).await;
                    });
                }
            }
        }

        Ok(())
    }
}

/// Handle a single accepted TCP connection: complete the TLS handshake, derive
/// the verified client identity from the peer certificate (mTLS), and serve
/// HTTP over the encrypted stream with that identity injected into extensions.
async fn serve_tls_connection(
    acceptor: TlsAcceptor,
    tcp: tokio::net::TcpStream,
    peer: SocketAddr,
    router: axum::Router,
) {
    let tls_stream = match acceptor.accept(tcp).await {
        Ok(s) => s,
        Err(e) => {
            // Handshake failure includes clients that failed mTLS verification.
            tracing::warn!("TLS handshake failed from {}: {}", peer, e);
            return;
        }
    };

    // Derive a *verified* identity from the peer certificate. rustls has
    // already validated the chain against the client CA (mTLS), so binding the
    // identity to the certificate fingerprint is cryptographically sound.
    let verified_identity: Option<VerifiedIdentity> = {
        let (_io, conn) = tls_stream.get_ref();
        conn.peer_certificates()
            .and_then(|certs| certs.first())
            .and_then(|cert| parse_client_identity_from_cert(cert.as_ref()).ok())
            .map(|identity| VerifiedIdentity { identity, verified: true })
    };

    // Per-request service: inject the verified identity, then dispatch to axum.
    let svc = tower::service_fn(move |mut req: Request<Incoming>| {
        if let Some(vid) = verified_identity.clone() {
            req.extensions_mut().insert(vid);
        }
        router.clone().oneshot(req)
    });

    let io = TokioIo::new(tls_stream);
    if let Err(e) = AutoBuilder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(io, TowerToHyperService::new(svc))
        .await
    {
        tracing::debug!("connection from {} ended: {}", peer, e);
    }
}

/// Build a rustls `ServerConfig` restricted to TLS 1.3, requiring and verifying
/// client certificates when the mode is `Mutual`.
fn build_rustls_server_config(tls: &TlsConfig) -> Result<Arc<ServerConfig>> {
    let certs = load_certs(&tls.cert_path)
        .with_context(|| format!("loading server cert {:?}", tls.cert_path))?;
    let key = load_private_key(&tls.key_path)
        .with_context(|| format!("loading server key {:?}", tls.key_path))?;

    // TLS 1.3 only.
    let versions: &[&'static tokio_rustls::rustls::SupportedProtocolVersion] =
        &[&tokio_rustls::rustls::version::TLS13];
    let builder = ServerConfig::builder_with_protocol_versions(versions);

    let config = match &tls.mode {
        TlsMode::Mutual => {
            let ca_path = tls.client_ca_path.as_ref().ok_or_else(|| {
                anyhow!("mTLS mode requires a client CA certificate (client_ca_path)")
            })?;
            let mut roots = RootCertStore::empty();
            for ca in load_certs(ca_path).with_context(|| format!("loading client CA {:?}", ca_path))? {
                roots.add(ca).context("adding client CA to trust store")?;
            }
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .context("building client certificate verifier")?;
            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
                .context("invalid server certificate/key")?
        }
        TlsMode::ServerOnly => {
            builder
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .context("invalid server certificate/key")?
        }
    };

    Ok(Arc::new(config))
}

/// Load a PEM certificate chain.
fn load_certs(path: &std::path::Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parsing PEM certificates")?;
    if certs.is_empty() {
        return Err(anyhow!("no certificates found in {:?}", path));
    }
    Ok(certs)
}

/// Load a PEM private key (PKCS#8 / PKCS#1 / SEC1).
fn load_private_key(path: &std::path::Path) -> Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .context("parsing PEM private key")?
        .ok_or_else(|| anyhow!("no private key found in {:?}", path))
}
