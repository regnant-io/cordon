//! HTTP server startup.
//!
//! Two serving paths:
//!
//! * **Plaintext** (`--no-tls`) — development only. Client identity comes from a
//!   header and is marked unverified, so any mode that claims a security
//!   guarantee refuses to run this way.
//! * **TLS 1.3**, optionally with mutual authentication. When mTLS is on, the
//!   verified peer certificate is parsed into a [`VerifiedIdentity`] and injected
//!   into request extensions, so handlers authenticate against the certificate
//!   rather than a header a caller can set.
//!
//! The TLS accept loop bounds what an unauthenticated peer can consume: a
//! handshake deadline, a cap on concurrent connections, and per-connection
//! cleanup on drop. Without those, opening sockets and never completing a
//! handshake is enough to exhaust the process.

use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};

use axum::extract::connect_info::ConnectInfo;
use axum::http::Request;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use hyper_util::service::TowerToHyperService;
use tokio::sync::Semaphore;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

use cordon_core::identity::parse_client_identity_from_cert;
use cordon_core::node::CordonNode;

use crate::{
    handlers::{AppState, ChainHealth},
    middleware::VerifiedIdentity,
    router::{build_api_router, build_metrics_router, build_ui_router},
    tls::{ensure_tls_certs, TlsConfig, TlsMode},
};

/// How often the audit chain is re-verified in the background.
const CHAIN_VERIFY_INTERVAL: Duration = Duration::from_secs(300);

/// The Cordon HTTP server.
pub struct ApiServer {
    node: Arc<CordonNode>,
    bind_addr: SocketAddr,
    tls_config: Option<TlsConfig>,
}

impl ApiServer {
    /// Create a server bound to `bind_addr`.
    pub fn new(
        node: Arc<CordonNode>,
        bind_addr: SocketAddr,
        tls_config: Option<TlsConfig>,
    ) -> Self {
        Self {
            node,
            bind_addr,
            tls_config,
        }
    }

    /// Serve until `shutdown` resolves.
    pub async fn run<F>(self, shutdown: F) -> Result<()>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let chain_health = Arc::new(ChainHealth::new());
        chain_health
            .clone()
            .spawn_refresher(self.node.clone(), CHAIN_VERIFY_INTERVAL);

        let state = AppState {
            node: self.node.clone(),
            chain_health,
        };

        // Metrics share the API listener but are gated on a loopback peer.
        let router = build_api_router(state.clone()).merge(build_metrics_router(state.clone()));

        let ui_handle = self.spawn_console(state)?;

        let listener = tokio::net::TcpListener::bind(&self.bind_addr)
            .await
            .with_context(|| format!("cannot bind to {}", self.bind_addr))?;

        let limits = self.node.config.limits.clone();

        match self.tls_config {
            None => {
                tracing::warn!(
                    addr = %self.bind_addr,
                    "Serving plain HTTP — client identity is taken from a header and is \
                     spoofable. Development only."
                );
                axum::serve(
                    listener,
                    router.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .with_graceful_shutdown(shutdown)
                .await
                .context("server error")?;
            }
            Some(tls) => {
                ensure_tls_certs(&tls).context("TLS setup failed")?;
                let require_mtls = matches!(tls.mode, TlsMode::Mutual);
                let acceptor = TlsAcceptor::from(
                    build_rustls_server_config(&tls).context("TLS configuration")?,
                );

                tracing::info!(
                    addr = %self.bind_addr,
                    mtls = require_mtls,
                    "Cordon API listening (TLS 1.3)"
                );

                // A permit is held for the whole life of a connection, so a peer
                // cannot open sockets faster than they are served.
                let connections = Arc::new(Semaphore::new(limits.max_connections));
                let handshake_timeout =
                    Duration::from_secs(limits.tls_handshake_timeout_seconds.max(1));

                tokio::pin!(shutdown);
                loop {
                    tokio::select! {
                        _ = &mut shutdown => {
                            tracing::info!("Shutdown requested; no longer accepting connections");
                            break;
                        }
                        accepted = listener.accept() => {
                            let (tcp, peer) = match accepted {
                                Ok(pair) => pair,
                                Err(e) => {
                                    tracing::warn!("accept error: {}", e);
                                    continue;
                                }
                            };

                            let Ok(permit) = connections.clone().try_acquire_owned() else {
                                tracing::warn!(
                                    %peer,
                                    limit = limits.max_connections,
                                    "Connection limit reached; refusing"
                                );
                                drop(tcp);
                                continue;
                            };

                            let acceptor = acceptor.clone();
                            let router = router.clone();
                            tokio::spawn(async move {
                                serve_tls_connection(
                                    acceptor,
                                    tcp,
                                    peer,
                                    router,
                                    handshake_timeout,
                                )
                                .await;
                                drop(permit);
                            });
                        }
                    }
                }
            }
        }

        if let Some(handle) = ui_handle {
            handle.abort();
        }
        self.node.shutdown().await;
        Ok(())
    }

    /// Start the operator console on its own loopback listener, if enabled.
    fn spawn_console(&self, state: AppState) -> Result<Option<tokio::task::JoinHandle<()>>> {
        let ui = &self.node.config.ui;
        if !ui.enabled {
            return Ok(None);
        }

        let addr: SocketAddr = format!("{}:{}", ui.bind_address, ui.port)
            .parse()
            .with_context(|| format!("invalid ui.bind_address {}:{}", ui.bind_address, ui.port))?;

        // Configuration validation already refuses a routable console address.
        // This is the second, independent check: a console that escaped onto a
        // routable interface would be an unauthenticated view of node state.
        if !addr.ip().is_loopback() {
            return Err(anyhow!(
                "refusing to serve the operator console on {} — it must be loopback",
                addr
            ));
        }

        let router = build_ui_router(state);
        let handle = tokio::spawn(async move {
            match tokio::net::TcpListener::bind(addr).await {
                Ok(listener) => {
                    tracing::info!(%addr, "Operator console at http://{}", addr);
                    if let Err(e) = axum::serve(listener, router).await {
                        tracing::error!("operator console stopped: {}", e);
                    }
                }
                Err(e) => tracing::error!(%addr, "cannot bind the operator console: {}", e),
            }
        });

        Ok(Some(handle))
    }
}

/// Complete one connection's TLS handshake, derive its identity, and serve it.
async fn serve_tls_connection(
    acceptor: TlsAcceptor,
    tcp: tokio::net::TcpStream,
    peer: SocketAddr,
    router: axum::Router,
    handshake_timeout: Duration,
) {
    // An unauthenticated peer must not be able to hold a connection open by
    // stalling mid-handshake.
    let tls_stream = match tokio::time::timeout(handshake_timeout, acceptor.accept(tcp)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            // Includes peers that failed client-certificate verification.
            tracing::debug!(%peer, "TLS handshake failed: {}", e);
            return;
        }
        Err(_) => {
            tracing::warn!(%peer, "TLS handshake timed out");
            return;
        }
    };

    // rustls has already validated the chain against the configured client CA,
    // so binding an identity to this certificate is sound. Parsing is what
    // turns it into a client ID; a certificate that yields none is refused
    // rather than given a synthesised identity.
    let verified_identity: Option<VerifiedIdentity> = {
        let (_io, connection) = tls_stream.get_ref();
        connection
            .peer_certificates()
            .and_then(|certs| certs.first())
            .and_then(|cert| match parse_client_identity_from_cert(cert.as_ref()) {
                Ok(identity) => Some(VerifiedIdentity {
                    source: identity.source,
                    identity,
                }),
                Err(e) => {
                    tracing::warn!(%peer, "cannot derive an identity from the client certificate: {}", e);
                    None
                }
            })
    };

    let service = tower::service_fn(move |mut req: Request<Incoming>| {
        req.extensions_mut().insert(ConnectInfo(peer));
        if let Some(identity) = verified_identity.clone() {
            req.extensions_mut().insert(identity);
        }
        router.clone().oneshot(req)
    });

    let io = TokioIo::new(tls_stream);
    if let Err(e) = AutoBuilder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(io, TowerToHyperService::new(service))
        .await
    {
        tracing::debug!(%peer, "connection closed: {}", e);
    }
}

/// Build a rustls configuration restricted to TLS 1.3, requiring and verifying
/// client certificates when the mode is mutual.
fn build_rustls_server_config(tls: &TlsConfig) -> Result<Arc<ServerConfig>> {
    let certs = load_certs(&tls.cert_path)
        .with_context(|| format!("loading server certificate {}", tls.cert_path.display()))?;
    let key = load_private_key(&tls.key_path)
        .with_context(|| format!("loading server key {}", tls.key_path.display()))?;

    let versions: &[&'static tokio_rustls::rustls::SupportedProtocolVersion] =
        &[&tokio_rustls::rustls::version::TLS13];
    let builder = ServerConfig::builder_with_protocol_versions(versions);

    let mut config = match &tls.mode {
        TlsMode::Mutual => {
            let ca_path = tls.client_ca_path.as_ref().ok_or_else(|| {
                anyhow!("mutual TLS requires a client CA certificate (network.client_ca_path)")
            })?;
            let mut roots = RootCertStore::empty();
            for ca in load_certs(ca_path)
                .with_context(|| format!("loading client CA {}", ca_path.display()))?
            {
                roots
                    .add(ca)
                    .context("adding the client CA to the trust store")?;
            }
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .context("building the client certificate verifier")?;
            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
                .context("invalid server certificate or key")?
        }
        TlsMode::ServerOnly => builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("invalid server certificate or key")?,
    };

    // Advertise both protocols so hyper's auto-detection negotiates rather than
    // guessing from the first bytes on the wire.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

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
        return Err(anyhow!("no certificates found in {}", path.display()));
    }
    Ok(certs)
}

/// Load a PEM private key (PKCS#8, PKCS#1, or SEC1).
fn load_private_key(path: &std::path::Path) -> Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .context("parsing the PEM private key")?
        .ok_or_else(|| anyhow!("no private key found in {}", path.display()))
}
