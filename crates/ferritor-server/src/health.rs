//! Health: whether the process is up (liveness), and whether it should get
//! secret traffic (readiness), for the CLI's preflight and load balancers.
//!
//! Over gRPC, the standard `grpc.health.v1` service ([`Readiness::grpc`]):
//! the overall status (service `""`) is always SERVING while the process
//! runs, sealed or not, for the CLI's preflight (a connection, and over TLS
//! the certificate, checked before a real call) and liveness checks.
//! [`SECRETS_SERVICE`] is SERVING only while ready: unsealed, and not
//! shutting down. So a load balancer in front of several servers takes a
//! sealed one out of rotation. Over HTTP, `GET /v1/health` reports the same
//! (see `http`).
//!
//! Shutting down: the first SIGINT/SIGTERM makes it not ready at once.
//! Once the drain starts, the server itself already tells clients to stop:
//! HTTP/2 connections get a GOAWAY and HTTP/1.1 keep-alive connections
//! close after their current request, and no new connection is accepted;
//! so the flip matters only before that. With `shutdown_delay_secs` (`main`)
//! the server reports not ready but keeps accepting and serving for that
//! long before draining: on Kubernetes, a pod's removal from the endpoints
//! reaches the proxies at about the same time as SIGTERM, and for a few
//! seconds new connections still arrive. Default 0: the drain starts at
//! once, and the flip is merely accurate.
//!
//! Neither asks the authorizer nor writes an audit entry: they tell nothing
//! beyond ready or not (and sealed or not), which any caller who can
//! connect learns anyway from a refused request. In secured mode the
//! handshake still requires a client certificate.
//!
//! Check, not Watch: tonic-health's Watch streams until the client hangs
//! up, so a balancer watching would hold every shutdown's drain open for
//! its full limit. Kubernetes' gRPC probes and Envoy use Check.

use std::sync::Arc;

use ferritor_core::proto::v1::secrets_service_server::SecretsServiceServer;
use tokio::sync::watch;
use tonic_health::ServingStatus;
use tonic_health::pb::health_server::{Health, HealthServer};

use crate::grpc::Secrets;
use crate::seal::Seal;

/// The service a load balancer should check: NOT_SERVING unless ready.
pub const SECRETS_SERVICE: &str =
    <SecretsServiceServer<Secrets> as tonic::server::NamedService>::NAME;

/// Whether this server should get secret traffic: unsealed, and not
/// shutting down.
pub struct Readiness {
    seal: Arc<Seal>,
    /// Set once, when shutdown starts; never cleared.
    stopping: watch::Sender<bool>,
}

impl Readiness {
    pub fn new(seal: Arc<Seal>) -> Arc<Self> {
        Arc::new(Self {
            seal,
            stopping: watch::Sender::new(false),
        })
    }

    /// Ready now: unsealed and not shutting down.
    pub fn is_ready(&self) -> bool {
        !*self.stopping.borrow() && !self.seal.is_sealed()
    }

    /// Whether sealed now (for the HTTP check's body).
    pub fn is_sealed(&self) -> bool {
        self.seal.is_sealed()
    }

    /// Not ready from now on: called when the drain starts, so a load
    /// balancer stops routing here first.
    pub fn shutting_down(&self) {
        self.stopping.send_replace(true);
    }

    /// The `grpc.health.v1` service, as described in the module docs. Its
    /// status for [`SECRETS_SERVICE`] is set before this returns (so a check
    /// never finds the service unknown), then follows the seal and the
    /// shutdown in a task of its own: a seal, unseal or shutdown shows there
    /// a moment later. The task holds only receivers, so it ends when the
    /// seal or this is dropped.
    pub async fn grpc(&self) -> HealthServer<impl Health> {
        let (reporter, server) = tonic_health::server::health_reporter();
        let mut sealed = self.seal.sealed_changes();
        let mut stopping = self.stopping.subscribe();
        reporter
            .set_service_status(SECRETS_SERVICE, status(&mut sealed, &mut stopping))
            .await;
        tokio::spawn(async move {
            loop {
                let changed = tokio::select! {
                    changed = sealed.changed() => changed,
                    changed = stopping.changed() => changed,
                };
                if changed.is_err() {
                    return;
                }
                reporter
                    .set_service_status(SECRETS_SERVICE, status(&mut sealed, &mut stopping))
                    .await;
            }
        });
        server
    }
}

/// The readiness status now, marking both values seen, so the next change
/// to either wakes [`Readiness::grpc`]'s task.
fn status(
    sealed: &mut watch::Receiver<bool>,
    stopping: &mut watch::Receiver<bool>,
) -> ServingStatus {
    let sealed = *sealed.borrow_and_update();
    let stopping = *stopping.borrow_and_update();
    if sealed || stopping {
        ServingStatus::NotServing
    } else {
        ServingStatus::Serving
    }
}
