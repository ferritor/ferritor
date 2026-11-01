//! `ferritor-csi-provider`: a provider for the Kubernetes Secrets Store CSI
//! Driver (`docs/src/content/docs/guides/csi.md`). One process per node serves every pod's ferritor
//! volumes: the driver hands it a volume's parameters and the pod's
//! service account token, the provider exchanges the token for that pod's
//! identity's certificate, reads the secrets with it, and returns the files,
//! which the driver writes into the pod's volume.
//!
//! Shares the agent's rules for refusals (`crate::agent::classify`): a
//! transient one leaves the volume as it is, an authoritative one is
//! remembered per identity and path with the agent's long backoff, so the
//! kubelet's quick retries and a rollout's replicas never drain an
//! identity's denial budget.

pub mod config;
pub mod provider;
mod request;

/// The driver's provider API (`proto/v1alpha1/service.proto`, vendored).
#[expect(clippy::allow_attributes, reason = "generated code")]
pub mod proto {
    tonic::include_proto!("v1alpha1");
}
