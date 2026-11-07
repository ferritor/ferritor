//! `SystemService` over the seal state machine and `SecretsService` over
//! secret CRUD: proto conversion and error mapping. Internal errors are
//! logged with their full chain but reach the client only as a generic
//! message.
//!
//! Incoming shares are moved into `Zeroizing` on arrival, so they're wiped on
//! every path, errors included. Outgoing shares can't be: prost needs a plain
//! `Vec<u8>` and drops it after encoding, as do the transport's buffers.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ferritor_core::crypto::ShareParams;
use ferritor_core::labels::{self, Labels};
use ferritor_core::messages::{self, reason};
use ferritor_core::proto::v1 as pb;
use ferritor_core::proto::v1::policy_service_server::{PolicyService, PolicyServiceServer};
use ferritor_core::proto::v1::secrets_service_server::{SecretsService, SecretsServiceServer};
use ferritor_core::proto::v1::system_service_server::SystemService;
use ferritor_datastore::{Datastore, DatastoreError, PathMetadata, SecretMetadata};
use serde_json::json;
use tonic::{Code, Request, Response, Status};
use tonic_types::{ErrorDetails, StatusExt};
use zeroize::Zeroizing;

use crate::audit::{self, Gate, Outcome, Refused};
use crate::authz::{Action, Caller, Target};
use crate::destroy::{Destroy, DestroyError};
use crate::error_chain;
use crate::keyring::{self, MismatchError};
use crate::namespaces::{NamespaceError, NamespaceInfo, Namespaces};
use crate::policies;
use crate::purge::{Purge, PurgeError};
use crate::rewrap::{Rewrap, RewrapError};
use crate::seal::{self, Seal, SealError};
use crate::secrets::{self, SecretsError};
use crate::tls;
use ferritor_core::path::Namespace;
use ferritor_keystore::{KekState, NamespaceState};

pub struct System {
    seal: Arc<Seal>,
    rewrap: Arc<Rewrap>,
    purge: Arc<Purge>,
    destroy: Arc<Destroy>,
    namespaces: Arc<Namespaces>,
    /// The data database, for the checks that span both databases (the
    /// KEK check after an unseal, the rotate and init guards).
    store: Datastore,
    gate: Arc<Gate>,
}

impl System {
    pub fn new(
        seal: Arc<Seal>,
        rewrap: Arc<Rewrap>,
        purge: Arc<Purge>,
        destroy: Arc<Destroy>,
        namespaces: Arc<Namespaces>,
        store: Datastore,
        gate: Arc<Gate>,
    ) -> Self {
        Self {
            seal,
            rewrap,
            purge,
            destroy,
            namespaces,
            store,
            gate,
        }
    }

    /// Refuses `operation` for a keys database that doesn't match the data
    /// database (see `keyring`), recording it as the call's outcome.
    fn mismatch(
        &self,
        caller: &Caller,
        action: Action,
        operation: &'static str,
        e: MismatchError,
    ) -> Status {
        let outcome = Outcome::Failed {
            error: error_chain(&e),
            details: None,
        };
        self.gate
            .outcome(caller, action, Target::System, operation, outcome);
        if matches!(e, MismatchError::KeysBehind { .. }) {
            tracing::error!(
                error = %error_chain(&e),
                "ROTATION REFUSED: the keys database is behind the data database"
            );
        }
        e.into()
    }

    /// The first thing every handler does: before reading the seal epoch or
    /// queueing for the admin lock, so a refused caller never waits behind
    /// admin work. Audited, like every decision (see `audit`).
    async fn allow<T>(&self, request: &Request<T>, action: Action) -> Result<Caller, Status> {
        let caller = caller(&self.gate, request, action)?;
        self.gate
            .check(&caller, action, Target::System)
            .await
            .map_err(Status::from)?;
        Ok(caller)
    }

    /// Whether `caller` may see rekey nonces (see `authz`). Only shapes the
    /// reply, so it isn't audited.
    fn may_rekey(&self, caller: &Caller) -> bool {
        self.gate.permits(caller, Action::Rekey, Target::System)
    }

    /// Whether a reply may show the auto-unseal key and errors, which name
    /// cloud accounts and roles.
    fn may_unseal(&self, caller: &Caller) -> bool {
        self.gate.permits(caller, Action::Unseal, Target::System)
    }

    /// `ferritor unseal --auto`: releases the auto-unseal hold in both
    /// databases, then unseals this server through its key management
    /// service, even if the release reached only one database (it was asked
    /// explicitly; the rest is retried in the background).
    async fn unseal_auto(
        &self,
        caller: &Caller,
        was_sealed: bool,
    ) -> Result<Response<pb::UnsealResponse>, Status> {
        if self.seal.auto_unseal_provider().is_none() {
            let error = "this server isn't configured for auto-unseal ([seal] in its config): \
                         unseal it with the shares, and release the hold with `ferritor unseal \
                         --release-hold`";
            self.gate.outcome(
                caller,
                Action::Unseal,
                Target::System,
                "unseal",
                Outcome::Failed {
                    error: error.to_owned(),
                    details: None,
                },
            );
            return Err(Status::failed_precondition(error));
        }
        let released = self.seal.release_hold().await;
        let outcome = self.seal.auto_unseal_released().await;
        let result: Result<(), SealError> = match outcome {
            seal::AutoOutcome::Unsealed | seal::AutoOutcome::NotNeeded => Ok(()),
            seal::AutoOutcome::Retry(e) | seal::AutoOutcome::Refused(e) => Err(e),
            seal::AutoOutcome::Held => Err(SealError::Corrupt("held past an explicit release")),
            seal::AutoOutcome::Waiting(why) => {
                let error = format!("auto-unseal can't unseal this server: {why}");
                self.gate.outcome(
                    caller,
                    Action::Unseal,
                    Target::System,
                    "unseal",
                    Outcome::Failed {
                        error: error.clone(),
                        details: Some(json!({"auto": true, "hold_released": released})),
                    },
                );
                return Err(Status::failed_precondition(error));
            }
        };
        self.record(caller, Action::Unseal, "unseal", &result, false, |()| {
            json!({
                "auto": true,
                "hold_released": if released { "both" } else { "partly" },
                "sealed": self.seal.is_sealed(),
            })
        });
        result?;
        if was_sealed && !self.seal.is_sealed() {
            unsealed(&self.seal, &self.gate, &self.store, "unseal");
        }
        let status = self.seal.status().await?;
        Ok(Response::new(pb::UnsealResponse {
            status: Some(seal_status(
                status,
                self.may_rekey(caller),
                self.may_unseal(caller),
            )),
        }))
    }

    /// Records what `operation` did in the audit log (see `audit`): details
    /// on success, the error otherwise. Never shares or nonces.
    fn record<T>(
        &self,
        caller: &Caller,
        action: Action,
        operation: &'static str,
        result: &Result<T, SealError>,
        writes: bool,
        details: impl FnOnce(&T) -> serde_json::Value,
    ) {
        let outcome = match result {
            Ok(done) => Outcome::Succeeded(details(done)),
            Err(e) => failed(e, writes),
        };
        self.gate
            .outcome(caller, action, Target::System, operation, outcome);
    }

    /// Share settings from the request, recording a refusal as the call's
    /// outcome (it was authorized, then failed).
    fn share_params(
        &self,
        caller: &Caller,
        action: Action,
        operation: &'static str,
        shares: u32,
        threshold: u32,
    ) -> Result<ShareParams, Status> {
        share_params(shares, threshold).inspect_err(|status| {
            let outcome = Outcome::Failed {
                error: status.message().to_owned(),
                details: None,
            };
            self.gate
                .outcome(caller, action, Target::System, operation, outcome);
        })
    }

    /// The namespace a request names, recording a refusal as the call's
    /// outcome (it was authorized, then failed).
    fn namespace(
        &self,
        caller: &Caller,
        action: Action,
        operation: &'static str,
        name: &str,
    ) -> Result<Namespace, Status> {
        Namespace::parse(name)
            .map_err(|e| Status::invalid_argument(error_chain(&NamespaceError::InvalidName(e))))
            .inspect_err(|status| {
                let outcome = Outcome::Failed {
                    error: status.message().to_owned(),
                    details: None,
                };
                self.gate
                    .outcome(caller, action, Target::System, operation, outcome);
            })
    }

    /// Records what a namespace change did (see [`System::record`]).
    fn record_namespace<T>(
        &self,
        caller: &Caller,
        operation: &'static str,
        name: &str,
        result: &Result<T, NamespaceError>,
        details: impl FnOnce(&T) -> serde_json::Value,
    ) {
        let outcome = match result {
            Ok(done) => Outcome::Succeeded(details(done)),
            // The keys database's write may have landed.
            Err(e @ NamespaceError::Keys(SealError::KeysTimeout)) => {
                Outcome::Unknown(error_chain(e))
            }
            Err(e) => Outcome::Failed {
                error: error_chain(e),
                details: Some(json!({"namespace": name})),
            },
        };
        self.gate.outcome(
            caller,
            Action::Namespace,
            Target::System,
            operation,
            outcome,
        );
    }
}

/// A failed admin call's audit outcome: `unknown` when it may have taken
/// effect anyway, which for a call that `writes` includes a keys database
/// that didn't answer in time (the write may have landed).
fn failed(e: &SealError, writes: bool) -> Outcome {
    let error = error_chain(e);
    match e {
        SealError::RekeyOutcomeUnknown => Outcome::Unknown(error),
        SealError::KeysTimeout if writes => Outcome::Unknown(error),
        // Refused, but the server just switched to the new root key.
        SealError::RekeyCommitted { generation } => Outcome::Failed {
            error,
            details: Some(json!({"adopted_generation": generation})),
        },
        _ => Outcome::Failed {
            error,
            details: None,
        },
    }
}

fn phase_name(phase: seal::RekeyPhase) -> &'static str {
    match phase {
        seal::RekeyPhase::Authorizing => "authorizing",
        seal::RekeyPhase::Verifying => "verifying",
        seal::RekeyPhase::Complete => "complete",
        seal::RekeyPhase::Cancelled => "cancelled",
    }
}

/// A rekey's progress for the audit log: everything but the nonce and the
/// new shares.
fn rekey_details(p: &seal::RekeyProgress) -> serde_json::Value {
    let mut details = json!({
        "phase": phase_name(p.phase),
        "progress": p.progress,
        "required": p.required,
    });
    if let Some(generation) = p.generation {
        details["generation"] = json!(generation);
    }
    details
}

fn status_details(s: &seal::Status) -> serde_json::Value {
    let mut details = json!({
        "sealed": s.sealed,
        "progress": s.progress,
        "threshold": s.threshold,
        "generation": s.generation,
    });
    if s.recommitted {
        details["recommitted"] = json!(true);
    }
    details
}

impl From<Refused> for Status {
    fn from(e: Refused) -> Self {
        match e {
            Refused::Denied(denied) => {
                Status::permission_denied(format!("permission denied: {denied}"))
            }
            // Without the source: the details are logged, not sent.
            unaudited @ Refused::Unaudited(_) => {
                with_reason(Code::Unavailable, unaudited.to_string(), reason::UNAUDITED)
            }
            sealed @ Refused::Sealed => {
                with_reason(Code::FailedPrecondition, sealed.to_string(), reason::SEALED)
            }
            unverified @ Refused::PolicyUnverified => with_reason(
                Code::Unavailable,
                unverified.to_string(),
                reason::POLICY_UNVERIFIED,
            ),
            limited @ Refused::Limited(refused) => rate_limited(refused, limited.to_string()),
            overloaded @ Refused::Overloaded => Status::unavailable(overloaded.to_string()),
        }
    }
}

impl From<PurgeError> for Status {
    fn from(e: PurgeError) -> Self {
        match e {
            PurgeError::Sealed => {
                with_reason(Code::FailedPrecondition, error_chain(&e), reason::SEALED)
            }
            PurgeError::DataTimeout => Status::unavailable(error_chain(&e)),
            PurgeError::Store(_) => {
                tracing::error!(error = %error_chain(&e), "internal error");
                Status::internal("internal error")
            }
        }
    }
}

impl From<MismatchError> for Status {
    fn from(e: MismatchError) -> Self {
        match e {
            MismatchError::KeysBehind { .. }
            | MismatchError::DataWithoutKeys
            | MismatchError::RowsWithoutNamespace { .. } => with_reason(
                Code::FailedPrecondition,
                error_chain(&e),
                reason::KEYS_DATABASE_MISMATCH,
            ),
            MismatchError::Keys(inner) => inner.into(),
            MismatchError::Data(DatastoreError::Timeout) => Status::unavailable(error_chain(&e)),
            MismatchError::Data(_) => {
                tracing::error!(error = %error_chain(&e), "internal error");
                Status::internal("internal error")
            }
        }
    }
}

impl From<DestroyError> for Status {
    fn from(e: DestroyError) -> Self {
        match e {
            DestroyError::Sealed => {
                with_reason(Code::FailedPrecondition, error_chain(&e), reason::SEALED)
            }
            DestroyError::UnknownVersion { .. } => Status::not_found(error_chain(&e)),
            DestroyError::NotRetired { state, .. } => Status::with_error_details(
                Code::FailedPrecondition,
                error_chain(&e),
                ErrorDetails::with_error_info(
                    reason::NOT_RETIRED,
                    messages::DOMAIN,
                    HashMap::from([("state".to_owned(), state.to_string())]),
                ),
            ),
            DestroyError::InUse { .. } => with_reason(
                Code::FailedPrecondition,
                error_chain(&e),
                reason::KEK_IN_USE,
            ),
            DestroyError::Busy => with_reason(Code::Aborted, error_chain(&e), reason::BUSY),
            DestroyError::DataTimeout => Status::unavailable(error_chain(&e)),
            DestroyError::Keys(inner) => inner.into(),
            DestroyError::Store(_) => {
                tracing::error!(error = %error_chain(&e), "internal error");
                Status::internal("internal error")
            }
        }
    }
}

impl From<RewrapError> for Status {
    fn from(e: RewrapError) -> Self {
        match e {
            RewrapError::Sealed => {
                with_reason(Code::FailedPrecondition, error_chain(&e), reason::SEALED)
            }
            RewrapError::DataTimeout | RewrapError::StaleKeyring(_) => {
                Status::unavailable(error_chain(&e))
            }
            RewrapError::Keys(inner) => inner.into(),
            RewrapError::Store(_) => {
                tracing::error!(error = %error_chain(&e), "internal error");
                Status::internal("internal error")
            }
        }
    }
}

impl From<NamespaceError> for Status {
    fn from(e: NamespaceError) -> Self {
        use NamespaceError as E;
        match e {
            E::Sealed => with_reason(Code::FailedPrecondition, error_chain(&e), reason::SEALED),
            E::InvalidName(_) | E::InvalidLabels(_) | E::NothingLost(_) => {
                Status::invalid_argument(error_chain(&e))
            }
            // Retryable once every server has refreshed.
            E::StillWritten { .. } => Status::aborted(error_chain(&e)),
            E::NotFound(_) => Status::not_found(error_chain(&e)),
            E::Exists(_) => Status::already_exists(error_chain(&e)),
            E::NotEmpty { rows, deleted, .. } => Status::with_error_details(
                Code::FailedPrecondition,
                error_chain(&e),
                ErrorDetails::with_error_info(
                    reason::NAMESPACE_NOT_EMPTY,
                    messages::DOMAIN,
                    HashMap::from([
                        ("rows".to_owned(), rows.to_string()),
                        ("deleted".to_owned(), deleted.to_string()),
                    ]),
                ),
            ),
            E::Mismatch(inner) => inner.into(),
            E::Busy => with_reason(Code::Aborted, error_chain(&e), reason::BUSY),
            E::DataTimeout => Status::unavailable(error_chain(&e)),
            E::Keys(inner) => inner.into(),
            E::Store(_) => {
                tracing::error!(error = %error_chain(&e), "internal error");
                Status::internal("internal error")
            }
        }
    }
}

/// FAILED_PRECONDITION with reason NO_NAMESPACE, naming it: only ever sent
/// to a caller already authorized for what it asked (see `secrets`).
fn no_namespace(message: String, namespace: &Namespace) -> Status {
    Status::with_error_details(
        Code::FailedPrecondition,
        message,
        ErrorDetails::with_error_info(
            reason::NO_NAMESPACE,
            messages::DOMAIN,
            HashMap::from([("namespace".to_owned(), namespace.to_string())]),
        ),
    )
}

impl From<SealError> for Status {
    fn from(e: SealError) -> Self {
        use SealError as E;
        match e {
            E::Sealed => with_reason(Code::FailedPrecondition, error_chain(&e), reason::SEALED),
            E::NoNamespace(ref namespace) => no_namespace(error_chain(&e), namespace),
            E::NotInitialized
            | E::RekeyInProgress
            | E::NoRekey
            | E::RekeyVerifying
            | E::RekeyAuthorizing
            | E::RekeyCommitted { .. } => Status::failed_precondition(error_chain(&e)),
            E::AlreadyInitialized => Status::already_exists(error_chain(&e)),
            E::InvalidShareParams { .. }
            | E::InvalidShare(_)
            | E::DuplicateShare(_)
            | E::NonceMismatch => Status::invalid_argument(error_chain(&e)),
            E::WrongShares => Status::permission_denied(error_chain(&e)),
            // Retryable: RekeyVerify again resolves it.
            E::RekeyOutcomeUnknown => Status::unavailable(error_chain(&e)),
            E::KeyringChanged(_) => Status::aborted(error_chain(&e)),
            E::RekeyedElsewhere { .. } => Status::failed_precondition(error_chain(&e)),
            E::KeysTimeout => Status::unavailable(error_chain(&e)),
            E::PolicyKeyUnusable => with_reason(
                Code::FailedPrecondition,
                error_chain(&e),
                reason::POLICY_UNVERIFIED,
            ),
            E::IssuingKeyUnusable | E::NoIssuingKey | E::IssuingKeysUnverified => {
                Status::failed_precondition(error_chain(&e))
            }
            E::IssuingFloor(_) => {
                tracing::warn!(error = %error_chain(&e), "issuing keys unchanged");
                Status::unavailable(
                    "the issuing revision floor (data database) couldn't be read; retry",
                )
            }
            E::IssuingKeyExists => Status::already_exists(error_chain(&e)),
            E::RootUncommitted { .. } => with_reason(
                Code::FailedPrecondition,
                error_chain(&e),
                reason::ROOT_UNCOMMITTED,
            ),
            E::RootBelowFloor { generation, floor } => Status::with_error_details(
                Code::FailedPrecondition,
                error_chain(&e),
                ErrorDetails::with_error_info(
                    reason::ROOT_BELOW_FLOOR,
                    messages::DOMAIN,
                    HashMap::from([
                        ("generation".to_owned(), generation.to_string()),
                        ("floor".to_owned(), floor.to_string()),
                    ]),
                ),
            ),
            E::RecommitDiscontinuous | E::RecommitNothingStored | E::InitAfterCommit { .. } => {
                Status::failed_precondition(error_chain(&e))
            }
            E::AutoUnseal(crate::auto_unseal::AutoUnsealError::Unavailable(_)) => {
                Status::unavailable(error_chain(&e))
            }
            E::AutoUnseal(_)
            | E::WrapMismatch
            | E::RekeyWouldChangeSeal { .. }
            | E::SealChangeUnconfigured { .. } => Status::failed_precondition(error_chain(&e)),
            E::RootLedger(_) => {
                tracing::warn!(error = %error_chain(&e), "root commitments unavailable");
                Status::unavailable(
                    "the root commitments (data database) couldn't be read or written; retry",
                )
            }
            E::VersionExhausted
            | E::Corrupt(_)
            | E::Keystore(_)
            | E::Crypto(_)
            | E::Identity(_) => {
                tracing::error!(error = %error_chain(&e), "internal error");
                Status::internal("internal error")
            }
        }
    }
}

/// A status whose condition the code alone doesn't identify: it carries a
/// `google.rpc.ErrorInfo` naming `reason` (see `ferritor_core::messages`), for
/// programs to match on instead of the message.
fn kek_state(state: KekState) -> pb::KekState {
    match state {
        KekState::Active => pb::KekState::Active,
        KekState::DecryptOnly => pb::KekState::DecryptOnly,
        KekState::Retired => pb::KekState::Retired,
        KekState::Destroyed => pb::KekState::Destroyed,
    }
}

pub fn with_reason(code: Code, message: impl Into<String>, reason: &str) -> Status {
    Status::with_error_details(
        code,
        message,
        ErrorDetails::with_error_info(reason, messages::DOMAIN, HashMap::new()),
    )
}

/// `RESOURCE_EXHAUSTED`, reason `RATE_LIMITED`, naming the limit, with a
/// `RetryInfo` when a time is known (an in-flight slot frees whenever a
/// call ends: 1 s).
pub fn rate_limited(refused: crate::ratelimit::Refused, message: String) -> Status {
    let mut details = ErrorDetails::with_error_info(
        reason::RATE_LIMITED,
        messages::DOMAIN,
        HashMap::from([("limit".to_owned(), refused.limit.name().to_owned())]),
    );
    details.set_retry_info(Some(refused.retry_after.unwrap_or(Duration::from_secs(1))));
    Status::with_error_details(Code::ResourceExhausted, message, details)
}

/// The `ErrorInfo` reason in `status`, if it has one from this server.
pub fn reason_of(status: &Status) -> Option<String> {
    status
        .get_error_details()
        .error_info()
        .filter(|info| info.domain == messages::DOMAIN)
        .map(|info| info.reason.clone())
}

/// Share count and threshold from the wire: each must fit in a `u8`, and
/// together satisfy [`ShareParams`].
fn share_params(shares: u32, threshold: u32) -> Result<ShareParams, Status> {
    let byte = |name, value: u32| {
        u8::try_from(value)
            .map_err(|_| Status::invalid_argument(format!("{name} must be at most 255")))
    };
    let params = ShareParams::new(byte("shares", shares)?, byte("threshold", threshold)?)
        .map_err(SealError::from)?;
    Ok(params)
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// The one place a proto `SealStatus` is built, for every reply carrying
/// one (status, unseal, seal). A rekey's nonce is shown only to callers who
/// may rekey: cancel needs nothing else.
///
/// The rest is shown to any caller who got this far, deliberately: seal and
/// unseal replies include it even for callers without `Status`. Sealed or
/// not, generation, share settings and rekey progress aren't sensitive, and
/// an operator allowed to seal or unseal needs them to know where things
/// stand.
/// After an unseal (shares, `--auto`, or at start): the stored policies
/// reported, and the KEK check against the data database started.
pub fn unsealed(seal: &Arc<Seal>, gate: &Arc<Gate>, store: &Datastore, trigger: &'static str) {
    tracing::info!(trigger, "unsealed");
    // The stored policies came in with the keyring (or didn't verify).
    gate.stored_policies_reloaded("unseal", &seal.policy_report());
    // Databases restored from backups that don't match leave rows no KEK
    // here can open: say so now, not at the first read.
    tokio::spawn({
        let (seal, gate, store) = (Arc::clone(seal), Arc::clone(gate), store.clone());
        async move { keyring::check_against_data(&seal, &gate, &store).await }
    });
}

/// A status for a reply. The rekey nonce only for callers who may rekey;
/// the auto-unseal key and errors (they name cloud accounts and roles)
/// only for callers who may unseal.
fn seal_status(s: seal::Status, show_nonce: bool, show_unseal: bool) -> pb::SealStatus {
    pb::SealStatus {
        auto_unseal: s.auto_unseal.map(|a| {
            let half = |h: seal::HoldHalf| pb::AutoUnsealHold {
                hold: h.hold,
                released: h.released,
                readable: h.readable,
            };
            pb::AutoUnsealStatus {
                provider: a.provider.unwrap_or_default().to_owned(),
                key_id: if show_unseal {
                    a.key_id.unwrap_or_default()
                } else {
                    String::new()
                },
                wrapped: a.wrapped,
                last_result: a.report.result.unwrap_or_default().to_owned(),
                last_error: if show_unseal {
                    a.report.error.unwrap_or_default()
                } else {
                    String::new()
                },
                keys_hold: Some(half(a.hold.keys)),
                data_hold: a.hold.data.map(half),
                held: a.hold.held(),
                held_here: a.hold.here,
            }
        }),
        initialized: s.initialized,
        sealed: s.sealed,
        shares: s.shares.into(),
        threshold: s.threshold.into(),
        progress: count(s.progress),
        generation: s.generation,
        rekey: s.rekey.map(|r| pb::RekeyProgress {
            nonce: if show_nonce { r.nonce } else { String::new() },
            phase: rekey_phase(r.phase).into(),
            progress: count(r.progress),
            required: r.required.into(),
            // Must stay empty: a status reply never carries share material.
            new_shares: Vec::new(),
            generation: r.generation.unwrap_or(0),
        }),
    }
}

fn pending_rekey(pending: seal::PendingRekey) -> pb::PendingRekey {
    match pending {
        seal::PendingRekey::None => pb::PendingRekey::None,
        seal::PendingRekey::Discarded => pb::PendingRekey::Discarded,
        seal::PendingRekey::Committed => pb::PendingRekey::Committed,
        seal::PendingRekey::Unknown => pb::PendingRekey::Unknown,
    }
}

fn rekey_phase(phase: seal::RekeyPhase) -> pb::RekeyPhase {
    match phase {
        seal::RekeyPhase::Authorizing => pb::RekeyPhase::Authorizing,
        seal::RekeyPhase::Verifying => pb::RekeyPhase::Verifying,
        seal::RekeyPhase::Complete => pb::RekeyPhase::Complete,
        seal::RekeyPhase::Cancelled => pb::RekeyPhase::Cancelled,
    }
}

fn rekey_progress(p: seal::RekeyProgress) -> pb::RekeyProgress {
    pb::RekeyProgress {
        nonce: p.nonce,
        phase: rekey_phase(p.phase).into(),
        progress: count(p.progress),
        required: p.required.into(),
        new_shares: p.new_shares.iter().map(|s| s.to_bytes().to_vec()).collect(),
        generation: p.generation.unwrap_or(0),
    }
}

#[tonic::async_trait]
impl SystemService for System {
    async fn init(
        &self,
        request: Request<pb::InitRequest>,
    ) -> Result<Response<pb::InitResponse>, Status> {
        let caller = self.allow(&request, Action::Init).await?;
        let req = request.into_inner();
        let params = self.share_params(&caller, Action::Init, "init", req.shares, req.threshold)?;
        keyring::ensure_no_orphaned_rows(&self.seal, &self.store)
            .await
            .map_err(|e| self.mismatch(&caller, Action::Init, "init", e))?;
        let result = self.seal.init(params).await;
        self.record(
            &caller,
            Action::Init,
            "init",
            &result,
            true,
            |_| json!({"shares": params.shares(), "threshold": params.threshold()}),
        );
        if matches!(result, Err(SealError::KeysTimeout)) {
            tracing::error!(
                %caller,
                "init timed out and may have been stored anyway, without its shares reaching \
                 the caller. If status now shows initialized and the audit log's init outcome \
                 is this one (this caller, now), nobody can unseal: nothing secret exists yet, \
                 so empty the keys database and init again. If it's from another caller, they \
                 hold valid shares: change nothing"
            );
        }
        let shares = result?;
        tracing::info!(shares = shares.len(), "seal initialized");
        // With auto-unseal, init leaves the server unsealed.
        if !self.seal.is_sealed() {
            unsealed(&self.seal, &self.gate, &self.store, "init");
        }
        Ok(Response::new(pb::InitResponse {
            shares: shares.iter().map(|s| s.to_bytes().to_vec()).collect(),
        }))
    }

    async fn status(
        &self,
        request: Request<pb::StatusRequest>,
    ) -> Result<Response<pb::StatusResponse>, Status> {
        let caller = self.allow(&request, Action::Status).await?;
        let status = self.seal.status().await?;
        // Totals only, never names (see `StatusResponse`): live namespaces
        // from the keys database, sealed or not (no key material), and the
        // vanished KEKs this server holds.
        let namespaces = if status.initialized {
            self.seal
                .stored_namespaces()
                .await?
                .iter()
                .filter(|ns| ns.state == NamespaceState::Active)
                .count()
        } else {
            0
        };
        Ok(Response::new(pb::StatusResponse {
            status: Some(seal_status(
                status,
                self.may_rekey(&caller),
                self.may_unseal(&caller),
            )),
            namespaces: count(namespaces),
            vanished_keks: self
                .seal
                .vanished_kek_count()
                .map_or(0, |n| u32::try_from(n).unwrap_or(u32::MAX)),
        }))
    }

    async fn unseal(
        &self,
        request: Request<pb::UnsealRequest>,
    ) -> Result<Response<pb::UnsealResponse>, Status> {
        let caller = self.allow(&request, Action::Unseal).await?;
        let req = request.into_inner();
        let was_sealed = self.seal.is_sealed();
        if req.auto {
            return self.unseal_auto(&caller, was_sealed).await;
        }
        let share = Zeroizing::new(req.share);
        let result = if req.recommit {
            self.seal.unseal_recommit(&share, req.reset).await
        } else {
            self.seal.unseal(&share, req.reset).await
        };
        // Released only once this call has the server unsealed, and only
        // when asked: unsealing one server with shares (for forensics, say)
        // mustn't let every other one auto-unseal at its next restart.
        let released = match &result {
            Ok(status) if req.release_hold && !status.sealed => {
                Some(self.seal.release_hold().await)
            }
            _ => None,
        };
        self.record(&caller, Action::Unseal, "unseal", &result, false, |s| {
            let mut details = status_details(s);
            if let Some(both) = released {
                details["hold_released"] = json!(if both { "both" } else { "partly" });
            }
            details
        });
        let status = result?;
        if was_sealed && !status.sealed {
            unsealed(&self.seal, &self.gate, &self.store, "unseal");
        }
        Ok(Response::new(pb::UnsealResponse {
            status: Some(seal_status(
                status,
                self.may_rekey(&caller),
                self.may_unseal(&caller),
            )),
        }))
    }

    async fn seal(
        &self,
        request: Request<pb::SealRequest>,
    ) -> Result<Response<pb::SealResponse>, Status> {
        // Refused callers get PERMISSION_DENIED before anything happens.
        // Once permitted, never an error: a failed call would read as
        // "still unsealed".
        let caller = self.allow(&request, Action::Seal).await?;
        let outcome = self.seal.seal().await;
        tracing::info!(pending_rekey = ?outcome.pending_rekey, "sealed");
        self.gate.stored_policies_dropped();
        let pending = match outcome.pending_rekey {
            seal::PendingRekey::None => "none",
            seal::PendingRekey::Discarded => "discarded",
            seal::PendingRekey::Committed => "committed",
            seal::PendingRekey::Unknown => "unknown",
        };
        if !outcome.hold_set {
            tracing::error!(
                "sealed, but the auto-unseal hold isn't set in both databases yet: a restart \
                 could auto-unseal this server (retrying the write)"
            );
        }
        let details = json!({"pending_rekey": pending, "hold_set": outcome.hold_set});
        self.gate.outcome(
            &caller,
            Action::Seal,
            Target::System,
            "seal",
            Outcome::Succeeded(details),
        );
        let (show_nonce, show_unseal) = (self.may_rekey(&caller), self.may_unseal(&caller));
        Ok(Response::new(pb::SealResponse {
            status: outcome
                .status
                .map(|s| seal_status(s, show_nonce, show_unseal)),
            pending_rekey: pending_rekey(outcome.pending_rekey).into(),
            hold_set: outcome.hold_set,
        }))
    }

    async fn rekey_start(
        &self,
        request: Request<pb::RekeyStartRequest>,
    ) -> Result<Response<pb::RekeyStartResponse>, Status> {
        let caller = self.allow(&request, Action::Rekey).await?;
        let req = request.into_inner();
        let params = self.share_params(
            &caller,
            Action::Rekey,
            "rekey_start",
            req.shares,
            req.threshold,
        )?;
        let change = match req.seal.as_str() {
            "" => None,
            asked => match seal::SealMode::parse(asked) {
                Some(mode) => Some(mode),
                None => {
                    let known = seal::SealMode::ALL.map(seal::SealMode::as_str).join(", ");
                    let error = format!("seal {asked:?}: one of {known}, or empty to keep it");
                    self.gate.outcome(
                        &caller,
                        Action::Rekey,
                        Target::System,
                        "rekey_start",
                        Outcome::Failed {
                            error: error.clone(),
                            details: None,
                        },
                    );
                    return Err(Status::invalid_argument(error));
                }
            },
        };
        let result = self.seal.rekey_start_changing(params, change).await;
        self.record(&caller, Action::Rekey, "rekey_start", &result, false, |p| {
            let mut details = rekey_details(p);
            details["shares"] = json!(params.shares());
            details["threshold"] = json!(params.threshold());
            // A change of how the root key is protected, for every server.
            details["seal"] = json!(change.map_or("kept", seal::SealMode::as_str));
            details
        });
        let progress = result?;
        Ok(Response::new(pb::RekeyStartResponse {
            progress: Some(rekey_progress(progress)),
        }))
    }

    async fn rekey_submit(
        &self,
        request: Request<pb::RekeySubmitRequest>,
    ) -> Result<Response<pb::RekeySubmitResponse>, Status> {
        let caller = self.allow(&request, Action::Rekey).await?;
        let req = request.into_inner();
        let share = Zeroizing::new(req.share);
        let result = self.seal.rekey_submit(&req.nonce, &share).await;
        self.record(
            &caller,
            Action::Rekey,
            "rekey_submit",
            &result,
            false,
            rekey_details,
        );
        let progress = result?;
        if !progress.new_shares.is_empty() {
            tracing::info!(
                shares = progress.new_shares.len(),
                "rekey authorized; new shares issued, awaiting verification"
            );
        }
        Ok(Response::new(pb::RekeySubmitResponse {
            progress: Some(rekey_progress(progress)),
        }))
    }

    async fn rekey_verify(
        &self,
        request: Request<pb::RekeyVerifyRequest>,
    ) -> Result<Response<pb::RekeyVerifyResponse>, Status> {
        let caller = self.allow(&request, Action::Rekey).await?;
        let req = request.into_inner();
        let share = Zeroizing::new(req.share);
        let result = self.seal.rekey_verify(&req.nonce, &share).await;
        self.record(
            &caller,
            Action::Rekey,
            "rekey_verify",
            &result,
            true,
            rekey_details,
        );
        let progress = result?;
        if progress.phase == seal::RekeyPhase::Complete {
            tracing::info!("rekeyed");
        }
        Ok(Response::new(pb::RekeyVerifyResponse {
            progress: Some(rekey_progress(progress)),
        }))
    }

    async fn rekey_cancel(
        &self,
        request: Request<pb::RekeyCancelRequest>,
    ) -> Result<Response<pb::RekeyCancelResponse>, Status> {
        // Same permission as starting one: the nonce alone is not enough.
        let caller = self.allow(&request, Action::Rekey).await?;
        let result = self.seal.rekey_cancel(&request.into_inner().nonce).await;
        self.record(
            &caller,
            Action::Rekey,
            "rekey_cancel",
            &result,
            false,
            rekey_details,
        );
        let progress = result?;
        Ok(Response::new(pb::RekeyCancelResponse {
            progress: Some(rekey_progress(progress)),
        }))
    }

    async fn rotate_kek(
        &self,
        request: Request<pb::RotateKekRequest>,
    ) -> Result<Response<pb::RotateKekResponse>, Status> {
        let caller = self.allow(&request, Action::Rotate).await?;
        let namespace = self.namespace(
            &caller,
            Action::Rotate,
            "rotate_kek",
            &request.into_inner().namespace,
        )?;
        keyring::ensure_keys_not_behind(&self.seal, &self.store, &namespace)
            .await
            .map_err(|e| self.mismatch(&caller, Action::Rotate, "rotate_kek", e))?;
        let mut result = self.seal.rotate(&namespace).await;
        if matches!(result, Err(SealError::NoNamespace(_))) {
            // Maybe created by another server since this one last loaded
            // its keyring: refresh, then try once more.
            if let Err(e) = keyring::refresh(&self.seal, &self.gate, "rotate", None, true).await {
                tracing::warn!(error = %error_chain(&e), "rotate: couldn't refresh the keyring");
            }
            result = self.seal.rotate(&namespace).await;
        }
        self.record(
            &caller,
            Action::Rotate,
            "rotate_kek",
            &result,
            true,
            |version| json!({"namespace": namespace.as_str(), "kek_version": version}),
        );
        let version = result?;
        tracing::info!(%namespace, version, "rotated KEK");
        Ok(Response::new(pb::RotateKekResponse { version }))
    }

    async fn rewrap(
        &self,
        request: Request<pb::RewrapRequest>,
    ) -> Result<Response<pb::RewrapResponse>, Status> {
        let caller = self.allow(&request, Action::Rewrap).await?;
        let req = request.into_inner();
        let namespace = if req.namespace.is_empty() {
            None
        } else {
            Some(self.namespace(&caller, Action::Rewrap, "rewrap", &req.namespace)?)
        };
        let result = self.rewrap.run(namespace.as_ref(), req.max_rows).await;
        let outcome = match &result {
            Ok(report) => Outcome::Succeeded(json!({
                "namespace": namespace.as_ref().map(Namespace::as_str),
                "rewrapped": report.rewrapped,
                "failed": report.failed,
                "done": report.done,
                "retired": audit::kek_refs(&report.retired),
                "released": audit::kek_refs(&report.released),
            })),
            // Batches commit one by one: a pass that stopped partway may
            // have moved some rows (harmless; the next pass carries on).
            Err(e) => Outcome::Unknown(error_chain(e)),
        };
        self.gate
            .outcome(&caller, Action::Rewrap, Target::System, "rewrap", outcome);
        let report = result?;
        crate::metrics::metrics().rewrapped(report.rewrapped);
        if report.failed > 0 {
            tracing::warn!(
                failed = report.failed,
                "rewrap left rows it couldn't unwrap"
            );
        }
        Ok(Response::new(pb::RewrapResponse {
            rewrapped: report.rewrapped,
            failed: report.failed,
            done: report.done,
            retired_keks: kek_refs(report.retired),
            released_keks: kek_refs(report.released),
        }))
    }

    async fn purge(
        &self,
        request: Request<pb::PurgeRequest>,
    ) -> Result<Response<pb::PurgeResponse>, Status> {
        let caller = self.allow(&request, Action::Purge).await?;
        let result = self.purge.run(request.into_inner().max_rows).await;
        let outcome = match &result {
            Ok(report) => Outcome::Succeeded(json!({
                "purged": report.purged,
                "done": report.done,
                "retention_secs": self.purge.retention().as_secs(),
            })),
            // Batches commit one by one: a pass that stopped partway may
            // have removed some rows.
            Err(e) => Outcome::Unknown(error_chain(e)),
        };
        self.gate
            .outcome(&caller, Action::Purge, Target::System, "purge", outcome);
        let report = result?;
        if report.purged > 0 {
            tracing::info!(purged = report.purged, "purged deleted secret versions");
        }
        Ok(Response::new(pb::PurgeResponse {
            purged: report.purged,
            done: report.done,
        }))
    }

    async fn destroy_kek(
        &self,
        request: Request<pb::DestroyKekRequest>,
    ) -> Result<Response<pb::DestroyKekResponse>, Status> {
        let caller = self.allow(&request, Action::DestroyKek).await?;
        let req = request.into_inner();
        let version = req.version;
        let namespace =
            self.namespace(&caller, Action::DestroyKek, "destroy_kek", &req.namespace)?;
        let result = self.destroy.run(&namespace, version).await;
        let outcome = match &result {
            Ok(done) => Outcome::Succeeded(json!({
                "namespace": done.namespace.as_str(),
                "version": done.version,
                "destroyed": done.destroyed,
                "kek_floor": done.kek_floor,
            })),
            // The keys database's write may have landed: retrying tells.
            Err(e @ DestroyError::Keys(SealError::KeysTimeout)) => Outcome::Unknown(error_chain(e)),
            Err(e) => Outcome::Failed {
                error: error_chain(e),
                details: Some(json!({"namespace": namespace.as_str(), "version": version})),
            },
        };
        self.gate.outcome(
            &caller,
            Action::DestroyKek,
            Target::System,
            "destroy_kek",
            outcome,
        );
        let done = result?;
        if done.destroyed {
            tracing::warn!(
                %namespace,
                version,
                kek_floor = done.kek_floor,
                "destroyed KEK version: whatever it wrapped can't be decrypted any more"
            );
        }
        Ok(Response::new(pb::DestroyKekResponse {
            destroyed: done.destroyed,
            kek_floor: done.kek_floor,
        }))
    }

    async fn create_namespace(
        &self,
        request: Request<pb::CreateNamespaceRequest>,
    ) -> Result<Response<pb::CreateNamespaceResponse>, Status> {
        let caller = self.allow(&request, Action::Namespace).await?;
        let req = request.into_inner();
        let labels: Labels = req.labels.into_iter().collect();
        let result = if req.past_lost_keks {
            self.namespaces
                .create_past_lost_keks(&req.name, &labels)
                .await
        } else {
            self.namespaces.create(&req.name, &labels).await
        };
        self.record_namespace(
            &caller,
            "create_namespace",
            &req.name,
            &result,
            |(ns, v)| {
                // Label keys only, as for paths: values may be anything.
                let mut details = json!({
                    "namespace": ns.as_str(),
                    "kek_version": v,
                    "labels": labels.keys().collect::<Vec<_>>(),
                });
                if req.past_lost_keks {
                    details["past_lost_keks"] = json!(true);
                }
                details
            },
        );
        let (namespace, kek_version) = result?;
        if req.past_lost_keks {
            tracing::warn!(
                %namespace,
                kek_version,
                "recreated a namespace the keys database lost, past its lost KEKs: rewrap against \
                 a server still holding them to move their rows"
            );
        } else {
            tracing::info!(%namespace, kek_version, "created namespace");
        }
        Ok(Response::new(pb::CreateNamespaceResponse { kek_version }))
    }

    async fn delete_namespace(
        &self,
        request: Request<pb::DeleteNamespaceRequest>,
    ) -> Result<Response<pb::DeleteNamespaceResponse>, Status> {
        // It destroys the namespace's KEKs, crypto-shredding every backup of
        // its rows: as irreversible as destroy-kek, so it needs that too.
        let caller = self.allow(&request, Action::Namespace).await?;
        self.allow(&request, Action::DestroyKek).await?;
        let name = request.into_inner().name;
        let result = self.namespaces.delete(&name).await;
        self.record_namespace(&caller, "delete_namespace", &name, &result, |done| {
            json!({
                "namespace": done.namespace.as_str(),
                "deleted": done.deleted,
                "destroyed": done.destroyed,
                "kek_floor": done.kek_floor,
                "paths_reclaimed": done.paths_reclaimed,
            })
        });
        let done = result?;
        if done.deleted {
            tracing::warn!(
                namespace = %done.namespace,
                destroyed = ?done.destroyed,
                kek_floor = done.kek_floor,
                paths_reclaimed = done.paths_reclaimed,
                "deleted namespace: its KEKs are destroyed, every backup of its rows is undecryptable"
            );
        }
        Ok(Response::new(pb::DeleteNamespaceResponse {
            deleted: done.deleted,
            destroyed: done.destroyed,
            kek_floor: done.kek_floor,
        }))
    }

    async fn get_namespace(
        &self,
        request: Request<pb::GetNamespaceRequest>,
    ) -> Result<Response<pb::GetNamespaceResponse>, Status> {
        self.allow(&request, Action::Namespace).await?;
        let info = self.namespaces.get(&request.into_inner().name).await?;
        Ok(Response::new(pb::GetNamespaceResponse {
            namespace: Some(namespace_info(info)),
        }))
    }

    async fn list_namespaces(
        &self,
        request: Request<pb::ListNamespacesRequest>,
    ) -> Result<Response<pb::ListNamespacesResponse>, Status> {
        self.allow(&request, Action::Namespace).await?;
        let infos = self.namespaces.list().await?;
        Ok(Response::new(pb::ListNamespacesResponse {
            namespaces: infos.into_iter().map(namespace_info).collect(),
        }))
    }

    async fn update_namespace_labels(
        &self,
        request: Request<pb::UpdateNamespaceLabelsRequest>,
    ) -> Result<Response<pb::UpdateNamespaceLabelsResponse>, Status> {
        let caller = self.allow(&request, Action::Namespace).await?;
        let req = request.into_inner();
        let set: Labels = req.set.into_iter().collect();
        let result = self
            .namespaces
            .update_labels(&req.name, &set, &req.remove)
            .await;
        self.record_namespace(
            &caller,
            "update_namespace_labels",
            &req.name,
            &result,
            |_| {
                json!({
                    "namespace": req.name,
                    "set": set.keys().collect::<Vec<_>>(),
                    "removed": req.remove,
                })
            },
        );
        Ok(Response::new(pb::UpdateNamespaceLabelsResponse {
            labels: result?.into_iter().collect(),
        }))
    }

    async fn identity_init(
        &self,
        request: Request<pb::IdentityInitRequest>,
    ) -> Result<Response<pb::IdentityInitResponse>, Status> {
        let caller = self.allow(&request, Action::Identity).await?;
        let result = self.seal.identity_init().await;
        self.record(&caller, Action::Identity, "identity_init", &result, true, |key| {
            json!({"version": key.version, "fingerprint": crate::fingerprint(&key.certificate)})
        });
        let key = result?;
        tracing::info!(
            version = key.version,
            "created the workload-identity issuing CA"
        );
        Ok(Response::new(pb::IdentityInitResponse {
            key: Some(issuing_key(&key)),
        }))
    }

    async fn identity_rotate(
        &self,
        request: Request<pb::IdentityRotateRequest>,
    ) -> Result<Response<pb::IdentityRotateResponse>, Status> {
        let caller = self.allow(&request, Action::Identity).await?;
        let revoke = request.into_inner().revoke;
        let result = self.seal.identity_rotate(revoke).await;
        self.record(
            &caller,
            Action::Identity,
            "identity_rotate",
            &result,
            true,
            |key| {
                json!({
                    "version": key.version,
                    "fingerprint": crate::fingerprint(&key.certificate),
                    "revoked_previous": revoke,
                })
            },
        );
        let key = result?;
        tracing::info!(
            version = key.version,
            revoke,
            "rotated the workload-identity issuing CA"
        );
        Ok(Response::new(pb::IdentityRotateResponse {
            key: Some(issuing_key(&key)),
        }))
    }

    async fn identity_status(
        &self,
        request: Request<pb::IdentityStatusRequest>,
    ) -> Result<Response<pb::IdentityStatusResponse>, Status> {
        self.allow(&request, Action::Identity).await?;
        let keys = self.seal.issuing_keys()?;
        Ok(Response::new(pb::IdentityStatusResponse {
            keys: keys.iter().map(issuing_key).collect(),
        }))
    }
}

/// An issuing key as the API shows it.
fn issuing_key(key: &seal::IssuingKeyInfo) -> pb::IssuingKey {
    use x509_parser::prelude::{FromDer, X509Certificate};
    let not_after = X509Certificate::from_der(&key.certificate)
        .map(|(_, cert)| cert.validity().not_after.timestamp())
        .unwrap_or_default();
    pb::IssuingKey {
        version: key.version,
        state: match key.state {
            ferritor_keystore::IssuingKeyState::Active => pb::IssuingKeyState::Active,
            ferritor_keystore::IssuingKeyState::Retired => pb::IssuingKeyState::Retired,
            ferritor_keystore::IssuingKeyState::Revoked => pb::IssuingKeyState::Revoked,
        }
        .into(),
        certificate: key.certificate.clone(),
        fingerprint: crate::fingerprint(&key.certificate),
        created_at_unix: key.created_at.unix_timestamp(),
        retired_at_unix: key.retired_at.map(|t| t.unix_timestamp()),
        not_after_unix: not_after,
    }
}

fn kek_refs(keks: Vec<(Namespace, u32)>) -> Vec<pb::KekRef> {
    keks.into_iter()
        .map(|(namespace, version)| pb::KekRef {
            namespace: namespace.to_string(),
            version,
        })
        .collect()
}

fn namespace_info(info: NamespaceInfo) -> pb::NamespaceInfo {
    pb::NamespaceInfo {
        name: info.name.to_string(),
        deleted: info.state == NamespaceState::Deleted,
        created_at_unix: info.created_at.unix_timestamp(),
        deleted_at_unix: info.deleted_at.map(|at| at.unix_timestamp()),
        labels: info.labels.into_iter().collect(),
        labels_updated_at_unix: info.labels_updated_at.map(|at| at.unix_timestamp()),
        keks: info
            .keks
            .into_iter()
            .map(|(version, state)| pb::KekVersion {
                version,
                state: kek_state(state).into(),
            })
            .collect(),
        kek_floor: info.kek_floor,
        vanished: info.vanished_here,
    }
}

pub struct Secrets {
    secrets: Arc<secrets::Secrets>,
}

/// `SecretsService` with its message limit sized from the largest put
/// (tonic's default is 4 MiB): a value too big, or too many labels, is then
/// refused by `Secrets`, as over the JSON API, not by the transport.
/// One `WatchSecrets` stream (see the RPC's docs and `watch`).
struct WatchStream {
    secrets: Arc<secrets::Secrets>,
    caller: Caller,
    watched: secrets::Watched,
    subscription: crate::watch::Subscription,
    certs: Option<Arc<Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>>>,
    revocation: Option<tls::Revocation>,
    peer: Option<std::net::SocketAddr>,
}

type WatchSender = tokio::sync::mpsc::Sender<Result<pb::WatchSecretsResponse, Status>>;

fn watch_event(event: pb::watch_secrets_response::Event) -> pb::WatchSecretsResponse {
    pb::WatchSecretsResponse { event: Some(event) }
}

/// When the leaf of `certs` expires, as a deadline (none without one).
fn certificate_deadline(
    certs: Option<&[tokio_rustls::rustls::pki_types::CertificateDer<'static>]>,
) -> Option<tokio::time::Instant> {
    use x509_parser::prelude::{FromDer, X509Certificate};
    let leaf = certs?.first()?;
    let (_, cert) = X509Certificate::from_der(leaf.as_ref()).ok()?;
    let left =
        cert.validity().not_after.timestamp() - time::OffsetDateTime::now_utc().unix_timestamp();
    let left = Duration::from_secs(u64::try_from(left).unwrap_or(0));
    Some(tokio::time::Instant::now() + left)
}

impl WatchStream {
    async fn run(mut self, tx: WatchSender) {
        if let Err(status) = self.serve(&tx).await {
            // The client may be gone already; nothing to tell then.
            tx.send(Err(status)).await.ok();
        }
    }

    /// Until the client leaves (`Ok`) or the stream must end (`Err`, sent
    /// to it as the stream's status).
    async fn serve(&mut self, tx: &WatchSender) -> Result<(), Status> {
        use crate::watch::Event;
        use pb::watch_secrets_response::Event as E;
        use tokio::sync::broadcast::error::RecvError;

        let closing = self
            .secrets
            .watch_hub()
            .map(|hub| hub.closing())
            .unwrap_or_default();
        let mut sealed = self.secrets.sealed_changes();
        let expires = certificate_deadline(self.certs.as_deref().map(Vec::as_slice));
        let mut recheck = tokio::time::interval(crate::watch::RECHECK);
        recheck.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        recheck.tick().await;
        if *sealed.borrow_and_update() {
            return Err(SecretsError::Sealed.into());
        }
        if tx
            .send(Ok(watch_event(E::Ready(pb::WatchReady {}))))
            .await
            .is_err()
        {
            return Ok(());
        }
        loop {
            let event = tokio::select! {
                () = tx.closed() => return Ok(()),
                () = closing.cancelled() => {
                    return Err(Status::unavailable("the server is shutting down; reconnect to another"));
                }
                changed = sealed.changed() => {
                    if changed.is_err() || *sealed.borrow_and_update() {
                        return Err(SecretsError::Sealed.into());
                    }
                    continue;
                }
                () = async {
                    match expires {
                        Some(at) => tokio::time::sleep_until(at).await,
                        None => std::future::pending().await,
                    }
                } => {
                    return Err(Status::unauthenticated(
                        "the client certificate expired: reconnect with a current one",
                    ));
                }
                _ = recheck.tick() => {
                    self.recheck().await?;
                    continue;
                }
                event = self.subscription.events.recv() => event,
            };
            let sent = match event {
                Ok(Event::Change(change)) if self.watched.covers(&change.path) => {
                    self.secrets
                        .still_watching_change(&self.caller, &self.watched, &change.path)
                        .await?;
                    E::Changed(pb::SecretChanged {
                        path: change.path.as_str().to_owned(),
                        version: change.version.unwrap_or(0),
                    })
                }
                Ok(Event::Change(_)) => continue,
                Ok(Event::Resync) => E::Resync(pb::WatchResync {}),
                Err(RecvError::Lagged(_)) => {
                    crate::metrics::metrics().watch_resync("lagged");
                    E::Resync(pb::WatchResync {})
                }
                Err(RecvError::Closed) => {
                    return Err(Status::unavailable("the change feed closed; reconnect"));
                }
            };
            if tx.send(Ok(watch_event(sent))).await.is_err() {
                return Ok(());
            }
        }
    }

    /// The certificate still valid and not revoked (what every request
    /// checks), and every permission still granted.
    async fn recheck(&self) -> Result<(), Status> {
        if self.certs.is_some() {
            tls::caller(
                self.secrets.gate(),
                self.certs.as_deref().map(Vec::as_slice),
                self.revocation.as_ref(),
                self.peer,
                Action::Read,
            )
            .map_err(|e| Status::unauthenticated(error_chain(&e)))?;
        }
        self.secrets
            .still_watching(&self.caller, &self.watched)
            .await
            .map_err(Status::from)
    }
}

pub fn secrets_service(secrets: Arc<secrets::Secrets>) -> SecretsServiceServer<Secrets> {
    SecretsServiceServer::new(Secrets::new(secrets)).max_decoding_message_size(MAX_MESSAGE)
}

/// The largest `PutSecretRequest`: the largest value, every label at its
/// longest (each a map entry: a few bytes of tags and lengths around key
/// and value, 16 is plenty), and room for the path and the other fields.
pub const MAX_MESSAGE: usize =
    secrets::MAX_VALUE_SIZE + labels::MAX_LABELS_SIZE + labels::MAX_LABELS * 16 + 4 * 1024;

/// `IdentityService`: the workload token exchange, on its own listener.
pub struct Identity {
    exchange: Arc<crate::identity::exchange::Exchange>,
}

/// The largest `ExchangeTokenRequest`: a token and a CSR, each bounded
/// (`token::MAX_TOKEN_BYTES`, `ca::MAX_CSR_BYTES`), and a little framing.
pub const MAX_EXCHANGE_MESSAGE: usize =
    crate::identity::token::MAX_TOKEN_BYTES + crate::identity::ca::MAX_CSR_BYTES + 1024;

pub fn identity_service(
    exchange: Arc<crate::identity::exchange::Exchange>,
) -> pb::identity_service_server::IdentityServiceServer<Identity> {
    pb::identity_service_server::IdentityServiceServer::new(Identity { exchange })
        .max_decoding_message_size(MAX_EXCHANGE_MESSAGE)
}

#[tonic::async_trait]
impl pb::identity_service_server::IdentityService for Identity {
    async fn exchange_token(
        &self,
        request: Request<pb::ExchangeTokenRequest>,
    ) -> Result<Response<pb::ExchangeTokenResponse>, Status> {
        use crate::identity::exchange::ExchangeError as E;
        let peer = request.remote_addr();
        let req = request.into_inner();
        match self.exchange.exchange(peer, &req.token, &req.csr).await {
            Ok(issued) => Ok(Response::new(pb::ExchangeTokenResponse {
                certificate: issued.certificate,
                identity: issued.identity,
                not_after_unix: issued.not_after.unix_timestamp(),
            })),
            Err(e @ (E::Token(_) | E::Map(_))) => Err(with_reason(
                Code::Unauthenticated,
                error_chain(&e),
                reason::TOKEN_REFUSED,
            )),
            Err(e @ E::Csr(_)) => Err(Status::invalid_argument(error_chain(&e))),
            Err(E::Sealed) => Err(with_reason(
                Code::FailedPrecondition,
                messages::SEALED.to_owned(),
                reason::SEALED,
            )),
            Err(e @ E::NoIssuingKey) => Err(Status::failed_precondition(error_chain(&e))),
            Err(e @ E::KeysUnavailable) => Err(Status::unavailable(error_chain(&e))),
            Err(e @ E::Unaudited) => Err(with_reason(
                Code::Unavailable,
                error_chain(&e),
                reason::UNAUDITED,
            )),
            Err(e @ E::RateLimited(refused)) => Err(rate_limited(refused, e.to_string())),
            Err(e @ E::Issue(_)) => {
                tracing::error!(error = %error_chain(&e), "internal error");
                Err(Status::internal("internal error"))
            }
        }
    }
}

impl Secrets {
    pub fn new(secrets: Arc<secrets::Secrets>) -> Self {
        Self { secrets }
    }
}

/// Who sent `request` (see [`tls::caller`]): a certificate that passed the
/// handshake but carries no valid identity is UNAUTHENTICATED, not
/// anonymous.
fn caller<T>(gate: &Gate, request: &Request<T>, action: Action) -> Result<Caller, Status> {
    let certs = request.peer_certs();
    tls::caller(
        gate,
        certs.as_deref().map(Vec::as_slice),
        request.extensions().get(),
        request.remote_addr(),
        action,
    )
    .map_err(|e| Status::unauthenticated(error_chain(&e)))
}

impl From<SecretsError> for Status {
    fn from(e: SecretsError) -> Self {
        use SecretsError as E;
        match e {
            E::InvalidPath(_)
            | E::InvalidPageToken
            | E::ValueTooLarge { .. }
            | E::InvalidLabels(_)
            | E::TooManyLabels { .. }
            | E::WatchSize { .. } => Status::invalid_argument(error_chain(&e)),
            E::Watch(
                full @ (crate::watch::SubscribeError::Full
                | crate::watch::SubscribeError::IdentityFull(_)),
            ) => {
                let limit = match full {
                    crate::watch::SubscribeError::IdentityFull(_) => "identity",
                    _ => "server",
                };
                Status::with_error_details(
                    Code::ResourceExhausted,
                    error_chain(&full),
                    ErrorDetails::with_error_info(
                        reason::WATCH_FULL,
                        messages::DOMAIN,
                        HashMap::from([("limit".to_owned(), limit.to_owned())]),
                    ),
                )
            }
            E::Watch(_) => Status::unavailable(error_chain(&e)),
            // A missing or invalid identity is UNAUTHENTICATED (see
            // `caller`); PERMISSION_DENIED is for a known caller the policy
            // refuses.
            E::Denied(_) => Status::permission_denied(error_chain(&e)),
            // Without the source: the details are logged, not sent.
            E::Unaudited(_) => with_reason(Code::Unavailable, e.to_string(), reason::UNAUDITED),
            E::Limited(refused) => rate_limited(refused, e.to_string()),
            E::Overloaded => Status::unavailable(e.to_string()),
            E::Sealed => with_reason(Code::FailedPrecondition, error_chain(&e), reason::SEALED),
            E::PolicyUnverified => with_reason(
                Code::Unavailable,
                error_chain(&e),
                reason::POLICY_UNVERIFIED,
            ),
            E::NoNamespace(ref namespace) => no_namespace(error_chain(&e), namespace),
            E::UnknownKek(kek_version) => Status::with_error_details(
                Code::FailedPrecondition,
                error_chain(&e),
                ErrorDetails::with_error_info(
                    reason::UNKNOWN_KEK,
                    messages::DOMAIN,
                    HashMap::from([("kek_version".to_owned(), kek_version.to_string())]),
                ),
            ),
            E::NotFound { .. } | E::VersionNotFound { .. } | E::NothingToRestore { .. } => {
                Status::not_found(error_chain(&e))
            }
            E::LiveVersion { latest, .. } => Status::with_error_details(
                Code::FailedPrecondition,
                error_chain(&e),
                ErrorDetails::with_error_info(
                    reason::LIVE_VERSION,
                    messages::DOMAIN,
                    HashMap::from([("latest".to_owned(), latest.to_string())]),
                ),
            ),
            E::DataTimeout | E::StaleKeyring(_) => Status::unavailable(error_chain(&e)),
            E::Busy(_) => with_reason(Code::Aborted, error_chain(&e), reason::BUSY),
            // Not retryable as is: the caller must read again first.
            E::VersionMismatch {
                expected, latest, ..
            } => {
                let mut metadata = HashMap::from([("expected".to_owned(), expected.to_string())]);
                if let Some(latest) = latest {
                    metadata.insert("latest".to_owned(), latest.to_string());
                }
                Status::with_error_details(
                    Code::FailedPrecondition,
                    error_chain(&e),
                    ErrorDetails::with_error_info(
                        reason::VERSION_MISMATCH,
                        messages::DOMAIN,
                        metadata,
                    ),
                )
            }
            E::Store(_) | E::Crypto(_) => {
                tracing::error!(error = %error_chain(&e), "internal error");
                Status::internal("internal error")
            }
        }
    }
}

fn secret_metadata(m: SecretMetadata) -> pb::SecretMetadata {
    pb::SecretMetadata {
        path: m.path.to_string(),
        version: m.version,
        created_at_unix: m.created_at.unix_timestamp(),
    }
}

#[tonic::async_trait]
impl SecretsService for Secrets {
    type WatchSecretsStream =
        tokio_stream::wrappers::ReceiverStream<Result<pb::WatchSecretsResponse, Status>>;

    async fn watch_secrets(
        &self,
        request: Request<pb::WatchSecretsRequest>,
    ) -> Result<Response<Self::WatchSecretsStream>, Status> {
        let caller = caller(self.secrets.gate(), &request, Action::Read)?;
        let certs = request.peer_certs();
        let revocation = request.extensions().get::<tls::Revocation>().cloned();
        let peer = request.remote_addr();
        let req = request.into_inner();
        let (watched, subscription) = self
            .secrets
            .watch(&caller, &req.paths, &req.prefixes)
            .await?;
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let stream = WatchStream {
            secrets: Arc::clone(&self.secrets),
            caller,
            watched,
            subscription,
            certs,
            revocation,
            peer,
        };
        // Not in the request's task: the call ends here (its rate-limit
        // admission with it), the stream lives on until it ends.
        tokio::spawn(stream.run(tx));
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    async fn get_secret(
        &self,
        request: Request<pb::GetSecretRequest>,
    ) -> Result<Response<pb::GetSecretResponse>, Status> {
        let caller = caller(self.secrets.gate(), &request, Action::Read)?;
        let req = request.into_inner();
        let version = (req.version != 0).then_some(req.version);
        let secret = self.secrets.get(&caller, &req.path, version).await?;
        Ok(Response::new(pb::GetSecretResponse {
            secret: Some(pb::Secret {
                metadata: Some(secret_metadata(secret.metadata)),
                // A plain copy for prost; `secret.value` itself is wiped.
                value: secret.value.to_vec(),
            }),
        }))
    }

    async fn put_secret(
        &self,
        request: Request<pb::PutSecretRequest>,
    ) -> Result<Response<pb::PutSecretResponse>, Status> {
        let caller = caller(self.secrets.gate(), &request, Action::Write)?;
        let req = request.into_inner();
        let value = Zeroizing::new(req.value);
        let labels: Labels = req.labels.into_iter().collect();
        let metadata = self
            .secrets
            .put_labeled(&caller, &req.path, &value, req.expected_version, &labels)
            .await?;
        Ok(Response::new(pb::PutSecretResponse {
            metadata: Some(secret_metadata(metadata)),
        }))
    }

    async fn restore_secret(
        &self,
        request: Request<pb::RestoreSecretRequest>,
    ) -> Result<Response<pb::RestoreSecretResponse>, Status> {
        let caller = caller(self.secrets.gate(), &request, Action::Write)?;
        let req = request.into_inner();
        let version = (req.version != 0).then_some(req.version);
        let restored = self.secrets.restore(&caller, &req.path, version).await?;
        Ok(Response::new(pb::RestoreSecretResponse {
            metadata: Some(secret_metadata(restored)),
        }))
    }

    async fn delete_secret(
        &self,
        request: Request<pb::DeleteSecretRequest>,
    ) -> Result<Response<pb::DeleteSecretResponse>, Status> {
        let caller = caller(self.secrets.gate(), &request, Action::Delete)?;
        self.secrets
            .delete(&caller, &request.into_inner().path)
            .await?;
        Ok(Response::new(pb::DeleteSecretResponse {}))
    }

    async fn list_secrets(
        &self,
        request: Request<pb::ListSecretsRequest>,
    ) -> Result<Response<pb::ListSecretsResponse>, Status> {
        let caller = caller(self.secrets.gate(), &request, Action::List)?;
        let req = request.into_inner();
        let labels: Labels = req.labels.into_iter().collect();
        let page = self
            .secrets
            .list(
                &caller,
                &req.prefix,
                req.page_size,
                &req.page_token,
                &labels,
            )
            .await?;
        Ok(Response::new(pb::ListSecretsResponse {
            secrets: page.secrets.into_iter().map(secret_metadata).collect(),
            next_page_token: page.next_page_token,
        }))
    }

    async fn list_versions(
        &self,
        request: Request<pb::ListVersionsRequest>,
    ) -> Result<Response<pb::ListVersionsResponse>, Status> {
        let caller = caller(self.secrets.gate(), &request, Action::List)?;
        let req = request.into_inner();
        let page = self
            .secrets
            .versions(&caller, &req.path, req.page_size, &req.page_token)
            .await?;
        Ok(Response::new(pb::ListVersionsResponse {
            versions: page
                .versions
                .into_iter()
                .map(|v| pb::SecretVersion {
                    deleted_at_unix: v.deleted_at.map(|at| at.unix_timestamp()),
                    metadata: Some(secret_metadata(v.metadata)),
                })
                .collect(),
            next_page_token: page.next_page_token,
        }))
    }

    async fn get_metadata(
        &self,
        request: Request<pb::GetMetadataRequest>,
    ) -> Result<Response<pb::GetMetadataResponse>, Status> {
        let caller = caller(self.secrets.gate(), &request, Action::List)?;
        let metadata = self
            .secrets
            .metadata(&caller, &request.into_inner().path)
            .await?;
        Ok(Response::new(pb::GetMetadataResponse {
            metadata: Some(path_metadata(metadata)),
        }))
    }

    async fn update_labels(
        &self,
        request: Request<pb::UpdateLabelsRequest>,
    ) -> Result<Response<pb::UpdateLabelsResponse>, Status> {
        let caller = caller(self.secrets.gate(), &request, Action::Label)?;
        let req = request.into_inner();
        let set: Labels = req.set.into_iter().collect();
        let labels = self
            .secrets
            .update_labels(&caller, &req.path, &set, &req.remove)
            .await?;
        Ok(Response::new(pb::UpdateLabelsResponse {
            labels: labels.into_iter().collect(),
        }))
    }
}

fn path_metadata(m: PathMetadata) -> pb::PathMetadata {
    pb::PathMetadata {
        path: m.path.to_string(),
        created_at_unix: m.created_at.unix_timestamp(),
        updated_at_unix: m.updated_at.unix_timestamp(),
        current_version: m.current_version,
        oldest_version: m.oldest_version,
        versions: m.versions,
        labels: m.labels.into_iter().collect(),
        labels_updated_at_unix: m.labels_updated_at.map(|at| at.unix_timestamp()),
    }
}

/// `PolicyService` over `policies`, with its message limit sized from the
/// largest apply (as for secrets).
pub fn policy_service(policies: Arc<policies::Policies>) -> PolicyServiceServer<Policies> {
    PolicyServiceServer::new(Policies { policies }).max_decoding_message_size(MAX_POLICY_MESSAGE)
}

/// The largest `ApplyPoliciesRequest` (`ferritor_core::policy::MAX_APPLY_BYTES`).
pub const MAX_POLICY_MESSAGE: usize = ferritor_core::policy::MAX_APPLY_BYTES;

pub struct Policies {
    policies: Arc<policies::Policies>,
}

impl From<policies::PoliciesError> for Status {
    fn from(e: policies::PoliciesError) -> Self {
        use policies::PoliciesError as E;
        match e {
            E::Invalid { .. } | E::Request(_) => Status::invalid_argument(error_chain(&e)),
            E::NotFound(_) => Status::not_found(error_chain(&e)),
            E::VersionMismatch {
                expected, current, ..
            } => {
                let mut metadata = HashMap::from([("expected".to_owned(), expected.to_string())]);
                if let Some(current) = current {
                    metadata.insert("current".to_owned(), current.to_string());
                }
                Status::with_error_details(
                    Code::FailedPrecondition,
                    error_chain(&e),
                    ErrorDetails::with_error_info(
                        reason::VERSION_MISMATCH,
                        messages::DOMAIN,
                        metadata,
                    ),
                )
            }
            E::RevisionMismatch { expected, current } => Status::with_error_details(
                Code::FailedPrecondition,
                error_chain(&e),
                ErrorDetails::with_error_info(
                    reason::VERSION_MISMATCH,
                    messages::DOMAIN,
                    HashMap::from([
                        ("expected".to_owned(), expected.to_string()),
                        ("current".to_owned(), current.to_string()),
                    ]),
                ),
            ),
            E::Denied(_) => Status::permission_denied(error_chain(&e)),
            E::Unaudited(_) => with_reason(Code::Unavailable, e.to_string(), reason::UNAUDITED),
            E::Sealed => with_reason(Code::FailedPrecondition, error_chain(&e), reason::SEALED),
            E::Unverified(_) => with_reason(
                Code::Unavailable,
                error_chain(&e),
                reason::POLICY_UNVERIFIED,
            ),
            E::KeysTimeout => Status::unavailable(error_chain(&e)),
            E::Limited(refused) => rate_limited(refused, e.to_string()),
            E::Overloaded => Status::unavailable(e.to_string()),
            E::RevisionFloor(_) => {
                tracing::warn!(error = %error_chain(&e), "policy write refused");
                Status::unavailable(
                    "the policy revision floor couldn't be read (data database): nothing was \
                     written",
                )
            }
            E::Seal(inner) => inner.into(),
            E::Keys(_) | E::Crypto(_) => {
                tracing::error!(error = %error_chain(&e), "internal error");
                Status::internal("internal error")
            }
        }
    }
}

fn secret_action(action: i32) -> Result<ferritor_core::policy::SecretAction, Status> {
    use ferritor_core::policy::SecretAction as A;
    match pb::SecretAction::try_from(action) {
        Ok(pb::SecretAction::Read) => Ok(A::Read),
        Ok(pb::SecretAction::Write) => Ok(A::Write),
        Ok(pb::SecretAction::Delete) => Ok(A::Delete),
        Ok(pb::SecretAction::List) => Ok(A::List),
        Ok(pb::SecretAction::Label) => Ok(A::Label),
        Ok(pb::SecretAction::Unspecified) | Err(_) => Err(Status::invalid_argument(format!(
            "unknown secret action {action}"
        ))),
    }
}

fn policy_spec(spec: pb::PolicySpec) -> Result<ferritor_core::policy::PolicySpec, Status> {
    Ok(ferritor_core::policy::PolicySpec {
        actions: spec
            .actions
            .into_iter()
            .map(secret_action)
            .collect::<Result<_, _>>()?,
        name: spec.name,
        identity: spec.identity,
        paths: spec.paths,
        all_paths: spec.all_paths,
        description: spec.description,
    })
}

fn policy_entry(entry: policies::Entry) -> pb::PolicyEntry {
    pb::PolicyEntry {
        name: entry.name,
        source: match entry.source {
            policies::Source::Config => pb::PolicySource::Config,
            policies::Source::Stored => pb::PolicySource::Stored,
        }
        .into(),
        identity: entry.identity,
        actions: entry.actions,
        paths: entry.paths,
        all_paths: entry.all_paths,
        description: entry.description,
        version: entry.version,
        created_at_unix: entry.created_at.map(|t| t.unix_timestamp()),
        updated_at_unix: entry.updated_at.map(|t| t.unix_timestamp()),
    }
}

#[tonic::async_trait]
impl PolicyService for Policies {
    async fn put_policy(
        &self,
        request: Request<pb::PutPolicyRequest>,
    ) -> Result<Response<pb::PutPolicyResponse>, Status> {
        let caller = caller(self.policies.gate(), &request, Action::Policy)?;
        let req = request.into_inner();
        let spec = policy_spec(req.policy.unwrap_or_default())?;
        let written = self
            .policies
            .put(&caller, &spec, req.expected_version)
            .await?;
        Ok(Response::new(pb::PutPolicyResponse {
            version: written.version,
            revision: written.revision,
            created: written.created,
        }))
    }

    async fn delete_policy(
        &self,
        request: Request<pb::DeletePolicyRequest>,
    ) -> Result<Response<pb::DeletePolicyResponse>, Status> {
        let caller = caller(self.policies.gate(), &request, Action::Policy)?;
        let req = request.into_inner();
        let done = self
            .policies
            .delete(&caller, &req.name, req.expected_version)
            .await?;
        Ok(Response::new(pb::DeletePolicyResponse {
            deleted: done.deleted,
            revision: done.revision,
        }))
    }

    async fn get_policy(
        &self,
        request: Request<pb::GetPolicyRequest>,
    ) -> Result<Response<pb::GetPolicyResponse>, Status> {
        let caller = caller(self.policies.gate(), &request, Action::Policy)?;
        let entry = self
            .policies
            .get(&caller, &request.into_inner().name)
            .await?;
        Ok(Response::new(pb::GetPolicyResponse {
            policy: Some(policy_entry(entry)),
        }))
    }

    async fn list_policies(
        &self,
        request: Request<pb::ListPoliciesRequest>,
    ) -> Result<Response<pb::ListPoliciesResponse>, Status> {
        let caller = caller(self.policies.gate(), &request, Action::Policy)?;
        let req = request.into_inner();
        let identity = (!req.identity.is_empty()).then_some(req.identity.as_str());
        let page = self
            .policies
            .list(&caller, identity, req.page_size, &req.page_token)
            .await?;
        let (stored, revision) = match page.stored {
            policies::StoredState::Loaded { revision } => (pb::StoredPolicyState::Loaded, revision),
            policies::StoredState::Sealed => (pb::StoredPolicyState::Sealed, 0),
            policies::StoredState::Unverified => (pb::StoredPolicyState::Unverified, 0),
        };
        Ok(Response::new(pb::ListPoliciesResponse {
            policies: page.entries.into_iter().map(policy_entry).collect(),
            next_page_token: page.next_page_token,
            stored: stored.into(),
            revision,
        }))
    }

    async fn apply_policies(
        &self,
        request: Request<pb::ApplyPoliciesRequest>,
    ) -> Result<Response<pb::ApplyPoliciesResponse>, Status> {
        let caller = caller(self.policies.gate(), &request, Action::Policy)?;
        let req = request.into_inner();
        let specs = req
            .policies
            .into_iter()
            .map(policy_spec)
            .collect::<Result<Vec<_>, _>>()?;
        let done = self
            .policies
            .apply(
                &caller,
                &specs,
                req.expected_revision,
                req.prune,
                req.dry_run,
            )
            .await?;
        Ok(Response::new(pb::ApplyPoliciesResponse {
            created: done.created,
            updated: done.updated,
            deleted: done.deleted,
            unchanged: done.unchanged,
            revision: done.revision,
            dry_run: done.dry_run,
            replaced_unverified: done.replaced_unverified,
            new_policy_key: done.new_policy_key,
        }))
    }

    async fn check_access(
        &self,
        request: Request<pb::CheckAccessRequest>,
    ) -> Result<Response<pb::CheckAccessResponse>, Status> {
        let caller = caller(self.policies.gate(), &request, Action::Policy)?;
        let req = request.into_inner();
        let checked = self
            .policies
            .check(&caller, &req.identity, &req.action, Some(&req.path))
            .await?;
        Ok(Response::new(pb::CheckAccessResponse {
            allowed: checked.allowed,
            granted_by: checked.granted_by,
            enforced: checked.enforced,
            undecided: checked
                .undecided
                .map(|why| why.name().to_owned())
                .unwrap_or_default(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `unknown` only where the call may have taken effect anyway.
    #[test]
    fn a_failure_is_unknown_only_if_it_may_have_landed() {
        let kind = |e: SealError, writes: bool| match failed(&e, writes) {
            Outcome::Succeeded(_) => "succeeded",
            Outcome::Failed { .. } => "failed",
            Outcome::Unknown(_) => "unknown",
        };
        assert_eq!(kind(SealError::RekeyOutcomeUnknown, true), "unknown");
        // A timed-out write may have been stored; a read changed nothing.
        assert_eq!(kind(SealError::KeysTimeout, true), "unknown");
        assert_eq!(kind(SealError::KeysTimeout, false), "failed");
        assert_eq!(kind(SealError::NonceMismatch, true), "failed");
        assert_eq!(kind(SealError::WrongShares, true), "failed");
    }

    /// Where the code alone is ambiguous, the status names the condition in
    /// an `ErrorInfo` reason; elsewhere it carries none.
    #[test]
    fn ambiguous_conditions_carry_a_reason() {
        use ferritor_core::path::SecretPath;

        let path = SecretPath::parse("app/db").unwrap();
        let cases: Vec<(Status, Code, Option<&str>)> = vec![
            (
                SecretsError::Sealed.into(),
                Code::FailedPrecondition,
                Some(reason::SEALED),
            ),
            (
                SealError::Sealed.into(),
                Code::FailedPrecondition,
                Some(reason::SEALED),
            ),
            (
                RewrapError::Sealed.into(),
                Code::FailedPrecondition,
                Some(reason::SEALED),
            ),
            (
                SecretsError::VersionMismatch {
                    path: path.clone(),
                    expected: 1,
                    latest: Some(2),
                }
                .into(),
                Code::FailedPrecondition,
                Some(reason::VERSION_MISMATCH),
            ),
            (
                SecretsError::Busy(path.clone()).into(),
                Code::Aborted,
                Some(reason::BUSY),
            ),
            (
                Refused::Unaudited(crate::audit::AuditError::Timeout).into(),
                Code::Unavailable,
                Some(reason::UNAUDITED),
            ),
            (
                SecretsError::UnknownKek(3).into(),
                Code::FailedPrecondition,
                Some(reason::UNKNOWN_KEK),
            ),
            (
                SecretsError::LiveVersion {
                    path: path.clone(),
                    latest: 2,
                }
                .into(),
                Code::FailedPrecondition,
                Some(reason::LIVE_VERSION),
            ),
            // The same code as UNAUDITED, but an ordinary timeout: no reason.
            (
                SecretsError::NoNamespace(Namespace::parse("app").unwrap()).into(),
                Code::FailedPrecondition,
                Some(reason::NO_NAMESPACE),
            ),
            (SecretsError::DataTimeout.into(), Code::Unavailable, None),
            // The same code as RATE_LIMITED, but the watch streams' caps.
            (
                SecretsError::Watch(crate::watch::SubscribeError::Full).into(),
                Code::ResourceExhausted,
                Some(reason::WATCH_FULL),
            ),
            (
                SecretsError::Watch(crate::watch::SubscribeError::IdentityFull(
                    std::num::NonZeroU32::MIN,
                ))
                .into(),
                Code::ResourceExhausted,
                Some(reason::WATCH_FULL),
            ),
        ];
        for (status, code, expected) in cases {
            assert_eq!(
                (status.code(), reason_of(&status).as_deref()),
                (code, expected),
                "{status:?}"
            );
        }

        // Which cap: the server's or the identity's.
        let limit = |e: crate::watch::SubscribeError| {
            let status: Status = SecretsError::Watch(e).into();
            status
                .get_error_details()
                .error_info()
                .and_then(|info| info.metadata.get("limit").cloned())
        };
        assert_eq!(
            limit(crate::watch::SubscribeError::Full).as_deref(),
            Some("server")
        );
        assert_eq!(
            limit(crate::watch::SubscribeError::IdentityFull(
                std::num::NonZeroU32::MIN
            ))
            .as_deref(),
            Some("identity")
        );

        let unknown_kek: Status = SecretsError::UnknownKek(3).into();
        let details = unknown_kek.get_error_details();
        assert_eq!(
            details.error_info().unwrap().metadata.get("kek_version"),
            Some(&"3".to_owned())
        );

        // A mismatch also says what was found, for programs.
        let mismatch: Status = SecretsError::VersionMismatch {
            path,
            expected: 1,
            latest: None,
        }
        .into();
        let details = mismatch.get_error_details();
        let info = details.error_info().unwrap();
        assert_eq!(
            (
                info.domain.as_str(),
                info.metadata.get("expected"),
                info.metadata.get("latest")
            ),
            (messages::DOMAIN, Some(&"1".to_owned()), None)
        );
    }

    /// The auto-unseal key and error text name cloud accounts and roles: a
    /// status shows them only to callers who may unseal; the provider, the
    /// result and the hold to everyone with `status`.
    #[test]
    fn the_auto_unseal_key_and_error_need_the_unseal_permission() {
        let status = || seal::Status {
            initialized: true,
            sealed: true,
            shares: 5,
            threshold: 3,
            generation: 1,
            progress: 0,
            rekey: None,
            recommitted: false,
            auto_unseal: Some(seal::AutoUnsealStatus {
                provider: Some("awskms"),
                key_id: Some("arn:aws:kms:ap-southeast-1:111122223333:key/k".to_owned()),
                wrapped: true,
                report: seal::AutoReport {
                    result: Some("denied"),
                    error: Some("User: arn:aws:sts::111122223333:assumed-role/r".to_owned()),
                },
                hold: seal::Hold {
                    keys: seal::HoldHalf {
                        hold: 2,
                        released: 2,
                        readable: true,
                    },
                    data: Some(seal::HoldHalf {
                        hold: 2,
                        released: 2,
                        readable: true,
                    }),
                    here: false,
                },
            }),
        };
        let monitoring = seal_status(status(), false, false).auto_unseal.unwrap();
        assert_eq!(
            (
                monitoring.provider.as_str(),
                monitoring.last_result.as_str(),
                monitoring.key_id.as_str(),
                monitoring.last_error.as_str()
            ),
            ("awskms", "denied", "", "")
        );
        assert!(monitoring.wrapped && !monitoring.held);
        let operator = seal_status(status(), false, true).auto_unseal.unwrap();
        assert!(operator.key_id.contains("111122223333"));
        assert!(operator.last_error.contains("assumed-role"));
    }

    /// A cancel refused because the rekey had committed is a failed cancel,
    /// but the key change must show in the entry, not only in its error.
    #[test]
    fn a_cancel_that_adopted_a_committed_rekey_says_so() {
        let outcome = failed(&SealError::RekeyCommitted { generation: 2 }, false);
        let Outcome::Failed { error, details } = outcome else {
            panic!("{outcome:?}");
        };
        assert_eq!(details, Some(json!({"adopted_generation": 2})));
        assert!(error.contains("generation 2"), "{error}");
    }
}
