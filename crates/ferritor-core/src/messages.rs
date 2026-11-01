//! What the server tells clients about an error, shared so server and
//! client can't drift apart.
//!
//! Programs tell conditions apart by **reason**, never by message text:
//! where the gRPC code alone is ambiguous, the server attaches a
//! `google.rpc.ErrorInfo` with [`DOMAIN`] and one of the [`reason`]s. (For
//! example, `FAILED_PRECONDITION` is a sealed server, a check-and-set
//! mismatch, or a KEK this server hasn't loaded.) The JSON API puts the same
//! reason, lowercased, in its error `code`. Messages are for people; the
//! constants below are the fixed ones, so the server says them the same way
//! everywhere.

/// `ErrorInfo.domain` for every reason below.
pub const DOMAIN: &str = "ferritor";

/// `ErrorInfo.reason` values.
pub mod reason {
    /// Refused because the server is sealed (`FAILED_PRECONDITION`): every
    /// call that needs the keys, secret operations and admin calls alike.
    /// Unseal it, then retry.
    pub const SEALED: &str = "SEALED";
    /// Allowed, but refused because the decision couldn't be recorded in
    /// the audit log (`UNAVAILABLE`). Nothing was done.
    pub const UNAUDITED: &str = "UNAUDITED";
    /// Too many concurrent writes to one path (`ABORTED`): retry the call
    /// as is.
    pub const BUSY: &str = "BUSY";
    /// A check-and-set found another latest version (`FAILED_PRECONDITION`):
    /// someone else wrote or deleted the secret since it was read. Read it
    /// again, then decide; retrying as is fails the same way. Metadata:
    /// `expected`, and `latest` unless there's no live version.
    pub const VERSION_MISMATCH: &str = "VERSION_MISMATCH";
    /// The secret is wrapped by a KEK version this server couldn't load,
    /// even after refreshing its keyring (`FAILED_PRECONDITION`): most
    /// likely another server rekeyed, so this one needs sealing and
    /// unsealing with the new shares; or ask another server. Metadata:
    /// `kek_version`.
    pub const UNKNOWN_KEK: &str = "UNKNOWN_KEK";
    /// A restore without a version found a live version
    /// (`FAILED_PRECONDITION`): without one, a restore only undoes a delete
    /// (brings the newest deleted version back while none is live). To
    /// bring back an older or trimmed version alongside the live one, name
    /// it. Metadata: `latest`.
    pub const LIVE_VERSION: &str = "LIVE_VERSION";
    /// DestroyKek on a KEK version that isn't retired
    /// (`FAILED_PRECONDITION`): the active one, or one rows still use. Run
    /// rewrap until it's done (and rotate first, for the active one).
    /// Metadata: `state`.
    pub const NOT_RETIRED: &str = "NOT_RETIRED";
    /// DestroyKek found rows still using the retired KEK version
    /// (`FAILED_PRECONDITION`), written by a server with an out-of-date
    /// keyring after it was retired. Nothing was destroyed; rewrap until
    /// done moves them, then destroy again.
    pub const KEK_IN_USE: &str = "KEK_IN_USE";
    /// A rotate or init refused because the keys database doesn't match
    /// the data database (`FAILED_PRECONDITION`): rows use a KEK version
    /// the keys database doesn't have (restored from an older backup), or
    /// an init found secrets from a keys database that's gone. Going ahead
    /// would reuse KEK versions for different keys and lose those rows for
    /// good. Restore the matching keys database (then seal and unseal), or
    /// for an init, empty the data database to start over.
    pub const KEYS_DATABASE_MISMATCH: &str = "KEYS_DATABASE_MISMATCH";
    /// The path's first segment isn't a namespace (`FAILED_PRECONDITION`),
    /// or a rotate named none: there's no default namespace, so a secret
    /// can only be stored under one created first (`ferritor namespace
    /// create`). Only ever answered after the caller is authorized, so it
    /// doesn't tell anyone else which namespaces exist. Metadata:
    /// `namespace`.
    pub const NO_NAMESPACE: &str = "NO_NAMESPACE";
    /// DeleteNamespace on a namespace that still has rows
    /// (`FAILED_PRECONDITION`), deleted ones included: delete its secrets,
    /// wait out the retention (`purge_deleted_after_days`), purge, then
    /// delete it. Metadata: `rows`, `deleted`.
    pub const NAMESPACE_NOT_EMPTY: &str = "NAMESPACE_NOT_EMPTY";
    /// The stored policies didn't verify (`UNAVAILABLE`): changed in the
    /// keys database behind the server's back, rolled back to an older set,
    /// or their key cleared. A secret request the config rules don't decide
    /// is refused, as is a policy put or delete; nothing was done. Re-apply
    /// the set from its source of truth (`ferritor policy apply --prune`), then
    /// find out who changed it.
    pub const POLICY_UNVERIFIED: &str = "POLICY_UNVERIFIED";
    /// Over one of the caller's rate limits (`RESOURCE_EXHAUSTED`): which
    /// one is in the metadata (`limit`: `rate`, `in_flight`, `denied`), and
    /// when to retry in a `RetryInfo`, when known. Nothing was done.
    pub const RATE_LIMITED: &str = "RATE_LIMITED";
    /// A workload's token exchange refused (`UNAUTHENTICATED`): the token
    /// didn't verify (an unknown issuer, its signature, its audience, its
    /// expiry…) or no mapping of its issuer gives it an identity. Nothing
    /// was issued; a new token may pass.
    pub const TOKEN_REFUSED: &str = "TOKEN_REFUSED";
    /// A watch stream refused because the server serves as many as it can
    /// (`RESOURCE_EXHAUSTED`): not the caller's rate limit. Watch through
    /// another server, or poll meanwhile.
    pub const WATCH_FULL: &str = "WATCH_FULL";
    /// An unseal refused (`FAILED_PRECONDITION`): no root commitment in the
    /// data database matches the root key. A data database restored from
    /// before a rekey, a failover that lost the write, or a substituted keys
    /// database: `ferritor unseal --recommit` with the shares decides which.
    pub const ROOT_UNCOMMITTED: &str = "ROOT_UNCOMMITTED";
    /// An unseal refused (`FAILED_PRECONDITION`): the keys database's root
    /// key is a generation below the data database's floor (a keys database
    /// restored, or failed over, past a rekey). The `ErrorInfo` metadata
    /// carries `generation` and `floor`.
    pub const ROOT_BELOW_FLOOR: &str = "ROOT_BELOW_FLOOR";
}

/// The message for [`reason::SEALED`].
pub const SEALED: &str = "the server is sealed";

/// The message for [`reason::POLICY_UNVERIFIED`] on a refused request.
pub const POLICY_UNVERIFIED: &str =
    "the stored policies couldn't be verified, so a request they decide is refused";

/// The message for [`reason::UNAUDITED`].
pub const UNAUDITED: &str = "the request could not be audited, so it was refused";
