//! The root commitments, kept in the data database (migration 0005 there):
//! an unseal accepts a root key only if a commitment for its generation
//! verifies under it ([`RootKey::verifies_root_commitment`]) and its
//! generation isn't below the root-generation floor. So substituting the
//! root key (a keys database with a `root_check`, KEKs and a seal config of
//! someone's own making) takes write access to both databases, whoever
//! unseals: operators with shares, or later a KMS.
//!
//! `Seal` reaches the data database only through [`RootLedger`], as it
//! does the revision floors, so it never holds a `Datastore`.
//!
//! [`RootKey::verifies_root_commitment`]: ferritor_core::crypto::RootKey::verifies_root_commitment

use std::future::Future;
use std::pin::Pin;

use ferritor_datastore::{Datastore, StoredVersion};

use crate::error_chain;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The data database's side of the root key: its commitments, the floor,
/// and the stored versions a re-commit proves continuity with. Errors are
/// the store's, as text.
pub trait RootLedger: Send + Sync {
    /// The highest generation known to have committed (0: none ever has).
    fn floor(&self) -> BoxFuture<'_, Result<u32, String>>;
    /// Raises the floor to `generation` (never lowers it).
    fn raise_floor(&self, generation: u32) -> BoxFuture<'_, Result<(), String>>;
    /// The commitments stored for `generation`.
    fn commitments(&self, generation: u32) -> BoxFuture<'_, Result<Vec<Vec<u8>>, String>>;
    /// Stores a commitment (insert-only).
    fn insert(&self, generation: u32, mac: Vec<u8>) -> BoxFuture<'_, Result<(), String>>;
    /// One stored version per (namespace, KEK version) any row uses.
    fn version_per_kek(&self) -> BoxFuture<'_, Result<Vec<StoredVersion>, String>>;
    /// The auto-unseal hold, this database's half: `(hold, released)`.
    fn hold(&self) -> BoxFuture<'_, Result<(u64, u64), String>>;
    /// Raises the hold (never lowers it).
    fn raise_hold(&self, hold: u64) -> BoxFuture<'_, Result<(), String>>;
    /// Raises `released` (never lowers it).
    fn release_hold(&self, released: u64) -> BoxFuture<'_, Result<(), String>>;
}

impl RootLedger for Datastore {
    fn floor(&self) -> BoxFuture<'_, Result<u32, String>> {
        Box::pin(async move {
            self.root_generation_floor()
                .await
                .map_err(|e| error_chain(&e))
        })
    }

    fn raise_floor(&self, generation: u32) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            self.raise_root_generation_floor(generation)
                .await
                .map_err(|e| error_chain(&e))
        })
    }

    fn commitments(&self, generation: u32) -> BoxFuture<'_, Result<Vec<Vec<u8>>, String>> {
        Box::pin(async move {
            self.root_commitments(generation)
                .await
                .map_err(|e| error_chain(&e))
        })
    }

    fn insert(&self, generation: u32, mac: Vec<u8>) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            self.insert_root_commitment(generation, &mac)
                .await
                .map_err(|e| error_chain(&e))
        })
    }

    fn version_per_kek(&self) -> BoxFuture<'_, Result<Vec<StoredVersion>, String>> {
        Box::pin(async move {
            Datastore::version_per_kek(self)
                .await
                .map_err(|e| error_chain(&e))
        })
    }

    fn hold(&self) -> BoxFuture<'_, Result<(u64, u64), String>> {
        Box::pin(async move { self.auto_unseal_hold().await.map_err(|e| error_chain(&e)) })
    }

    fn raise_hold(&self, hold: u64) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            self.raise_auto_unseal_hold(hold)
                .await
                .map_err(|e| error_chain(&e))
        })
    }

    fn release_hold(&self, released: u64) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            self.release_auto_unseal_hold(released)
                .await
                .map_err(|e| error_chain(&e))
        })
    }
}
