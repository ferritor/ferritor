//! The `ferritor` CLI: operator commands (init, unseal, seal, rekey, rotate) and
//! secret CRUD, over gRPC only. A library so its pieces can be unit tested;
//! `main.rs` only parses arguments and reports errors.

pub mod cli;
mod input;
mod policy;
mod run;

pub use policy::{NotAllowed, read_policy_file};
pub use run::{ServerError, Unproven, Unreachable, hint, run};
