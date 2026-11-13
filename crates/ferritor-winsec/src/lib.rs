//! Windows security for ferritor's binaries: who may open a file, a
//! directory or the process itself, as access lists (DACLs). Windows has no
//! file modes or groups and no `PR_SET_DUMPABLE`; these are the stand-ins
//! (`docs/src/content/docs/guides/agent.md`, "Windows").
//!
//! The one crate in the workspace allowed `unsafe`, all of it in `imp`,
//! each block with the reason it's sound. Empty on every other platform.

#[cfg(windows)]
mod imp;

#[cfg(windows)]
pub use imp::*;
