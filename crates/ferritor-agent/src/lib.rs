//! `ferritor-agent`: keeps an application's secrets current as files, as a
//! sidecar next to it or a service on its host (`docs/src/content/docs/guides/agent.md`). A library so
//! its pieces can be tested; the binary only wires them up.

pub mod agent;
pub mod config;
mod connection;
pub mod csi;
pub mod files;
mod notify;
pub mod run;
