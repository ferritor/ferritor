//! Each binary of this package says its own name with `--version`: the
//! provider is a binary of `ferritor-agent`, whose name it would show
//! otherwise.
//!
//! Unix only: the provider binary is Linux-only, and a cross-built test
//! runs on another machine than the one that built the binaries.
#![cfg(unix)]

use std::process::Command;

use ferritor_testkit::TestResult;

fn version(binary: &str) -> TestResult<String> {
    let out = Command::new(binary).arg("--version").output()?;
    assert!(out.status.success());
    Ok(String::from_utf8(out.stdout)?)
}

#[test]
fn each_binary_reports_its_own_name() -> TestResult<()> {
    let v = env!("CARGO_PKG_VERSION");
    assert_eq!(
        version(env!("CARGO_BIN_EXE_ferritor-agent"))?,
        format!("ferritor-agent {v}\n")
    );
    assert_eq!(
        version(env!("CARGO_BIN_EXE_ferritor-csi-provider"))?,
        format!("ferritor-csi-provider {v}\n")
    );
    Ok(())
}
