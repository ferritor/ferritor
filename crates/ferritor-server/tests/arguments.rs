//! The server binary's arguments: `--version` and `--help`, nothing else
//! (it's configured by `ferritor.toml` and `FERRITOR_*` only).

use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use ferritor_testkit::TestResult;

/// Runs the server with `args`, killed after a few seconds: a server that
/// started instead of exiting fails the test rather than hanging it.
fn server(args: &[&str]) -> TestResult<Output> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ferritor-server"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait()?.is_none() {
        if Instant::now() > deadline {
            child.kill()?;
            return Err("the server kept running instead of exiting".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(child.wait_with_output()?)
}

#[test]
fn version_prints_the_servers_name_and_version() -> TestResult<()> {
    let out = server(&["--version"])?;
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8(out.stdout)?,
        format!("ferritor-server {}\n", env!("CARGO_PKG_VERSION"))
    );
    Ok(())
}

#[test]
fn an_unknown_argument_is_refused_before_anything_starts() -> TestResult<()> {
    let out = server(&["--confg", "ferritor.toml"])?;
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(stderr.contains("--confg"), "{stderr}");
    // Refused by the argument parser: no settings loaded, nothing logged.
    assert!(!stderr.contains("metrics"), "{stderr}");
    Ok(())
}
