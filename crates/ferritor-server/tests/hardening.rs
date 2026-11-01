//! The server's own process hardening (`forbid_memory_access`), in a test
//! binary of its own: it changes the whole process.

/// After the call, the process is undumpable: no core dump, and neither
/// ptrace nor `/proc/<pid>/mem` for the same user.
#[cfg(target_os = "linux")]
#[test]
fn the_process_is_not_dumpable() {
    use rustix::process::{DumpableBehavior, dumpable_behavior};

    assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::Dumpable);
    ferritor_server::forbid_memory_access().unwrap();
    assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
    // The kernel hands an undumpable process's /proc files to root.
    let mem = std::fs::metadata("/proc/self/mem").unwrap();
    assert_eq!(std::os::unix::fs::MetadataExt::uid(&mem), 0);
}
