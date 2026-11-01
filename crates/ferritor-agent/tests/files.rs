//! The output directory's writer, on real directories.

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ferritor_agent::files::{DATA, DIR_MODE, FilesError, OutputFile, STATUS, Writer};
use ferritor_testkit::TestResult;
use zeroize::Zeroizing;

/// A fresh directory, removed when dropped.
struct Dir(PathBuf);

impl Dir {
    fn new(base: &Path, name: &str) -> TestResult<Self> {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let dir = base.join(format!(
            "ferritor-agent-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir)?;
        Ok(Self(dir))
    }

    fn temp(name: &str) -> TestResult<Self> {
        Self::new(&std::env::temp_dir(), name)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

fn file(name: &str, contents: &str, mode: u32) -> OutputFile {
    OutputFile {
        name: name.to_owned(),
        contents: Zeroizing::new(contents.as_bytes().to_vec()),
        mode,
    }
}

/// The generation directories (`..<time>`), sorted.
fn generations(dir: &Path) -> TestResult<Vec<String>> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("..") && entry.file_type()?.is_dir() {
            found.push(name);
        }
    }
    found.sort();
    Ok(found)
}

/// Files are what the application opens, by their names, through `..data`;
/// their modes and the directories' are set exactly; replacing a set adds
/// and removes names.
#[test]
fn a_set_is_written_with_its_modes_and_replaced_whole() {
    let dir = Dir::temp("set").unwrap();
    let mut writer = Writer::open(&dir.0, None, true).unwrap();
    writer
        .write(&[
            file("db-password", "foo", 0o440),
            file("tls.key", "k1", 0o400),
        ])
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(dir.0.join("db-password")).unwrap(),
        "foo"
    );
    assert_eq!(
        std::fs::read_link(dir.0.join("db-password")).unwrap(),
        Path::new(DATA).join("db-password")
    );
    let real = dir.0.join(std::fs::read_link(dir.0.join(DATA)).unwrap());
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode(&real.join("db-password")), 0o440);
    assert_eq!(mode(&real.join("tls.key")), 0o400);
    assert_eq!(mode(&real), DIR_MODE);

    writer
        .write(&[
            file("db-password", "bar", 0o440),
            file("redis-password", "r", 0o440),
        ])
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(dir.0.join("db-password")).unwrap(),
        "bar"
    );
    assert_eq!(
        std::fs::read_to_string(dir.0.join("redis-password")).unwrap(),
        "r"
    );
    // No longer in the set: its name is gone, not left dangling.
    assert!(std::fs::symlink_metadata(dir.0.join("tls.key")).is_err());
}

/// Values are written as they are: no newline added, any bytes.
#[test]
fn values_are_written_byte_for_byte() {
    let dir = Dir::temp("bytes").unwrap();
    let mut writer = Writer::open(&dir.0, None, true).unwrap();
    let bytes = vec![0_u8, 255, b'\n', b'x'];
    writer
        .write(&[OutputFile {
            name: "raw".to_owned(),
            contents: Zeroizing::new(bytes.clone()),
            mode: 0o440,
        }])
        .unwrap();
    assert_eq!(std::fs::read(dir.0.join("raw")).unwrap(), bytes);
}

/// One previous generation is kept across a swap (a reader that resolved
/// `..data` just before still finds its files), and removed at the next.
#[test]
fn the_previous_generation_is_kept_until_the_next_swap() {
    let dir = Dir::temp("previous").unwrap();
    let mut writer = Writer::open(&dir.0, None, true).unwrap();
    writer.write(&[file("a", "1", 0o440)]).unwrap();
    let first = dir.0.join(std::fs::read_link(dir.0.join(DATA)).unwrap());
    writer.write(&[file("a", "2", 0o440)]).unwrap();
    assert_eq!(std::fs::read_to_string(first.join("a")).unwrap(), "1");
    assert_eq!(generations(&dir.0).unwrap().len(), 2);
    writer.write(&[file("a", "3", 0o440)]).unwrap();
    assert!(!first.exists());
    assert_eq!(generations(&dir.0).unwrap().len(), 2);
}

/// A reader that resolves `..data` once and reads every file under the
/// resolved directory sees one set, never two, never a missing or partial
/// file, while the writer swaps.
#[test]
fn a_reader_through_the_resolved_directory_sees_one_set() {
    let dir = Dir::temp("reader").unwrap();
    let mut writer = Writer::open(&dir.0, None, true).unwrap();
    writer
        .write(&[file("cert", "0", 0o440), file("key", "0", 0o440)])
        .unwrap();
    let done = Arc::new(AtomicBool::new(false));
    let reader = std::thread::spawn({
        let (dir, done) = (dir.0.clone(), Arc::clone(&done));
        move || -> Result<u64, String> {
            let mut reads = 0;
            while !done.load(Ordering::Relaxed) {
                let target = std::fs::read_link(dir.join(DATA)).map_err(|e| e.to_string())?;
                let set = dir.join(target);
                let read = |name: &str| {
                    std::fs::read_to_string(set.join(name)).map_err(|e| format!("{name}: {e}"))
                };
                let (cert, key) = (read("cert")?, read("key")?);
                if cert != key || cert.is_empty() {
                    return Err(format!("a mixed set: cert {cert:?}, key {key:?}"));
                }
                reads += 1;
            }
            Ok(reads)
        }
    });
    for n in 1..=200 {
        let n = n.to_string();
        writer
            .write(&[file("cert", &n, 0o440), file("key", &n, 0o440)])
            .unwrap();
        std::thread::sleep(Duration::from_millis(2));
    }
    done.store(true, Ordering::Relaxed);
    let reads = reader.join().unwrap().unwrap();
    assert!(reads > 0);
}

/// An agent that stopped between writing a generation and swapping to it
/// leaves it behind: the next start removes it, and the temporary names,
/// and keeps the set `..data` points to.
#[test]
fn a_restart_removes_what_a_stopped_render_left() {
    let dir = Dir::temp("stray").unwrap();
    {
        let mut writer = Writer::open(&dir.0, None, true).unwrap();
        writer.write(&[file("a", "kept", 0o440)]).unwrap();
        writer.write(&[file("a", "kept too", 0o440)]).unwrap();
    }
    std::fs::create_dir(dir.0.join("..2026_01_01_00_00_00.000000000.9")).unwrap();
    std::fs::write(dir.0.join("..data.tmp"), "").unwrap();
    // The application's own file in the directory is none of the agent's.
    std::fs::write(dir.0.join("theirs"), "x").unwrap();

    let _writer = Writer::open(&dir.0, None, true).unwrap();
    assert_eq!(generations(&dir.0).unwrap().len(), 1);
    assert!(!dir.0.join("..data.tmp").exists());
    assert_eq!(
        std::fs::read_to_string(dir.0.join("a")).unwrap(),
        "kept too"
    );
    assert!(dir.0.join("theirs").exists());
}

/// The status file sits next to the set, never in it, with the mode given.
#[test]
fn the_status_is_outside_the_set() {
    let dir = Dir::temp("status").unwrap();
    let mut writer = Writer::open(&dir.0, None, true).unwrap();
    writer.write(&[file("a", "1", 0o440)]).unwrap();
    writer
        .write_status(&serde_json::json!({"ok": true}), 0o440)
        .unwrap();
    let status = std::fs::read_to_string(dir.0.join(STATUS)).unwrap();
    assert!(status.contains("\"ok\": true"), "{status}");
    let set = dir.0.join(std::fs::read_link(dir.0.join(DATA)).unwrap());
    assert!(!set.join(STATUS).exists());
    let mode = std::fs::metadata(dir.0.join(STATUS))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o7777, 0o440);
}

/// A group the agent belongs to (here its own) is set on the files and
/// the generation's directory.
#[test]
fn the_group_is_set() {
    let dir = Dir::temp("group").unwrap();
    let gid = rustix::process::getgid().as_raw();
    let mut writer = Writer::open(&dir.0, Some(gid), true).unwrap();
    writer.write(&[file("a", "1", 0o440)]).unwrap();
    let set = dir.0.join(std::fs::read_link(dir.0.join(DATA)).unwrap());
    assert_eq!(std::fs::metadata(set.join("a")).unwrap().gid(), gid);
    assert_eq!(std::fs::metadata(&set).unwrap().gid(), gid);
}

/// Without `allow_disk`, a directory that isn't in memory is refused, and
/// one in a tmpfs (`/dev/shm`) is fine.
#[test]
fn a_directory_on_disk_is_refused_unless_allowed() {
    let shm = Path::new("/dev/shm");
    if shm.is_dir() {
        let dir = Dir::new(shm, "shm").unwrap();
        Writer::open(&dir.0, None, false).unwrap();
    }
    // The build's own directory, normally on disk.
    let disk = Dir::new(Path::new(env!("CARGO_TARGET_TMPDIR")), "disk").unwrap();
    let fs_type = rustix::fs::statfs(&disk.0).unwrap().f_type;
    if [0x0102_1994, 0x8584_58f6].contains(&u64::try_from(fs_type).unwrap()) {
        eprintln!("skipped: {} is itself in memory", disk.0.display());
        return;
    }
    assert!(matches!(
        Writer::open(&disk.0, None, false),
        Err(FilesError::NotInMemory { .. })
    ));
    Writer::open(&disk.0, None, true).unwrap();
}

/// `..data` pointing outside the directory (whoever can write it can set
/// the link: an application mounting it writable, a hand edit) is never
/// believed: after opening and two writes, which would remove the
/// generation before last, what it pointed to is untouched.
#[test]
fn a_data_link_pointing_outside_is_never_deleted() {
    for relative in [false, true] {
        let base = Dir::temp("base").unwrap();
        let victim = base.0.join("victim");
        std::fs::create_dir(&victim).unwrap();
        std::fs::write(victim.join("precious"), "keep me").unwrap();
        let dir = base.0.join("out");
        std::fs::create_dir(&dir).unwrap();
        let target = if relative {
            PathBuf::from("../victim")
        } else {
            victim.clone()
        };
        std::os::unix::fs::symlink(&target, dir.join(DATA)).unwrap();

        let mut writer = Writer::open(&dir, None, true).unwrap();
        writer.write(&[file("a", "1", 0o440)]).unwrap();
        writer.write(&[file("a", "2", 0o440)]).unwrap();
        writer.write(&[file("a", "3", 0o440)]).unwrap();
        assert_eq!(
            std::fs::read_to_string(victim.join("precious")).unwrap(),
            "keep me",
            "relative: {relative}"
        );
        assert_eq!(std::fs::read_to_string(dir.join("a")).unwrap(), "3");
    }
}

/// A name shaped like a generation but a symlink, or one of the agent's
/// own names, isn't a generation: open doesn't believe it either.
#[test]
fn only_a_real_generation_directory_is_believed() {
    let base = Dir::temp("fake").unwrap();
    let victim = base.0.join("victim");
    std::fs::create_dir(&victim).unwrap();
    std::fs::write(victim.join("precious"), "keep me").unwrap();
    let dir = base.0.join("out");
    std::fs::create_dir(&dir).unwrap();
    // A link named like a generation, pointing outside, and `..data` to it.
    std::os::unix::fs::symlink(&victim, dir.join("..2026_01_01_00_00_00.000000000.1")).unwrap();
    std::os::unix::fs::symlink("..2026_01_01_00_00_00.000000000.1", dir.join(DATA)).unwrap();

    let mut writer = Writer::open(&dir, None, true).unwrap();
    for n in 0..3 {
        writer.write(&[file("a", &n.to_string(), 0o440)]).unwrap();
    }
    assert!(victim.join("precious").exists());
}

/// A write that fails before the swap (here: a name twice, so the second
/// can't be created; on a full tmpfs, `ENOSPC`) leaves no partial
/// generation behind, however often it's retried, and the set in place
/// stays.
#[test]
fn a_failed_write_leaves_nothing_behind() {
    let dir = Dir::temp("failed").unwrap();
    let mut writer = Writer::open(&dir.0, None, true).unwrap();
    writer.write(&[file("a", "good", 0o440)]).unwrap();
    let before = generations(&dir.0).unwrap();
    for _ in 0..3 {
        assert!(
            writer
                .write(&[file("a", "1", 0o440), file("a", "2", 0o440)])
                .is_err()
        );
    }
    assert_eq!(generations(&dir.0).unwrap(), before);
    assert_eq!(std::fs::read_to_string(dir.0.join("a")).unwrap(), "good");
}

/// A write whose swap fails (here: `..data` is a directory, so renaming the
/// new link over it can't succeed; a full tmpfs can refuse the link)
/// leaves no generation and no temporary link behind, however often it's
/// retried.
#[test]
fn a_failed_swap_leaves_nothing_behind() {
    let dir = Dir::temp("swap").unwrap();
    let mut writer = Writer::open(&dir.0, None, true).unwrap();
    std::fs::create_dir(dir.0.join(DATA)).unwrap();
    std::fs::write(dir.0.join(DATA).join("in-the-way"), "").unwrap();
    for _ in 0..3 {
        assert!(writer.write(&[file("a", "1", 0o440)]).is_err());
    }
    let left: Vec<String> = generations(&dir.0)
        .unwrap()
        .into_iter()
        .filter(|name| name != DATA)
        .collect();
    assert!(left.is_empty(), "{left:?}");
    assert!(std::fs::symlink_metadata(dir.0.join("..data.tmp")).is_err());
}
