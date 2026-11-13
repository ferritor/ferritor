//! The output directory's writer, on real directories: on Linux and on
//! Windows (whose access lists stand in for the modes and the group).

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

/// A link to a directory, as the platform makes one.
fn link_dir(target: &Path, link: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    return std::os::unix::fs::symlink(target, link);
    #[cfg(windows)]
    return std::os::windows::fs::symlink_dir(target, link);
}

/// A file's or directory's mode bits.
#[cfg(unix)]
fn mode(path: &Path) -> TestResult<u32> {
    use std::os::unix::fs::PermissionsExt as _;
    Ok(std::fs::metadata(path)?.permissions().mode() & 0o7777)
}

/// An access list: whether it's protected (nothing inherited), and its
/// entries as (SID string, mask), sorted.
#[cfg(windows)]
type Acl = (bool, Vec<(String, u32)>);

/// The access list of `path` (a link itself, not what it points to).
#[cfg(windows)]
fn dacl(path: &Path) -> TestResult<Acl> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsHandle as _;
    let handle = std::fs::OpenOptions::new()
        .access_mode(0x0002_0000) // READ_CONTROL
        .custom_flags(0x0200_0000 | 0x0020_0000) // directories, links themselves
        .open(path)?;
    let dacl = ferritor_winsec::read_dacl(handle.as_handle(), ferritor_winsec::Object::File)?;
    assert!(
        dacl.entries.iter().all(|e| e.allowed && !e.inherited),
        "{dacl:?}"
    );
    let mut entries = Vec::new();
    for e in &dacl.entries {
        entries.push((e.sid.to_string_form()?, e.mask));
    }
    entries.sort();
    Ok((dacl.protected, entries))
}

/// What every file and directory the agent writes allows on Windows: its
/// own account, SYSTEM and Administrators everything, plus `extra`.
#[cfg(windows)]
fn expected_dacl(extra: &[(String, u32)]) -> TestResult<Acl> {
    use ferritor_winsec::{FULL, Sid};
    const SYSTEM: &str = "S-1-5-18";
    let mut entries = vec![(SYSTEM.to_owned(), FULL), ("S-1-5-32-544".to_owned(), FULL)];
    // As LocalSystem the agent's own entry is SYSTEM's, given once.
    let me = Sid::current_user()?.to_string_form()?;
    if me != SYSTEM {
        entries.push((me, FULL));
    }
    entries.extend_from_slice(extra);
    entries.sort();
    Ok((true, entries))
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
    #[cfg(unix)]
    {
        assert_eq!(mode(&real.join("db-password")).unwrap(), 0o440);
        assert_eq!(mode(&real.join("tls.key")).unwrap(), 0o400);
        assert_eq!(mode(&real).unwrap(), DIR_MODE);
    }
    // No group: the agent, SYSTEM and Administrators only, whatever the mode.
    #[cfg(windows)]
    {
        let _ = DIR_MODE;
        assert_eq!(
            dacl(&real.join("db-password")).unwrap(),
            expected_dacl(&[]).unwrap()
        );
        assert_eq!(
            dacl(&real.join("tls.key")).unwrap(),
            expected_dacl(&[]).unwrap()
        );
        assert_eq!(dacl(&real).unwrap(), expected_dacl(&[]).unwrap());
    }

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
    #[cfg(unix)]
    assert_eq!(mode(&dir.0.join(STATUS)).unwrap(), 0o440);
    #[cfg(windows)]
    assert_eq!(
        dacl(&dir.0.join(STATUS)).unwrap(),
        expected_dacl(&[]).unwrap()
    );
}

/// A group the agent belongs to (here its own) is set on the files and
/// the generation's directory.
#[cfg(unix)]
#[test]
fn the_group_is_set() {
    use std::os::unix::fs::MetadataExt as _;
    let dir = Dir::temp("group").unwrap();
    let gid = rustix::process::getgid().as_raw();
    let group = ferritor_agent::files::Group::Id(gid);
    let mut writer = Writer::open(&dir.0, Some(&group), true).unwrap();
    writer.write(&[file("a", "1", 0o440)]).unwrap();
    let set = dir.0.join(std::fs::read_link(dir.0.join(DATA)).unwrap());
    assert_eq!(std::fs::metadata(set.join("a")).unwrap().gid(), gid);
    assert_eq!(std::fs::metadata(&set).unwrap().gid(), gid);
}

/// On Windows the group is an account or group name: it may read a file
/// whose mode gives the group read, and list the generation's directory;
/// a file the mode keeps from the group (0o400) it can't open. No other
/// entry, nothing inherited.
#[cfg(windows)]
#[test]
fn the_group_may_read_what_its_mode_allows() {
    use ferritor_winsec::{READ, READ_AND_LIST};
    let dir = Dir::temp("group").unwrap();
    let group = ferritor_agent::files::Group::Name("BUILTIN\\Users".to_owned());
    let mut writer = Writer::open(&dir.0, Some(&group), true).unwrap();
    writer
        .write(&[file("shared", "1", 0o440), file("private", "2", 0o400)])
        .unwrap();
    let set = dir.0.join(std::fs::read_link(dir.0.join(DATA)).unwrap());
    let users = "S-1-5-32-545".to_owned();
    assert_eq!(
        dacl(&set.join("shared")).unwrap(),
        expected_dacl(&[(users.clone(), READ)]).unwrap()
    );
    assert_eq!(
        dacl(&set.join("private")).unwrap(),
        expected_dacl(&[]).unwrap()
    );
    assert_eq!(
        dacl(&set).unwrap(),
        expected_dacl(&[(users, READ_AND_LIST)]).unwrap()
    );
}

/// A group that doesn't name an account is refused at open, by name.
#[cfg(windows)]
#[test]
fn an_unknown_group_is_refused() {
    let dir = Dir::temp("nogroup").unwrap();
    let group = ferritor_agent::files::Group::Name("no-such-account-ferritor".to_owned());
    assert!(matches!(
        Writer::open(&dir.0, Some(&group), true),
        Err(FilesError::Account { .. })
    ));
}

/// Windows has no memory-backed directory: without `allow_disk` it's
/// refused, saying so.
#[cfg(windows)]
#[test]
fn windows_needs_allow_disk() {
    let dir = Dir::temp("disk").unwrap();
    assert!(matches!(
        Writer::open(&dir.0, None, false),
        Err(FilesError::DiskOnly { .. })
    ));
    Writer::open(&dir.0, None, true).unwrap();
}

/// An application holding a file open without letting it be deleted (most
/// Windows programs: .NET, the C runtime) keeps that generation from being
/// removed. The writes go on all the same; the generation is removed at
/// the first write after the file is closed. Replacing the visible name of
/// a file held open works too: the link isn't what's open.
#[cfg(windows)]
#[test]
fn a_file_held_open_never_fails_a_write() {
    use std::os::windows::fs::OpenOptionsExt as _;
    const FILE_SHARE_READ: u32 = 1;
    let dir = Dir::temp("held").unwrap();
    let mut writer = Writer::open(&dir.0, None, true).unwrap();
    writer.write(&[file("a", "1", 0o440)]).unwrap();
    let first = std::fs::read_link(dir.0.join(DATA)).unwrap();
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(dir.0.join("a"))
        .unwrap();
    for n in 2..=4 {
        writer.write(&[file("a", &n.to_string(), 0o440)]).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.0.join("a")).unwrap(),
            n.to_string()
        );
    }
    assert!(dir.0.join(&first).exists());
    assert!(!writer.leftovers().is_empty());
    drop(held);
    writer.write(&[file("a", "5", 0o440)]).unwrap();
    assert!(!dir.0.join(&first).exists());
    assert!(writer.leftovers().is_empty(), "{:?}", writer.leftovers());
    // The current set and the one before it.
    assert_eq!(generations(&dir.0).unwrap().len(), 2);
}

/// At open, a stray generation held open is kept for later rather than
/// failing the start.
#[cfg(windows)]
#[test]
fn a_stray_held_open_never_fails_a_start() {
    use std::os::windows::fs::OpenOptionsExt as _;
    const FILE_SHARE_READ: u32 = 1;
    let dir = Dir::temp("heldstray").unwrap();
    {
        let mut writer = Writer::open(&dir.0, None, true).unwrap();
        writer.write(&[file("a", "1", 0o440)]).unwrap();
    }
    let stray = dir.0.join("..2026_01_01_00_00_00.000000000.9");
    std::fs::create_dir(&stray).unwrap();
    std::fs::write(stray.join("old"), "x").unwrap();
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(stray.join("old"))
        .unwrap();
    let mut writer = Writer::open(&dir.0, None, true).unwrap();
    assert!(stray.exists());
    drop(held);
    writer.write(&[file("a", "2", 0o440)]).unwrap();
    assert!(!stray.exists());
}

/// A junction named like a generation, and `..data` pointing at it, is
/// never believed: what it points to is left alone.
#[cfg(windows)]
#[test]
fn a_junction_is_never_a_generation() {
    let base = Dir::temp("junction").unwrap();
    let victim = base.0.join("victim");
    std::fs::create_dir(&victim).unwrap();
    std::fs::write(victim.join("precious"), "keep me").unwrap();
    let dir = base.0.join("out");
    std::fs::create_dir(&dir).unwrap();
    let fake = dir.join("..2026_01_01_00_00_00.000000000.1");
    let made = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(&fake)
        .arg(&victim)
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    std::os::windows::fs::symlink_dir("..2026_01_01_00_00_00.000000000.1", dir.join(DATA)).unwrap();
    let mut writer = Writer::open(&dir, None, true).unwrap();
    for n in 0..3 {
        writer.write(&[file("a", &n.to_string(), 0o440)]).unwrap();
    }
    assert!(victim.join("precious").exists());
}

/// Without `allow_disk`, a directory that isn't in memory is refused, and
/// one in a tmpfs (`/dev/shm`) is fine.
#[cfg(unix)]
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
    if [0x0102_1994, 0x8584_58f6].contains(&u64::try_from(i128::from(fs_type)).unwrap()) {
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
            Path::new("..").join("victim")
        } else {
            victim.clone()
        };
        link_dir(&target, &dir.join(DATA)).unwrap();

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
    link_dir(&victim, &dir.join("..2026_01_01_00_00_00.000000000.1")).unwrap();
    link_dir(
        Path::new("..2026_01_01_00_00_00.000000000.1"),
        &dir.join(DATA),
    )
    .unwrap();

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
