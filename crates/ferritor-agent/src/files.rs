//! Writing an output directory: the set of files swapped atomically, the
//! layout Kubernetes uses for Secret volumes.
//!
//! ```text
//! dir/
//!   ..2026_10_24_10_02_11.123456789/   a generation: every file, as written
//!   ..data -> ..2026_10_24_10_02_11.123456789
//!   db-password -> ..data/db-password  what the application opens
//!   ..status.json                      outside the set
//! ```
//!
//! A render writes a new generation (each file created, written, synced),
//! then swaps `..data` onto it with one rename, then adds or removes the
//! visible links. A reader that resolves `..data` once and reads every file
//! under the resolved directory sees one set, old or new; a reader opening
//! files by their visible names, one after another, can see two (see
//! `docs/src/content/docs/guides/agent.md`). The generation `..data` pointed to before a swap is kept
//! until the next one, so a reader that resolved it a moment before still
//! finds its files.
//!
//! On Windows the same layout, with Windows' own links (`symlink_dir` for
//! `..data`, `symlink_file` for the visible names, which take the "Create
//! symbolic links" privilege: checked at open) and access lists instead of
//! modes and groups (`ferritor-winsec`). A generation whose file an
//! application holds open can't be removed there until it's closed: it's
//! kept and removed at a later write.

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::Serialize;
use zeroize::Zeroizing;

/// The link the application's files point through.
pub const DATA: &str = "..data";
/// The agent's status, next to the set, never in it.
pub const STATUS: &str = "..status.json";
/// Generations, and the agent's temporary names, start with this.
const GENERATION_PREFIX: &str = "..";
const DATA_TMP: &str = "..data.tmp";
const STATUS_TMP: &str = "..status.json.tmp";
/// The directories' mode: the files' group may enter them.
pub const DIR_MODE: u32 = 0o750;

/// A link made and removed at open, on Windows, to check the privilege.
const LINK_CHECK: &str = "..link-check";

/// Filesystem types that keep data in memory (`statfs`'s `f_type`).
#[cfg(unix)]
const TMPFS_MAGIC: u64 = 0x0102_1994;
#[cfg(unix)]
const RAMFS_MAGIC: u64 = 0x8584_58f6;

/// The files' group: a gid on Unix; on Windows an account or group name
/// (`DOMAIN\name`, `NT SERVICE\app`, `BUILTIN\Users`), given read access.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(untagged)]
pub enum Group {
    Id(u32),
    Name(String),
}

#[derive(Debug, thiserror::Error)]
pub enum FilesError {
    #[error("{op} {}", .path.display())]
    Io {
        op: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "{} isn't in memory (filesystem type {fs_type:#x}, not tmpfs or ramfs): values \
         would be written to a disk; use a memory-backed directory (an emptyDir with \
         medium: Memory, RuntimeDirectory=), or set allow_disk = true",
        .dir.display()
    )]
    NotInMemory { dir: PathBuf, fs_type: u64 },
    #[error(
        "{}: Windows has no memory-backed directory, so values are written to disk; \
         set allow_disk = true (and encrypt the disk)",
        .dir.display()
    )]
    DiskOnly { dir: PathBuf },
    #[error(
        "{}: creating links needs the \"Create symbolic links\" privilege: run the agent \
         as LocalSystem (a service's default), grant the right to its account \
         (secpol.msc, User Rights Assignment), or turn on Developer Mode",
        .dir.display()
    )]
    NoLinkPrivilege { dir: PathBuf },
    #[error("group {group:?}: {reason}")]
    Group { group: String, reason: String },
    #[error("looking up the account {name:?}")]
    Account {
        name: String,
        #[source]
        source: std::io::Error,
    },
}

fn io<'a>(op: &'static str, path: &'a Path) -> impl FnOnce(std::io::Error) -> FilesError + 'a {
    move |source| FilesError::Io {
        op,
        path: path.to_owned(),
        source,
    }
}

/// One file of a set: its name, its contents (wiped when dropped), its mode.
pub struct OutputFile {
    pub name: String,
    pub contents: Zeroizing<Vec<u8>>,
    pub mode: u32,
}

/// Whether a filesystem type keeps its data in memory.
#[cfg(unix)]
fn in_memory(fs_type: u64) -> bool {
    matches!(fs_type, TMPFS_MAGIC | RAMFS_MAGIC)
}

/// Who may open what the writer creates: on Unix the group set on it, on
/// Windows the accounts of its access lists.
#[cfg(unix)]
struct Access {
    group: Option<u32>,
}

#[cfg(windows)]
struct Access {
    agent: ferritor_winsec::Sid,
    system: ferritor_winsec::Sid,
    administrators: ferritor_winsec::Sid,
    group: Option<ferritor_winsec::Sid>,
}

impl Access {
    #[cfg(unix)]
    fn new(group: Option<&Group>) -> Result<Self, FilesError> {
        match group {
            None => Ok(Self { group: None }),
            Some(Group::Id(gid)) => Ok(Self { group: Some(*gid) }),
            Some(Group::Name(name)) => Err(FilesError::Group {
                group: name.clone(),
                reason: "a numeric gid on Unix".to_owned(),
            }),
        }
    }

    #[cfg(windows)]
    fn new(group: Option<&Group>) -> Result<Self, FilesError> {
        use ferritor_winsec::Sid;
        fn account(name: &str) -> impl FnOnce(std::io::Error) -> FilesError + '_ {
            move |source| FilesError::Account {
                name: name.to_owned(),
                source,
            }
        }
        let group = match group {
            None => None,
            Some(Group::Name(name)) => Some(Sid::lookup(name).map_err(account(name))?),
            Some(Group::Id(gid)) => {
                return Err(FilesError::Group {
                    group: gid.to_string(),
                    reason: "an account or group name on Windows".to_owned(),
                });
            }
        };
        Ok(Self {
            agent: Sid::current_user().map_err(account("this process's own"))?,
            system: Sid::local_system().map_err(account("SYSTEM"))?,
            administrators: Sid::administrators().map_err(account("Administrators"))?,
            group,
        })
    }
}

/// An output directory and its generations.
pub struct Writer {
    dir: PathBuf,
    access: Access,
    /// The generation `..data` points to, if any.
    current: Option<String>,
    /// The one before it, kept for readers that resolved `..data` before
    /// the last swap; removed at the next.
    previous: Option<String>,
    /// Makes generation names unique within a clock tick.
    sequence: u64,
    /// Generations that couldn't be removed when they were due (on Windows,
    /// a file in one an application holds open): tried again at each write.
    leftovers: Vec<String>,
    /// The leftovers already warned of: once each, not at every write.
    warned: std::collections::HashSet<String>,
}

impl Writer {
    /// Opens `dir` (creating it if missing): refuses one that isn't in
    /// memory unless `allow_disk`, and removes generations left by an agent
    /// that stopped between writing one and swapping to it.
    pub fn open(dir: &Path, group: Option<&Group>, allow_disk: bool) -> Result<Self, FilesError> {
        let access = Access::new(group)?;
        if !dir.exists() {
            std::fs::create_dir_all(dir).map_err(io("creating", dir))?;
            set_access(dir, DIR_MODE, &access, Kind::Dir)?;
        }
        if !allow_disk {
            check_in_memory(dir)?;
        }
        #[cfg(windows)]
        check_link_privilege(dir)?;
        // Whatever `..data` points to is kept as the current generation, and
        // removed two writes later: so it's believed only if it is one of
        // the agent's generations inside `dir`. Anyone who can write the
        // directory can set the link, and a target like `/some/dir` or
        // `../x` would otherwise be deleted with the agent's rights.
        let current = match std::fs::read_link(dir.join(DATA)) {
            Ok(target) => match target.to_str().filter(|name| is_generation(dir, name)) {
                Some(name) => Some(name.to_owned()),
                None => {
                    tracing::warn!(
                        dir = %dir.display(),
                        target = %target.display(),
                        "..data points somewhere that isn't one of this agent's generations; \
                         ignoring it (is the directory writable by someone else?)"
                    );
                    None
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(io("reading", &dir.join(DATA))(e)),
        };
        // The previous generation isn't known after a restart, so it's
        // removed with the other strays: a reader that resolved `..data`
        // just before the agent restarted may find its files gone, once.
        let mut writer = Self {
            dir: dir.to_owned(),
            access,
            current,
            previous: None,
            sequence: 0,
            leftovers: Vec::new(),
            warned: std::collections::HashSet::new(),
        };
        writer.remove_strays()?;
        writer.remove_leftovers();
        Ok(writer)
    }

    /// Writes `files` as the new set: a new generation, `..data` swapped
    /// onto it, the visible links added (and those of files no longer in
    /// the set removed), the generation before the previous one removed.
    pub fn write(&mut self, files: &[OutputFile]) -> Result<(), FilesError> {
        let generation = self.generation_name();
        let path = self.dir.join(&generation);
        std::fs::create_dir(&path).map_err(io("creating", &path))?;
        // Until `..data` points at it, a failure leaves nothing behind
        // (filling it, or making the link and renaming it into place: a full
        // tmpfs can refuse either): a stray generation would otherwise stay
        // until a restart, one more each round the failure repeats, on a
        // full tmpfs eating the memory that's already short.
        if let Err(e) = self
            .fill(&path, files)
            .and_then(|()| self.swap(&generation))
        {
            let _ = remove_link(&self.dir.join(DATA_TMP));
            if let Err(cleanup) = remove_generation(&self.dir, &generation) {
                tracing::warn!(error = %cleanup, "removing a partly written generation failed");
            }
            return Err(e);
        }

        // The application's names, through `..data`: added for new files,
        // removed for files the set no longer has.
        for file in files {
            let link = self.dir.join(&file.name);
            let target = Path::new(DATA).join(&file.name);
            if std::fs::read_link(&link).ok().as_deref() != Some(target.as_path()) {
                let tmp = self
                    .dir
                    .join(format!("{GENERATION_PREFIX}{}.tmp", file.name));
                let _ = remove_link(&tmp);
                link_file(&target, &tmp).map_err(io("linking", &tmp))?;
                std::fs::rename(&tmp, &link).map_err(io("linking", &link))?;
            }
        }
        self.remove_unlisted_links(files)?;
        sync_dir(&self.dir)?;

        let replaced = self.current.replace(generation);
        if let Some(older) = std::mem::replace(&mut self.previous, replaced) {
            self.leftovers.push(older);
        }
        // The swap is done: a generation that can't be removed now (a file
        // in it held open, on Windows) doesn't fail the write; it's kept
        // and tried again next time.
        self.remove_leftovers();
        Ok(())
    }

    /// Removes the generations that were due, keeping those that can't be
    /// removed yet.
    fn remove_leftovers(&mut self) {
        let dir = &self.dir;
        let warned = &mut self.warned;
        self.leftovers
            .retain(|name| match remove_generation(dir, name) {
                Ok(()) => {
                    if warned.remove(name) {
                        tracing::info!(generation = %name, "an old generation was removed at last");
                    }
                    false
                }
                Err(e) => {
                    if warned.insert(name.clone()) {
                        tracing::warn!(
                            generation = %name,
                            error = %crate::agent::error_chain(&e),
                            "an old generation can't be removed yet (a file in it held open?); \
                             trying again at each write"
                        );
                    }
                    true
                }
            });
    }

    /// Generations that couldn't be removed yet.
    pub fn leftovers(&self) -> &[String] {
        &self.leftovers
    }

    /// Writes the status file, atomically by itself, outside the set.
    pub fn write_status(&self, status: &impl Serialize, mode: u32) -> Result<(), FilesError> {
        let tmp = self.dir.join(STATUS_TMP);
        let json = serde_json::to_vec_pretty(status).map_err(|e| FilesError::Io {
            op: "encoding",
            path: tmp.clone(),
            source: e.into(),
        })?;
        let _ = std::fs::remove_file(&tmp);
        let mut file = create(&tmp)?;
        file.write_all(&json).map_err(io("writing", &tmp))?;
        file.sync_all().map_err(io("syncing", &tmp))?;
        drop(file);
        set_access(&tmp, mode, &self.access, Kind::File)?;
        let path = self.dir.join(STATUS);
        std::fs::rename(&tmp, &path).map_err(io("replacing", &path))
    }

    /// Points `..data` at `generation`: a new link, renamed over the old
    /// one in one step.
    fn swap(&self, generation: &str) -> Result<(), FilesError> {
        let tmp = self.dir.join(DATA_TMP);
        match remove_link(&tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io("removing", &tmp)(e)),
        }
        link_dir(Path::new(generation), &tmp).map_err(io("linking", &tmp))?;
        let data = self.dir.join(DATA);
        std::fs::rename(&tmp, &data).map_err(io("swapping", &data))
    }

    /// Writes every file of a new generation at `path`, and syncs it.
    fn fill(&self, path: &Path, files: &[OutputFile]) -> Result<(), FilesError> {
        set_access(path, DIR_MODE, &self.access, Kind::Dir)?;
        for file in files {
            self.write_file(&path.join(&file.name), file)?;
        }
        sync_dir(path)
    }

    fn write_file(&self, path: &Path, file: &OutputFile) -> Result<(), FilesError> {
        let mut out = create(path)?;
        out.write_all(&file.contents).map_err(io("writing", path))?;
        out.sync_all().map_err(io("syncing", path))?;
        drop(out);
        set_access(path, file.mode, &self.access, Kind::File)
    }

    /// `..<UTC time>.<sequence>`: sortable, and unique even if the clock
    /// repeats a value.
    fn generation_name(&mut self) -> String {
        self.sequence += 1;
        let now = time::OffsetDateTime::now_utc();
        format!(
            "..{:04}_{:02}_{:02}_{:02}_{:02}_{:02}.{:09}.{}",
            now.year(),
            u8::from(now.month()),
            now.day(),
            now.hour(),
            now.minute(),
            now.second(),
            now.nanosecond(),
            self.sequence
        )
    }

    /// Removes generations and temporary names other than the current one
    /// and the previous (an agent that stopped mid-render leaves them).
    fn remove_strays(&mut self) -> Result<(), FilesError> {
        for entry in std::fs::read_dir(&self.dir).map_err(io("listing", &self.dir))? {
            let entry = entry.map_err(io("listing", &self.dir))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !name.starts_with(GENERATION_PREFIX) || name == DATA || name == STATUS {
                continue;
            }
            if Some(name) == self.current.as_deref() || Some(name) == self.previous.as_deref() {
                continue;
            }
            let path = entry.path();
            // Not following symlinks: a link named like a generation is
            // removed as a link, never what it points to.
            if entry.file_type().map_err(io("listing", &path))?.is_dir() {
                // Kept for a later write if it can't go now (held open).
                self.leftovers.push(name.to_owned());
            } else {
                remove_link(&path).map_err(io("removing", &path))?;
            }
        }
        Ok(())
    }

    /// Removes the visible links of files the set no longer has: links
    /// through `..data` whose name isn't among `files`.
    fn remove_unlisted_links(&self, files: &[OutputFile]) -> Result<(), FilesError> {
        for entry in std::fs::read_dir(&self.dir).map_err(io("listing", &self.dir))? {
            let entry = entry.map_err(io("listing", &self.dir))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.starts_with(GENERATION_PREFIX) || files.iter().any(|f| f.name == name) {
                continue;
            }
            let path = entry.path();
            let ours = std::fs::read_link(&path).is_ok_and(|target| target.starts_with(DATA));
            if ours {
                remove_link(&path).map_err(io("removing", &path))?;
            }
        }
        Ok(())
    }
}

/// A new file, refusing to follow or replace anything already there
/// (`O_CREAT | O_EXCL` fails on any existing name, a symlink included).
fn create(path: &Path) -> Result<File, FilesError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    // Only the agent until the mode is set; the umask can only narrow it
    // further, so the mode is set explicitly afterwards. (On Windows the
    // file starts with its generation's access list, set before it.)
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path).map_err(io("creating", path))
}

/// What a path is, for its access list.
#[derive(Clone, Copy)]
enum Kind {
    File,
    Dir,
}

/// The group, then the mode.
#[cfg(unix)]
fn set_access(path: &Path, mode: u32, access: &Access, _kind: Kind) -> Result<(), FilesError> {
    use std::os::unix::fs::PermissionsExt as _;
    if let Some(group) = access.group {
        std::os::unix::fs::chown(path, None, Some(group))
            .map_err(io("setting the group of", path))?;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(io("setting the mode of", path))
}

/// A protected access list (nothing inherited): the agent's account, SYSTEM
/// and Administrators everything; the group reading (and, for a directory,
/// listing) only if the mode gives the group read. The mode's owner bits
/// don't apply: the agent must be able to replace and remove what it wrote.
/// A directory's entries are inherited by what's created in it, until that
/// gets its own.
#[cfg(windows)]
fn set_access(path: &Path, mode: u32, access: &Access, kind: Kind) -> Result<(), FilesError> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsHandle as _;

    use ferritor_winsec::{Entry, FULL, Object, READ, READ_AND_LIST};
    // FILE_FLAG_BACKUP_SEMANTICS opens a directory, FILE_FLAG_OPEN_REPARSE_POINT
    // a link itself rather than what it points to.
    const BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const READ_CONTROL: u32 = 0x0002_0000;
    let inherit = matches!(kind, Kind::Dir);
    let mut entries = vec![
        Entry {
            sid: &access.system,
            mask: FULL,
            inherit,
        },
        Entry {
            sid: &access.administrators,
            mask: FULL,
            inherit,
        },
    ];
    // Running as LocalSystem, the agent is SYSTEM: one entry, not two.
    if access.agent != access.system {
        entries.push(Entry {
            sid: &access.agent,
            mask: FULL,
            inherit,
        });
    }
    if let Some(group) = &access.group
        && mode & 0o040 != 0
    {
        entries.push(Entry {
            sid: group,
            mask: if inherit { READ_AND_LIST } else { READ },
            inherit,
        });
    }
    let handle = OpenOptions::new()
        .access_mode(WRITE_DAC | READ_CONTROL)
        .custom_flags(OPEN_REPARSE_POINT | if inherit { BACKUP_SEMANTICS } else { 0 })
        .open(path)
        .map_err(io("opening, to set its access list,", path))?;
    ferritor_winsec::set_protected_dacl(handle.as_handle(), Object::File, &entries)
        .map_err(io("setting the access list of", path))
}

#[cfg(unix)]
fn sync_dir(path: &Path) -> Result<(), FilesError> {
    File::open(path)
        .and_then(|dir| dir.sync_all())
        .map_err(io("syncing", path))
}

/// Windows can't open a directory to sync it without more privilege than
/// the agent needs; NTFS journals the renames themselves.
#[cfg(windows)]
#[expect(clippy::unnecessary_wraps, reason = "the same signature as on Unix")]
fn sync_dir(_path: &Path) -> Result<(), FilesError> {
    Ok(())
}

/// Refuses a directory that isn't in memory (tmpfs, ramfs).
#[cfg(unix)]
fn check_in_memory(dir: &Path) -> Result<(), FilesError> {
    let stat = rustix::fs::statfs(dir).map_err(|e| FilesError::Io {
        op: "checking the filesystem of",
        path: dir.to_owned(),
        source: e.into(),
    })?;
    // Signed on Linux, u32 on macOS: through i128 converts either.
    let fs_type = u64::try_from(i128::from(stat.f_type)).unwrap_or(u64::MAX);
    if !in_memory(fs_type) {
        return Err(FilesError::NotInMemory {
            dir: dir.to_owned(),
            fs_type,
        });
    }
    Ok(())
}

/// Windows has none: every directory is on a disk.
#[cfg(windows)]
fn check_in_memory(dir: &Path) -> Result<(), FilesError> {
    Err(FilesError::DiskOnly {
        dir: dir.to_owned(),
    })
}

/// Makes and removes a link, so a missing privilege fails at open, by name,
/// rather than at the first write.
#[cfg(windows)]
fn check_link_privilege(dir: &Path) -> Result<(), FilesError> {
    /// ERROR_PRIVILEGE_NOT_HELD.
    const PRIVILEGE_NOT_HELD: i32 = 1314;
    let probe = dir.join(LINK_CHECK);
    let _ = remove_link(&probe);
    match link_file(Path::new(DATA), &probe) {
        Ok(()) => remove_link(&probe).map_err(io("removing", &probe)),
        Err(e) if e.raw_os_error() == Some(PRIVILEGE_NOT_HELD) => {
            Err(FilesError::NoLinkPrivilege {
                dir: dir.to_owned(),
            })
        }
        Err(e) => Err(io("linking", &probe)(e)),
    }
}

/// A link to a directory (`..data` to a generation).
fn link_dir(target: &Path, link: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    return std::os::unix::fs::symlink(target, link);
    #[cfg(windows)]
    return std::os::windows::fs::symlink_dir(target, link);
}

/// A link to a file (a visible name to `..data\<name>`).
fn link_file(target: &Path, link: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    return std::os::unix::fs::symlink(target, link);
    #[cfg(windows)]
    return std::os::windows::fs::symlink_file(target, link);
}

/// Removes a link itself, never what it points to: on Windows a link to a
/// directory (or a junction) is removed as a directory.
fn remove_link(path: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileTypeExt as _;
        if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink_dir()) {
            return std::fs::remove_dir(path);
        }
    }
    std::fs::remove_file(path)
}

/// Whether `name` is one of the agent's generations in `dir`: one path
/// component starting with `..`, none of its other `..` names, and a real
/// directory there (not a symlink).
fn is_generation(dir: &Path, name: &str) -> bool {
    let one_component = matches!(
        Path::new(name).components().collect::<Vec<_>>().as_slice(),
        [std::path::Component::Normal(_)]
    );
    one_component
        && name.starts_with(GENERATION_PREFIX)
        && ![DATA, STATUS, DATA_TMP, STATUS_TMP, LINK_CHECK].contains(&name)
        && !name.ends_with(".tmp")
        && std::fs::symlink_metadata(dir.join(name)).is_ok_and(|m| m.file_type().is_dir())
}

/// Removes the generation `name` in `dir`, and nothing else: anything that
/// isn't one of the agent's generations there is left alone.
fn remove_generation(dir: &Path, name: &str) -> Result<(), FilesError> {
    let path = dir.join(name);
    if !is_generation(dir, name) {
        if std::fs::symlink_metadata(&path).is_ok() {
            tracing::warn!(path = %path.display(), "not removing what isn't one of this agent's generations");
        }
        return Ok(());
    }
    match std::fs::remove_dir_all(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io("removing", &path)(e)),
    }
}
