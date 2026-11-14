#![expect(
    unsafe_code,
    reason = "Win32's security API: every call is unsafe; each block says why it's sound"
)]

use std::ffi::{OsStr, OsString, c_void};
use std::io;
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::windows::io::{AsRawHandle as _, BorrowedHandle};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::OnceLock;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER,
    ERROR_NO_MORE_FILES, GENERIC_ALL, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_OBJECT_TYPE,
    SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, ACL_SIZE_INFORMATION, AclSizeInformation,
    AddAccessAllowedAceEx, CONTAINER_INHERIT_ACE, CreateWellKnownSid, DACL_SECURITY_INFORMATION,
    DuplicateTokenEx, GetAce, GetAclInformation, GetLengthSid, GetSecurityDescriptorControl,
    GetTokenInformation, INHERITED_ACE, InitializeAcl, InitializeSecurityDescriptor, IsValidSid,
    LookupAccountNameW, OBJECT_INHERIT_ACE, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
    SECURITY_MAX_SID_SIZE, SID_NAME_USE, SecurityImpersonation, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, SetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY,
    TOKEN_DEFAULT_DACL, TOKEN_DUPLICATE, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_USER,
    TokenDefaultDacl, TokenPrimary, TokenUser, WELL_KNOWN_SID_TYPE, WinBuiltinAdministratorsSid,
    WinCreatorOwnerRightsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateFileW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_EXECUTE,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, READ_CONTROL, SYNCHRONIZE,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, SECURITY_DESCRIPTOR_REVISION,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, GetCurrentProcess, GetCurrentProcessId, GetCurrentThread,
    GetExitCodeProcess, OpenProcessToken, OpenThread, PROCESS_ALL_ACCESS, PROCESS_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, STARTUPINFOW, THREAD_ALL_ACCESS,
    THREAD_QUERY_LIMITED_INFORMATION, WaitForSingleObject,
};

/// Everything on a file or directory.
pub const FULL: u32 = FILE_ALL_ACCESS;
/// Reading a file (its data, attributes and access list).
pub const READ: u32 = FILE_GENERIC_READ;
/// Listing and entering a directory, and reading what's in it.
pub const READ_AND_LIST: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;

/// A security identifier (an account, a group, a well-known principal), in
/// its binary form, which is canonical: two equal SIDs have equal bytes.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Sid(Vec<u8>);

impl Sid {
    /// The account this process runs as (its token's user): `LocalSystem`
    /// for a service by default.
    pub fn current_user() -> io::Result<Self> {
        let buffer = token_information(&process_token(TOKEN_QUERY)?, TokenUser)?;
        // SAFETY: the buffer holds a TOKEN_USER (`token_information`, which
        // aligns it), whose SID points into the same buffer, which lives
        // until the end of this function.
        unsafe {
            let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
            Self::copy_from(user.User.Sid)
        }
    }

    /// An account or group by name (`DOMAIN\name`, `name`, `NT SERVICE\x`,
    /// `BUILTIN\Users`), resolved by Windows.
    pub fn lookup(name: &str) -> io::Result<Self> {
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let mut sid_len = 0u32;
        let mut domain_len = 0u32;
        let mut kind: SID_NAME_USE = 0;
        // SAFETY: a size query: null buffers with zero lengths, valid out
        // pointers; `wide` is NUL-terminated.
        let ok = unsafe {
            LookupAccountNameW(
                ptr::null(),
                wide.as_ptr(),
                ptr::null_mut(),
                &mut sid_len,
                ptr::null_mut(),
                &mut domain_len,
                &mut kind,
            )
        };
        // SAFETY: reads this thread's last error, nothing else.
        if ok == 0 && unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
            return Err(io::Error::last_os_error());
        }
        let mut sid = vec![0u8; usize::try_from(sid_len).map_err(io::Error::other)?];
        let mut domain = vec![0u16; usize::try_from(domain_len).map_err(io::Error::other)?];
        // SAFETY: both buffers are writable for the lengths passed, which
        // are the sizes the query returned.
        if unsafe {
            LookupAccountNameW(
                ptr::null(),
                wide.as_ptr(),
                sid.as_mut_ptr().cast(),
                &mut sid_len,
                domain.as_mut_ptr(),
                &mut domain_len,
                &mut kind,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        sid.truncate(usize::try_from(sid_len).map_err(io::Error::other)?);
        Ok(Self(sid))
    }

    /// `NT AUTHORITY\SYSTEM`.
    pub fn local_system() -> io::Result<Self> {
        Self::well_known(WinLocalSystemSid)
    }

    /// `BUILTIN\Administrators`.
    pub fn administrators() -> io::Result<Self> {
        Self::well_known(WinBuiltinAdministratorsSid)
    }

    /// `OWNER RIGHTS` (S-1-3-4): an entry for it replaces the rights an
    /// object's owner otherwise always has (reading and rewriting the
    /// access list).
    pub fn owner_rights() -> io::Result<Self> {
        Self::well_known(WinCreatorOwnerRightsSid)
    }

    fn well_known(kind: WELL_KNOWN_SID_TYPE) -> io::Result<Self> {
        let mut sid = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut len = SECURITY_MAX_SID_SIZE;
        // SAFETY: the buffer is writable for `len` bytes, the largest SID;
        // a null domain is allowed for these well-known SIDs.
        if unsafe { CreateWellKnownSid(kind, ptr::null_mut(), sid.as_mut_ptr().cast(), &mut len) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        sid.truncate(usize::try_from(len).map_err(io::Error::other)?);
        Ok(Self(sid))
    }

    /// Copies the SID at `sid`.
    ///
    /// # Safety
    /// `sid` must point to a valid SID for the duration of the call.
    unsafe fn copy_from(sid: PSID) -> io::Result<Self> {
        // SAFETY: the caller promises a valid SID; IsValidSid checks its
        // structure before GetLengthSid trusts it.
        let len = unsafe {
            if IsValidSid(sid) == 0 {
                return Err(io::Error::other("not a valid SID"));
            }
            GetLengthSid(sid)
        };
        let len = usize::try_from(len).map_err(io::Error::other)?;
        // SAFETY: a valid SID of `len` bytes (above), read only.
        let bytes = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), len) };
        Ok(Self(bytes.to_vec()))
    }

    /// For the Win32 calls that take a SID: they only read it, though the
    /// type is a mutable pointer.
    fn as_psid(&self) -> PSID {
        self.0.as_ptr().cast_mut().cast()
    }

    /// The string form, `S-1-5-18` and the like.
    pub fn to_string_form(&self) -> io::Result<String> {
        let mut text: *mut u16 = ptr::null_mut();
        // SAFETY: a valid SID (every constructor makes one) and a valid out
        // pointer, for a string Windows allocates.
        if unsafe { ConvertSidToStringSidW(self.as_psid(), &mut text) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the call succeeded, so `text` is a NUL-terminated string
        // it allocated with LocalAlloc, freed once copied.
        unsafe {
            let mut len = 0;
            while *text.add(len) != 0 {
                len += 1;
            }
            let string = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
            LocalFree(text.cast());
            Ok(string)
        }
    }
}

impl std::fmt::Debug for Sid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.to_string_form() {
            Ok(text) => f.write_str(&text),
            Err(_) => f.write_str("<SID>"),
        }
    }
}

/// One entry of an access list: `sid` is allowed `mask`; with `inherit`,
/// objects created inside a directory get the entry too.
pub struct Entry<'a> {
    pub sid: &'a Sid,
    pub mask: u32,
    pub inherit: bool,
}

/// What a handle is: a file or directory, or a kernel object (a process, a
/// thread).
#[derive(Clone, Copy)]
pub enum Object {
    File,
    Process,
    Thread,
}

impl Object {
    fn kind(self) -> SE_OBJECT_TYPE {
        match self {
            Self::File => SE_FILE_OBJECT,
            Self::Process | Self::Thread => SE_KERNEL_OBJECT,
        }
    }
}

/// Replaces the access list of what `handle` refers to with exactly
/// `entries`, protected: nothing inherited from its parent. The handle must
/// have been opened with `WRITE_DAC`.
pub fn set_protected_dacl(
    handle: BorrowedHandle<'_>,
    object: Object,
    entries: &[Entry<'_>],
) -> io::Result<()> {
    let mut acl = build_acl(entries)?;
    // SAFETY: `handle` is open (borrowed for this call), the ACL was built
    // by InitializeAcl and AddAccessAllowedAceEx in a buffer that outlives
    // the call, and the owner, group and SACL are left alone (null).
    let error = unsafe {
        SetSecurityInfo(
            handle.as_raw_handle(),
            object.kind(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            acl.as_mut_ptr().cast::<ACL>(),
            ptr::null(),
        )
    };
    win32(error)
}

/// An access list as built for `entries`, in a buffer aligned for `ACL`
/// (u32s: an ACL and its entries are DWORD-aligned).
fn build_acl(entries: &[Entry<'_>]) -> io::Result<Vec<u32>> {
    // ACCESS_ALLOWED_ACE ends with the SID's first DWORD (`SidStart`).
    let per_entry = size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>();
    let size = entries
        .iter()
        .fold(size_of::<ACL>(), |size, e| size + per_entry + e.sid.0.len());
    let size = size.next_multiple_of(4);
    let mut buffer = vec![0u32; size / 4];
    let acl = buffer.as_mut_ptr().cast::<ACL>();
    let length = u32::try_from(size).map_err(io::Error::other)?;
    // SAFETY: the buffer is writable and aligned for `length` bytes.
    if unsafe { InitializeAcl(acl, length, ACL_REVISION) } == 0 {
        return Err(io::Error::last_os_error());
    }
    for entry in entries {
        let flags = if entry.inherit {
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        } else {
            0
        };
        // SAFETY: an initialized ACL sized for every entry (above), and a
        // valid SID, which the call copies.
        if unsafe {
            AddAccessAllowedAceEx(acl, ACL_REVISION, flags, entry.mask, entry.sid.as_psid())
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(buffer)
}

/// Creates `path` as a new file (`AlreadyExists` if there is one) that
/// only the current user may open: a protected access list of the user,
/// SYSTEM and Administrators (as OpenSSH wants of a private key), nothing
/// inherited from the folder. The Windows counterpart of creating it with
/// mode 0600. The list is part of the creation itself (`CreateFileW`'s
/// security attributes), so the file never exists with any other: a list
/// set afterwards would leave a moment in which an account the folder
/// grants rights on new files could open a handle and keep that access.
/// The returned handle is unshared besides, until it closes.
pub fn create_private_file(path: &Path) -> io::Result<std::fs::File> {
    use std::os::windows::io::{FromRawHandle as _, OwnedHandle};

    let (user, system, administrators) = (
        Sid::current_user()?,
        Sid::local_system()?,
        Sid::administrators()?,
    );
    let mut entries = vec![
        Entry {
            sid: &system,
            mask: FULL,
            inherit: false,
        },
        Entry {
            sid: &administrators,
            mask: FULL,
            inherit: false,
        },
    ];
    // Running as LocalSystem, the user is SYSTEM: one entry, not two.
    if user != system {
        entries.push(Entry {
            sid: &user,
            mask: FULL,
            inherit: false,
        });
    }
    let acl = build_acl(&entries)?;
    let mut descriptor = SECURITY_DESCRIPTOR {
        Revision: 0,
        Sbz1: 0,
        Control: 0,
        Owner: ptr::null_mut(),
        Group: ptr::null_mut(),
        Sacl: ptr::null_mut(),
        Dacl: ptr::null_mut(),
    };
    let sd: PSECURITY_DESCRIPTOR = (&raw mut descriptor).cast();
    // SAFETY: `sd` points at a SECURITY_DESCRIPTOR, writable, that outlives
    // every use below; the ACL it's given (absolute form: a pointer, not a
    // copy) was built by `build_acl` and outlives it too.
    let ok = unsafe {
        InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION) != 0
            && SetSecurityDescriptorDacl(sd, 1, acl.as_ptr().cast::<ACL>(), 0) != 0
            // Protected, said outright: a file system that would merge the
            // folder's inheritable entries into an explicit list mustn't.
            && SetSecurityDescriptorControl(sd, SE_DACL_PROTECTED, SE_DACL_PROTECTED) != 0
    };
    if !ok {
        return Err(io::Error::last_os_error());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).map_err(io::Error::other)?,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    let name = wide_nul(path.as_os_str())?;
    // SAFETY: `name` is NUL-terminated UTF-16, `attributes` and the
    // descriptor and ACL it points to live until the call returns, and no
    // template file is given.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            FILE_GENERIC_WRITE | READ_CONTROL,
            0,
            &raw const attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a valid handle CreateFileW just opened, owned by nothing else.
    Ok(std::fs::File::from(unsafe {
        OwnedHandle::from_raw_handle(handle)
    }))
}

/// An access list as read back: for checks and tests.
#[derive(Debug)]
pub struct Dacl {
    /// Nothing inherited from the parent.
    pub protected: bool,
    pub entries: Vec<DaclEntry>,
}

#[derive(Debug)]
pub struct DaclEntry {
    /// Allowed (`true`) or denied.
    pub allowed: bool,
    pub sid: Sid,
    pub mask: u32,
    /// Came from the parent rather than set on the object.
    pub inherited: bool,
}

/// Reads the access list of what `handle` refers to (opened with
/// `READ_CONTROL`). Entries other than plain allow and deny ones (objects',
/// callbacks') are left out.
pub fn read_dacl(handle: BorrowedHandle<'_>, object: Object) -> io::Result<Dacl> {
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `handle` is open for this call; valid out pointers; Windows
    // allocates the descriptor (freed by `Local` below) and points `dacl`
    // into it.
    let error = unsafe {
        GetSecurityInfo(
            handle.as_raw_handle(),
            object.kind(),
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    win32(error)?;
    let descriptor = Local(descriptor);
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: a descriptor GetSecurityInfo returned, still allocated.
    if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let protected = control & SE_DACL_PROTECTED != 0;
    if dacl.is_null() {
        // No access list at all: everyone may do everything.
        return Err(io::Error::other(
            "no access list (everyone has full access)",
        ));
    }
    let mut info = ACL_SIZE_INFORMATION {
        AceCount: 0,
        AclBytesInUse: 0,
        AclBytesFree: 0,
    };
    let info_len = u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).map_err(io::Error::other)?;
    // SAFETY: `dacl` points into the live descriptor; `info` is writable
    // for its own size.
    if unsafe {
        GetAclInformation(
            dacl,
            ptr::from_mut(&mut info).cast(),
            info_len,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut entries = Vec::new();
    for index in 0..info.AceCount {
        let mut ace: *mut c_void = ptr::null_mut();
        // SAFETY: `index` is below the ACL's entry count; `ace` is a valid
        // out pointer, pointed into the ACL.
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: every entry starts with an ACE_HEADER. Allow and deny
        // entries have the same layout, ACCESS_ALLOWED_ACE, whose SID starts
        // at `SidStart`; the descriptor holding them is alive.
        unsafe {
            let header = &*ace.cast::<ACE_HEADER>();
            let kind = u32::from(header.AceType);
            if kind != ACCESS_ALLOWED_ACE_TYPE && kind != ACCESS_DENIED_ACE_TYPE {
                continue;
            }
            let allowed_ace = &*ace.cast::<ACCESS_ALLOWED_ACE>();
            let sid = Sid::copy_from(ptr::from_ref(&allowed_ace.SidStart).cast_mut().cast())?;
            entries.push(DaclEntry {
                allowed: kind == ACCESS_ALLOWED_ACE_TYPE,
                sid,
                mask: allowed_ace.Mask,
                inherited: u32::from(header.AceFlags) & INHERITED_ACE != 0,
            });
        }
    }
    Ok(Dacl { protected, entries })
}

/// Locks this process and its threads against other processes, as far as
/// access lists can. SYSTEM keeps every right. This process's own account
/// may only ask for its name and exit code, wait for it and end it, and wait
/// for and query its threads: never read or write its memory, start a thread
/// in it, read or set a thread's registers, suspend one or queue it work, or
/// rewrite any of these lists (`OWNER RIGHTS` takes away what an owner
/// otherwise always has). Administrators holding `SeDebugPrivilege` still
/// get in: the lists don't apply to them.
///
/// A thread is an object of its own, with its own list, taken from the
/// token's default access list when it's created. So, in this order: the
/// process's list, the token's default list (every thread created from now
/// on gets it, and so does anything else created without a list of its own,
/// a child process and its threads included), then every thread already
/// running is given the same list as a new one: the main thread, the
/// loader's workers, any a library started. A thread started meanwhile
/// already has the new default.
///
/// Run as SYSTEM (a service's default account), its account is SYSTEM, which
/// keeps every right: the lists then keep out every other account.
///
/// The default list also goes to every child: Windows builds a new
/// process's own access list from it, and gives the child a copy of it,
/// which would keep the child's account out of the child itself. So a
/// command is started with `spawn_unlocked`, never `std::process`, which
/// gives it the default list the token had before this call.
pub fn protect_current_process() -> io::Result<()> {
    let original = process_token(TOKEN_QUERY)
        .and_then(|token| token_information(&token, TokenDefaultDacl))
        .map_err(step("reading the token's default access list"))?;
    // Kept once: a second call must not save the locked list as the original.
    let _ = ORIGINAL_DEFAULT_DACL.set(original);
    let system = Sid::local_system()?;
    let user = Sid::current_user()?;
    let owner = Sid::owner_rights()?;
    // SAFETY: the pseudo-handle is valid for the whole life of the process
    // and needs no closing; borrowed only for this call.
    let process = unsafe { BorrowedHandle::borrow_raw(GetCurrentProcess()) };
    set_protected_dacl(
        process,
        Object::Process,
        &restricted(
            &system,
            &user,
            &owner,
            PROCESS_ALL_ACCESS,
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | PROCESS_TERMINATE,
        ),
    )
    .map_err(step("setting the process's access list"))?;
    set_default_dacl(&restricted(
        &system,
        &user,
        &owner,
        GENERIC_ALL,
        // The default list is for every kind of object, and a right's bit
        // means something else for each: only SYNCHRONIZE and the two
        // "limited information" rights, which for a thread are querying
        // its basic information (0x800) and resuming it (0x1000, harmless
        // without suspending). A child started the usual way would get this
        // list too, and then can't open itself (PowerShell dies): commands
        // start through `spawn_unlocked`, never `std::process`.
        SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
    ))
    .map_err(step("setting the token's default access list"))?;
    let threads = restricted(
        &system,
        &user,
        &owner,
        THREAD_ALL_ACCESS,
        SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION,
    );
    for_each_thread(
        |thread| match set_protected_dacl(thread, Object::Thread, &threads) {
            // A thread already locked (by an earlier call, or started from the
            // locked default list meanwhile) may refuse a new list even through
            // a handle `SeDebugPrivilege` opened: seen on Windows Server 2025.
            // It needs none if its list already keeps the account out.
            Err(e)
                if e.kind() == io::ErrorKind::PermissionDenied
                    && already_locked(thread, &system)? =>
            {
                Ok(())
            }
            result => result.map_err(step("setting a thread's access list")),
        },
    )
    .map_err(step("listing the threads"))
}

/// Everything a locked thread's list may give anyone but SYSTEM: waiting for
/// it, querying its basic information, resuming it (harmless without
/// suspending it), reading the list (`OWNER RIGHTS`).
const LOCKED_THREAD_OTHERS: u32 =
    SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION | 0x1000 /* THREAD_RESUME */ | READ_CONTROL;

/// Whether the thread's list gives no one but SYSTEM more than
/// `LOCKED_THREAD_OTHERS`. Not whether it's marked protected: one made from
/// the default list isn't, and a thread has no parent to inherit from.
fn already_locked(thread: BorrowedHandle<'_>, system: &Sid) -> io::Result<bool> {
    let dacl = read_dacl(thread, Object::Thread).map_err(step("reading a thread's access list"))?;
    Ok(dacl
        .entries
        .iter()
        .filter(|e| e.allowed && e.sid != *system)
        .all(|e| e.mask & !LOCKED_THREAD_OTHERS == 0))
}

/// Says which step an error came from, keeping its kind.
fn step(what: &'static str) -> impl Fn(io::Error) -> io::Error {
    move |e| io::Error::new(e.kind(), format!("{what}: {e}"))
}

/// The token's default access list as it was before `protect_current_process`
/// locked it: a `TOKEN_DEFAULT_DACL` at the start of the buffer, pointing to
/// the list after it. The buffer never moves (it's only read from here on),
/// so the pointer stays good.
static ORIGINAL_DEFAULT_DACL: OnceLock<Vec<u64>> = OnceLock::new();

/// A command started by `spawn_unlocked`.
pub struct Child {
    process: OwnedRaw,
    id: u32,
}

impl Child {
    /// Its process id.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Waits up to `timeout` for it to end: its exit code, or `None` if it's
    /// still running (then left to itself).
    pub fn wait(&self, timeout: Duration) -> io::Result<Option<u32>> {
        let millis = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX - 1);
        // SAFETY: a process handle this `Child` owns, open until it drops.
        match unsafe { WaitForSingleObject(self.process.0, millis) } {
            WAIT_OBJECT_0 => {
                let mut code = 0u32;
                // SAFETY: as above; `code` is a valid out pointer.
                if unsafe { GetExitCodeProcess(self.process.0, &mut code) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(Some(code))
            }
            WAIT_TIMEOUT => Ok(None),
            _ => Err(io::Error::last_os_error()),
        }
    }
}

/// Starts `program` with `args`, as this process's account, with the token's
/// default access list as it was before `protect_current_process` (as any
/// other process of the account starts): the command's own account may then
/// open the command as usual (PowerShell won't start otherwise). Otherwise as
/// `std::process::Command` would: this process's environment and directory;
/// no handles inherited, so the command's output goes to this process's
/// console if it has one, nowhere if not.
///
/// `program` without a directory is looked for in the system directory, the
/// Windows directory, then `PATH`, never the current directory; `.exe` is
/// added if it has no extension. A batch file is refused: Windows would run
/// it through `cmd.exe`, which parses the arguments by rules of its own.
pub fn spawn_unlocked(program: &OsStr, args: &[OsString]) -> io::Result<Child> {
    let program = resolve_program(program)?;
    // Windows drops trailing dots and spaces from a name: `run.bat.` is
    // `run.bat`, and a batch file still.
    let name = program.to_string_lossy();
    if Path::new(name.trim_end_matches(['.', ' ']))
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("bat") || e.eq_ignore_ascii_case("cmd"))
    {
        return Err(io::Error::other(
            "a batch file: run it through cmd.exe /c, which then parses its arguments",
        ));
    }
    let application = wide_nul(program.as_os_str())?;
    let mut line = command_line(program.as_os_str(), args)?;

    let own = process_token(TOKEN_DUPLICATE | TOKEN_QUERY)?;
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: a token opened with TOKEN_DUPLICATE; no attributes (the new
    // token gets a default list, and isn't inheritable); a valid out pointer,
    // whose handle `OwnedRaw` closes.
    if unsafe {
        DuplicateTokenEx(
            own.0,
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
            ptr::null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut token,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let token = OwnedRaw(token);
    if let Some(original) = ORIGINAL_DEFAULT_DACL.get() {
        let length = u32::try_from(size_of::<TOKEN_DEFAULT_DACL>()).map_err(io::Error::other)?;
        // SAFETY: a token of our own opened with TOKEN_ADJUST_DEFAULT; the
        // buffer holds a TOKEN_DEFAULT_DACL pointing into itself (as
        // GetTokenInformation wrote it, never moved since), copied by the call.
        if unsafe {
            SetTokenInformation(token.0, TokenDefaultDacl, original.as_ptr().cast(), length)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
    }

    let startup = STARTUPINFOW {
        cb: u32::try_from(size_of::<STARTUPINFOW>()).map_err(io::Error::other)?,
        ..STARTUPINFOW::default()
    };
    let mut info = PROCESS_INFORMATION {
        hProcess: ptr::null_mut(),
        hThread: ptr::null_mut(),
        dwProcessId: 0,
        dwThreadId: 0,
    };
    // SAFETY: a primary token with the access CreateProcessAsUserW needs;
    // `application` and `line` are NUL-terminated and alive for the call
    // (`line` writable, as the call requires); no security attributes (the
    // process and its thread get the new token's default list, the original
    // one); no handles inherited; null environment and directory (this
    // process's); a STARTUPINFOW of its own size; a valid out pointer for the
    // two handles, each closed by `OwnedRaw`.
    if unsafe {
        CreateProcessAsUserW(
            token.0,
            application.as_ptr(),
            line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            0,
            ptr::null(),
            ptr::null(),
            &startup,
            &mut info,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    drop(OwnedRaw(info.hThread));
    Ok(Child {
        process: OwnedRaw(info.hProcess),
        id: info.dwProcessId,
    })
}

/// Where `program` is: as given if it names a directory, else the first of
/// the system directory, the Windows directory and `PATH`'s that has it.
fn resolve_program(program: &OsStr) -> io::Result<PathBuf> {
    let given = Path::new(program);
    let name = if given.extension().is_none() {
        let mut name = program.to_owned();
        name.push(".exe");
        PathBuf::from(name)
    } else {
        given.to_path_buf()
    };
    if given.components().count() > 1 || given.has_root() {
        return Ok(if given.is_file() {
            given.to_path_buf()
        } else {
            name
        });
    }
    let mut dirs = vec![
        system_dir(GetSystemDirectoryW)?,
        system_dir(GetWindowsDirectoryW)?,
    ];
    if let Some(path) = std::env::var_os("PATH") {
        dirs.extend(std::env::split_paths(&path).filter(|d| d.is_absolute()));
    }
    dirs.into_iter()
        .map(|dir| dir.join(&name))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} isn't in the system directories or PATH", name.display()),
            )
        })
}

/// The system or Windows directory, from the call that names it.
fn system_dir(call: unsafe extern "system" fn(*mut u16, u32) -> u32) -> io::Result<PathBuf> {
    let mut buffer = vec![0u16; 512];
    let length = u32::try_from(buffer.len()).map_err(io::Error::other)?;
    // SAFETY: the buffer is writable for `length` characters; the call
    // writes at most that, NUL included, and returns the length without it
    // (0 on failure, more than `length` if it didn't fit).
    let written = unsafe { call(buffer.as_mut_ptr(), length) };
    if written == 0 || written >= length {
        return Err(io::Error::last_os_error());
    }
    buffer.truncate(usize::try_from(written).map_err(io::Error::other)?);
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}

/// `text` as UTF-16 with a NUL at the end, refused if it holds one.
fn wide_nul(text: &OsStr) -> io::Result<Vec<u16>> {
    let mut wide: Vec<u16> = text.encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a NUL in a path or command",
        ));
    }
    wide.push(0);
    Ok(wide)
}

/// The command line a program's C runtime splits back into `program` and
/// `args` (the rules of `CommandLineToArgvW`): the program quoted (a path has
/// no quotes), each argument quoted if it needs it, its backslashes doubled
/// only where they precede a quote.
fn command_line(program: &OsStr, args: &[OsString]) -> io::Result<Vec<u16>> {
    const QUOTE: u16 = b'"' as u16;
    const BACKSLASH: u16 = b'\\' as u16;
    let program: Vec<u16> = program.encode_wide().collect();
    if program.contains(&QUOTE) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a quote in a program's path",
        ));
    }
    let mut line = vec![QUOTE];
    line.extend(program);
    line.push(QUOTE);
    for arg in args {
        line.push(u16::from(b' '));
        let arg: Vec<u16> = arg.encode_wide().collect();
        let plain = !arg.is_empty()
            && !arg
                .iter()
                .any(|&c| matches!(c, 0x20 | 0x09 | 0x0a | 0x0b) || c == QUOTE);
        if plain {
            line.extend(arg);
            continue;
        }
        line.push(QUOTE);
        let mut backslashes = 0;
        for c in arg {
            if c == BACKSLASH {
                backslashes += 1;
                continue;
            }
            let doubled = if c == QUOTE {
                2 * backslashes + 1
            } else {
                backslashes
            };
            line.extend(std::iter::repeat_n(BACKSLASH, doubled));
            backslashes = 0;
            line.push(c);
        }
        line.extend(std::iter::repeat_n(BACKSLASH, 2 * backslashes));
        line.push(QUOTE);
    }
    if line.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a NUL in a path or command",
        ));
    }
    line.push(0);
    Ok(line)
}

/// SYSTEM everything (`all`), the account `limited`, `OWNER RIGHTS` reading
/// the list only. The account's entry is left out when it is SYSTEM, which
/// already has everything.
fn restricted<'a>(
    system: &'a Sid,
    user: &'a Sid,
    owner: &'a Sid,
    all: u32,
    limited: u32,
) -> Vec<Entry<'a>> {
    let mut entries = vec![Entry {
        sid: system,
        mask: all,
        inherit: false,
    }];
    if user != system {
        entries.push(Entry {
            sid: user,
            mask: limited,
            inherit: false,
        });
    }
    entries.push(Entry {
        sid: owner,
        mask: READ_CONTROL,
        inherit: false,
    });
    entries
}

/// Sets this process's token's default access list.
fn set_default_dacl(entries: &[Entry<'_>]) -> io::Result<()> {
    let token = process_token(TOKEN_ADJUST_DEFAULT)?;
    let mut acl = build_acl(entries)?;
    let default = TOKEN_DEFAULT_DACL {
        DefaultDacl: acl.as_mut_ptr().cast::<ACL>(),
    };
    let length = u32::try_from(size_of::<TOKEN_DEFAULT_DACL>()).map_err(io::Error::other)?;
    // SAFETY: a token opened with TOKEN_ADJUST_DEFAULT; `default` points to
    // an ACL built by `build_acl` in a buffer alive for the call, which
    // copies it into the token.
    if unsafe {
        SetTokenInformation(
            token.0,
            TokenDefaultDacl,
            ptr::from_ref(&default).cast(),
            length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Calls `f` with a handle (`WRITE_DAC` and `READ_CONTROL`) to every thread
/// of this process running when the snapshot is taken. A thread that ended
/// since is skipped, and so is one this account can't open to change: its
/// list already keeps this account out.
fn for_each_thread(mut f: impl FnMut(BorrowedHandle<'_>) -> io::Result<()>) -> io::Result<()> {
    const WRITE_DAC: u32 = 0x0004_0000;
    // SAFETY: GetCurrentProcessId has no preconditions.
    let pid = unsafe { GetCurrentProcessId() };
    // SAFETY: a snapshot of every thread on the system (the process id is
    // ignored for threads); its handle is closed by `OwnedRaw`.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let snapshot = OwnedRaw(snapshot);
    let mut entry = THREADENTRY32 {
        dwSize: u32::try_from(size_of::<THREADENTRY32>()).map_err(io::Error::other)?,
        cntUsage: 0,
        th32ThreadID: 0,
        th32OwnerProcessID: 0,
        tpBasePri: 0,
        tpDeltaPri: 0,
        dwFlags: 0,
    };
    // SAFETY: an open snapshot, and an entry whose `dwSize` is its size.
    let mut more = unsafe { Thread32First(snapshot.0, &mut entry) } != 0;
    while more {
        if entry.th32OwnerProcessID == pid {
            // SAFETY: OpenThread has no preconditions; a null result is an
            // error, and a handle is closed by `OwnedRaw`.
            let thread = unsafe { OpenThread(WRITE_DAC | READ_CONTROL, 0, entry.th32ThreadID) };
            if thread.is_null() {
                // SAFETY: reads this thread's last error, nothing else.
                match unsafe { GetLastError() } {
                    // Ended since the snapshot.
                    ERROR_INVALID_PARAMETER => {}
                    // Its list already keeps this account out (a thread
                    // another account created, the service manager's for
                    // a service's main thread): so it keeps out any other
                    // process of this account too.
                    ERROR_ACCESS_DENIED => {}
                    _ => return Err(io::Error::last_os_error()),
                }
            } else {
                let thread = OwnedRaw(thread);
                // SAFETY: open until `thread` drops, after this call.
                f(unsafe { BorrowedHandle::borrow_raw(thread.0) })?;
            }
        }
        // SAFETY: as for Thread32First.
        more = unsafe { Thread32Next(snapshot.0, &mut entry) } != 0;
    }
    // SAFETY: reads this thread's last error, nothing else.
    match unsafe { GetLastError() } {
        ERROR_NO_MORE_FILES => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}

/// A token's information of class `class`, in a buffer of u64s, so aligned
/// for any of the structures it may hold (pointer-aligned at most).
fn token_information(token: &OwnedRaw, class: TOKEN_INFORMATION_CLASS) -> io::Result<Vec<u64>> {
    let mut needed = 0u32;
    // SAFETY: a size query: a null buffer of length 0, and a valid out
    // pointer for the length; it fails with ERROR_INSUFFICIENT_BUFFER.
    unsafe { GetTokenInformation(token.0, class, ptr::null_mut(), 0, &mut needed) };
    let mut buffer = vec![0u64; usize::try_from(needed).unwrap_or(0).div_ceil(8)];
    let length = u32::try_from(buffer.len() * 8).map_err(io::Error::other)?;
    // SAFETY: the buffer is writable for `length` bytes, which is at least
    // what the query asked for.
    if unsafe {
        GetTokenInformation(
            token.0,
            class,
            buffer.as_mut_ptr().cast(),
            length,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(buffer)
}

/// This process's token, opened for `access`.
fn process_token(access: u32) -> io::Result<OwnedRaw> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: the pseudo-handle from GetCurrentProcess needs no closing and
    // is valid for this process's lifetime; `token` is a valid out pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(OwnedRaw(token))
}

/// Reads this process's own access list (for checks and tests).
pub fn current_process_dacl() -> io::Result<Dacl> {
    // SAFETY: as in `protect_current_process`.
    let handle = unsafe { BorrowedHandle::borrow_raw(GetCurrentProcess()) };
    read_dacl(handle, Object::Process)
}

/// Reads the calling thread's access list (for checks and tests).
pub fn current_thread_dacl() -> io::Result<Dacl> {
    // SAFETY: the thread pseudo-handle is valid on the calling thread for as
    // long as it runs and needs no closing; borrowed only for this call.
    let handle = unsafe { BorrowedHandle::borrow_raw(GetCurrentThread()) };
    read_dacl(handle, Object::Thread)
}

fn win32(error: u32) -> io::Result<()> {
    match error {
        0 => Ok(()),
        code => Err(io::Error::from_raw_os_error(
            i32::try_from(code).unwrap_or(i32::MAX),
        )),
    }
}

/// A handle closed when dropped.
struct OwnedRaw(HANDLE);

impl Drop for OwnedRaw {
    fn drop(&mut self) {
        // SAFETY: a handle this crate opened and owns, closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// Memory Windows allocated with LocalAlloc, freed when dropped.
struct Local(*mut c_void);

impl Drop for Local {
    fn drop(&mut self) {
        // SAFETY: allocated by the call that returned it, freed once.
        unsafe { LocalFree(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_sids_have_their_string_forms() -> io::Result<()> {
        assert_eq!(Sid::local_system()?.to_string_form()?, "S-1-5-18");
        assert_eq!(Sid::administrators()?.to_string_form()?, "S-1-5-32-544");
        assert_eq!(Sid::owner_rights()?.to_string_form()?, "S-1-3-4");
        Ok(())
    }

    #[test]
    fn a_name_resolves_to_its_sid() -> io::Result<()> {
        assert_eq!(
            Sid::lookup("BUILTIN\\Administrators")?,
            Sid::administrators()?
        );
        assert_eq!(Sid::lookup("NT AUTHORITY\\SYSTEM")?, Sid::local_system()?);
        assert!(Sid::lookup("no-such-account-ferritor-test").is_err());
        Ok(())
    }

    /// What another process of the agent's account must never get on a
    /// thread: its registers (read or set), suspending it, queueing it work
    /// (an APC takes `THREAD_SET_CONTEXT`), impersonating through it, its
    /// list rewritten.
    const THREAD_TAKEOVER: u32 = 0x0002 // THREAD_SUSPEND_RESUME
        | 0x0008 // THREAD_GET_CONTEXT
        | 0x0010 // THREAD_SET_CONTEXT
        | 0x0020 // THREAD_SET_INFORMATION
        | 0x0080 // THREAD_SET_THREAD_TOKEN
        | 0x0100 // THREAD_IMPERSONATE
        | 0x0200 // THREAD_DIRECT_IMPERSONATION
        | 0x0004_0000 // WRITE_DAC
        | 0x0008_0000 // WRITE_OWNER
        | GENERIC_ALL
        | 0x4000_0000 // GENERIC_WRITE
        | 0x8000_0000; // GENERIC_READ (GET_CONTEXT, for a thread)

    /// No allowed entry but SYSTEM's grants a way into the thread.
    fn assert_locked(dacl: &Dacl, which: &str) -> io::Result<()> {
        let system = Sid::local_system()?;
        assert!(
            dacl.entries.iter().any(|e| e.allowed && e.sid == system),
            "{which}: SYSTEM keeps its rights: {dacl:?}"
        );
        for entry in dacl.entries.iter().filter(|e| e.allowed && e.sid != system) {
            assert_eq!(
                entry.mask & THREAD_TAKEOVER,
                0,
                "{which}: {:?} may take the thread over: {dacl:?}",
                entry.sid
            );
        }
        Ok(())
    }

    /// Threads started after the lock (from the token's default list) and
    /// threads already running (given the list) alike, the calling one
    /// too; a thread can't be read for its registers or hijacked by its own
    /// account. The whole test binary is locked by it, which the other
    /// tests don't mind.
    #[test]
    fn every_thread_is_locked_against_its_own_account() -> io::Result<()> {
        let (go, wait) = std::sync::mpsc::channel::<()>();
        let before = std::thread::spawn(move || {
            let _ = wait.recv();
            current_thread_dacl()
        });
        protect_current_process()?;
        let after = std::thread::spawn(current_thread_dacl);
        let _ = go.send(());
        let joined = |t: std::thread::JoinHandle<io::Result<Dacl>>| {
            t.join()
                .map_err(|_| io::Error::other("the thread panicked"))?
        };
        assert_locked(&joined(before)?, "a thread running before")?;
        assert_locked(&joined(after)?, "a thread started after")?;
        assert_locked(&current_thread_dacl()?, "the calling thread")?;
        let process = current_process_dacl()?;
        assert!(process.protected, "{process:?}");
        Ok(())
    }

    fn line(program: &str, args: &[&str]) -> io::Result<String> {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let mut wide = command_line(OsStr::new(program), &args)?;
        assert_eq!(wide.pop(), Some(0));
        Ok(String::from_utf16_lossy(&wide))
    }

    /// `CommandLineToArgvW`'s rules: quotes only where needed, backslashes
    /// doubled only before a quote (an escaped one, or the closing one).
    #[test]
    fn a_command_line_splits_back_into_its_arguments() -> io::Result<()> {
        assert_eq!(line(r"C:\p.exe", &[])?, r#""C:\p.exe""#);
        assert_eq!(line("p", &["a", "b c", ""])?, r#""p" a "b c" """#);
        assert_eq!(
            line("p", &[r"C:\dir\", r"C:\my dir\"])?,
            r#""p" C:\dir\ "C:\my dir\\""#
        );
        assert_eq!(
            line("p", &[r#"say "hi""#, r#"a\"b"#])?,
            r#""p" "say \"hi\"" "a\\\"b""#
        );
        assert!(line("p\"q", &[]).is_err());
        assert!(line("p", &["a\0b"]).is_err());
        Ok(())
    }

    /// The regression: with the token's default list locked, a child
    /// started the usual way can't open itself, and PowerShell dies at
    /// startup. Started by `spawn_unlocked`, it runs and exits as told.
    #[test]
    fn a_command_runs_unlocked_after_the_lock() -> io::Result<()> {
        protect_current_process()?;
        let args: Vec<OsString> = [
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-Process -Id $PID).Id | Out-Null; exit 7",
        ]
        .iter()
        .map(OsString::from)
        .collect();
        let child = spawn_unlocked(OsStr::new("powershell"), &args)?;
        assert_eq!(child.wait(Duration::from_secs(60))?, Some(7));
        for batch in [
            r"C:\Windows\x.bat",
            r"C:\Windows\x.CMD",
            r"C:\Windows\x.bat. .",
        ] {
            // Refused for what it is, not because it doesn't exist.
            let refused = spawn_unlocked(OsStr::new(batch), &[]).err();
            assert!(
                refused
                    .as_ref()
                    .is_some_and(|e| e.to_string().contains("a batch file")),
                "{batch}: {refused:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn the_current_user_is_a_sid() -> io::Result<()> {
        let user = Sid::current_user()?;
        assert!(user.to_string_form()?.starts_with("S-1-5-"));
        Ok(())
    }

    /// A private file: exactly the user, SYSTEM and Administrators, even in
    /// a folder whose new files everyone gets Full control of (inheritable,
    /// so the descriptor's protection is what keeps it out); nobody else
    /// opens it while the creating handle is open; an existing file is never
    /// replaced.
    #[test]
    fn a_private_file_is_its_users_alone() -> io::Result<()> {
        use std::io::{Read as _, Write as _};
        use std::os::windows::fs::OpenOptionsExt as _;
        use std::os::windows::io::AsHandle as _;
        use windows_sys::Win32::Security::WinWorldSid;
        use windows_sys::Win32::Storage::FileSystem::WRITE_DAC;

        const BACKUP_SEMANTICS: u32 = 0x0200_0000; // opens a directory
        let dir = std::env::temp_dir().join(format!("ferritor-winsec-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let (user, everyone) = (Sid::current_user()?, Sid::well_known(WinWorldSid)?);
        let folder = std::fs::OpenOptions::new()
            .access_mode(WRITE_DAC | READ_CONTROL)
            .custom_flags(BACKUP_SEMANTICS)
            .open(&dir)?;
        set_protected_dacl(
            folder.as_handle(),
            Object::File,
            &[
                Entry {
                    sid: &user,
                    mask: FULL,
                    inherit: true,
                },
                Entry {
                    sid: &everyone,
                    mask: FULL,
                    inherit: true,
                },
            ],
        )?;
        drop(folder);
        // The folder does give everyone its new files: a plain one inherits it.
        let plain = dir.join("plain");
        std::fs::write(&plain, b"")?;
        let plain = std::fs::OpenOptions::new()
            .access_mode(READ_CONTROL)
            .open(&plain)?;
        let inherited = read_dacl(plain.as_handle(), Object::File)?;
        assert!(
            inherited
                .entries
                .iter()
                .any(|e| e.sid == everyone && e.inherited)
        );
        drop(plain);
        let path = dir.join("key.pem");

        let mut file = create_private_file(&path)?;
        // Unshared: even its own user can't open it beside the handle.
        assert!(std::fs::File::open(&path).is_err());
        let dacl = read_dacl(file.as_handle(), Object::File)?;
        file.write_all(b"secret")?;
        file.sync_all()?;
        drop(file);

        assert!(dacl.protected);
        assert!(
            dacl.entries
                .iter()
                .all(|e| e.allowed && !e.inherited && e.mask == FULL)
        );
        let (system, administrators) = (Sid::local_system()?, Sid::administrators()?);
        // No dedup: a second entry for one of them is a regression too.
        let sids: Vec<&Sid> = dacl.entries.iter().map(|e| &e.sid).collect();
        let mut expected = vec![&system, &administrators];
        if user != system {
            expected.push(&user);
        }
        assert_eq!(sids.len(), expected.len());
        assert!(expected.iter().all(|sid| sids.contains(sid)));

        // Closed, its user reads it as usual; it's never created twice.
        let mut contents = String::new();
        std::fs::File::open(&path)?.read_to_string(&mut contents)?;
        assert_eq!(contents, "secret");
        let again = create_private_file(&path).map(drop);
        assert_eq!(
            again.err().map(|e| e.kind()),
            Some(io::ErrorKind::AlreadyExists)
        );
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
