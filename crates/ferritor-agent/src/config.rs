//! The agent's configuration (TOML), checked as a whole when it loads: a
//! mistake refuses to start, with what's wrong, rather than surfacing as a
//! missing file in the application later. Unknown keys are refused too.

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub use crate::files::Group;
use ferritor_client::exchange::TokenSource;
use ferritor_core::path::SecretPath;
use serde::Deserialize;

use crate::metrics::{MetricsConfig, RawMetrics};

/// The default poll interval (`interval_secs`), and its bounds.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(60);
pub const MIN_INTERVAL: Duration = Duration::from_secs(5);
pub const MAX_INTERVAL: Duration = Duration::from_secs(86_400);

/// A file's mode unless the config gives one: owner and group may read.
pub const DEFAULT_FILE_MODE: u32 = 0o440;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading {}", .path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parsing the configuration")]
    Parse(#[source] toml::de::Error),
    /// What's wrong and where (`output 1, secret billing/app/x: …`).
    #[error("{0}")]
    Invalid(String),
}

/// How the agent finds out a secret changed (see `docs/src/content/docs/guides/agent.md`): `get` reads
/// every secret each interval (needs `read`), `list` lists their prefixes
/// and reads only what moved (needs `list` too).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Detect {
    #[default]
    Get,
    List,
}

/// What happens to a secret's file once the server refuses it for good
/// (`PERMISSION_DENIED`, `NOT_FOUND`): kept as last delivered, or removed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnRevoked {
    #[default]
    Keep,
    Remove,
}

/// A signal the agent may send an application on a change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    Hup,
    Int,
    Term,
    Usr1,
    Usr2,
}

impl Signal {
    fn parse(name: &str) -> Option<Self> {
        Some(match name.strip_prefix("SIG").unwrap_or(name) {
            "HUP" => Self::Hup,
            "INT" => Self::Int,
            "TERM" => Self::Term,
            "USR1" => Self::Usr1,
            "USR2" => Self::Usr2,
            _ => return None,
        })
    }
}

/// Which process a signal goes to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignalTarget {
    /// The pid in this file, read at each change.
    PidFile(PathBuf),
    /// Every process with this name (across containers only with a shared
    /// process namespace).
    Process(String),
}

/// How the application learns its files changed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Notify {
    /// It re-reads them itself.
    #[default]
    Nothing,
    Signal {
        signal: Signal,
        target: SignalTarget,
    },
    /// Run in the agent's own environment (for a sidecar, its container).
    Command(Vec<String>),
}

/// Where the server is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerSettings {
    /// `http://`: dev mode, loopback only.
    Plain(String),
    Tls {
        addr: String,
        ca: PathBuf,
        cert: PathBuf,
        key: PathBuf,
    },
    /// `https://`, with a certificate from the server's token exchange
    /// (workload identity) instead of files.
    Exchange { addr: String, source: TokenSource },
}

impl ServerSettings {
    /// The address, for logs.
    pub fn addr(&self) -> &str {
        match self {
            Self::Plain(addr) | Self::Tls { addr, .. } | Self::Exchange { addr, .. } => addr,
        }
    }
}

/// One secret rendered into one file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Secret {
    pub path: SecretPath,
    /// The file's name in the output directory.
    pub file: String,
    pub mode: u32,
    /// Pinned to this version (never refreshed), if given.
    pub version: Option<u32>,
    /// Without it, the first render fails (`once` exits non-zero).
    pub required: bool,
    pub on_revoked: OnRevoked,
    pub detect: Detect,
}

/// One directory of files, swapped as a set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub dir: PathBuf,
    /// The files' and directories' group: on Unix a gid (the agent must be
    /// a member; unset, the directory's, `fsGroup` in Kubernetes), on
    /// Windows an account or group name given read access (unset, only the
    /// agent's account, SYSTEM and Administrators).
    pub group: Option<Group>,
    /// Write to a directory that isn't in memory (tmpfs, ramfs). Required
    /// on Windows, which has no memory-backed filesystem.
    pub allow_disk: bool,
    pub notify: Notify,
    pub secrets: Vec<Secret>,
    /// What `list` detection lists, for the secrets that use it: the
    /// output's `list_prefix`, or the distinct parents of their paths.
    pub list_prefixes: Vec<SecretPath>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub server: ServerSettings,
    pub interval: Duration,
    /// Keep a watch stream open (`run`), to hear of a change at once
    /// rather than at the next round.
    pub watch: bool,
    pub outputs: Vec<Output>,
    /// `[metrics]`: the exporter, and where the scrape is served.
    pub metrics: MetricsConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    server: String,
    ca: Option<PathBuf>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    token_file: Option<PathBuf>,
    exchange: Option<String>,
    interval_secs: Option<u64>,
    watch: Option<bool>,
    #[serde(default)]
    detect: Detect,
    #[serde(default)]
    output: Vec<RawOutput>,
    metrics: Option<RawMetrics>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOutput {
    dir: PathBuf,
    group: Option<Group>,
    #[serde(default)]
    allow_disk: bool,
    list_prefix: Option<String>,
    on_revoked: Option<OnRevoked>,
    mode: Option<u32>,
    on_change: Option<RawOnChange>,
    #[serde(default)]
    secret: Vec<RawSecret>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOnChange {
    signal: Option<String>,
    pid_file: Option<PathBuf>,
    process: Option<String>,
    command: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSecret {
    path: String,
    file: Option<String>,
    mode: Option<u32>,
    version: Option<u32>,
    required: Option<bool>,
    on_revoked: Option<OnRevoked>,
    detect: Option<Detect>,
}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(message.into())
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(text).map_err(ConfigError::Parse)?;
        let server = server(&raw)?;
        let interval = match raw.interval_secs {
            None => DEFAULT_INTERVAL,
            Some(secs) => {
                let interval = Duration::from_secs(secs);
                if !(MIN_INTERVAL..=MAX_INTERVAL).contains(&interval) {
                    return Err(invalid(format!(
                        "interval_secs must be between {} and {}",
                        MIN_INTERVAL.as_secs(),
                        MAX_INTERVAL.as_secs()
                    )));
                }
                interval
            }
        };
        if raw.output.is_empty() {
            return Err(invalid("no [[output]]: nothing to render"));
        }
        let mut dirs = HashSet::new();
        let mut outputs = Vec::with_capacity(raw.output.len());
        for (i, output) in raw.output.into_iter().enumerate() {
            let output = self::output(output, raw.detect)
                .map_err(|e| invalid(format!("output {}: {e}", i + 1)))?;
            if !dirs.insert(dir_key(&output.dir)) {
                return Err(invalid(format!(
                    "output {}: {} is another output's directory too",
                    i + 1,
                    output.dir.display()
                )));
            }
            outputs.push(output);
        }
        let metrics = crate::metrics::resolve(raw.metrics, ferritor_metrics::DEFAULT_AGENT_ADDR)
            .map_err(invalid)?;
        Ok(Self {
            server,
            interval,
            watch: raw.watch.unwrap_or(true),
            outputs,
            metrics,
        })
    }
}

fn server(raw: &RawConfig) -> Result<ServerSettings, ConfigError> {
    let addr = raw.server.clone();
    if addr.starts_with("http://") {
        if raw.ca.is_some()
            || raw.cert.is_some()
            || raw.key.is_some()
            || raw.token_file.is_some()
            || raw.exchange.is_some()
        {
            return Err(invalid(
                "ca, cert, key, token_file and exchange are for TLS: use an https:// server \
                 with them",
            ));
        }
        return Ok(ServerSettings::Plain(addr));
    }
    if !addr.starts_with("https://") {
        return Err(invalid(format!(
            "server {addr:?}: an http:// or https:// address"
        )));
    }
    let Some(ca) = &raw.ca else {
        return Err(invalid(
            "an https:// server needs ca: the CA certificate to verify it with",
        ));
    };
    let files = raw.cert.is_some() || raw.key.is_some();
    let exchanged = raw.token_file.is_some() || raw.exchange.is_some();
    match (&raw.cert, &raw.key, &raw.token_file, &raw.exchange) {
        _ if files && exchanged => Err(invalid(
            "cert and key, or token_file and exchange: a certificate from files or from the \
             token exchange, not both",
        )),
        (Some(cert), Some(key), None, None) => Ok(ServerSettings::Tls {
            addr,
            ca: ca.clone(),
            cert: cert.clone(),
            key: key.clone(),
        }),
        (None, None, Some(token_file), Some(exchange)) => {
            if !exchange.starts_with("https://") {
                return Err(invalid(format!(
                    "exchange {exchange:?}: the server's [identity] listener, an https:// address"
                )));
            }
            Ok(ServerSettings::Exchange {
                addr,
                source: TokenSource {
                    exchange_addr: exchange.clone(),
                    ca: ca.clone(),
                    token_file: token_file.clone(),
                },
            })
        }
        _ if exchanged => Err(invalid(
            "token_file and exchange go together: the platform token, and the server's \
             [identity] listener to exchange it at",
        )),
        _ => Err(invalid(
            "an https:// server needs a client certificate: cert and key, or token_file and \
             exchange (workload identity)",
        )),
    }
}

fn output(raw: RawOutput, default_detect: Detect) -> Result<Output, String> {
    if !raw.dir.is_absolute() {
        return Err(format!(
            "dir {} must be an absolute path",
            raw.dir.display()
        ));
    }
    if raw.secret.is_empty() {
        return Err("no [[output.secret]]: nothing to render".to_owned());
    }
    let default_mode = match raw.mode {
        None => DEFAULT_FILE_MODE,
        Some(mode) => check_mode(mode)?,
    };
    let default_on_revoked = raw.on_revoked.unwrap_or_default();
    let list_prefix = raw
        .list_prefix
        .as_deref()
        .map(|prefix| SecretPath::parse(prefix).map_err(|e| format!("list_prefix {prefix:?}: {e}")))
        .transpose()?;
    let mut files = HashSet::new();
    let mut secrets = Vec::with_capacity(raw.secret.len());
    for raw in raw.secret {
        let path = SecretPath::parse(&raw.path).map_err(|e| format!("path {:?}: {e}", raw.path))?;
        let secret = secret(raw, path, default_mode, default_on_revoked, default_detect)
            .map_err(|e| format!("secret {}", e))?;
        if !files.insert(file_key(&secret.file)) {
            return Err(format!(
                "secret {}: file {:?} is another secret's file too",
                secret.path, secret.file
            ));
        }
        secrets.push(secret);
    }
    let list_prefixes = list_prefixes(&secrets, list_prefix.as_ref())?;
    if let Some(group) = &raw.group {
        check_group(group)?;
    }
    check_disk(raw.allow_disk)?;
    let notify = raw.on_change.map(notify).transpose()?.unwrap_or_default();
    check_notify(&notify)?;
    Ok(Output {
        dir: raw.dir,
        group: raw.group,
        allow_disk: raw.allow_disk,
        notify,
        secrets,
        list_prefixes,
    })
}

fn secret(
    raw: RawSecret,
    path: SecretPath,
    default_mode: u32,
    default_on_revoked: OnRevoked,
    default_detect: Detect,
) -> Result<Secret, String> {
    let context = |e: String| format!("{path}: {e}");
    let file = match raw.file {
        Some(file) => file,
        // The path's last segment, a valid file name by the path's rules.
        None => last_segment(&path).to_owned(),
    };
    check_file_name(&file).map_err(context)?;
    let mode = match raw.mode {
        None => default_mode,
        Some(mode) => check_mode(mode).map_err(context)?,
    };
    if raw.version == Some(0) {
        return Err(context(
            "version must be at least 1 (0 isn't a version)".to_owned(),
        ));
    }
    Ok(Secret {
        file,
        mode,
        version: raw.version,
        required: raw.required.unwrap_or(true),
        on_revoked: raw.on_revoked.unwrap_or(default_on_revoked),
        detect: raw.detect.unwrap_or(default_detect),
        path,
    })
}

fn last_segment(path: &SecretPath) -> &str {
    path.as_str()
        .rsplit_once('/')
        .map_or(path.as_str(), |(_, last)| last)
}

/// One name in the output directory: no `/`, not `.` or `..`, and not
/// starting with `..`, which the agent's own entries use (`..data`, the
/// generations, `..status.json`). On Windows also none of the characters
/// or device names it refuses, and no trailing dot or space, which it drops.
fn check_file_name(file: &str) -> Result<(), String> {
    if file.is_empty() || file.contains('/') || file.contains('\0') {
        return Err(format!("file {file:?}: one file name, without '/'"));
    }
    if file == "." || file.starts_with("..") {
        return Err(format!(
            "file {file:?}: names starting with \"..\" are the agent's own"
        ));
    }
    if cfg!(windows) {
        check_windows_file_name(file)?;
    }
    Ok(())
}

/// What Windows refuses (or silently changes) in a file name.
fn check_windows_file_name(file: &str) -> Result<(), String> {
    if let Some(c) = file
        .chars()
        .find(|c| matches!(c, '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') || c.is_control())
    {
        return Err(format!(
            "file {file:?}: {c:?} isn't allowed in a Windows file name"
        ));
    }
    if file.ends_with('.') || file.ends_with(' ') {
        return Err(format!(
            "file {file:?}: Windows drops a trailing dot or space from a name"
        ));
    }
    let stem = file
        .split('.')
        .next()
        .unwrap_or(file)
        .trim_end()
        .to_ascii_uppercase();
    // COM and LPT with a digit, the superscripts ¹²³ included.
    let port = stem
        .strip_prefix("COM")
        .or_else(|| stem.strip_prefix("LPT"))
        .is_some_and(|rest| {
            let mut chars = rest.chars();
            matches!(
                (chars.next(), chars.next()),
                (Some('0'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}'), None)
            )
        });
    let device = port
        || matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        );
    if device {
        return Err(format!("file {file:?}: a Windows device name"));
    }
    Ok(())
}

/// How two file names are compared: as the platform's filesystem does.
/// Windows ignores case, comparing names uppercased a character at a time
/// (its own table maps each character to one): a character whose
/// uppercase is several (`ß`) stays as it is.
fn file_key(file: &str) -> String {
    if cfg!(windows) {
        file.chars()
            .map(|c| {
                let mut upper = c.to_uppercase();
                match (upper.next(), upper.next()) {
                    (Some(u), None) => u,
                    _ => c,
                }
            })
            .collect()
    } else {
        file.to_owned()
    }
}

/// How two output directories are compared: component by component, each
/// as `file_key` compares names. On Windows a drive or share is the same
/// written verbatim (`\\?\C:\`, `\\?\UNC\host\share\`) or not.
fn dir_key(dir: &Path) -> Vec<String> {
    use std::path::{Component, Prefix};
    if !cfg!(windows) {
        return dir
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
    }
    dir.components()
        .map(|c| match c {
            Component::Prefix(prefix) => match prefix.kind() {
                Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => {
                    format!("{}:", char::from(drive.to_ascii_uppercase()))
                }
                Prefix::UNC(host, share) | Prefix::VerbatimUNC(host, share) => format!(
                    "\\\\{}\\{}",
                    file_key(&host.to_string_lossy()),
                    file_key(&share.to_string_lossy())
                ),
                _ => file_key(&prefix.as_os_str().to_string_lossy()),
            },
            other => file_key(&other.as_os_str().to_string_lossy()),
        })
        .collect()
}

/// A gid on Unix, an account or group name on Windows.
fn check_group(group: &Group) -> Result<(), String> {
    match group {
        Group::Id(_) if cfg!(windows) => Err(
            "group: on Windows, an account or group name (\"DOMAIN\\\\name\", \"NT SERVICE\\\\app\"), \
             not a number"
                .to_owned(),
        ),
        Group::Name(name) if !cfg!(windows) => Err(format!(
            "group {name:?}: a numeric gid (names are for Windows)"
        )),
        Group::Name(name) if name.trim().is_empty() => {
            Err("group: an account or group name".to_owned())
        }
        _ => Ok(()),
    }
}

/// Windows has no memory-backed filesystem: the values go to a disk, which
/// the config must say it knows.
fn check_disk(allow_disk: bool) -> Result<(), String> {
    if cfg!(windows) && !allow_disk {
        return Err(
            "allow_disk = true is required on Windows, which has no memory-backed directory: \
             the values are written to disk (encrypt it, BitLocker)"
                .to_owned(),
        );
    }
    Ok(())
}

/// Windows has no signals: only a command can tell the application. Nor a
/// batch file as the program: Windows runs one through `cmd.exe`, which
/// parses the arguments by rules of its own.
fn check_notify(notify: &Notify) -> Result<(), String> {
    if !cfg!(windows) {
        return Ok(());
    }
    match notify {
        Notify::Signal { .. } => {
            Err("on_change signal: Windows has no signals; use on_change command".to_owned())
        }
        Notify::Command(command)
            if command.first().is_some_and(|program| {
                // Windows drops trailing dots and spaces: `run.bat.` is a
                // batch file too.
                Path::new(program.trim_end_matches(['.', ' ']))
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("bat") || e.eq_ignore_ascii_case("cmd"))
            }) =>
        {
            Err("on_change command: a batch file; run it through \"cmd.exe\", \"/c\"".to_owned())
        }
        _ => Ok(()),
    }
}

/// At most `0o777`, and nothing for others: a secret readable by every user
/// on the host is a mistake, not a setting.
fn check_mode(mode: u32) -> Result<u32, String> {
    if mode > 0o777 {
        return Err(format!("mode {mode:#o}: at most 0o777"));
    }
    if mode & 0o007 != 0 {
        return Err(format!(
            "mode {mode:#o}: no permissions for others (use the group instead)"
        ));
    }
    Ok(mode)
}

/// The prefixes `list` detection lists for the secrets that use it: the
/// output's `list_prefix` (which must cover them), or their distinct
/// parents. A single-segment path has no parent but everything, which
/// would need `list` on every path: refused without a `list_prefix`.
fn list_prefixes(
    secrets: &[Secret],
    list_prefix: Option<&SecretPath>,
) -> Result<Vec<SecretPath>, String> {
    let listed: Vec<&Secret> = secrets
        .iter()
        .filter(|secret| secret.detect == Detect::List && secret.version.is_none())
        .collect();
    if listed.is_empty() {
        return Ok(Vec::new());
    }
    if let Some(prefix) = list_prefix {
        if let Some(outside) = listed.iter().find(|secret| !secret.path.is_under(prefix)) {
            return Err(format!(
                "secret {}: not under list_prefix {prefix}",
                outside.path
            ));
        }
        return Ok(vec![prefix.clone()]);
    }
    let mut parents = BTreeSet::new();
    for secret in listed {
        let Some((parent, _)) = secret.path.as_str().rsplit_once('/') else {
            return Err(format!(
                "secret {}: a single-segment path has no prefix to list but everything; \
                 set the output's list_prefix, or detect = \"get\" for this secret",
                secret.path
            ));
        };
        parents.insert(SecretPath::parse(parent).map_err(|e| format!("{parent}: {e}"))?);
    }
    Ok(parents.into_iter().collect())
}

fn notify(raw: RawOnChange) -> Result<Notify, String> {
    match (raw.signal, raw.pid_file, raw.process, raw.command) {
        (None, None, None, None) => Ok(Notify::Nothing),
        (None, None, None, Some(command)) => {
            if command.first().is_none_or(String::is_empty) {
                return Err("on_change command: a program to run".to_owned());
            }
            Ok(Notify::Command(command))
        }
        (Some(signal), pid_file, process, None) => {
            let signal = Signal::parse(&signal).ok_or_else(|| {
                format!("on_change signal {signal:?}: one of HUP, INT, TERM, USR1, USR2")
            })?;
            let target = match (pid_file, process) {
                (Some(pid_file), None) => SignalTarget::PidFile(pid_file),
                (None, Some(process)) if !process.is_empty() => SignalTarget::Process(process),
                _ => {
                    return Err(
                        "on_change signal: needs exactly one of pid_file and process".to_owned(),
                    );
                }
            };
            Ok(Notify::Signal { signal, target })
        }
        (None, ..) => Err("on_change pid_file and process need a signal".to_owned()),
        (Some(_), .., Some(_)) => Err("on_change: a signal or a command, not both".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    const EXAMPLE: &str = r#"
        server = "https://ferritor.internal:7070"
        ca = "/etc/ferritor/ca.pem"
        cert = "/var/run/ferritor-identity/tls.crt"
        key = "/var/run/ferritor-identity/tls.key"

        [[output]]
        dir = "/run/secrets/app"
        group = 1000
        on_change = { signal = "HUP", pid_file = "/run/app/app.pid" }

        [[output.secret]]
        path = "billing/app/db-password"

        [[output.secret]]
        path = "billing/app/tls/cert"
        file = "tls.crt"

        [[output.secret]]
        path = "billing/app/tls/key"
        file = "tls.key"
        mode = 0o400
    "#;

    fn parse(text: &str) -> Result<Config, String> {
        Config::parse(text).map_err(|e| {
            let mut message = e.to_string();
            let mut source = std::error::Error::source(&e);
            while let Some(s) = source {
                message.push_str(&format!(": {s}"));
                source = s.source();
            }
            message
        })
    }

    /// An output directory, as the platform writes one (Windows: a drive,
    /// and the disk allowed, which it requires), and one not absolute.
    #[cfg(unix)]
    const DIR: &str = "dir = \"/run/s\"";
    #[cfg(unix)]
    const RELATIVE_DIR: &str = "dir = \"run/s\"";
    #[cfg(windows)]
    const DIR: &str = "dir = 'C:\\s'\nallow_disk = true";
    #[cfg(windows)]
    const RELATIVE_DIR: &str = "dir = 's'\nallow_disk = true";

    /// One output with `secret` (a `[[output.secret]]` body) and output
    /// settings `extra`, against a plain server.
    fn with_secret(extra: &str, secret: &str) -> String {
        format!(
            "server = \"http://127.0.0.1:7070\"\n[[output]]\n{DIR}\n{extra}\n\
             [[output.secret]]\n{secret}\n"
        )
    }

    /// Workload identity: a token file and the exchange instead of a
    /// certificate's files.
    #[test]
    fn a_token_file_and_the_exchange_stand_in_for_a_certificate() {
        let text = with_secret("", "path = \"a/b\"").replace(
            "server = \"http://127.0.0.1:7070\"\n",
            "server = \"https://ferritor.internal:7070\"\nca = \"/etc/ferritor/ca.pem\"\n\
             token_file = \"/var/run/secrets/tokens/ferritor\"\n\
             exchange = \"https://ferritor.internal:7071\"\n",
        );
        let config = parse(&text).unwrap();
        assert_eq!(
            config.server,
            ServerSettings::Exchange {
                addr: "https://ferritor.internal:7070".to_owned(),
                source: TokenSource {
                    exchange_addr: "https://ferritor.internal:7071".to_owned(),
                    ca: "/etc/ferritor/ca.pem".into(),
                    token_file: "/var/run/secrets/tokens/ferritor".into(),
                },
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_example_loads_with_its_defaults() {
        let config = parse(EXAMPLE).unwrap();
        assert_eq!(config.interval, DEFAULT_INTERVAL);
        assert!(matches!(config.server, ServerSettings::Tls { .. }));
        let output = &config.outputs[0];
        assert_eq!(output.group, Some(crate::files::Group::Id(1000)));
        assert!(!output.allow_disk);
        assert_eq!(
            output.notify,
            Notify::Signal {
                signal: Signal::Hup,
                target: SignalTarget::PidFile("/run/app/app.pid".into())
            }
        );
        let files: Vec<(&str, u32)> = output
            .secrets
            .iter()
            .map(|s| (s.file.as_str(), s.mode))
            .collect();
        assert_eq!(
            files,
            [
                ("db-password", 0o440),
                ("tls.crt", 0o440),
                ("tls.key", 0o400)
            ]
        );
        let first = &output.secrets[0];
        assert_eq!(
            (
                first.required,
                first.on_revoked,
                first.detect,
                first.version
            ),
            (true, OnRevoked::Keep, Detect::Get, None)
        );
        // `get` lists nothing.
        assert!(output.list_prefixes.is_empty());
    }

    /// `list` lists the distinct parents, or the output's `list_prefix`,
    /// which must cover every listed secret; pinned secrets aren't listed.
    #[test]
    fn list_prefixes_are_derived_or_given() {
        let config = parse(&format!(
            "server = \"http://127.0.0.1:7070\"\ndetect = \"list\"\n[[output]]\n\
             {DIR}\n\
             [[output.secret]]\npath = \"billing/app/tls/cert\"\nfile = \"c\"\n\
             [[output.secret]]\npath = \"billing/app/tls/key\"\nfile = \"k\"\n\
             [[output.secret]]\npath = \"billing/app/db\"\n\
             [[output.secret]]\npath = \"billing/old/db\"\nfile = \"old\"\nversion = 3\n",
        ))
        .unwrap();
        let prefixes: Vec<&str> = config.outputs[0]
            .list_prefixes
            .iter()
            .map(SecretPath::as_str)
            .collect();
        assert_eq!(prefixes, ["billing/app", "billing/app/tls"]);

        let given = parse(&with_secret(
            "list_prefix = \"billing/app\"",
            "path = \"billing/app/tls/cert\"\ndetect = \"list\"",
        ))
        .unwrap();
        assert_eq!(given.outputs[0].list_prefixes[0].as_str(), "billing/app");
    }

    /// The same example as written for Windows: a drive's path, the group an
    /// account or group name, a command to tell the application.
    #[cfg(windows)]
    #[test]
    fn the_windows_example_loads_with_its_defaults() {
        let config = parse(
            r#"
            server = "https://ferritor.internal:7070"
            ca = 'C:\ProgramData\ferritor\ca.pem'
            cert = 'C:\ProgramData\ferritor\agent.crt'
            key = 'C:\ProgramData\ferritor\agent.key'

            [[output]]
            dir = 'C:\ProgramData\ferritor\secrets\app'
            allow_disk = true
            group = 'NT SERVICE\app'
            on_change = { command = ["powershell", "-NoProfile", "-Command", "Restart-Service app"] }

            [[output.secret]]
            path = "billing/app/db-password"
        "#,
        )
        .unwrap();
        let output = &config.outputs[0];
        assert_eq!(
            output.group,
            Some(crate::files::Group::Name("NT SERVICE\\app".to_owned()))
        );
        assert!(output.allow_disk);
        assert!(matches!(output.notify, Notify::Command(_)));
        assert_eq!(output.secrets[0].file, "db-password");
    }

    /// What can't work on Windows is refused there when the config loads:
    /// a gid, signals, no `allow_disk`, names Windows can't hold, and two
    /// names it would treat as one.
    #[cfg(windows)]
    #[test]
    fn windows_refuses_what_it_cant_do() {
        for (text, says) in [
            (
                with_secret("group = 1000", "path = \"a/b\""),
                "not a number",
            ),
            (
                with_secret(
                    "on_change = { signal = \"HUP\", pid_file = 'C:\\p' }",
                    "path = \"a/b\"",
                ),
                "Windows has no signals",
            ),
            (
                with_secret(
                    "on_change = { command = ['C:\\app\\reload.CMD'] }",
                    "path = \"a/b\"",
                ),
                "a batch file",
            ),
            (
                with_secret(
                    "on_change = { command = ['C:\\app\\run.bat. .'] }",
                    "path = \"a/b\"",
                ),
                "a batch file",
            ),
            (
                with_secret("", "path = \"a/b\"").replace("allow_disk = true\n", ""),
                "allow_disk = true is required",
            ),
            (
                with_secret("", "path = \"a/b\"\nfile = \"a:b\""),
                "isn't allowed",
            ),
            (
                with_secret("", "path = \"a/b\"\nfile = 'a\\b'"),
                "isn't allowed",
            ),
            (
                with_secret("", "path = \"a/b\"\nfile = \"x.\""),
                "trailing dot",
            ),
            (with_secret("", "path = \"a/con\""), "device name"),
            (
                with_secret("", "path = \"a/b\"\nfile = \"COM1.txt\""),
                "device name",
            ),
            (
                with_secret("", "path = \"a/b\"\nfile = \"lpt\u{b2}.log\""),
                "device name",
            ),
            (
                with_secret("", "path = \"a/b\"\nfile = \"conin$\""),
                "device name",
            ),
            (
                with_secret("", "path = \"a/b\"\nfile = \"CONOUT$.txt\""),
                "device name",
            ),
            (
                format!(
                    "{}[[output]]\ndir = 'c:/S'\nallow_disk = true\n[[output.secret]]\npath = \"c/d\"\n",
                    with_secret("", "path = \"a/b\"")
                ),
                "another output's directory",
            ),
            (
                format!(
                    "{}[[output]]\ndir = '\\\\?\\C:\\S'\nallow_disk = true\n[[output.secret]]\npath = \"c/d\"\n",
                    with_secret("", "path = \"a/b\"")
                ),
                "another output's directory",
            ),
            (
                with_secret(
                    "",
                    "path = \"a/b\"\nfile = \"Key\"\n[[output.secret]]\npath = \"a/c\"\nfile = \"key\"",
                ),
                "another secret's file",
            ),
        ] {
            let error = parse(&text).unwrap_err();
            assert!(error.contains(says), "{text}\n=> {error}");
        }
    }

    /// On Unix a group is a gid; a name is refused (Windows' kind).
    #[cfg(unix)]
    #[test]
    fn unix_takes_a_gid_not_a_name() {
        let error = parse(&with_secret("group = \"staff\"", "path = \"a/b\"")).unwrap_err();
        assert!(error.contains("a numeric gid"), "{error}");
    }

    #[test]
    fn mistakes_refuse_to_start() {
        for (text, says) in [
            (
                with_secret("", "path = \"a/b\"\nunknown = 1"),
                "unknown field",
            ),
            (with_secret("", "path = \"/a\""), "path \"/a\""),
            (
                with_secret("", "path = \"a/b\"\nfile = \"x/y\""),
                "without '/'",
            ),
            (
                with_secret("", "path = \"a/b\"\nfile = \"..data\""),
                "agent's own",
            ),
            (with_secret("", "path = \"a/..b\""), "agent's own"),
            (
                with_secret("", "path = \"a/b\"\nmode = 0o444"),
                "no permissions for others",
            ),
            (
                with_secret("", "path = \"a/b\"\nmode = 0o1440"),
                "at most 0o777",
            ),
            (with_secret("", "path = \"a/b\"\nversion = 0"), "at least 1"),
            (
                with_secret("", "path = \"billing\"\ndetect = \"list\""),
                "single-segment",
            ),
            (
                with_secret(
                    "list_prefix = \"other\"",
                    "path = \"billing/x\"\ndetect = \"list\"",
                ),
                "not under list_prefix",
            ),
            (
                with_secret(
                    "on_change = { signal = \"KILL\", pid_file = \"/p\" }",
                    "path = \"a/b\"",
                ),
                "one of HUP",
            ),
            (
                with_secret("on_change = { signal = \"HUP\" }", "path = \"a/b\""),
                "exactly one of pid_file and process",
            ),
            (
                with_secret(
                    "on_change = { signal = \"HUP\", pid_file = \"/p\", command = [\"x\"] }",
                    "path = \"a/b\"",
                ),
                "not both",
            ),
            (
                with_secret("on_change = { command = [] }", "path = \"a/b\""),
                "a program to run",
            ),
            (
                with_secret("", "path = \"a/b\"").replace(DIR, RELATIVE_DIR),
                "absolute",
            ),
            (
                with_secret("", "path = \"a/b\"\n[[output.secret]]\npath = \"c/b\""),
                "another secret's file",
            ),
            (
                "server = \"http://127.0.0.1:7070\"\n".to_owned(),
                "nothing to render",
            ),
            (
                with_secret("", "path = \"a/b\"").replace("http://", "https://"),
                "needs ca",
            ),
            (
                format!("ca = \"/c\"\n{}", with_secret("", "path = \"a/b\"")),
                "are for TLS",
            ),
            (
                with_secret("", "path = \"a/b\"")
                    .replace("http://", "https://")
                    .replacen('\n', "\nca = \"/c\"\n", 1),
                "needs a client certificate",
            ),
            (
                with_secret("", "path = \"a/b\"")
                    .replace("http://", "https://")
                    .replacen('\n', "\nca = \"/c\"\ntoken_file = \"/t\"\n", 1),
                "go together",
            ),
            (
                with_secret("", "path = \"a/b\"")
                    .replace("http://", "https://")
                    .replacen(
                        '\n',
                        "\nca = \"/c\"\ncert = \"/x\"\nkey = \"/k\"\ntoken_file = \"/t\"\n",
                        1,
                    ),
                "not both",
            ),
            (
                with_secret("", "path = \"a/b\"")
                    .replace("http://", "https://")
                    .replacen(
                        '\n',
                        "\nca = \"/c\"\ntoken_file = \"/t\"\nexchange = \"http://x:1\"\n",
                        1,
                    ),
                "an https:// address",
            ),
            (
                format!("token_file = \"/t\"\n{}", with_secret("", "path = \"a/b\"")),
                "are for TLS",
            ),
            (
                format!("interval_secs = 1\n{}", with_secret("", "path = \"a/b\"")),
                "between 5 and 86400",
            ),
            (
                format!(
                    "{}[[output]]\n{DIR}\n[[output.secret]]\npath = \"c/d\"\n",
                    with_secret("", "path = \"a/b\"")
                ),
                "another output's directory",
            ),
        ] {
            let error = parse(&text).unwrap_err();
            assert!(error.contains(says), "{text}\n=> {error}");
        }
    }
}
