//! Command-line arguments. Shares and secret values are never arguments:
//! those end up in shell history and in `/proc/<pid>/cmdline`. They're read
//! from stdin instead (a hidden prompt on a terminal).

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "ferritor",
    version,
    about = "Operate a ferritor server and use its secrets."
)]
pub struct Cli {
    /// Server address.
    #[arg(
        long,
        global = true,
        env = "FERRITOR_ADDR",
        default_value = "http://127.0.0.1:7070"
    )]
    pub addr: String,

    /// CA certificate (PEM) to verify the server with. Needs an https://
    /// address.
    #[arg(long, global = true, env = "FERRITOR_CA")]
    pub ca: Option<PathBuf>,

    /// Client certificate (PEM) carrying your `ferritor://<name>` identity.
    /// Required with https: the server only accepts client certificates.
    #[arg(long, global = true, env = "FERRITOR_CERT", requires = "key")]
    pub cert: Option<PathBuf>,

    /// The client certificate's private key (PEM).
    #[arg(long, global = true, env = "FERRITOR_KEY", requires = "cert")]
    pub key: Option<PathBuf>,

    /// Workload identity, instead of --cert and --key: a platform token
    /// (a CI job's OIDC token, say) exchanged for a short-lived client
    /// certificate before the command, kept in memory only. Needs
    /// --exchange.
    #[arg(
        long,
        global = true,
        env = "FERRITOR_TOKEN_FILE",
        requires = "exchange",
        conflicts_with = "cert"
    )]
    pub token_file: Option<PathBuf>,

    /// The server's token exchange (its `[identity] listen_addr`), an
    /// https:// address. Verified with --ca.
    #[arg(
        long,
        global = true,
        env = "FERRITOR_EXCHANGE",
        requires = "token_file"
    )]
    pub exchange: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Show whether the server is initialized and sealed.
    Status,
    /// Generate the root key and print its shares. They are shown only once.
    Init {
        #[arg(long, default_value_t = 5)]
        shares: u32,
        #[arg(long, default_value_t = 3)]
        threshold: u32,
    },
    /// Submit one unseal share, read from stdin.
    Unseal {
        /// Discard the shares submitted so far instead (reads no share).
        #[arg(long)]
        reset: bool,
        /// If no root commitment in the data database matches the root key
        /// (restored from before a rekey, or a failover lost it), store one
        /// once a stored secret proves the key is the one the data was
        /// written under. An alarm in the audit log.
        #[arg(long, conflicts_with = "reset")]
        recommit: bool,
        /// Auto-unseal: release the hold an explicit seal set (every
        /// server's), then unseal this server through its key management
        /// service. Reads no share. On an unsealed server it only releases
        /// the hold.
        #[arg(long, conflicts_with_all = ["reset", "recommit", "release_hold"])]
        auto: bool,
        /// Once unsealed (by the share completing the threshold, or already),
        /// release the auto-unseal hold, as `--auto` does: it takes the
        /// unseal permission. A plain unseal with shares leaves it.
        #[arg(long, conflicts_with = "reset")]
        release_hold: bool,
    },
    /// Seal the server: drop its keys. Always succeeds.
    Seal,
    /// Add a new active KEK version to a namespace.
    Rotate {
        /// The namespace whose KEK to rotate (others are untouched).
        #[arg(long)]
        namespace: String,
    },
    /// After a rotation: move DEKs still wrapped by older KEK versions of
    /// their namespace to its active one, then retire versions no secret
    /// uses any more. Repeats the server's bounded pass until done; safe to
    /// rerun or interrupt.
    Rewrap {
        /// Rows per call (0: the server's default).
        #[arg(long, default_value_t = 0)]
        max_rows: u32,
        /// Only this namespace (default: every namespace).
        #[arg(long)]
        namespace: Option<String>,
    },
    /// Remove deleted secret versions for good once they're past the server's
    /// retention (its `purge_deleted_after_days`). Repeats the server's
    /// bounded pass until done; safe to rerun or interrupt, e.g. from cron.
    Purge {
        /// Rows per call (0: the server's default).
        #[arg(long, default_value_t = 0)]
        max_rows: u32,
    },
    /// Destroy a retired KEK version for good: nothing it wrapped can be
    /// decrypted any more, from any copy of the data database. Irreversible.
    /// Only a retired version (`ferritor rewrap` retires one once no secret
    /// uses it). Writes pause briefly while it fences the version off. Safe
    /// to repeat.
    DestroyKek {
        /// The namespace the KEK belongs to.
        #[arg(long)]
        namespace: String,
        /// The KEK version, as `ferritor rewrap` reported it retired.
        version: u32,
    },
    /// Manage namespaces: a secret's path starts with its namespace, and
    /// nothing can be stored under one that doesn't exist.
    #[command(subcommand)]
    Namespace(NamespaceCommand),
    /// Manage the stored policies: the applications' grants (secret actions
    /// only), kept in the database. The operators' rules are in ferritor.toml
    /// and listed here as `config:…`, read-only.
    #[command(subcommand)]
    Policy(PolicyCommand),
    /// Manage the workload-identity issuing CA: the key that signs the
    /// short-lived client certificates workloads get for a platform token.
    #[command(subcommand)]
    Identity(IdentityCommand),
    /// Exchange --token-file at --exchange for a short-lived client
    /// certificate, and write it and its key for later commands (--cert,
    /// --key): one exchange for a CI job's many commands.
    Login {
        /// Where to write the certificate (PEM).
        #[arg(long)]
        cert_out: PathBuf,
        /// Where to write its private key (PEM), readable by you alone.
        #[arg(long)]
        key_out: PathBuf,
    },
    /// Work with an audit log offline (no server involved).
    #[command(subcommand)]
    Audit(Audit),
    /// Replace the root key and its shares (two phases: submit, then verify).
    #[command(subcommand)]
    Rekey(Rekey),
    /// Print a secret's value (raw bytes).
    Get {
        path: String,
        /// A specific version (from 1) instead of the latest. Leave it out
        /// for the latest; 0 is rejected rather than quietly meaning latest.
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
        version: Option<u32>,
    },
    /// Store the next version of a secret: all of stdin, byte for byte, or
    /// one line at a hidden prompt on a terminal.
    Put {
        path: String,
        /// Store an empty value. Refused by default: empty input from a
        /// script or cron job (stdin closed or `< /dev/null`) is far more
        /// likely an accident than an intended value.
        #[arg(long)]
        allow_empty: bool,
        /// Check-and-set: store only if the latest version is still this
        /// one (as read with `ferritor get`), so a concurrent change isn't
        /// silently overwritten. 0: only if the secret doesn't exist yet.
        #[arg(long, value_name = "VERSION")]
        expected_version: Option<u32>,
        /// Set a label on the secret with this put (repeatable): plain
        /// metadata, not encrypted, so never a secret. Needs the `label`
        /// permission too.
        #[arg(long = "label", value_name = "KEY=VALUE", value_parser = parse_label)]
        labels: Vec<(String, String)>,
    },
    /// Delete every version of a secret.
    Delete { path: String },
    /// Bring a deleted version back (undo a delete, or a trim under the
    /// server's max_versions), within the server's deletion retention.
    /// Without --version it undoes a delete: it restores the newest deleted
    /// version, only while the secret has no live version; older ones stay
    /// deleted.
    Restore {
        path: String,
        /// The deleted version to restore, alongside any live one (for an
        /// older or trimmed version). Leave it out to undo a delete.
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
        version: Option<u32>,
    },
    /// Show a secret's history, newest first: every version still stored,
    /// live or deleted (restorable with `ferritor restore --version` until
    /// purged). Metadata only, never values.
    Versions { path: String },
    /// List the latest version of every secret below a prefix.
    List {
        #[arg(default_value = "")]
        prefix: String,
        /// Only secrets with this label (repeatable: every one must match).
        #[arg(long = "label", value_name = "KEY=VALUE", value_parser = parse_label)]
        labels: Vec<(String, String)>,
    },
    /// Show or change a secret's metadata: when it was created and last
    /// updated, its versions, and its labels (custom key=value metadata,
    /// plain and not encrypted: never put a secret in one).
    #[command(subcommand)]
    Metadata(Metadata),
}

#[derive(Debug, Subcommand)]
pub enum Metadata {
    /// Show a secret's metadata (never its value).
    Get { path: String },
    /// Set labels on a secret (added, or replacing a label's value).
    Set {
        path: String,
        #[arg(required = true, value_name = "KEY=VALUE", value_parser = parse_label)]
        labels: Vec<(String, String)>,
    },
    /// Remove labels from a secret (absent ones are fine).
    Unset {
        path: String,
        #[arg(required = true, value_name = "KEY")]
        keys: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum IdentityCommand {
    /// Create the issuing CA (once): a new key, wrapped by the root key.
    Init,
    /// Replace the issuing key with a new one. The old one's certificates
    /// stay trusted until they expire, unless --now.
    Rotate {
        /// Cut the old key off at once (it may be compromised), with every
        /// retired one: nothing they signed is trusted from now on, so every
        /// workload exchanges again.
        #[arg(long)]
        now: bool,
    },
    /// Show every issuing key and its state.
    Status,
}

#[derive(Debug, Subcommand)]
pub enum NamespaceCommand {
    /// Create a namespace (or re-create a deleted one), with its first KEK.
    Create {
        /// The namespace: one path segment, the first of its secrets' paths.
        name: String,
        /// Set a label on it (repeatable): plain metadata, never a secret.
        #[arg(long = "label", value_name = "KEY=VALUE", value_parser = parse_label)]
        labels: Vec<(String, String)>,
        /// Recovery: recreate a namespace the keys database lost while its
        /// secrets remain (a failover lost its creation, and no backup has
        /// it), with its first KEK past every lost version. Run it against
        /// a server still holding the lost KEKs, after every server has
        /// refreshed, then `ferritor rewrap` there. If a keys backup has the
        /// namespace, restore that instead.
        #[arg(long)]
        past_lost_keks: bool,
    },
    /// Delete an empty namespace, destroying its KEKs: every backup of its
    /// secrets becomes undecryptable. Irreversible. Only once it has no
    /// secret at all, deleted ones included: delete them, wait out the
    /// server's retention (purge_deleted_after_days), `ferritor purge`, then
    /// delete it. Needs the destroy_kek permission too. Safe to repeat.
    Delete {
        /// The namespace to delete.
        name: String,
    },
    /// List every namespace, live and deleted.
    List,
    /// Show a namespace: its state, KEKs, KEK floor and labels.
    Get {
        /// The namespace to show.
        name: String,
    },
    /// Set labels on a namespace (added, or replacing a label's value).
    Label {
        /// The namespace to label.
        name: String,
        /// Labels to set (added, or replacing a label's value).
        #[arg(required = true, value_name = "KEY=VALUE", value_parser = parse_label)]
        labels: Vec<(String, String)>,
    },
    /// Remove labels from a namespace (absent ones are fine).
    Unlabel {
        /// The namespace to change.
        name: String,
        /// Label keys to remove.
        #[arg(required = true, value_name = "KEY")]
        keys: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// List the config rules and the stored policies.
    List {
        /// Only this identity's rules.
        #[arg(long)]
        identity: Option<String>,
    },
    /// Show one rule: a stored policy, or a config rule (`config:…`).
    Get {
        /// The policy's name.
        name: String,
    },
    /// Create or replace one stored policy.
    Put {
        /// The policy's name (secret-path rules, e.g. apps/billing-read).
        name: String,
        /// The identity it grants to (the `<name>` of `ferritor://<name>`).
        #[arg(long)]
        identity: String,
        /// A secret action to grant (repeatable): read, write, delete,
        /// list, label.
        #[arg(long = "action", required = true, value_parser = parse_secret_action)]
        actions: Vec<ferritor_core::policy::SecretAction>,
        /// A path prefix it applies to, as whole segments (repeatable).
        #[arg(long = "path", required_unless_present = "all_paths")]
        paths: Vec<String>,
        /// Every path instead.
        #[arg(long, conflicts_with = "paths")]
        all_paths: bool,
        /// What it's for (plain text, at most 1 KiB).
        #[arg(long, default_value = "")]
        description: String,
        /// Check-and-set: 0 only creates; N only replaces version N.
        #[arg(long, value_name = "VERSION")]
        expected_version: Option<u32>,
    },
    /// Delete one stored policy (absent is fine).
    Delete {
        /// The policy's name.
        name: String,
        /// Only if it's still at this version.
        #[arg(long, value_name = "VERSION")]
        expected_version: Option<u32>,
    },
    /// Make the stored policies match a file, in one atomic call: create
    /// and replace what it lists, and with --prune delete the rest. The file
    /// is checked here first (unknown keys and actions, admin actions, an
    /// invalid name or path), so a typo is refused before anything is sent.
    Apply {
        /// The policies: TOML (`[[policy]]` entries, as in ferritor.toml plus
        /// `name` and `description`) or JSON (`{"policies": [...]}`, the
        /// JSON API's apply body); `-` reads stdin.
        #[arg(short = 'f', long = "file", value_name = "FILE")]
        file: PathBuf,
        /// Delete every stored policy the file doesn't list. Also the repair
        /// for a stored set that doesn't verify.
        #[arg(long)]
        prune: bool,
        /// Show what would change; change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Only if the stored set is still at this revision.
        #[arg(long, value_name = "REVISION")]
        expected_revision: Option<u64>,
    },
    /// Whether an identity may do an action, and which rules grant it. Exit
    /// status 0 if allowed, 1 if not.
    Check {
        #[arg(long)]
        identity: String,
        /// Any action name (read, write, rotate, …).
        #[arg(long)]
        action: String,
        /// For a secret action: the secret or prefix (default: every secret).
        #[arg(long)]
        path: Option<String>,
    },
}

fn parse_secret_action(
    arg: &str,
) -> Result<ferritor_core::policy::SecretAction, ferritor_core::policy::PolicyError> {
    ferritor_core::policy::SecretAction::parse(arg)
}

/// A `key=value` label argument, checked like the server checks it.
fn parse_label(arg: &str) -> Result<(String, String), ferritor_core::labels::LabelError> {
    ferritor_core::labels::parse_pair(arg)
}

#[derive(Debug, Subcommand)]
pub enum Audit {
    /// Check an audit log (stdin, as the server wrote it) for tampering:
    /// every line's link to the one before, and every signature. Prints one
    /// line per chain (one per server run): complete (ends with a signed
    /// chain_end), open (the last chain, not ended: a running or crashed
    /// server), unterminated, unverifiable or broken.
    ///
    /// Exit status: 0 if every entry is covered by a signature; 2 if nothing
    /// is broken but something is unproven (an open, unterminated or
    /// unverifiable chain, or lines outside any chain); 1 if broken.
    Verify {
        /// The server's audit public key (PEM: `openssl pkey -in
        /// audit-key.pem -pubout`). Repeat it for a log spanning a key
        /// change: each chain is checked with the key it names.
        #[arg(long, required = true)]
        public_key: Vec<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
pub enum Rekey {
    /// Start a rekey to a new share count and threshold.
    Start {
        #[arg(long, default_value_t = 5)]
        shares: u32,
        #[arg(long, default_value_t = 3)]
        threshold: u32,
        /// Change how the root key is protected, for every server: `shamir`
        /// (the shares alone), `awskms` or `gcpkms` (wrapped by the
        /// answering server's configured KMS key too, the provider it's
        /// configured with). Without it, the rekey keeps the deployment's,
        /// and is refused through a server configured otherwise.
        #[arg(long, value_parser = ["shamir", "awskms", "gcpkms"])]
        seal: Option<String>,
    },
    /// Submit one current share (stdin). The last one prints the new shares.
    Submit {
        #[arg(long)]
        nonce: String,
    },
    /// Submit one of the new shares (stdin). The last one commits the rekey.
    Verify {
        #[arg(long)]
        nonce: String,
    },
    /// Abandon the rekey; the current shares keep working.
    Cancel {
        #[arg(long)]
        nonce: String,
    },
}
