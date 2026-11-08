//! Running a command against the server. Results go to stdout, guidance and
//! warnings to stderr, so `ferritor get … > file` and `ferritor init … > shares`
//! capture only the data.

use std::collections::{BTreeMap, HashMap};
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use ferritor_core::audit_chain;
use ferritor_core::crypto::Share;
use ferritor_core::messages::reason;
use ferritor_core::proto::v1 as pb;
use ferritor_core::proto::v1::secrets_service_client::SecretsServiceClient;
use ferritor_core::proto::v1::system_service_client::SystemServiceClient;
use tonic::Code;
use zeroize::Zeroizing;

use crate::cli::{
    Audit, Cli, Command, IdentityCommand, Metadata, NamespaceCommand, PolicyCommand, Rekey,
};
use crate::input::{self, hex, unhex};

use ferritor_client::exchange::{ExchangeError, Issued, TokenSource};
use ferritor_client::{ConnectError, Server, Transport};
pub use ferritor_client::{ServerError, Unreachable, answer};

/// The server to talk to, from the CLI's options: checks the address and
/// TLS options fit together before anything is sent, so a mismatch is a
/// clear error rather than a failed handshake.
async fn server(cli: &Cli) -> anyhow::Result<Server> {
    let https = cli.addr.starts_with("https://");
    if let Some(source) = token_source(cli)? {
        if !https {
            anyhow::bail!("--token-file is for TLS: use an https:// address with it");
        }
        let issued = exchange(&source).await?;
        return Ok(Server::issued(&cli.addr, &source.ca, &issued)?.with_wait_notice(wait_notice));
    }
    let server = match (https, &cli.ca, &cli.cert, &cli.key) {
        (false, None, None, None) => Server::plain(&cli.addr),
        (false, ..) => {
            anyhow::bail!("--ca, --cert and --key are for TLS: use an https:// address with them")
        }
        (true, Some(ca), Some(cert), Some(key)) => Server::tls(&cli.addr, ca, cert, key)?,
        (true, None, ..) => anyhow::bail!(
            "an https:// server needs --ca (or FERRITOR_CA): the CA certificate to verify it with"
        ),
        (true, Some(_), ..) => anyhow::bail!(
            "an https:// server needs --cert and --key (or FERRITOR_CERT and FERRITOR_KEY), or \
             --token-file and --exchange: it only accepts callers with a client certificate"
        ),
    };
    Ok(server.with_wait_notice(wait_notice))
}

/// The token exchange's settings, if --token-file is given.
fn token_source(cli: &Cli) -> anyhow::Result<Option<TokenSource>> {
    let (Some(token_file), Some(exchange)) = (&cli.token_file, &cli.exchange) else {
        return Ok(None);
    };
    if !exchange.starts_with("https://") {
        anyhow::bail!("--exchange {exchange:?}: the server's token exchange, an https:// address");
    }
    let Some(ca) = &cli.ca else {
        anyhow::bail!(
            "--token-file needs --ca (or FERRITOR_CA): the CA certificate to verify the server with"
        );
    };
    Ok(Some(TokenSource {
        exchange_addr: exchange.clone(),
        ca: ca.clone(),
        token_file: token_file.clone(),
    }))
}

async fn exchange(source: &TokenSource) -> anyhow::Result<Issued> {
    ferritor_client::exchange::exchange(source)
        .await
        .map_err(|e| match e {
            // The server's refusal, findable by `hint`.
            ExchangeError::Refused { addr, source } => anyhow::Error::new(*source)
                .context(format!("the token exchange at {addr} gave no certificate")),
            other => anyhow::Error::new(other),
        })
}

/// `ferritor login`: one exchange, its certificate and key written (the key
/// created readable by the user alone, replacing any file there).
async fn login(
    cli: &Cli,
    cert_out: &std::path::Path,
    key_out: &std::path::Path,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    let Some(source) = token_source(cli)? else {
        anyhow::bail!(
            "login needs --token-file and --exchange (or FERRITOR_TOKEN_FILE and FERRITOR_EXCHANGE)"
        );
    };
    let issued = exchange(&source).await?;
    write_private(key_out, issued.key().as_bytes())
        .with_context(|| format!("writing {}", key_out.display()))?;
    std::fs::write(cert_out, &issued.certificate)
        .with_context(|| format!("writing {}", cert_out.display()))?;
    let expires = time::OffsetDateTime::from(issued.not_after)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "?".to_owned());
    writeln!(out, "identity: {}\nexpires: {expires}", issued.identity)?;
    eprintln!(
        "Use it with --cert {} --key {} (or FERRITOR_CERT and FERRITOR_KEY) until it expires.",
        cert_out.display(),
        key_out.display()
    );
    Ok(())
}

/// Writes `contents` to `path` with mode 0600, replacing what's there
/// (removed first, so an existing file's wider mode isn't kept). On
/// Windows the new file takes its directory's inherited ACL.
fn write_private(path: &std::path::Path, contents: &[u8]) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

/// A short rate limit being waited out (`ferritor_client::retry`), on stderr.
fn wait_notice(limit: &str, wait: Duration) {
    eprintln!(
        "rate limited by the server ({limit}): retrying in {} ms",
        wait.as_millis()
    );
}

/// A channel to `server`; an unreachable server stays an [`Unreachable`]
/// of its own, which [`hint`] looks for.
async fn channel(server: &Server) -> anyhow::Result<Transport> {
    ferritor_client::connect(server).await.map_err(|e| match e {
        ConnectError::Unreachable(unreachable) => anyhow::Error::new(unreachable),
        other => anyhow::Error::new(other),
    })
}

/// A share typed at a hidden prompt or piped in, as hex.
fn read_share(prompt: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let line = input::secret_line(prompt).context("reading the share")?;
    if line.trim().is_empty() {
        anyhow::bail!("no share given (stdin was empty)");
    }
    Ok(unhex(&line)?)
}

/// Hands the operators their shares: stdout, flushed. The server already
/// holds the root key they belong to, so if stdout fails (`| head -1`, a
/// full disk, a closed terminal; Rust ignores SIGPIPE, so these are plain
/// errors) the shares would be gone for good. So the whole set goes to
/// stderr as a last resort, and the error says where they ended up.
fn deliver_shares(out: &mut impl Write, shares: &[Vec<u8>]) -> anyhow::Result<()> {
    let Err(stdout_error) = print_shares(out, shares).and_then(|()| out.flush()) else {
        return Ok(());
    };
    let mut err = io::stderr().lock();
    let fallback = writeln!(
        err,
        "Could not write the shares to stdout ({stdout_error}). All of them, here instead:"
    )
    .and_then(|()| print_shares(&mut err, shares))
    .and_then(|()| err.flush());
    Err(match fallback {
        Ok(()) => anyhow::Error::new(stdout_error)
            .context("writing the shares to stdout failed; they are on stderr above"),
        Err(_) => anyhow::Error::new(stdout_error)
            .context("writing the shares failed on both stdout and stderr: they are lost"),
    })
}

/// Shares printed to a terminal stay in its scrollback (and possibly a
/// terminal log); a redirect to a file avoids that.
fn warn_about_scrollback() {
    if io::stdout().is_terminal() {
        eprintln!(
            "The shares are in this terminal's scrollback: clear it once they're handed out\n\
             (or next time, redirect stdout to a file)."
        );
    }
}

/// `share <id> (generation <g>): <hex>`, one per line.
fn print_shares(out: &mut impl Write, shares: &[Vec<u8>]) -> io::Result<()> {
    for (i, bytes) in shares.iter().enumerate() {
        match Share::from_bytes(bytes) {
            Ok(share) => writeln!(
                out,
                "share {} (generation {}): {}",
                share.id(),
                share.generation(),
                hex(bytes)
            )?,
            // Not ours to judge: print it anyway, it's the operators' key.
            Err(_) => writeln!(out, "share #{}: {}", i + 1, hex(bytes))?,
        }
    }
    Ok(())
}

fn print_status(out: &mut impl Write, s: &pb::SealStatus) -> io::Result<()> {
    if !s.initialized {
        return writeln!(out, "not initialized");
    }
    writeln!(out, "{}", if s.sealed { "sealed" } else { "unsealed" })?;
    writeln!(out, "shares: {}, threshold: {}", s.shares, s.threshold)?;
    writeln!(out, "generation: {}", s.generation)?;
    if s.sealed {
        writeln!(out, "unseal progress: {}/{}", s.progress, s.threshold)?;
    }
    if let Some(rekey) = &s.rekey {
        let phase = match rekey.phase() {
            pb::RekeyPhase::Authorizing => "authorizing (current shares)".to_owned(),
            pb::RekeyPhase::Verifying => match rekey.generation {
                0 => "verifying (new shares)".to_owned(),
                g => format!("verifying (new shares, generation {g})"),
            },
            // Status never sends these; if it ever does, show what it was.
            other => other.as_str_name().to_owned(),
        };
        writeln!(out, "rekey: {phase}, {}/{}", rekey.progress, rekey.required)?;
        // The server leaves it out for callers who may not rekey.
        if !rekey.nonce.is_empty() {
            writeln!(out, "rekey nonce: {}", rekey.nonce)?;
        }
    }
    if let Some(auto) = &s.auto_unseal {
        print_auto_unseal(out, auto)?;
    }
    if let Some(guidance) = rekey_guidance(s) {
        eprintln!("{guidance}");
    }
    Ok(())
}

fn print_auto_unseal(out: &mut impl Write, a: &pb::AutoUnsealStatus) -> io::Result<()> {
    let half = |h: &Option<pb::AutoUnsealHold>| match h {
        Some(h) if h.readable => format!("hold {}, released {}", h.hold, h.released),
        Some(_) => "unreadable (counts as held)".to_owned(),
        None => "-".to_owned(),
    };
    if a.provider.is_empty() {
        writeln!(out, "auto-unseal: not configured (shares only)")?;
    } else {
        writeln!(out, "auto-unseal: {} {}", a.provider, a.key_id)?;
        writeln!(
            out,
            "auto-unseal wrap for this generation: {}",
            if a.wrapped { "yes" } else { "no" }
        )?;
        if !a.last_result.is_empty() {
            writeln!(out, "auto-unseal last attempt: {}", a.last_result)?;
        }
        if !a.last_error.is_empty() {
            writeln!(out, "auto-unseal last error: {}", a.last_error)?;
        }
    }
    writeln!(
        out,
        "auto-unseal hold: {} (held here: {}; keys database: {}; data database: {})",
        if a.held { "HELD" } else { "released" },
        if a.held_here {
            "yes, until this server is unsealed"
        } else {
            "no"
        },
        half(&a.keys_hold),
        half(&a.data_hold)
    )?;
    Ok(())
}

/// What to do about a rekey in progress, from the status alone.
fn rekey_guidance(s: &pb::SealStatus) -> Option<String> {
    let rekey = s.rekey.as_ref()?;
    let nonce = &rekey.nonce;
    if nonce.is_empty() {
        return Some(
            "A rekey is in progress. Its nonce is shown only to callers allowed to rekey; \
             ask an operator who is."
                .to_owned(),
        );
    }
    Some(match rekey.phase() {
        pb::RekeyPhase::Authorizing => format!(
            "A rekey is in progress. Continue with `ferritor rekey submit --nonce {nonce}`,\n\
             or abandon it with `ferritor rekey cancel --nonce {nonce}`."
        ),
        // The commit landed but wasn't confirmed: the stored generation is
        // already the one the new shares carry.
        pb::RekeyPhase::Verifying if rekey.generation != 0 && s.generation == rekey.generation => {
            format!(
                "The new key is already stored (generation {}): the rekey's commit landed\n\
                 but wasn't confirmed. Only the new shares unseal now; keep them. Run\n\
                 `ferritor rekey verify --nonce {nonce}` again to finish.",
                rekey.generation
            )
        }
        pb::RekeyPhase::Verifying => format!(
            "A rekey is in progress. Continue with `ferritor rekey verify --nonce {nonce}`,\n\
             or abandon it with `ferritor rekey cancel --nonce {nonce}`."
        ),
        other => format!(
            "The server reported an unexpected rekey phase ({}). Check `ferritor status`\n\
             again; to abandon it, `ferritor rekey cancel --nonce {nonce}`.",
            other.as_str_name()
        ),
    })
}

type SystemClient = SystemServiceClient<Transport>;
type SecretsClient = SecretsServiceClient<Transport>;

async fn system_client(addr: &Server) -> anyhow::Result<SystemClient> {
    Ok(SystemServiceClient::new(channel(addr).await?))
}

async fn secrets_client(addr: &Server) -> anyhow::Result<SecretsClient> {
    Ok(SecretsServiceClient::new(channel(addr).await?))
}

pub async fn run(cli: &Cli) -> anyhow::Result<()> {
    // Only for commands that connect: an offline one ignores the server
    // settings.
    let addr = || server(cli);
    let out = &mut io::stdout().lock();
    match &cli.command {
        Command::Status => status(system_client(&addr().await?).await?, out).await,
        Command::Init { shares, threshold } => {
            init(
                system_client(&addr().await?).await?,
                *shares,
                *threshold,
                out,
            )
            .await
        }
        Command::Unseal {
            reset,
            recommit,
            auto,
            release_hold,
        } => {
            let flags = UnsealFlags {
                reset: *reset,
                recommit: *recommit,
                auto: *auto,
                release_hold: *release_hold,
            };
            unseal(system_client(&addr().await?).await?, flags, out).await
        }
        Command::Seal => seal(system_client(&addr().await?).await?, out).await,
        Command::Rotate { namespace } => {
            rotate(system_client(&addr().await?).await?, namespace, out).await
        }
        Command::Rewrap {
            max_rows,
            namespace,
        } => {
            rewrap(
                system_client(&addr().await?).await?,
                *max_rows,
                namespace.clone().unwrap_or_default(),
                out,
            )
            .await
        }
        Command::Purge { max_rows } => {
            purge(system_client(&addr().await?).await?, *max_rows, out).await
        }
        Command::DestroyKek { namespace, version } => {
            destroy_kek(
                system_client(&addr().await?).await?,
                namespace,
                *version,
                out,
            )
            .await
        }
        Command::Namespace(command) => {
            namespace_command(system_client(&addr().await?).await?, command, out).await
        }
        Command::Policy(command) => {
            let client = crate::policy::PolicyClient::new(channel(&addr().await?).await?);
            crate::policy::policy_command(client, command, out).await
        }
        Command::Identity(command) => {
            identity_command(system_client(&addr().await?).await?, command, out).await
        }
        Command::Rekey(rekey) => {
            rekey_command(system_client(&addr().await?).await?, rekey, out).await
        }
        Command::Login { cert_out, key_out } => login(cli, cert_out, key_out, out).await,
        Command::Audit(Audit::Verify { public_key }) => {
            verify_audit_log(public_key, io::stdin().lock(), out)
        }
        Command::Get { path, version } => {
            get(secrets_client(&addr().await?).await?, path, *version, out).await
        }
        Command::Put {
            path,
            allow_empty,
            expected_version,
            labels,
        } => {
            put(
                secrets_client(&addr().await?).await?,
                path,
                *allow_empty,
                *expected_version,
                label_map(labels)?,
                out,
            )
            .await
        }
        Command::Delete { path } => delete(secrets_client(&addr().await?).await?, path, out).await,
        Command::Restore { path, version } => {
            restore(secrets_client(&addr().await?).await?, path, *version, out).await
        }
        Command::Versions { path } => {
            history(secrets_client(&addr().await?).await?, path, out).await
        }
        Command::List { prefix, labels } => {
            list(
                secrets_client(&addr().await?).await?,
                prefix,
                label_map(labels)?,
                out,
            )
            .await
        }
        Command::Metadata(Metadata::Get { path }) => {
            metadata(secrets_client(&addr().await?).await?, path, out).await
        }
        Command::Metadata(Metadata::Set { path, labels }) => {
            let set = label_map(labels)?;
            update_labels(
                secrets_client(&addr().await?).await?,
                path,
                set,
                Vec::new(),
                out,
            )
            .await
        }
        Command::Metadata(Metadata::Unset { path, keys }) => {
            update_labels(
                secrets_client(&addr().await?).await?,
                path,
                HashMap::new(),
                keys.clone(),
                out,
            )
            .await
        }
    }
}

async fn status(mut client: SystemClient, out: &mut impl Write) -> anyhow::Result<()> {
    let reply = answer(client.status(pb::StatusRequest {}).await)?;
    let status = reply.status.context("no status in the reply")?;
    print_status(out, &status)?;
    if status.initialized {
        writeln!(out, "namespaces: {}", reply.namespaces)?;
        if reply.namespaces == 0 {
            eprintln!(
                "No namespace yet: nothing can be stored until one exists (`ferritor namespace \
                 create <name>`; a secret's path starts with its namespace)."
            );
        }
    }
    if reply.vanished_keks > 0 {
        writeln!(
            out,
            "vanished KEKs held by this server: {}",
            reply.vanished_keks
        )?;
        eprintln!(
            "The keys database lost these KEKs (`ferritor namespace list` shows which); this \
             server's memory has the last copy, kept for reading only. Don't seal or restart \
             it: run `ferritor rewrap` against this server (this --addr) to move their rows onto \
             a stored KEK (see https://ferritor.dev/operations/high-availability)."
        );
    }
    Ok(())
}

/// A namespace's KEK versions and their states, oldest first: what to check
/// before `ferritor destroy-kek` (only a retired version can go).
fn keks(keks: &[pb::KekVersion]) -> String {
    if keks.is_empty() {
        return "none".to_owned();
    }
    keks.iter()
        .map(|kek| {
            let state = match kek.state() {
                pb::KekState::Active => "active",
                pb::KekState::DecryptOnly => "decrypt-only",
                pb::KekState::Retired => "retired",
                pb::KekState::Destroyed => "destroyed",
                pb::KekState::Unspecified => "unknown",
            };
            format!("{} {state}", kek.version)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

async fn init(
    mut client: SystemClient,
    shares: u32,
    threshold: u32,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    let reply = answer(client.init(pb::InitRequest { shares, threshold }).await)?;
    deliver_shares(out, &reply.shares)?;
    eprintln!(
        "Initialized: {shares} shares, any {threshold} unseal. The server is still sealed.\n\
         These shares are shown only once. Give each to a different operator,\n\
         then unseal with `ferritor unseal`, once per share."
    );
    warn_about_scrollback();
    Ok(())
}

#[derive(Clone, Copy)]
struct UnsealFlags {
    reset: bool,
    recommit: bool,
    auto: bool,
    release_hold: bool,
}

async fn unseal(
    mut client: SystemClient,
    flags: UnsealFlags,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    let share = if flags.reset || flags.auto {
        Zeroizing::new(Vec::new())
    } else {
        read_share("Unseal share (hidden): ")?
    };
    let reply = answer(
        client
            .unseal(pb::UnsealRequest {
                share: share.to_vec(),
                reset: flags.reset,
                recommit: flags.recommit,
                auto: flags.auto,
                release_hold: flags.release_hold,
            })
            .await,
    )?;
    print_status(out, &reply.status.context("no status in the reply")?)?;
    Ok(())
}

async fn seal(mut client: SystemClient, out: &mut impl Write) -> anyhow::Result<()> {
    let reply = answer(client.seal(pb::SealRequest {}).await)?;
    writeln!(out, "sealed")?;
    if !reply.hold_set {
        eprintln!(
            "WARNING: the server is sealed, but the auto-unseal hold is NOT set in both\n\
             databases yet (one couldn't be written): a restart could unseal it again.\n\
             The server keeps retrying; check `ferritor status` (\"held\") before relying\n\
             on it, and for a lockout that holds regardless, disable the KMS key."
        );
    }
    if let Some(status) = &reply.status {
        writeln!(out, "generation: {}", status.generation)?;
    }
    match reply.pending_rekey() {
        pb::PendingRekey::Committed => eprintln!(
            "WARNING: a rekey in progress had already been stored. Only the NEW shares\n\
             unseal now (generation above). Keep them; the old ones are useless."
        ),
        pb::PendingRekey::Unknown => eprintln!(
            "WARNING: a rekey in progress could not be confirmed either way. Keep BOTH\n\
             the old and the new shares until an unseal succeeds; `ferritor status` shows\n\
             which generation is current."
        ),
        pb::PendingRekey::Discarded => {
            eprintln!("A rekey in progress was discarded; the current shares still work.");
        }
        pb::PendingRekey::None | pb::PendingRekey::Unspecified => {}
    }
    Ok(())
}

async fn rotate(
    mut client: SystemClient,
    namespace: &str,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    let reply = answer(
        client
            .rotate_kek(pb::RotateKekRequest {
                namespace: namespace.to_owned(),
            })
            .await,
    )?;
    writeln!(out, "active KEK version: {}", reply.version)?;
    Ok(())
}

async fn rewrap(
    mut client: SystemClient,
    max_rows: u32,
    namespace: String,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    let (mut rewrapped, mut failed, mut retired) = (0_u64, 0_u64, Vec::new());
    let mut released = Vec::new();
    loop {
        let request = pb::RewrapRequest {
            max_rows,
            namespace: namespace.clone(),
        };
        let reply = match answer(client.rewrap(request).await) {
            Ok(reply) => reply,
            Err(e) => {
                // Earlier calls' work is done and stays done.
                if rewrapped > 0 || !retired.is_empty() {
                    eprintln!(
                        "Before the error: rewrapped {rewrapped}, retired {}.",
                        kek_refs(&retired)
                    );
                }
                return Err(e.into());
            }
        };
        rewrapped += reply.rewrapped;
        failed += reply.failed;
        retired.extend(reply.retired_keks);
        released.extend(reply.released_keks);
        if reply.done {
            break;
        }
        eprintln!("rewrapped {rewrapped} so far…");
    }
    writeln!(out, "rewrapped: {rewrapped}")?;
    writeln!(out, "retired KEKs: {}", kek_refs(&retired))?;
    if !released.is_empty() {
        writeln!(
            out,
            "released vanished KEKs: {} (their rows were rescued)",
            kek_refs(&released)
        )?;
    }
    if failed > 0 {
        anyhow::bail!(
            "{failed} DEKs did not unwrap and were left as they are (corrupted or tampered \
             with?); see the server log. Their KEK versions stay unretired."
        );
    }
    Ok(())
}

async fn purge(
    mut client: SystemClient,
    max_rows: u32,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    let mut purged = 0_u64;
    loop {
        let reply = match answer(client.purge(pb::PurgeRequest { max_rows }).await) {
            Ok(reply) => reply,
            Err(e) => {
                // Earlier calls' work is done and stays done.
                if purged > 0 {
                    eprintln!("Before the error: purged {purged}.");
                }
                return Err(e.into());
            }
        };
        purged += reply.purged;
        if reply.done {
            break;
        }
        eprintln!("purged {purged} so far…");
    }
    writeln!(out, "purged: {purged}")?;
    Ok(())
}

async fn destroy_kek(
    mut client: SystemClient,
    namespace: &str,
    version: u32,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    let reply = answer(
        client
            .destroy_kek(pb::DestroyKekRequest {
                namespace: namespace.to_owned(),
                version,
            })
            .await,
    )?;
    if reply.destroyed {
        writeln!(out, "destroyed KEK {namespace}/{version}")?;
    } else {
        writeln!(out, "KEK {namespace}/{version} was already destroyed")?;
    }
    writeln!(out, "KEK floor: {}", reply.kek_floor)?;
    Ok(())
}

/// KEKs as `namespace/version`, comma-separated.
fn kek_refs(keks: &[pb::KekRef]) -> String {
    if keks.is_empty() {
        return "none".to_owned();
    }
    keks.iter()
        .map(|kek| format!("{}/{}", kek.namespace, kek.version))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `issuing key <v>: <state>, created …[, retired …], expires …, sha256 …`.
fn print_issuing_key(out: &mut impl Write, key: &pb::IssuingKey) -> io::Result<()> {
    let state = match key.state() {
        pb::IssuingKeyState::Active => "active",
        pb::IssuingKeyState::Retired => "retired",
        pb::IssuingKeyState::Revoked => "revoked",
        pb::IssuingKeyState::Unspecified => "unknown",
    };
    let retired = key
        .retired_at_unix
        .map(|at| format!(", retired {}", utc(at)))
        .unwrap_or_default();
    writeln!(
        out,
        "issuing key {}: {state}, created {}{retired}, expires {}, sha256 {}",
        key.version,
        utc(key.created_at_unix),
        utc(key.not_after_unix),
        key.fingerprint
    )
}

async fn identity_command(
    mut client: SystemClient,
    command: &IdentityCommand,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    match command {
        IdentityCommand::Init => {
            let reply = answer(client.identity_init(pb::IdentityInitRequest {}).await)?;
            let key = reply.key.context("no key in the reply")?;
            print_issuing_key(out, &key)?;
        }
        IdentityCommand::Rotate { now } => {
            let reply = answer(
                client
                    .identity_rotate(pb::IdentityRotateRequest { revoke: *now })
                    .await,
            )?;
            let key = reply.key.context("no key in the reply")?;
            print_issuing_key(out, &key)?;
            if *now {
                eprintln!(
                    "The previous keys are revoked: every workload certificate they signed is \
                     refused from now on, so workloads exchange their tokens again."
                );
            }
        }
        IdentityCommand::Status => {
            let reply = answer(client.identity_status(pb::IdentityStatusRequest {}).await)?;
            if reply.keys.is_empty() {
                writeln!(
                    out,
                    "no issuing CA (create one with `ferritor identity init`)"
                )?;
            }
            for key in &reply.keys {
                print_issuing_key(out, key)?;
            }
        }
    }
    Ok(())
}

async fn namespace_command(
    mut client: SystemClient,
    command: &NamespaceCommand,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    match command {
        NamespaceCommand::Create {
            name,
            labels,
            past_lost_keks,
        } => {
            let reply = answer(
                client
                    .create_namespace(pb::CreateNamespaceRequest {
                        name: name.clone(),
                        labels: label_map(labels)?,
                        past_lost_keks: *past_lost_keks,
                    })
                    .await,
            )?;
            writeln!(out, "created namespace {name}")?;
            writeln!(out, "active KEK version: {}", reply.kek_version)?;
            if *past_lost_keks {
                eprintln!(
                    "Now run `ferritor rewrap --namespace {name}` against every server still holding \
                     its lost KEKs (this --addr first), to move their rows onto the new KEK (see \
                     https://ferritor.dev/operations/high-availability)."
                );
            }
        }
        NamespaceCommand::Delete { name } => {
            let reply = answer(
                client
                    .delete_namespace(pb::DeleteNamespaceRequest { name: name.clone() })
                    .await,
            )?;
            if reply.deleted {
                writeln!(out, "deleted namespace {name}")?;
                writeln!(
                    out,
                    "destroyed KEK versions: {}",
                    versions(&reply.destroyed)
                )?;
            } else {
                writeln!(out, "namespace {name} was already deleted")?;
            }
            writeln!(out, "KEK floor: {}", reply.kek_floor)?;
        }
        NamespaceCommand::List => {
            let reply = answer(client.list_namespaces(pb::ListNamespacesRequest {}).await)?;
            for ns in reply.namespaces {
                let state = if ns.deleted { "deleted" } else { "active" };
                let vanished = if ns.vanished.is_empty() {
                    String::new()
                } else {
                    format!("; VANISHED (held here only): {}", versions(&ns.vanished))
                };
                writeln!(
                    out,
                    "{}\t{state}\tKEKs: {}; floor {}{vanished}",
                    ns.name,
                    keks(&ns.keks),
                    ns.kek_floor
                )?;
            }
        }
        NamespaceCommand::Get { name } => {
            let reply = answer(
                client
                    .get_namespace(pb::GetNamespaceRequest { name: name.clone() })
                    .await,
            )?;
            let ns = reply.namespace.context("no namespace in the reply")?;
            writeln!(out, "namespace: {}", ns.name)?;
            writeln!(
                out,
                "state: {}",
                if ns.deleted { "deleted" } else { "active" }
            )?;
            writeln!(out, "created: {}", utc(ns.created_at_unix))?;
            if let Some(at) = ns.deleted_at_unix {
                writeln!(out, "deleted: {}", utc(at))?;
            }
            writeln!(out, "KEK versions: {}", keks(&ns.keks))?;
            match ns.kek_floor {
                0 => writeln!(out, "KEK floor: unknown")?,
                floor => writeln!(out, "KEK floor: {floor}")?,
            }
            if !ns.vanished.is_empty() {
                writeln!(
                    out,
                    "vanished KEK versions held by this server: {}",
                    versions(&ns.vanished)
                )?;
            }
            print_labels(out, ns.labels.into_iter().collect())?;
            if let Some(at) = ns.labels_updated_at_unix {
                writeln!(out, "labels updated: {}", utc(at))?;
            }
        }
        NamespaceCommand::Label { name, labels } => {
            let reply = answer(
                client
                    .update_namespace_labels(pb::UpdateNamespaceLabelsRequest {
                        name: name.clone(),
                        set: label_map(labels)?,
                        remove: Vec::new(),
                    })
                    .await,
            )?;
            print_labels(out, reply.labels.into_iter().collect())?;
        }
        NamespaceCommand::Unlabel { name, keys } => {
            let reply = answer(
                client
                    .update_namespace_labels(pb::UpdateNamespaceLabelsRequest {
                        name: name.clone(),
                        set: HashMap::new(),
                        remove: keys.clone(),
                    })
                    .await,
            )?;
            print_labels(out, reply.labels.into_iter().collect())?;
        }
    }
    Ok(())
}

fn versions(versions: &[u32]) -> String {
    if versions.is_empty() {
        return "none".to_owned();
    }
    versions
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

async fn rekey_command(
    mut client: SystemClient,
    rekey: &Rekey,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    match rekey {
        Rekey::Start {
            shares,
            threshold,
            seal,
        } => {
            let reply = answer(
                client
                    .rekey_start(pb::RekeyStartRequest {
                        shares: *shares,
                        threshold: *threshold,
                        seal: seal.clone().unwrap_or_default(),
                    })
                    .await,
            )?;
            let progress = reply.progress.context("no progress in the reply")?;
            writeln!(out, "nonce: {}", progress.nonce)?;
            eprintln!(
                "Rekey started. Submit {} current shares, one per call:\n  \
                 ferritor rekey submit --nonce {}",
                progress.required, progress.nonce
            );
        }
        Rekey::Submit { nonce } => {
            let share = read_share("Current share (hidden): ")?;
            let reply = answer(
                client
                    .rekey_submit(pb::RekeySubmitRequest {
                        nonce: nonce.clone(),
                        share: share.to_vec(),
                    })
                    .await,
            )?;
            let progress = reply.progress.context("no progress in the reply")?;
            if progress.new_shares.is_empty() {
                writeln!(
                    out,
                    "authorizing: {}/{}",
                    progress.progress, progress.required
                )?;
            } else {
                deliver_shares(out, &progress.new_shares)?;
                eprintln!(
                    "These are the NEW shares. Nothing has changed yet: the current shares\n\
                     keep working until {} of these are verified, one per call:\n  \
                     ferritor rekey verify --nonce {nonce}\n\
                     If these are lost before then, `ferritor rekey cancel --nonce {nonce}`\n\
                     and start again.",
                    progress.required
                );
                warn_about_scrollback();
            }
        }
        Rekey::Verify { nonce } => {
            let share = read_share("New share (hidden): ")?;
            let reply = answer(
                client
                    .rekey_verify(pb::RekeyVerifyRequest {
                        nonce: nonce.clone(),
                        share: share.to_vec(),
                    })
                    .await,
            )?;
            let Some(progress) = reply.progress else {
                // Accepted, but complete or not is unknown: neither claim
                // it, nor fail (which could read as "nothing happened").
                writeln!(out, "verify accepted").ok();
                eprintln!(
                    "The reply had no progress, so whether the rekey is complete is unknown.\n\
                     Keep BOTH the old and the new shares, and check `ferritor status`: if its\n\
                     generation matches the new shares', the rekey is done."
                );
                return Ok(());
            };
            if progress.phase() == pb::RekeyPhase::Complete {
                // The new root key is stored: from here nothing may report an
                // error, or an operator could keep the old shares and destroy
                // the new ones. (Hence no follow-up call, and output errors
                // ignored.)
                match progress.generation {
                    0 => writeln!(out, "rekey complete").ok(),
                    generation => writeln!(out, "rekey complete: generation {generation}").ok(),
                };
                eprintln!("Only the new shares unseal from now on; destroy the old ones.");
            } else {
                writeln!(
                    out,
                    "verifying: {}/{}",
                    progress.progress, progress.required
                )?;
            }
        }
        Rekey::Cancel { nonce } => {
            answer(
                client
                    .rekey_cancel(pb::RekeyCancelRequest {
                        nonce: nonce.clone(),
                    })
                    .await,
            )?;
            writeln!(out, "cancelled")?;
            eprintln!("The current shares keep working.");
        }
    }
    Ok(())
}

async fn get(
    mut client: SecretsClient,
    path: &str,
    version: Option<u32>,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    let reply = answer(
        client
            .get_secret(pb::GetSecretRequest {
                path: path.to_owned(),
                // The proto's 0 means latest; --version itself starts at 1.
                version: version.unwrap_or(0),
            })
            .await,
    )?;
    let value = Zeroizing::new(reply.secret.context("no secret in the reply")?.value);
    out.write_all(&value)?;
    // Raw bytes for pipes; a terminal gets a tidy line end.
    if io::stdout().is_terminal() && !value.ends_with(b"\n") {
        writeln!(out)?;
    }
    Ok(())
}

async fn put(
    mut client: SecretsClient,
    path: &str,
    allow_empty: bool,
    expected_version: Option<u32>,
    labels: HashMap<String, String>,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    let value = input::secret_value("Value (hidden): ").context("reading the value")?;
    if value.is_empty() && !allow_empty {
        anyhow::bail!(
            "refusing to store an empty value: stdin was empty (pass --allow-empty if \
             that's intended)"
        );
    }
    let reply = answer(
        client
            .put_secret(pb::PutSecretRequest {
                path: path.to_owned(),
                value: value.to_vec(),
                expected_version,
                labels,
            })
            .await,
    )?;
    // Stored: report it, even if the reply is short on detail.
    match reply.metadata {
        Some(m) => writeln!(out, "{} version {}", m.path, m.version).ok(),
        None => writeln!(out, "{path} stored").ok(),
    };
    Ok(())
}

async fn restore(
    mut client: SecretsClient,
    path: &str,
    version: Option<u32>,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    let reply = answer(
        client
            .restore_secret(pb::RestoreSecretRequest {
                path: path.to_owned(),
                version: version.unwrap_or(0),
            })
            .await,
    )?;
    match reply.metadata {
        Some(m) => writeln!(out, "{} version {} restored", m.path, m.version)?,
        None => writeln!(out, "{path} restored")?,
    }
    Ok(())
}

async fn delete(mut client: SecretsClient, path: &str, out: &mut impl Write) -> anyhow::Result<()> {
    answer(
        client
            .delete_secret(pb::DeleteSecretRequest {
                path: path.to_owned(),
            })
            .await,
    )?;
    writeln!(out, "deleted {path}")?;
    Ok(())
}

/// Fetches every page before printing anything, so a failure partway (a
/// seal, a dropped connection) prints no partial list that a script could
/// take for the whole one.
async fn list(
    mut client: SecretsClient,
    prefix: &str,
    labels: HashMap<String, String>,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    let mut secrets = Vec::new();
    let mut page_token = String::new();
    loop {
        let reply = answer(
            client
                .list_secrets(pb::ListSecretsRequest {
                    prefix: prefix.to_owned(),
                    // The server's default.
                    page_size: 0,
                    page_token: page_token.clone(),
                    labels: labels.clone(),
                })
                .await,
        )?;
        secrets.extend(reply.secrets);
        if reply.next_page_token.is_empty() {
            break;
        }
        // A server handing back the same token would loop forever.
        anyhow::ensure!(
            reply.next_page_token != page_token,
            "the server returned the same page token twice"
        );
        page_token = reply.next_page_token;
    }
    for secret in secrets {
        writeln!(out, "{}\tversion {}", secret.path, secret.version)?;
    }
    Ok(())
}

/// One line per version, newest first: `version N\tcreated <time>\tlive`, or
/// `\tdeleted <time>`. Every page first, like `list`.
async fn history(
    mut client: SecretsClient,
    path: &str,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    let mut versions = Vec::new();
    let mut page_token = String::new();
    loop {
        let reply = answer(
            client
                .list_versions(pb::ListVersionsRequest {
                    path: path.to_owned(),
                    page_size: 0,
                    page_token: page_token.clone(),
                })
                .await,
        )?;
        versions.extend(reply.versions);
        if reply.next_page_token.is_empty() {
            break;
        }
        anyhow::ensure!(
            reply.next_page_token != page_token,
            "the server returned the same page token twice"
        );
        page_token = reply.next_page_token;
    }
    for version in versions {
        let metadata = version.metadata.unwrap_or_default();
        let state = match version.deleted_at_unix {
            None => "live".to_owned(),
            Some(at) => format!("deleted {}", utc(at)),
        };
        writeln!(
            out,
            "version {}\tcreated {}\t{state}",
            metadata.version,
            utc(metadata.created_at_unix)
        )?;
    }
    Ok(())
}

/// `--label` arguments as a map; a key given twice is refused rather than
/// one silently winning.
fn label_map(labels: &[(String, String)]) -> anyhow::Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    for (key, value) in labels {
        anyhow::ensure!(
            map.insert(key.clone(), value.clone()).is_none(),
            "label `{key}` is given twice"
        );
    }
    Ok(map)
}

/// A secret's metadata, one `name: value` line each; labels sorted, one
/// `  key=value` line each.
async fn metadata(
    mut client: SecretsClient,
    path: &str,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    let reply = answer(
        client
            .get_metadata(pb::GetMetadataRequest {
                path: path.to_owned(),
            })
            .await,
    )?;
    let m = reply.metadata.context("no metadata in the reply")?;
    writeln!(out, "path: {}", m.path)?;
    writeln!(out, "created: {}", utc(m.created_at_unix))?;
    writeln!(out, "updated: {}", utc(m.updated_at_unix))?;
    match m.current_version {
        Some(version) => writeln!(out, "current version: {version}")?,
        None => writeln!(out, "current version: none (every version is deleted)")?,
    }
    match m.oldest_version {
        Some(version) => writeln!(out, "oldest version: {version}")?,
        None => writeln!(out, "oldest version: none (every version was purged)")?,
    }
    writeln!(out, "versions stored: {}", m.versions)?;
    print_labels(out, m.labels.into_iter().collect())?;
    if let Some(at) = m.labels_updated_at_unix {
        writeln!(out, "labels updated: {}", utc(at))?;
    }
    Ok(())
}

async fn update_labels(
    mut client: SecretsClient,
    path: &str,
    set: HashMap<String, String>,
    remove: Vec<String>,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    let reply = answer(
        client
            .update_labels(pb::UpdateLabelsRequest {
                path: path.to_owned(),
                set,
                remove,
            })
            .await,
    )?;
    print_labels(out, reply.labels.into_iter().collect())?;
    Ok(())
}

fn print_labels(out: &mut impl Write, labels: BTreeMap<String, String>) -> io::Result<()> {
    if labels.is_empty() {
        return writeln!(out, "labels: none");
    }
    writeln!(out, "labels:")?;
    for (key, value) in labels {
        writeln!(out, "  {key}={value}")?;
    }
    Ok(())
}

/// A Unix time as RFC 3339, UTC; the raw number if it's out of range.
pub(crate) fn utc(unix: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| unix.to_string())
}

/// `ferritor audit verify` found nothing broken, but not every entry is
/// covered by a signature: exit status 2, so scripts can tell it from a
/// broken log (1) and a proven one (0).
#[derive(Debug, thiserror::Error)]
#[error("the audit log isn't broken, but not all of it is proven by a signature (see above)")]
pub struct Unproven;

/// One line per chain on `out`, then [`Unproven`] or an error unless every
/// chain is complete.
pub fn verify_audit_log(
    public_keys: &[PathBuf],
    log: impl io::BufRead,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    use ed25519_dalek::VerifyingKey;
    use ed25519_dalek::pkcs8::DecodePublicKey;
    use ferritor_core::audit_chain::{ChainState, Verdict};

    let keys = public_keys
        .iter()
        .map(|path| {
            let pem = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            VerifyingKey::from_public_key_pem(&pem).map_err(|e| {
                anyhow::anyhow!(
                    "{} is not an Ed25519 public key in PEM ({e}); make it with `openssl pkey \
                     -in audit-key.pem -pubout`",
                    path.display()
                )
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let report = audit_chain::verify(log, &keys).context("reading the audit log")?;
    if let Some(stray) = &report.stray {
        writeln!(
            out,
            "line {}: {}, so no signature covers them",
            stray.line, stray.what
        )?;
    }
    for chain in &report.chains {
        let tail = match chain.unsigned_tail {
            0 => String::new(),
            n => format!("; its last {n} entries are not signed"),
        };
        let state = match &chain.state {
            ChainState::Complete => "complete: every entry signed".to_owned(),
            ChainState::Open => format!(
                "OPEN: no chain_end yet: a server still running, or one that crashed or was \
                 killed{tail}"
            ),
            ChainState::Unterminated => format!(
                "UNTERMINATED: no chain_end, yet another chain follows: a crash, a failed \
                 write, a cut, or entries appended by someone else{tail}"
            ),
            ChainState::Unverifiable(why) => format!("UNVERIFIABLE: {why}"),
            ChainState::Broken(problem) => {
                format!("BROKEN at line {}: {}", problem.line, problem.what)
            }
        };
        writeln!(
            out,
            "chain {} from line {}: {} entries, {state}",
            chain.chain, chain.first_line, chain.entries
        )?;
        if let Some(damaged) = &chain.damaged_last_line {
            writeln!(
                out,
                "  its last line ({}) is damaged: {} (a failed or interrupted write)",
                damaged.line, damaged.what
            )?;
        }
    }
    match report.verdict() {
        Verdict::Proven => Ok(()),
        Verdict::Unproven if report.chains.is_empty() => Err(anyhow::Error::new(Unproven)
            .context("no audit chain found: not an audit log, or one from before chaining")),
        Verdict::Unproven => Err(Unproven.into()),
        Verdict::Broken => anyhow::bail!("the audit log is BROKEN: it was changed (see above)"),
    }
}

/// What to do next, for errors where the message alone doesn't say.
pub fn hint(command: &Command, error: &anyhow::Error) -> Option<&'static str> {
    if let Some(unreachable) = error.downcast_ref::<Unreachable>() {
        // Connecting failed, so no request was sent: in an emergency the
        // operator must not read this as "probably sealed".
        return Some(match (command, unreachable.tls()) {
            (Command::Seal, false) => {
                "the seal request never reached the server, so this did NOT seal it: if the \
                 server is running, it is still unsealed. Check --addr / FERRITOR_ADDR and retry."
            }
            (Command::Seal, true) => {
                "the seal request never reached the server, so this did NOT seal it: if the \
                 server is running, it is still unsealed. Check --addr / FERRITOR_ADDR and --ca, \
                 --cert, --key, and retry."
            }
            (_, false) => "is the server running? Set the address with --addr or FERRITOR_ADDR.",
            (_, true) => {
                "is the server running (--addr / FERRITOR_ADDR)? If it is, the TLS handshake \
                 failed: check that --ca is the CA that signed the server's certificate, and \
                 that --cert/--key are a matching pair signed by the server's client CA, not \
                 expired or revoked, with client-auth usage and one ferritor://<name> URI SAN."
            }
        });
    }
    let server = error.downcast_ref::<ServerError>()?;
    // The call may or may not have taken effect: the server's database timed
    // out (UNAVAILABLE), our own request timeout fired (tonic reports
    // CANCELLED "Timeout expired"), a deadline passed, or the connection
    // dropped mid-call (UNKNOWN). None of these carry the server's verdict.
    let reason = server.reason.as_deref();
    // Refused before anything happened: not unclear at all.
    let unaudited = reason == Some(reason::UNAUDITED);
    let unclear = !unaudited
        && matches!(
            server.code,
            Code::Unavailable | Code::Cancelled | Code::DeadlineExceeded | Code::Unknown
        );
    match (server.code, command) {
        _ if unaudited => Some(
            "nothing was done: the server refuses requests it can't record in its audit log \
             (its stdout). Its operator must fix that; then retry.",
        ),
        _ if reason == Some(reason::TOKEN_REFUSED) => Some(
            "the server's token exchange refused the token (the message says why): check that \
             --token-file holds a current token from an issuer in the server's [identity], \
             with its audience, and claims one of its mappings accepts.",
        ),
        // Refused before anything happened.
        (Code::PermissionDenied, Command::Seal) => Some(
            "this did NOT seal the server: you aren't allowed to. If it must be sealed now, \
             ask an operator who is.",
        ),
        // Seal itself never fails on the server, so any of these is the
        // transport: the request may or may not have arrived.
        (_, Command::Seal) if unclear => Some(
            "the server may already be sealed; check `ferritor status`, and retry, since seal is \
             safe to repeat.",
        ),
        // A plain retry isn't enough here: if the commit landed, a second
        // verify only says "no rekey in progress", and destroying the wrong
        // set of shares locks everyone out.
        (_, Command::Rekey(Rekey::Verify { .. })) if unclear => Some(
            "the rekey may or may not have been stored. Keep BOTH the old and the new shares. \
             `ferritor status` shows the current generation: if it matches the new shares' \
             generation, the rekey is done; otherwise run `ferritor rekey verify` again.",
        ),
        // The shares exist only in the reply that didn't arrive: if the init
        // was stored, nobody can ever unseal. Nothing secret exists yet, so
        // starting over is safe, unless the stored init is someone else's.
        // That's told by who and when, not by result: when the client gave
        // up (its own timeout, a dropped connection), the server may have
        // finished normally and recorded `succeeded` for this very init.
        (_, Command::Init { .. }) if unclear => Some(
            "the server may or may not have been initialized. Run `ferritor status`: if it says \
             not initialized, just retry. If it says initialized, find the init outcome in \
             the server's audit log. If it's from your identity at the time of your call \
             (succeeded or unknown), your shares never arrived and nobody can unseal: nothing \
             secret is stored yet, so empty the keys database and run `ferritor init` again. If \
             it's from another caller, they hold valid shares: change nothing. (In dev mode \
             every caller is null, so only the time tells them apart.)",
        ),
        // With a check-and-set, a retry can't double-store: if the first
        // attempt landed, the latest version moved on and the retry is
        // refused.
        (
            _,
            Command::Put {
                expected_version: Some(_),
                ..
            },
        ) if unclear => Some(
            "the value may or may not have been stored. Retrying with the same \
             --expected-version is safe: if the first attempt landed, the retry is refused \
             as a mismatch, and `ferritor get` shows whether the latest version is yours.",
        ),
        (_, Command::Put { .. }) if unclear => Some(
            "the value may or may not have been stored: retrying is safe, but can create an \
             extra version.",
        ),
        (_, Command::Metadata(Metadata::Set { .. } | Metadata::Unset { .. })) if unclear => Some(
            "the labels may or may not have changed. Retrying is safe: setting a label or \
             removing one twice ends the same way.",
        ),
        (_, Command::Purge { .. }) if unclear => {
            Some("purging is safe to repeat or interrupt: run `ferritor purge` again to carry on.")
        }
        (_, Command::DestroyKek { .. }) if unclear => Some(
            "the KEK may or may not have been destroyed. Retrying is safe: if the first attempt \
             landed, the retry says it was already destroyed.",
        ),
        (_, Command::Namespace(NamespaceCommand::Create { .. })) if unclear => Some(
            "the namespace may or may not have been created: `ferritor namespace get` tells. \
             Retrying is safe: if the first attempt landed, the retry says it already exists.",
        ),
        (_, Command::Namespace(NamespaceCommand::Delete { .. })) if unclear => Some(
            "the namespace may or may not have been deleted. Retrying is safe: if the first \
             attempt landed, the retry says it was already deleted.",
        ),
        (
            _,
            Command::Namespace(NamespaceCommand::Label { .. } | NamespaceCommand::Unlabel { .. }),
        ) if unclear => Some(
            "the labels may or may not have changed. Retrying is safe: setting a label or \
             removing one twice ends the same way.",
        ),
        (
            _,
            Command::Policy(
                PolicyCommand::Put { .. }
                | PolicyCommand::Delete { .. }
                | PolicyCommand::Apply { .. },
            ),
        ) if unclear => Some(
            "the change may or may not have been stored. Retrying is safe: putting, deleting or \
             applying the same policies twice ends the same way (`ferritor policy list` shows the \
             revision).",
        ),
        (_, Command::Identity(IdentityCommand::Init)) if unclear => Some(
            "the issuing CA may or may not have been created: `ferritor identity status` tells. \
             Retrying is safe: if the first attempt landed, the retry says it already exists.",
        ),
        (_, Command::Identity(IdentityCommand::Rotate { .. })) if unclear => Some(
            "the rotation may or may not have happened, and it isn't safe to repeat: each one \
             adds a key. Check `ferritor identity status` before rotating again.",
        ),
        (_, Command::Rewrap { .. }) if unclear => Some(
            "rewrapping is safe to repeat or interrupt: run `ferritor rewrap` again to carry on.",
        ),
        // Safe with or without --version: with one, that version is live
        // once the first attempt landed; without, a restore only undoes a
        // delete. Either way the retry is refused.
        (_, Command::Restore { .. }) if unclear => Some(
            "the restore may or may not have happened. Retrying is safe: if the first \
             attempt landed, the retry is refused and restores nothing.",
        ),
        (_, Command::Delete { .. }) if unclear => Some(
            "the delete may or may not have happened. Retrying is safe: if the first attempt \
             went through, the retry reports \"not found\".",
        ),
        (Code::Unavailable, _) => Some("the server or its database didn't answer in time; retry."),
        (Code::Cancelled | Code::DeadlineExceeded, _) => {
            Some("the request timed out before the server answered; retry.")
        }
        _ if reason == Some(reason::KEYS_DATABASE_MISMATCH) => Some(
            "the keys database doesn't match the data database (restored from an older backup, \
             or lost). Restore the keys-database backup that matches, then seal and unseal \
             (the server log names the missing KEK versions); don't rotate or init until \
             then. To start over instead, empty the data database first. For a namespace no \
             backup has (a failover lost its creation): `ferritor namespace create <name> \
             --past-lost-keks` against a server still holding its KEKs, then `ferritor rewrap`.",
        ),
        _ if reason == Some(reason::ROOT_UNCOMMITTED) => Some(
            "nothing was unsealed: the data database has no commitment to this root key. After \
             restoring the data database from before a rekey (or a failover that lost the \
             write), submit the shares again with `ferritor unseal --recommit`: it re-commits the \
             key if a stored secret opens under it. If it's refused, the keys database holds a \
             root key that isn't this deployment's: find out who changed it.",
        ),
        _ if reason == Some(reason::ROOT_BELOW_FLOOR) => Some(
            "nothing was unsealed: the keys database is older than the last rekey the data \
             database knows of. One generation behind after a failover: the old shares are the \
             right ones and the floor must be lowered by hand (see \
             https://ferritor.dev/operations/high-availability). Further behind: restore the \
             matching keys-database backup (see https://ferritor.dev/operations/backup-restore).",
        ),
        _ if reason == Some(reason::NOT_RETIRED) => Some(
            "only a retired KEK version can be destroyed: run `ferritor rewrap` until it retires \
             it (for the active version, `ferritor rotate --namespace <name>` first; `ferritor \
             namespace get <name>` shows each version's state).",
        ),
        _ if reason == Some(reason::KEK_IN_USE) => Some(
            "nothing was destroyed: run `ferritor rewrap` until it's done (it moves those rows), \
             then `ferritor destroy-kek` again.",
        ),
        _ if reason == Some(reason::SEALED) => {
            Some("unseal it first: `ferritor unseal`, once per share.")
        }
        _ if reason == Some(reason::LIVE_VERSION) => Some(
            "without --version, restore only undoes a delete. To bring back an older version \
             alongside the live one, name it: `ferritor restore --version N` (see `ferritor \
             versions`).",
        ),
        _ if reason == Some(reason::NO_NAMESPACE) => Some(
            "a secret's path starts with its namespace, and that one doesn't exist (`ferritor \
             namespace list`). Check the path, or create it: `ferritor namespace create <name>` \
             (needs the namespace permission).",
        ),
        _ if reason == Some(reason::NAMESPACE_NOT_EMPTY) => Some(
            "nothing was deleted: a namespace goes only once it has no secret at all, deleted \
             ones included. Delete its secrets, wait out the server's retention \
             (purge_deleted_after_days), run `ferritor purge`, then delete it again.",
        ),
        _ if reason == Some(reason::POLICY_UNVERIFIED) => Some(
            "the stored policies don't verify: someone changed the keys database behind ferritor's \
             back, put an older set back, or cleared their key. Re-apply them from their source \
             of truth (`ferritor policy apply --prune -f <file>`), then find out who changed it. \
             For a rekey: repair them first, then rekey.",
        ),
        _ if reason == Some(reason::VERSION_MISMATCH) => Some(
            "someone else changed it since you read it: `ferritor get` it again, decide, and put \
             with the new --expected-version.",
        ),
        _ if reason == Some(reason::RATE_LIMITED) => Some(match server.limit.as_deref() {
            Some("in_flight") => {
                "nothing was done: this identity has as many calls running on this server as it \
                 may. Retry once some finish; if it needs more at once, its operator can raise \
                 its max_in_flight ([[rate_limit.identity]] in ferritor.toml)."
            }
            Some("denied") => {
                "nothing was done: this identity made too many requests its policies deny, so \
                 the server refuses all of its requests for a moment. Look for what is being \
                 denied (the server's audit log, `ferritor policy list`): usually a missing grant, \
                 retried."
            }
            _ => {
                "nothing was done: this identity is over its requests per second on this \
                 server. Retry at the time given, slower; if it needs more, its operator can \
                 raise its requests_per_second ([[rate_limit.identity]] in ferritor.toml)."
            }
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use ferritor_core::messages;

    use super::*;

    fn refused(code: Code, message: &str) -> anyhow::Error {
        ServerError {
            code,
            message: message.to_owned(),
            cause: None,
            reason: None,
            limit: None,
            retry_after: None,
        }
        .into()
    }

    /// Refused with an `ErrorInfo` reason, as the server sends them.
    fn refused_for(code: Code, reason: &str) -> anyhow::Error {
        ServerError {
            code,
            message: "whatever the server says".to_owned(),
            cause: None,
            reason: Some(reason.to_owned()),
            limit: None,
            retry_after: None,
        }
        .into()
    }

    fn verify() -> Command {
        Command::Rekey(Rekey::Verify {
            nonce: "n".to_owned(),
        })
    }

    /// An init whose reply was lost may have been stored without anyone
    /// getting the shares: the hint says how to tell, and how to recover.
    #[test]
    fn an_unclear_init_says_how_to_recover() {
        let init = Command::Init {
            shares: 5,
            threshold: 3,
        };
        for (code, message) in [
            (
                Code::Unavailable,
                "the keys database did not respond in time",
            ),
            (Code::Cancelled, "Timeout expired"),
            (Code::Unknown, "transport error"),
        ] {
            let hint = hint(&init, &refused(code, message)).unwrap_or_default();
            assert!(hint.contains("ferritor status"), "{code:?}: {hint}");
            assert!(hint.contains("never arrive"), "{code:?}: {hint}");
            // Before any destructive step: whose init it was, told by
            // identity and time, since a client-side timeout leaves the
            // server's own outcome `succeeded`.
            let audit = hint.find("audit log").unwrap_or(usize::MAX);
            assert!(
                audit < hint.find("empty the keys database").unwrap_or(0),
                "{hint}"
            );
            for needle in [
                "your identity at the time of your call",
                "(succeeded or unknown)",
                "another caller, they hold valid shares: change nothing",
            ] {
                assert!(hint.contains(needle), "{needle:?} missing: {hint}");
            }
        }
        // A clear refusal stored nothing: no recovery story.
        let invalid = refused(Code::InvalidArgument, "threshold must be between 2 and…");
        assert_eq!(hint(&init, &invalid), None);
    }

    #[test]
    fn an_unclear_verify_says_to_keep_both_sets_of_shares() {
        // Server-side unknown, our own timeout, a deadline, a dropped call.
        for (code, message) in [
            (
                Code::Unavailable,
                "could not confirm whether the new root key was stored",
            ),
            (Code::Cancelled, "Timeout expired"),
            (Code::DeadlineExceeded, "deadline exceeded"),
            (Code::Unknown, "transport error"),
        ] {
            let hint = hint(&verify(), &refused(code, message)).unwrap_or_default();
            assert!(hint.contains("Keep BOTH"), "{code:?}: {hint}");
            assert!(hint.contains("ferritor status"), "{code:?}: {hint}");
        }
    }

    /// Hints follow the server's reason, not its wording: the same text
    /// without the reason gets no sealed hint.
    #[test]
    fn hints_match_reasons_not_messages() {
        let get = Command::Get {
            path: "app/db".to_owned(),
            version: None,
        };
        let sealed = hint(&get, &refused_for(Code::FailedPrecondition, reason::SEALED));
        assert_eq!(
            sealed,
            Some("unseal it first: `ferritor unseal`, once per share.")
        );
        let just_text = refused(Code::FailedPrecondition, messages::SEALED);
        assert_eq!(hint(&get, &just_text), None);

        let unseal = Command::Unseal {
            reset: false,
            recommit: false,
            auto: false,
            release_hold: false,
        };
        let uncommitted = hint(
            &unseal,
            &refused_for(Code::FailedPrecondition, reason::ROOT_UNCOMMITTED),
        )
        .unwrap_or_default();
        assert!(uncommitted.contains("--recommit"), "{uncommitted}");

        let put = Command::Put {
            path: "app/db".to_owned(),
            allow_empty: false,
            expected_version: Some(1),
            labels: Vec::new(),
        };
        let mismatch = hint(
            &put,
            &refused_for(Code::FailedPrecondition, reason::VERSION_MISMATCH),
        )
        .unwrap_or_default();
        assert!(mismatch.contains("ferritor get"), "{mismatch}");
    }

    /// A rate-limited request was refused outright, and the hint names what
    /// to do about the limit that refused it; the message says when.
    #[test]
    fn a_rate_limit_says_which_and_when() {
        let put = Command::Put {
            path: "app/db".to_owned(),
            allow_empty: false,
            expected_version: None,
            labels: Vec::new(),
        };
        let limited = |limit: &str| ServerError {
            code: Code::ResourceExhausted,
            message: "rate limited".to_owned(),
            cause: None,
            reason: Some(reason::RATE_LIMITED.to_owned()),
            limit: Some(limit.to_owned()),
            retry_after: Some(Duration::from_millis(4100)),
        };
        for (limit, says) in [
            ("rate", "requests_per_second"),
            ("in_flight", "max_in_flight"),
            ("denied", "missing grant"),
        ] {
            let error = limited(limit);
            assert_eq!(error.to_string(), "rate limited (in 5 s)");
            let hint = hint(&put, &error.into()).unwrap_or_default();
            assert!(hint.starts_with("nothing was done"), "{hint}");
            assert!(hint.contains(says), "{limit}: {hint}");
        }
    }

    /// An unaudited request was refused outright: not "may or may not".
    #[test]
    fn an_unaudited_request_says_nothing_was_done() {
        let unaudited = refused_for(Code::Unavailable, reason::UNAUDITED);
        for command in [
            verify(),
            Command::Put {
                path: "a".to_owned(),
                allow_empty: false,
                expected_version: None,
                labels: Vec::new(),
            },
            Command::Status,
        ] {
            let hint = hint(&command, &unaudited).unwrap_or_default();
            assert!(hint.starts_with("nothing was done"), "{hint}");
        }
    }

    #[test]
    fn a_clear_verify_failure_gets_no_rekey_hint() {
        let wrong = refused(
            Code::PermissionDenied,
            "the submitted shares do not reconstruct",
        );
        assert_eq!(hint(&verify(), &wrong), None);
    }

    /// Retrying an unclear restore is safe with a version or without (a
    /// retry after one that landed is refused either way); refused for a
    /// live version, the hint says to name one.
    #[test]
    fn an_unclear_restore_is_safe_to_retry() {
        let restore = |version| Command::Restore {
            path: "app/db".to_owned(),
            version,
        };
        let lost = refused(Code::Cancelled, "Timeout expired");
        let named = hint(&restore(Some(2)), &lost).unwrap_or_default();
        assert!(named.contains("Retrying is safe"), "{named}");
        let newest = hint(&restore(None), &lost).unwrap_or_default();
        assert!(newest.contains("Retrying is safe"), "{newest}");
        let live = hint(
            &restore(None),
            &refused_for(Code::FailedPrecondition, reason::LIVE_VERSION),
        )
        .unwrap_or_default();
        assert!(live.contains("--version N"), "{live}");
    }

    /// With a check-and-set, retrying an unclear put can't store twice: the
    /// hint says so instead of warning about an extra version.
    #[test]
    fn an_unclear_check_and_set_put_is_safe_to_retry() {
        let put = |expected_version| Command::Put {
            path: "app/db".to_owned(),
            allow_empty: false,
            expected_version,
            labels: Vec::new(),
        };
        let lost = refused(Code::Cancelled, "Timeout expired");
        let checked = hint(&put(Some(3)), &lost).unwrap_or_default();
        assert!(
            checked.contains("same --expected-version is safe"),
            "{checked}"
        );
        let plain = hint(&put(None), &lost).unwrap_or_default();
        assert!(plain.contains("extra version"), "{plain}");
    }

    /// UNAVAILABLE, our own timeout (CANCELLED), a deadline and a dropped
    /// call all leave a write's outcome equally unknown.
    #[test]
    fn every_unclear_outcome_on_a_write_gets_its_hint() {
        let put = Command::Put {
            path: "app/db".to_owned(),
            allow_empty: false,
            expected_version: None,
            labels: Vec::new(),
        };
        let delete = Command::Delete {
            path: "app/db".to_owned(),
        };
        for code in [
            Code::Unavailable,
            Code::Cancelled,
            Code::DeadlineExceeded,
            Code::Unknown,
        ] {
            let error = refused(code, "whatever");
            let put_hint = hint(&put, &error).unwrap_or_default();
            assert!(put_hint.contains("extra version"), "{code:?}: {put_hint}");
            let delete_hint = hint(&delete, &error).unwrap_or_default();
            assert!(delete_hint.contains("not found"), "{code:?}: {delete_hint}");
        }
    }

    #[test]
    fn a_seal_cut_off_mid_call_may_have_sealed() {
        for code in [
            Code::Unavailable,
            Code::Cancelled,
            Code::DeadlineExceeded,
            Code::Unknown,
        ] {
            let hint = hint(&Command::Seal, &refused(code, "Timeout expired")).unwrap_or_default();
            assert!(hint.contains("may already be sealed"), "{code:?}: {hint}");
            assert!(hint.contains("safe to repeat"), "{code:?}: {hint}");
        }
    }

    #[test]
    fn an_empty_message_falls_back_to_the_code() {
        for message in ["", "  "] {
            assert_eq!(
                refused(Code::Internal, message).to_string(),
                "Internal error (gRPC Internal)"
            );
        }
        assert_eq!(
            refused(Code::NotFound, "secret `x` not found").to_string(),
            "secret `x` not found"
        );
    }

    fn status_with(
        generation: u32,
        phase: pb::RekeyPhase,
        rekey_generation: u32,
    ) -> pb::SealStatus {
        pb::SealStatus {
            initialized: true,
            generation,
            rekey: Some(pb::RekeyProgress {
                nonce: "n".to_owned(),
                phase: phase.into(),
                generation: rekey_generation,
                ..pb::RekeyProgress::default()
            }),
            ..pb::SealStatus::default()
        }
    }

    #[test]
    fn rekey_guidance_follows_the_phase() {
        let authorizing = status_with(1, pb::RekeyPhase::Authorizing, 0);
        assert!(rekey_guidance(&authorizing).is_some_and(|g| g.contains("rekey submit")));
        let verifying = status_with(1, pb::RekeyPhase::Verifying, 2);
        assert!(rekey_guidance(&verifying).is_some_and(|g| g.contains("rekey verify")));
        assert_eq!(rekey_guidance(&pb::SealStatus::default()), None);
    }

    /// Verifying, but the stored generation is already the new one: the
    /// commit landed unconfirmed. Say so, not just "continue verifying".
    #[test]
    fn an_unconfirmed_commit_that_landed_is_recognised() {
        let landed = status_with(2, pb::RekeyPhase::Verifying, 2);
        let guidance = rekey_guidance(&landed).unwrap_or_default();
        assert!(
            guidance.contains("already stored (generation 2)"),
            "{guidance}"
        );
        assert!(guidance.contains("rekey verify --nonce n"), "{guidance}");
    }

    #[test]
    fn a_hidden_nonce_says_who_can_act() {
        let mut hidden = status_with(1, pb::RekeyPhase::Verifying, 2);
        if let Some(rekey) = hidden.rekey.as_mut() {
            rekey.nonce.clear();
        }
        let guidance = rekey_guidance(&hidden).unwrap_or_default();
        assert!(guidance.contains("allowed to rekey"), "{guidance}");
        assert!(!guidance.contains("--nonce"), "{guidance}");
    }

    #[test]
    fn a_refused_seal_says_it_did_not_seal() {
        let hint = hint(
            &Command::Seal,
            &refused(Code::PermissionDenied, "permission denied: …"),
        )
        .unwrap_or_default();
        assert!(hint.contains("did NOT seal"), "{hint}");
    }

    #[test]
    fn an_unexpected_phase_is_shown_not_mapped_to_submit() {
        let odd = status_with(1, pb::RekeyPhase::Complete, 2);
        let guidance = rekey_guidance(&odd).unwrap_or_default();
        assert!(guidance.contains("REKEY_PHASE_COMPLETE"), "{guidance}");
        assert!(!guidance.contains("rekey submit"), "{guidance}");
    }

    #[test]
    fn other_timeouts_just_say_retry() {
        let hint = hint(
            &Command::Status,
            &refused(Code::Cancelled, "Timeout expired"),
        );
        assert_eq!(
            hint,
            Some("the request timed out before the server answered; retry.")
        );
    }
}
