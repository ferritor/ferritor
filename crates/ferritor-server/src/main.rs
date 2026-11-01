use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use ferritor_core::audit_chain;
use ferritor_core::proto::v1::system_service_server::SystemServiceServer;
use ferritor_datastore::Datastore;
use ferritor_keystore::Keystore;
use ferritor_server::audit::{AuditLog, Drain, Gate, PolicyReload};
use ferritor_server::authz::StoredPolicies;
use ferritor_server::config::{CertificatePem, ReloadError, ReloadedPolicy, Settings};
use ferritor_server::crl::StaleWatch;
use ferritor_server::destroy::Destroy;
use ferritor_server::health::Readiness;
use ferritor_server::identity::exchange::{self, Exchange};
use ferritor_server::namespaces::Namespaces;
use ferritor_server::policies::Policies;
use ferritor_server::purge::Purge;
use ferritor_server::rewrap::Rewrap;
use ferritor_server::seal::{Seal, SealError};
use ferritor_server::secrets::Secrets;
use ferritor_server::tls;
use ferritor_server::tls::ServerTls;
use ferritor_server::watch::Watch;
use ferritor_server::{error_chain, grpc, http, keyring, metrics};
use secrecy::{ExposeSecret, SecretString};
use sqlx::migrate::Migrator;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Connection, PgConnection, PgPool};
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tonic::service::Routes;
use tracing_subscriber::EnvFilter;

/// The ferritor server: gRPC and the JSON API on one port, the audit log on
/// stdout, logs on stderr. Configured by `ferritor.toml` in the working
/// directory and `FERRITOR_*` environment variables
/// (https://ferritor.dev/reference/configuration), never by arguments.
#[derive(Parser)]
#[command(version)]
struct Args {}

// The images' static builds link musl, whose allocator made reads 2.8 times
// slower than glibc's (docs/src/content/docs/operations/performance.md).
#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// A pool whose connections give up on their own: acquiring one is bounded,
/// and `statement_timeout` makes Postgres abandon a statement the client has
/// stopped waiting for. (The stores also bound every call client side, which
/// covers what Postgres can't see, like a network partition.)
async fn connect(
    url: &SecretString,
    timeout: Duration,
    max_connections: u32,
) -> anyhow::Result<PgPool> {
    let options = url.expose_secret().parse::<PgConnectOptions>()?.options([
        ("statement_timeout", timeout.as_millis()),
        // Safety net: a transaction left idle (say, a staged put held
        // across an unrelated await by future code) is rolled back.
        ("idle_in_transaction_session_timeout", timeout.as_millis()),
    ]);
    Ok(PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(timeout)
        .connect_with(options)
        .await?)
}

/// Generous: only reaching the database is bounded, not the migration.
const MIGRATION_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Runs migrations over a one-off connection without `statement_timeout`:
/// a large migration may legitimately take longer than any query should. Only
/// connecting is bounded, so an unreachable host fails startup instead of
/// hanging until the OS gives up on the TCP connect.
async fn migrate(url: &SecretString, migrator: &Migrator) -> anyhow::Result<()> {
    let mut connection = tokio::time::timeout(
        MIGRATION_CONNECT_TIMEOUT,
        PgConnection::connect(url.expose_secret()),
    )
    .await
    .context("timed out connecting")??;
    migrator.run(&mut connection).await?;
    connection.close().await?;
    Ok(())
}

/// Watches for SIGINT (Ctrl-C) and SIGTERM (how systemd, Docker and
/// Kubernetes stop a process) from the start, so a failure to install the
/// handlers stops startup rather than leaving a server that can't be
/// stopped gracefully. Catching them replaces the default "exit at once",
/// so this task must provide every way out:
///
/// - Before `serving` is set (migrating, connecting: possibly a 30 s wait
///   on an unreachable database), a signal exits at once: nothing is in
///   flight.
/// - While serving, the first signal starts a graceful drain (the returned
///   receiver resolves), because a call cut off midway is exactly when an
///   outcome becomes unclear to its caller (a put, or a rekey verify that
///   commits unseen). The drain is bounded by [`DRAIN_LIMIT`].
/// - A second signal exits almost at once, whatever is still running: it
///   only waits (at most [`SECOND_SIGNAL_FLUSH`]) for the audit log to
///   write what's queued, set in `audit` once the log exists. "Seal, then
///   stop" is exactly when a seal's entry may still be queued.
fn watch_signals(
    serving: Arc<AtomicBool>,
    audit: Arc<OnceLock<Drain>>,
) -> anyhow::Result<oneshot::Receiver<&'static str>> {
    let mut interrupt = signal(SignalKind::interrupt()).context("installing the SIGINT handler")?;
    let mut terminate =
        signal(SignalKind::terminate()).context("installing the SIGTERM handler")?;
    let (first, received) = oneshot::channel();
    tokio::spawn(async move {
        // 128 + the signal number, as if it had killed the process.
        let mut next = async || -> (&'static str, i32) {
            tokio::select! {
                _ = interrupt.recv() => ("SIGINT", 130),
                _ = terminate.recv() => ("SIGTERM", 143),
            }
        };
        let (signal, code) = next().await;
        if !serving.load(Ordering::SeqCst) {
            tracing::info!(signal, "stopped during startup");
            std::process::exit(code);
        }
        first.send(signal).ok();
        let (signal, code) = next().await;
        tracing::warn!(
            signal,
            "second signal: exiting now, without waiting for in-flight calls"
        );
        if let Some(drain) = audit.get()
            && !drain.clone().wait(SECOND_SIGNAL_FLUSH).await
        {
            tracing::error!("AUDIT LOG NOT FLUSHED before exiting: queued entries may be lost");
        }
        std::process::exit(code);
    });
    Ok(received)
}

/// How long a graceful shutdown waits for in-flight calls (the connections,
/// then the calls whose client left: `tls::Detach`): a client that stalls
/// mid-request (headers never finished) would otherwise hold the drain open
/// forever. After it, `main` stops waiting, but doesn't stop them: each
/// connection and each call runs in its own task, which ends only when the
/// process exits, after the audit drain. So an abandoned call can
/// still finish meanwhile (a put included), and its audit entry can land
/// after the drain's marker and be lost. A small window, and logged. With
/// the audit drain, well inside the 30 s Kubernetes allows before SIGKILL
/// (with `shutdown_delay_secs` on top: see [`KUBERNETES_GRACE`]).
const DRAIN_LIMIT: Duration = Duration::from_secs(15);

/// Kubernetes' default `terminationGracePeriodSeconds`: the time from
/// SIGTERM to SIGKILL. Startup warns if the shutdown delay, the drain and
/// the audit drain could together take longer.
const KUBERNETES_GRACE: Duration = Duration::from_secs(30);

/// How long shutdown waits for the last metrics export.
const METRICS_FLUSH_LIMIT: Duration = Duration::from_secs(3);

/// How long a second signal waits for the audit log before exiting.
const SECOND_SIGNAL_FLUSH: Duration = Duration::from_secs(1);

/// On every SIGHUP, re-reads the settings and reloads what can change
/// while serving: the `[[policy]]` (swapped into the gate) and, in secured
/// mode, the server certificate and key (new handshakes present them), so
/// renewing a short-lived certificate needs no restart, and the CRLs (for
/// every request from now on, open connections too). Everything else
/// takes effect on restart. Whatever fails to reload keeps running as it
/// was, and says so loudly; every attempt is audited, with fingerprints.
async fn reload_on_hangup(
    mut hangup: Signal,
    tls: Option<ServerTls>,
    seal: Arc<Seal>,
    gate: Arc<Gate>,
    exchange: Option<Arc<Exchange>>,
) {
    while hangup.recv().await.is_some() {
        // The keyring too: independent of the settings file. In its own
        // task, so the policy reload (how access is revoked in a hurry)
        // doesn't wait behind the admin lock or a slow keys database.
        tokio::spawn({
            let (seal, gate) = (Arc::clone(&seal), Arc::clone(&gate));
            async move {
                keyring::refresh(&seal, &gate, "sighup", None, true)
                    .await
                    .ok();
                refresh_policies(&seal, &gate, "sighup", true).await;
            }
        });
        let settings = match Settings::load() {
            Ok(settings) => settings,
            Err(e) => {
                let error = error_chain(&ReloadError::Load(e));
                tracing::error!(%error, "NOTHING RELOADED: still running as before");
                gate.reload_policy(PolicyReload::Failed(error.clone()));
                if tls.is_some() {
                    gate.certificate_reloaded(Err(error.clone()));
                    gate.revocation_reloaded(Err(error));
                }
                continue;
            }
        };
        match settings.limits() {
            Ok(limits) => {
                tracing::info!("reloaded the rate limits");
                gate.reload_limits(limits);
            }
            Err(error) => {
                tracing::error!(%error, "RATE LIMITS NOT RELOADED: still running the previous ones");
            }
        }
        match settings.authz_for_reload(tls.is_some()) {
            Ok(Some(ReloadedPolicy { authz, info })) => {
                tracing::info!(
                    rules = info.rules,
                    fingerprint = info.fingerprint,
                    "reloaded the [[policy]] (settings other than it, the server certificate \
                     and the CRLs take effect on restart)"
                );
                gate.reload_policy(PolicyReload::Reloaded(authz, info));
            }
            Ok(None) => {
                tracing::info!("SIGHUP in dev mode: no policy to reload");
                gate.reload_policy(PolicyReload::Skipped("dev mode: no policy"));
            }
            Err(e) => {
                let error = error_chain(&e);
                tracing::error!(%error, "POLICY NOT RELOADED: still running the previous one");
                gate.reload_policy(PolicyReload::Failed(error));
            }
        }
        let Some(tls) = &tls else { continue };
        let reloaded = match settings.certificate() {
            Ok(Some(CertificatePem { cert, key })) => tls
                .reload_certificate(&cert, &key)
                .map_err(|e| error_chain(&e)),
            Ok(None) => {
                Err("the settings no longer have [tls]: changing modes needs a restart".to_owned())
            }
            Err(e) => Err(error_chain(&e)),
        };
        match &reloaded {
            Ok(fingerprint) => {
                tracing::info!(fingerprint, "reloaded the server certificate");
            }
            Err(error) => {
                tracing::error!(%error, "CERTIFICATE NOT RELOADED: still presenting the previous one");
            }
        }
        gate.certificate_reloaded(reloaded);
        let reloaded = match &settings.tls {
            Some(tls_settings) => tls_settings
                .crl_pem()
                .map_err(|e| error_chain(&e))
                .and_then(|pem| tls.reload_crl(pem.as_deref()).map_err(|e| error_chain(&e))),
            None => {
                Err("the settings no longer have [tls]: changing modes needs a restart".to_owned())
            }
        };
        match &reloaded {
            Ok(Some(crls)) => tracing::info!(
                crls = crls.len(),
                revoked = crls.iter().map(|crl| crl.revoked).sum::<usize>(),
                "reloaded the CRLs"
            ),
            Ok(None) => tracing::info!("reloaded: no CRL file, no client certificate revoked"),
            Err(error) => {
                tracing::error!(%error, "CRL NOT RELOADED: still checking against the previous one");
            }
        }
        gate.revocation_reloaded(reloaded);
        reload_identity(&settings, &gate, exchange.as_deref()).await;
    }
}

/// The `[identity]` part of a SIGHUP: issuers, mappings, cutoffs and their
/// keys (see `Exchange::reload`). Its listener needs a restart, as does
/// adding the section to a server started without it.
async fn reload_identity(settings: &Settings, gate: &Gate, exchange: Option<&Exchange>) {
    let identity = match settings.identity() {
        Ok(identity) => identity,
        Err(error) => {
            tracing::error!(%error, "[identity] NOT RELOADED: still running the previous one");
            gate.identity_reloaded(Err(error));
            return;
        }
    };
    let Some(exchange) = exchange else {
        if identity.is_some() {
            tracing::warn!("[identity] was added: it takes effect on restart");
            gate.identity_reloaded(Ok(Err("[identity] was added: it takes effect on restart")));
        }
        return;
    };
    match exchange.reload(identity.clone()).await {
        Ok(()) => {
            if identity.is_none() {
                tracing::warn!(
                    "[identity] was removed: nothing is exchanged, and no certificate it issued \
                     is accepted any more (its listener stays open until restart)"
                );
            } else {
                tracing::info!("reloaded [identity] and its issuers' keys");
            }
            gate.identity_reloaded(Ok(Ok(identity.as_ref())));
        }
        Err(error) => {
            tracing::error!(%error, "[identity] NOT RELOADED: still running the previous one");
            gate.identity_reloaded(Err(error));
        }
    }
}

/// Fetches the URL issuers' keys again every [`exchange::REFRESH`].
async fn refresh_issuer_keys_periodically(exchange: Arc<Exchange>) {
    let mut ticks = tokio::time::interval(exchange::REFRESH);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick is immediate; the keys were just loaded.
    ticks.tick().await;
    loop {
        ticks.tick().await;
        exchange.refresh().await;
    }
}

/// How often the CRLs in force are checked for going stale.
const CRL_STALE_CHECK: Duration = Duration::from_secs(60);

/// Warns once when a CRL in force passes its `nextUpdate` while serving
/// (one already stale at load was warned about then): it's still used, but
/// may be missing revocations. Checked every [`CRL_STALE_CHECK`].
async fn warn_when_crls_go_stale(tls: ServerTls) {
    let mut ticks = tokio::time::interval(CRL_STALE_CHECK);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut watch = StaleWatch::default();
    loop {
        ticks.tick().await;
        let crls = tls.crls().unwrap_or_default();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        for stale in watch.check(&crls, now) {
            tracing::warn!(
                issuer = stale.issuer,
                next_update = stale.next_update,
                "a CRL in force went past its nextUpdate: still used, but it may be missing \
                 revocations (renew it and send SIGHUP)"
            );
        }
    }
}

/// Refreshes the keyring every `every` while unsealed (see
/// `ferritor_server::keyring`), so a rotation by another server is picked up
/// even by a server that only writes (it would otherwise keep wrapping new
/// DEKs with its old active KEK). A run of failures (a rekey elsewhere, say)
/// is audited once, at its start; each is logged.
/// The auto-unseal provider `config` names, in a build that has it.
#[cfg(feature = "aws-kms")]
async fn auto_unseal_provider(
    config: &ferritor_server::auto_unseal::AwsKmsConfig,
) -> anyhow::Result<Arc<dyn ferritor_server::auto_unseal::AutoUnseal>> {
    Ok(Arc::new(
        ferritor_server::aws_kms::AwsKms::new(config).await,
    ))
}

#[cfg(not(feature = "aws-kms"))]
async fn auto_unseal_provider(
    _: &ferritor_server::auto_unseal::AwsKmsConfig,
) -> anyhow::Result<Arc<dyn ferritor_server::auto_unseal::AutoUnseal>> {
    anyhow::bail!(
        "seal.provider = \"awskms\", but this build has no AWS KMS support (built without \
         the `aws-kms` feature)"
    )
}

async fn refresh_keyring_periodically(seal: Arc<Seal>, gate: Arc<Gate>, every: Duration) {
    let mut ticks = tokio::time::interval(every);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick is immediate; the keyring was just loaded (or isn't).
    ticks.tick().await;
    let mut failing = false;
    loop {
        ticks.tick().await;
        match keyring::refresh(&seal, &gate, "periodic", None, !failing).await {
            Ok(_) => failing = false,
            Err(SealError::Sealed) => {}
            Err(_) => failing = true,
        }
    }
}

/// How often the whole stored set is re-read and re-verified even if its
/// revision didn't change, so a row edited behind the server's back is
/// caught within this, independent of the revision poll and the keyring
/// refresh (either may be turned off).
const POLICY_REVERIFY: Duration = Duration::from_secs(60);

async fn reverify_policies_periodically(seal: Arc<Seal>, gate: Arc<Gate>) {
    let mut ticks = tokio::time::interval(POLICY_REVERIFY);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick is immediate; the set was just loaded (or isn't).
    ticks.tick().await;
    loop {
        ticks.tick().await;
        refresh_policies(&seal, &gate, "periodic", true).await;
    }
}

/// Ends rate-limit episodes that went quiet, reporting them, and forgets
/// idle callers (see `ratelimit`).
async fn end_quiet_limits(gate: Arc<Gate>) {
    let mut ticks = tokio::time::interval(Duration::from_secs(2));
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticks.tick().await;
        gate.end_quiet_limits(std::time::Instant::now());
    }
}

/// Polls the stored policies' revision, reloading them on a change: the
/// longest a change through another server takes to reach this one.
async fn poll_policies(seal: Arc<Seal>, gate: Arc<Gate>, every: Duration) {
    let mut ticks = tokio::time::interval(every);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticks.tick().await;
        refresh_policies(&seal, &gate, "poll", false).await;
    }
}

/// Reloads the stored policies (see `Seal::refresh_policies`) and records
/// what happened.
async fn refresh_policies(seal: &Seal, gate: &Gate, trigger: &'static str, full: bool) {
    match seal.refresh_policies(full).await {
        Ok(refresh) => gate.stored_policies_reloaded(trigger, &refresh),
        Err(e) => {
            // The keys database didn't answer: the set in force stays.
            tracing::warn!(trigger, error = %error_chain(&e), "couldn't check the stored policies");
            metrics::metrics().reload("policy_store", "failed");
        }
    }
}

/// How long a request waits for its audit entry to be written before it's
/// refused as unaudited. Writing a line takes microseconds; this only fires
/// when stdout is stalled.
const AUDIT_TIMEOUT: Duration = Duration::from_secs(2);

/// How long shutdown waits for the audit writer to finish its queue.
const AUDIT_DRAIN_LIMIT: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // First of all, before anything secret is read (the `.env` below may
    // hold database passwords): no core dumps, no same-user ptrace or
    // /proc/<pid>/mem. The environment is in memory from the start, so this
    // covers it too.
    ferritor_server::forbid_memory_access()
        .context("making the process undumpable (PR_SET_DUMPABLE)")?;
    // Before anything else is read: `--version` and `--help` print and exit
    // (to stdout, which carries the audit log only once the server runs),
    // and any other argument is refused, never silently ignored.
    Args::parse();
    // Development convenience: the workspace `.env`, if any, in debug builds
    // only. dotenvy searches the working directory and every parent, so a
    // release build run from /srv/ferritor would otherwise quietly load
    // /srv/.env, another application's, and any FERRITOR_* lines in it.
    if cfg!(debug_assertions) {
        dotenvy::dotenv().ok();
    }
    // Stderr: stdout is the audit log, and carries nothing else.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        // No colour codes in a file or the journal.
        .with_ansi(std::io::stderr().is_terminal())
        .with_env_filter(
            // sqlx logs routine migration notices at INFO.
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn")),
        )
        .init();
    // Before anything records: instruments bind to the provider in place
    // when they're created.
    let meter_provider = metrics::init(metrics::Export::from_env()?)
        .context("starting the OTLP metrics exporter")?;
    if meter_provider.is_some() {
        tracing::info!("exporting metrics over OTLP (OTEL_EXPORTER_OTLP_* settings)");
    } else {
        tracing::info!("metrics off: no OTEL_EXPORTER_OTLP_ENDPOINT");
    }

    let serving = Arc::new(AtomicBool::new(false));
    let audit_for_signals = Arc::new(OnceLock::new());
    let first_signal = watch_signals(Arc::clone(&serving), Arc::clone(&audit_for_signals))?;
    // Installed now: SIGHUP's default action would end the process.
    let hangup = signal(SignalKind::hangup()).context("installing the SIGHUP handler")?;
    let settings = Settings::load().context("loading settings")?;
    let security = settings
        .security()
        .context("setting up TLS and the policy")?;
    let (database_timeout, lock_timeout) = (settings.database_timeout(), settings.lock_timeout());
    migrate(&settings.keys_database_url, &ferritor_keystore::MIGRATOR)
        .await
        .context("migrating the keys database")?;
    migrate(&settings.data_database_url, &ferritor_datastore::MIGRATOR)
        .await
        .context("migrating the data database")?;
    let keys_pool = connect(
        &settings.keys_database_url,
        database_timeout,
        settings.keys_database_max_connections,
    )
    .await
    .context("connecting to the keys database")?;
    let data_pool = connect(
        &settings.data_database_url,
        database_timeout,
        settings.data_database_max_connections,
    )
    .await
    .context("connecting to the data database")?;

    // The revision floors (stored policies, issuing keys) and the root
    // commitments live in the data database, out of a keys-database
    // writer's reach (see `policy_store::RevisionFloor`, `root_ledger`).
    let floors = Datastore::new(data_pool.clone()).with_timeout(database_timeout);
    let seal = Seal::new(Keystore::new(keys_pool).with_timeout(database_timeout))
        .with_commit_check_timeout(lock_timeout)
        .with_revision_floor(Arc::new(floors.clone()))
        .with_root_ledger(Arc::new(floors));
    // Auto-unseal ([seal]): the provider's client now; its first call when
    // the loop below starts.
    let seal = Arc::new(match settings.auto_unseal().map_err(anyhow::Error::msg)? {
        Some(config) => {
            tracing::info!(
                provider = "awskms",
                region = config.region,
                "auto-unseal: the server unseals itself at start (the shares stay the recovery \
                 path)"
            );
            seal.with_auto_unseal(auto_unseal_provider(&config).await?)
        }
        None => seal,
    });
    // The policy (secured mode) or allow-everything (dev mode, loopback
    // only), each decision recorded in the audit log.
    match &security.audit_key {
        Some(key) => tracing::info!(
            key = audit_chain::key_fingerprint(&key.verifying_key()),
            "audit log checkpoints signed (verify with `ferritor audit verify --public-key`)"
        ),
        None => tracing::warn!(
            "dev mode without audit_signing_key: the audit log is chained but unsigned, so edits \
             to it can't be proven"
        ),
    }
    let (audit, audit_drain) = AuditLog::stdout(AUDIT_TIMEOUT, security.audit_key.clone())
        .context("starting the audit log")?;
    audit_for_signals.set(audit_drain.clone()).ok();
    let gate = Arc::new(Gate::new(security.authz, audit));
    gate.policy_loaded(security.policy.as_ref());
    // Workload identity (secured mode only, checked when the settings
    // loaded): the exchange, and the TLS layer's trust in what it issues.
    let identity = settings.identity().map_err(anyhow::Error::msg)?;
    let exchange = match identity {
        Some(identity) => {
            let addr = identity.listen_addr;
            let exchange = Exchange::new(Arc::clone(&seal), Arc::clone(&gate), identity)
                .await
                .map_err(anyhow::Error::msg)
                .context("loading [identity]")?;
            Some((addr, Arc::new(exchange)))
        }
        None => None,
    };
    // Rate limits (see `ratelimit`), checked when the settings loaded.
    let limits = settings.limits().map_err(anyhow::Error::msg)?;
    tracing::info!(
        server_max_in_flight = limits.server_max_in_flight.get(),
        "rate limits in force (reloaded on SIGHUP; the server-wide cap at restart)"
    );
    gate.use_limits(limits, database_timeout);
    tokio::spawn(end_quiet_limits(Arc::clone(&gate)));
    let _gauges = metrics::observe(Arc::clone(&seal), security.tls.clone(), Arc::clone(&gate));
    if let Some(tls) = &security.tls {
        gate.certificate_loaded(&tls.certificate_fingerprint());
        let crls = tls.crls();
        match &crls {
            Some(crls) => tracing::info!(
                crls = crls.len(),
                revoked = crls.iter().map(|crl| crl.revoked).sum::<usize>(),
                "client certificates checked against CRLs (reloaded on SIGHUP)"
            ),
            None => tracing::info!(
                "no [tls] crl: client certificates can't be revoked, only expire (keep them short-lived)"
            ),
        }
        gate.revocation_loaded(crls);
    }
    if let Some(tls) = &security.tls {
        tokio::spawn(warn_when_crls_go_stale(tls.clone()));
    }
    // The exchange's own listener: TLS, no client certificate (the token is
    // the credential), the same server certificate.
    let exchange_serving = match (&exchange, &security.tls) {
        (Some((addr, exchange)), Some(tls)) => {
            tls.use_workload_trust(exchange.trust());
            tokio::spawn(refresh_issuer_keys_periodically(Arc::clone(exchange)));
            let listener = TcpListener::bind(addr)
                .await
                .with_context(|| format!("listening on {addr} ([identity] listen_addr)"))?;
            let tls = tls
                .without_client_auth()
                .context("setting up the [identity] listener's TLS")?;
            tracing::info!(%addr, "serving the workload token exchange");
            Some((
                listener,
                tls,
                Routes::new(grpc::identity_service(Arc::clone(exchange))),
            ))
        }
        _ => None,
    };
    tokio::spawn(reload_on_hangup(
        hangup,
        security.tls.clone(),
        Arc::clone(&seal),
        Arc::clone(&gate),
        exchange.as_ref().map(|(_, exchange)| Arc::clone(exchange)),
    ));
    if settings.keyring_refresh_secs > 0 {
        tokio::spawn(refresh_keyring_periodically(
            Arc::clone(&seal),
            Arc::clone(&gate),
            Duration::from_secs(settings.keyring_refresh_secs),
        ));
    }
    let datastore = Datastore::new(data_pool)
        .with_timeout(database_timeout)
        .with_lock_timeout(lock_timeout)
        .with_max_versions(settings.max_versions);
    let rewrap = Arc::new(Rewrap::new(Arc::clone(&seal), datastore.clone()));
    tracing::info!(
        max_versions = settings.max_versions,
        purge_deleted_after_days = settings.purge_deleted_after_days,
        "retention: live versions kept per secret (0: all), days a deleted version is kept"
    );
    if settings.purge_deleted_after_days == 0 {
        tracing::warn!(
            "purge_deleted_after_days is 0: every deleted secret version can be purged at once, \
             leaving no window to restore one"
        );
    }
    let purge = Arc::new(Purge::new(
        Arc::clone(&seal),
        datastore.clone(),
        settings.purge_retention(),
    ));
    let destroy = Arc::new(Destroy::new(Arc::clone(&seal), datastore.clone()));
    let namespaces = Arc::new(Namespaces::new(Arc::clone(&seal), datastore.clone()));
    // WatchSecrets' change feed (see `watch`).
    let watch = Watch::new();
    let _watch_gauges = metrics::observe_watch(Arc::clone(&watch));
    tokio::spawn(Arc::clone(&watch).run(datastore.clone()));
    let secrets = Arc::new(
        Secrets::new(Arc::clone(&seal), datastore.clone(), Arc::clone(&gate))
            .with_watch(Arc::clone(&watch)),
    );
    // The stored policies decide what the config rules don't (secret
    // actions only), once unsealed and verified.
    gate.use_stored_policies(Arc::clone(&seal) as Arc<dyn StoredPolicies>);
    // Unseals through the configured service whenever sealed, unless held.
    tokio::spawn(ferritor_server::auto_unseal::keep_unsealed(
        Arc::clone(&seal),
        Arc::clone(&gate),
        datastore.clone(),
    ));
    let policies = Arc::new(Policies::new(Arc::clone(&seal), Arc::clone(&gate)));
    tokio::spawn(reverify_policies_periodically(
        Arc::clone(&seal),
        Arc::clone(&gate),
    ));
    if settings.policy_refresh_secs > 0 {
        tokio::spawn(poll_policies(
            Arc::clone(&seal),
            Arc::clone(&gate),
            Duration::from_secs(settings.policy_refresh_secs),
        ));
    }
    if security.tls.is_none()
        && let Ok(stored) = seal.keystore().policy_snapshot().await
        && !stored.policies.is_empty()
    {
        tracing::warn!(
            count = stored.policies.len(),
            "stored policies exist, but dev mode doesn't enforce them (everyone may do \
             everything); `ferritor policy check` evaluates them as secured mode would"
        );
    }

    let mode = if security.tls.is_some() {
        "TLS with client certificates and the [[policy]]"
    } else {
        "dev mode: plaintext, everyone allowed, loopback only"
    };
    let listener = TcpListener::bind(settings.listen_addr)
        .await
        .with_context(|| format!("listening on {}", settings.listen_addr))?;
    // One port: the JSON API's routes, plus gRPC's services.
    let readiness = Readiness::new(Arc::clone(&seal));
    let routes = Routes::from(http::router(
        Arc::clone(&secrets),
        Arc::clone(&readiness),
        Arc::clone(&policies),
    ))
    .add_service(readiness.grpc().await)
    .add_service(SystemServiceServer::new(grpc::System::new(
        seal, rewrap, purge, destroy, namespaces, datastore, gate,
    )))
    .add_service(grpc::secrets_service(secrets))
    .add_service(grpc::policy_service(policies));
    tracing::info!(addr = %settings.listen_addr, mode, "serving gRPC and the JSON API; sealed");
    let shutdown_delay = Duration::from_secs(settings.shutdown_delay_secs);
    if shutdown_delay + DRAIN_LIMIT + AUDIT_DRAIN_LIMIT > KUBERNETES_GRACE {
        tracing::warn!(
            shutdown_delay_secs = settings.shutdown_delay_secs,
            "the shutdown delay, the drain ({DRAIN_LIMIT:?}) and the audit drain \
             ({AUDIT_DRAIN_LIMIT:?}) can take longer than Kubernetes' default 30 s before \
             SIGKILL: raise terminationGracePeriodSeconds to match"
        );
    }
    let (draining, drain_started) = oneshot::channel::<()>();
    // Both listeners drain together.
    let drain = CancellationToken::new();
    let exchange_drain = drain.clone().cancelled_owned();
    let shutdown = async move {
        let Ok(signal) = first_signal.await else {
            // The watcher is gone (it only ever ends the process).
            return std::future::pending().await;
        };
        // First of all: the readiness check says NOT_SERVING (503). The
        // drain itself tells connected clients to stop (GOAWAY, closed
        // keep-alives) and accepts no new connection; the delay keeps
        // serving meanwhile, for load balancers still routing here.
        readiness.shutting_down();
        if !shutdown_delay.is_zero() {
            tracing::info!(
                signal,
                "shutting down: not ready any more; still serving for {shutdown_delay:?} so \
                 load balancers stop routing here, then draining (a second signal exits at \
                 once)"
            );
            tokio::time::sleep(shutdown_delay).await;
        }
        tracing::info!(
            signal,
            "shutting down: not ready any more, draining in-flight calls (at most \
             {DRAIN_LIMIT:?}; a second signal exits at once)"
        );
        draining.send(()).ok();
        drain.cancel();
        // Watch streams last as long as their clients: ended now, or they'd
        // hold the drain open to its limit.
        watch.close();
    };
    let deadline = async {
        if drain_started.await.is_ok() {
            tokio::time::sleep(DRAIN_LIMIT).await;
        } else {
            std::future::pending::<()>().await;
        }
    };
    serving.store(true, Ordering::SeqCst);
    let served = tls::serve(
        tls::server(security.max_connection_age, security.connection_age_grace),
        routes,
        listener,
        security.tls,
        shutdown,
    );
    let exchange_served = async {
        match exchange_serving {
            Some((listener, tls, routes)) => {
                tls::serve(
                    tls::server(security.max_connection_age, security.connection_age_grace),
                    routes,
                    listener,
                    Some(tls),
                    exchange_drain,
                )
                .await
            }
            None => Ok(()),
        }
    };
    tokio::select! {
        served = async { tokio::try_join!(served, exchange_served) } => {
            served.context("serving")?;
        }
        () = deadline => tracing::warn!(
            "calls still open after {DRAIN_LIMIT:?} (a client stalled mid-request?): no longer \
             waiting for them; they end when the process exits"
        ),
    }
    // Everything queued so far gets written (a last seal's entry may be in
    // it), even if a connection abandoned at the deadline still holds a gate.
    if !audit_drain.wait(AUDIT_DRAIN_LIMIT).await {
        tracing::error!(
            "AUDIT LOG NOT FLUSHED: the writer didn't finish within {AUDIT_DRAIN_LIMIT:?}; \
             queued entries (a seal's, possibly) are lost"
        );
    }
    if let Some(provider) = meter_provider {
        // Flushes the last export; blocking, so off the runtime's workers,
        // and bounded: a collector that doesn't answer mustn't hold the
        // exit for the exporter's own timeout (10 s by default).
        let flushed = tokio::time::timeout(
            METRICS_FLUSH_LIMIT,
            tokio::task::spawn_blocking(move || provider.shutdown()),
        )
        .await;
        match flushed {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(e))) => tracing::warn!(error = %e, "flushing metrics at shutdown failed"),
            Ok(Err(e)) => tracing::warn!(error = %e, "flushing metrics at shutdown failed"),
            Err(_) => tracing::warn!(
                "the metrics collector didn't answer within {METRICS_FLUSH_LIMIT:?}; the last \
                 export is lost"
            ),
        }
    }
    tracing::info!("shut down");
    Ok(())
}
