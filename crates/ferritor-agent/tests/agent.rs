//! The agent against a real server in process (TLS, client certificates,
//! an authorizer whose grants a test can change), polled with simulated
//! time: `poll(now)` decides by the `now` it's given, so minutes of rounds
//! take milliseconds.
//!
//! Unix only: the server, in process here, runs on Unix.
#![cfg(unix)]

use std::net::SocketAddr;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use ferritor_agent::agent::{Agent, Revoked, Round};
use ferritor_agent::config::Config;
use ferritor_core::crypto::ShareParams;
use ferritor_core::labels::Labels;
use ferritor_core::path::SecretPath;
use ferritor_datastore::Datastore;
use ferritor_keystore::Keystore;
use ferritor_server::audit::{AuditLog, Gate};
use ferritor_server::authz::{Action, Authorizer, Caller, Denied, Target};
use ferritor_server::health::Readiness;
use ferritor_server::identity::exchange::Exchange;
use ferritor_server::identity::mapping::{Mapping, Template};
use ferritor_server::identity::{
    DEFAULT_EXCHANGE_BURST, DEFAULT_MAX_TOKEN_AGE, Identity, Issuer, JwksSource,
};
use ferritor_server::namespaces::Namespaces;
use ferritor_server::ratelimit::{Limits, Quota};
use ferritor_server::seal::Seal;
use ferritor_server::secrets::Secrets;
use ferritor_server::watch::Watch;
use ferritor_server::{grpc, tls};
use ferritor_testkit::jwt::{AUDIENCE, ISS, TokenIssuer};
use ferritor_testkit::pki::{Ca, Pem};
use ferritor_testkit::{Captured, TestDatabase, TestResult};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tonic::service::Routes;

const AGENT: &str = "apps/agent";
const WRITER: &str = "ops/writer";
const INTERVAL: Duration = Duration::from_secs(60);

/// Grants: (identity, action, path prefix), changeable while serving.
#[derive(Default)]
struct Grants(Mutex<Vec<(String, Action, String)>>);

impl Grants {
    fn allow(&self, identity: &str, action: Action, prefix: &str) {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).push((
            identity.to_owned(),
            action,
            prefix.to_owned(),
        ));
    }

    fn revoke(&self, identity: &str, action: Action, prefix: &str) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|(i, a, p)| !(i == identity && *a == action && p == prefix));
    }
}

impl Authorizer for Grants {
    fn authorize(&self, caller: &Caller, action: Action, target: Target<'_>) -> Result<(), Denied> {
        let path = match target {
            Target::Path(path) | Target::Below(path) => Some(path),
            Target::All | Target::System => None,
        };
        let allowed = match (caller, path) {
            (Caller::Identity(identity), Some(path)) => self
                .0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .any(|(i, a, prefix)| {
                    i == identity.as_str()
                        && *a == action
                        && SecretPath::parse(prefix)
                            .is_ok_and(|prefix| *path == prefix || path.is_under(&prefix))
                }),
            _ => false,
        };
        if allowed {
            Ok(())
        } else {
            Err(Denied::new(caller, action, target))
        }
    }
}

struct Env {
    keys: TestDatabase,
    data: TestDatabase,
    seal: Arc<Seal>,
    shares: Vec<Vec<u8>>,
    secrets: Arc<Secrets>,
    gate: Arc<Gate>,
    grants: Arc<Grants>,
    audit: Captured,
    addr: SocketAddr,
    ca: Ca,
    dir: PathBuf,
    /// With workload identity: the token issuer and the exchange's address.
    identity: Option<(TokenIssuer, SocketAddr)>,
    serving: Vec<JoinHandle<()>>,
}

impl Env {
    async fn new() -> TestResult<Self> {
        Self::start(None).await
    }

    /// With `lifetime`: an issuing CA and the token exchange too, issuing
    /// certificates that live that long (the config's minimum doesn't
    /// apply: `Identity` is built here).
    async fn start(lifetime: Option<Duration>) -> TestResult<Self> {
        let keys = TestDatabase::new(
            "KEYS_DATABASE_URL",
            "ferritor_agent_test",
            &ferritor_keystore::MIGRATOR,
        )
        .await?;
        let data = TestDatabase::new(
            "DATA_DATABASE_URL",
            "ferritor_agent_test",
            &ferritor_datastore::MIGRATOR,
        )
        .await?;
        let seal = Arc::new(Seal::new(Keystore::new(keys.pool().clone())));
        let shares: Vec<Vec<u8>> = seal
            .init(ShareParams::new(3, 2)?)
            .await?
            .iter()
            .map(|share| share.to_bytes().to_vec())
            .collect();
        for share in &shares[..2] {
            seal.unseal(share, false).await?;
        }
        let namespaces = Namespaces::new(Arc::clone(&seal), Datastore::new(data.pool().clone()));
        namespaces.create("billing", &Labels::new()).await?;
        let grants = Arc::new(Grants::default());
        grants.allow(WRITER, Action::Write, "billing");
        grants.allow(WRITER, Action::Delete, "billing");
        let audit = Captured::default();
        let gate = Arc::new(Gate::new(
            Arc::clone(&grants) as Arc<dyn Authorizer>,
            AuditLog::new(audit.clone(), Duration::from_secs(5))?,
        ));
        let watch = Watch::new();
        let feed = tokio::spawn(Arc::clone(&watch).run(Datastore::new(data.pool().clone())));
        let secrets = Arc::new(
            Secrets::new(
                Arc::clone(&seal),
                Datastore::new(data.pool().clone()),
                Arc::clone(&gate),
            )
            .with_watch(Arc::clone(&watch)),
        );
        let ca = Ca::new()?;
        let pem = ca.server()?;
        let tls_config = tls::server_tls(
            pem.cert.as_bytes(),
            pem.key.as_bytes(),
            ca.cert.as_bytes(),
            None,
        )?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ferritor-agent-e2e-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("ca.pem"), &ca.cert)?;
        let age = Duration::from_secs(600);
        let mut serving = vec![feed];
        let mut identity = None;
        if let Some(lifetime) = lifetime {
            seal.identity_init().await?;
            let issuer = TokenIssuer::new(&dir)?;
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let exchange_addr = listener.local_addr()?;
            let exchange = Arc::new(
                Exchange::new(
                    Arc::clone(&seal),
                    Arc::clone(&gate),
                    Identity {
                        listen_addr: exchange_addr,
                        lifetime,
                        issuers: vec![Issuer {
                            name: "ci".to_owned(),
                            iss: ISS.to_owned(),
                            audience: AUDIENCE.to_owned(),
                            max_token_age: DEFAULT_MAX_TOKEN_AGE,
                            exchange_burst: DEFAULT_EXCHANGE_BURST,
                            jwks: JwksSource::File(issuer.jwks.clone()),
                            mappings: vec![Mapping {
                                template: Template::parse("ci/{repository_owner}/agent", "ci")?,
                                require: Vec::new(),
                            }],
                            not_before: None,
                        }],
                        revoked: Vec::new(),
                    },
                )
                .await?,
            );
            tls_config.use_workload_trust(exchange.trust());
            let exchange_tls = tls_config.without_client_auth()?;
            let routes = Routes::new(grpc::identity_service(exchange));
            serving.push(tokio::spawn(async move {
                tls::serve(
                    tls::server(age, age),
                    routes,
                    listener,
                    Some(exchange_tls),
                    std::future::pending(),
                )
                .await
                .ok();
            }));
            identity = Some((issuer, exchange_addr));
        }
        let routes = Routes::new(Readiness::new(Arc::clone(&seal)).grpc().await)
            .add_service(grpc::secrets_service(Arc::clone(&secrets)));
        serving.push(tokio::spawn(async move {
            tls::serve(
                tls::server(age, age),
                routes,
                listener,
                Some(tls_config),
                std::future::pending(),
            )
            .await
            .ok();
        }));
        let env = Self {
            keys,
            data,
            seal,
            shares,
            secrets,
            gate,
            grants,
            audit,
            addr,
            ca,
            dir,
            identity,
            serving,
        };
        env.identity(AGENT)?;
        Ok(env)
    }

    /// Writes a client certificate for `identity` where the agent reads it.
    fn identity(&self, identity: &str) -> TestResult<()> {
        let Pem { cert, key, .. } = self.ca.client(identity)?;
        std::fs::write(self.dir.join("cert.pem"), cert)?;
        std::fs::write(self.dir.join("key.pem"), key)?;
        Ok(())
    }

    async fn put(&self, path: &str, value: &str) -> TestResult<u32> {
        let caller = Caller::Identity(SecretPath::parse(WRITER)?);
        Ok(self
            .secrets
            .put(&caller, path, value.as_bytes())
            .await?
            .version)
    }

    async fn delete(&self, path: &str) -> TestResult<()> {
        let caller = Caller::Identity(SecretPath::parse(WRITER)?);
        Ok(self.secrets.delete(&caller, path).await?)
    }

    /// The output directory `name`, under this test's directory.
    fn out(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// The agent's config: this server, its files, `outputs` (TOML).
    fn config(&self, top: &str, outputs: &str) -> TestResult<Config> {
        let text = format!(
            "server = \"https://localhost:{port}\"\nca = \"{dir}/ca.pem\"\n\
             cert = \"{dir}/cert.pem\"\nkey = \"{dir}/key.pem\"\n{top}\n{outputs}",
            port = self.addr.port(),
            dir = self.dir.display(),
        );
        Ok(Config::parse(&text)?)
    }

    fn agent(&self, top: &str, outputs: &str) -> TestResult<Agent> {
        Ok(Agent::new(self.config(top, outputs)?)?)
    }

    /// Callers of the authorization decisions on `action`, in order.
    fn decisions(&self, action: &str) -> Vec<(String, String)> {
        self.audit
            .lines()
            .iter()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|e| e["event"] == "authorization" && e["action"] == action)
            .map(|e| {
                (
                    e["caller"].as_str().unwrap_or_default().to_owned(),
                    e["decision"].as_str().unwrap_or_default().to_owned(),
                )
            })
            .collect()
    }

    /// The agent's config with a token file and the exchange, instead of
    /// a certificate's files.
    fn exchange_config(&self, outputs: &str) -> TestResult<Config> {
        let (_, exchange) = self.identity.as_ref().ok_or("no exchange")?;
        let text = format!(
            "server = \"https://localhost:{port}\"\nca = \"{dir}/ca.pem\"\n\
             token_file = \"{dir}/token\"\nexchange = \"https://localhost:{exchange}\"\n\
             {outputs}",
            port = self.addr.port(),
            exchange = exchange.port(),
            dir = self.dir.display(),
        );
        Ok(Config::parse(&text)?)
    }

    /// Writes a token for `owner` where the agent reads it.
    fn token(&self, owner: &str) -> TestResult<()> {
        let (issuer, _) = self.identity.as_ref().ok_or("no exchange")?;
        let token = issuer.token(&serde_json::json!({"repository_owner": owner}))?;
        std::fs::write(self.dir.join("token"), token)?;
        Ok(())
    }

    /// The identities certificates were issued to, in order.
    fn exchanged(&self) -> Vec<String> {
        self.audit
            .lines()
            .iter()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|e| e["event"] == "exchange" && e["outcome"] == "issued")
            .map(|e| e["identity"].as_str().unwrap_or_default().to_owned())
            .collect()
    }

    async fn destroy(self) -> TestResult<()> {
        for serving in &self.serving {
            serving.abort();
        }
        std::fs::remove_dir_all(&self.dir).ok();
        self.keys.destroy().await?;
        self.data.destroy().await
    }
}

/// One output at `dir` (in the test's directory, allowed on disk) with
/// `secrets` (`[[output.secret]]` bodies) and output settings `extra`.
fn output(dir: &Path, extra: &str, secrets: &[&str]) -> String {
    let mut text = format!(
        "[[output]]\ndir = \"{}\"\nallow_disk = true\n{extra}\n",
        dir.display()
    );
    for secret in secrets {
        text.push_str("[[output.secret]]\n");
        text.push_str(secret);
        text.push('\n');
    }
    text
}

fn read(dir: &Path, file: &str) -> Option<String> {
    std::fs::read_to_string(dir.join(file)).ok()
}

fn status(dir: &Path) -> TestResult<serde_json::Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(
        dir.join(ferritor_agent::files::STATUS),
    )?)?)
}

/// `once` renders every secret into its file, then returns; the status file
/// says what's held.
#[tokio::test]
async fn once_renders_every_secret() {
    let env = Env::new().await.unwrap();
    env.grants.allow(AGENT, Action::Read, "billing/app");
    env.put("billing/app/db-password", "foo").await.unwrap();
    env.put("billing/app/redis-password", "bar").await.unwrap();
    let out = env.out("app");
    let mut agent = env
        .agent(
            "",
            &output(
                &out,
                "",
                &[
                    "path = \"billing/app/db-password\"",
                    "path = \"billing/app/redis-password\"",
                ],
            ),
        )
        .unwrap();
    ferritor_agent::run::once(&mut agent, Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(read(&out, "db-password").as_deref(), Some("foo"));
    assert_eq!(read(&out, "redis-password").as_deref(), Some("bar"));
    let status = status(&out).unwrap();
    assert_eq!(status["rendered"], true);
    assert_eq!(status["secrets"][0]["version"], 1);
    assert!(status["last_success"].is_string(), "{status}");
    env.destroy().await.unwrap();
}

/// With `get`, every round reads every secret; a new version is in the
/// file after the next round. A pinned secret is read once, never again.
#[tokio::test]
async fn a_new_version_arrives_at_the_next_round() {
    let env = Env::new().await.unwrap();
    env.grants.allow(AGENT, Action::Read, "billing/app");
    env.put("billing/app/db", "v1").await.unwrap();
    env.put("billing/app/pinned", "p1").await.unwrap();
    let out = env.out("app");
    let mut agent = env
        .agent(
            "",
            &output(
                &out,
                "",
                &[
                    "path = \"billing/app/db\"",
                    "path = \"billing/app/pinned\"\nversion = 1",
                ],
            ),
        )
        .unwrap();
    let t0 = Instant::now();
    let first = agent.poll(t0).await;
    assert_eq!((first.calls, first.written), (2, 1));
    env.put("billing/app/db", "v2").await.unwrap();
    env.put("billing/app/pinned", "p2").await.unwrap();
    let second = agent.poll(t0 + INTERVAL).await;
    assert_eq!((second.calls, second.written), (1, 1));
    assert_eq!(read(&out, "db").as_deref(), Some("v2"));
    assert_eq!(read(&out, "pinned").as_deref(), Some("p1"));
    // Nothing new: nothing written.
    let third = agent.poll(t0 + 2 * INTERVAL).await;
    assert_eq!((third.calls, third.written), (1, 0));
    env.destroy().await.unwrap();
}

/// With `list`, a round is one listing; only a secret whose version moved
/// is read. A secret gone from the listing (deleted) is refused as not
/// found, and its file kept (`on_revoked = "keep"`).
#[tokio::test]
async fn list_reads_only_what_changed() {
    let env = Env::new().await.unwrap();
    env.grants.allow(AGENT, Action::Read, "billing/app");
    env.grants.allow(AGENT, Action::List, "billing/app");
    for name in ["a", "b", "c"] {
        env.put(&format!("billing/app/{name}"), "1").await.unwrap();
    }
    let out = env.out("app");
    let mut agent = env
        .agent(
            "detect = \"list\"",
            &output(
                &out,
                "",
                &[
                    "path = \"billing/app/a\"",
                    "path = \"billing/app/b\"",
                    "path = \"billing/app/c\"",
                ],
            ),
        )
        .unwrap();
    let t0 = Instant::now();
    assert_eq!(agent.poll(t0).await.calls, 4);
    assert_eq!(agent.poll(t0 + INTERVAL).await.calls, 1);
    env.put("billing/app/b", "2").await.unwrap();
    let changed = agent.poll(t0 + 2 * INTERVAL).await;
    assert_eq!((changed.calls, changed.written), (2, 1));
    assert_eq!(read(&out, "b").as_deref(), Some("2"));
    assert_eq!(env.decisions("list").len(), 3);

    env.delete("billing/app/c").await.unwrap();
    let gone = agent.poll(t0 + 3 * INTERVAL).await;
    assert_eq!((gone.calls, gone.written), (1, 0));
    assert_eq!(read(&out, "c").as_deref(), Some("1"));
    assert_eq!(status(&out).unwrap()["secrets"][2]["refused"], "not_found");
    env.destroy().await.unwrap();
}

/// A required secret the identity may not read: `once` fails at once.
/// `run` renders nothing until it's granted (the first set needs every
/// required secret), and retries it after the interval, then twice that,
/// then four times, never sooner, whatever else happens meanwhile.
#[tokio::test]
async fn a_denied_secret_fails_once_and_backs_off_long() {
    let env = Env::new().await.unwrap();
    env.grants.allow(AGENT, Action::Read, "billing/app");
    env.put("billing/app/ok", "fine").await.unwrap();
    env.put("billing/secret/db", "hidden").await.unwrap();
    let out = env.out("app");
    let outputs = output(
        &out,
        "",
        &["path = \"billing/app/ok\"", "path = \"billing/secret/db\""],
    );
    let mut once = env.agent("", &outputs).unwrap();
    let refused = ferritor_agent::run::once(&mut once, Duration::from_secs(10))
        .await
        .unwrap_err();
    assert!(
        refused.to_string().contains("billing/secret/db"),
        "{refused}"
    );

    let mut agent = env.agent("", &outputs).unwrap();
    let t0 = Instant::now();
    assert_eq!(
        agent.poll(t0).await,
        Round {
            calls: 2,
            written: 0,
            transient: false
        }
    );
    assert_eq!(
        agent.refused_required(),
        [(
            SecretPath::parse("billing/secret/db").unwrap(),
            Revoked::PermissionDenied
        )]
    );
    // Before the interval: only the readable one is asked.
    assert_eq!(agent.poll(t0 + Duration::from_secs(1)).await.calls, 1);
    assert_eq!(agent.poll(t0 + Duration::from_secs(59)).await.calls, 1);
    assert_eq!(agent.poll(t0 + INTERVAL).await.calls, 2);
    // Then twice the interval.
    assert_eq!(agent.poll(t0 + 2 * INTERVAL).await.calls, 1);
    assert_eq!(agent.poll(t0 + 3 * INTERVAL).await.calls, 2);
    assert!(read(&out, "ok").is_none());

    // Then four times: not at 5, next at 7.
    env.grants.allow(AGENT, Action::Read, "billing/secret");
    assert_eq!(agent.poll(t0 + 5 * INTERVAL).await.calls, 1);
    let granted = agent.poll(t0 + 7 * INTERVAL).await;
    assert_eq!(granted.written, 1);
    assert_eq!(read(&out, "db").as_deref(), Some("hidden"));
    env.destroy().await.unwrap();
}

/// Sealed, then unreachable: the round fails, the files stay, nothing is
/// asked before the backoff ends (1 s, then 2 s…), and it recovers.
#[tokio::test]
async fn transient_failures_keep_the_files_and_recover() {
    let env = Env::new().await.unwrap();
    env.grants.allow(AGENT, Action::Read, "billing/app");
    env.put("billing/app/db", "v1").await.unwrap();
    let out = env.out("app");
    let mut agent = env
        .agent("", &output(&out, "", &["path = \"billing/app/db\""]))
        .unwrap();
    let t0 = Instant::now();
    agent.poll(t0).await;

    env.seal.seal().await;
    let sealed = agent.poll(t0 + INTERVAL).await;
    assert!(sealed.transient);
    assert_eq!(read(&out, "db").as_deref(), Some("v1"));
    assert!(status(&out).unwrap()["last_error"].is_string());
    // Within the first backoff (at most 1.1 s): not even asked.
    assert_eq!(
        agent
            .poll(t0 + INTERVAL + Duration::from_millis(500))
            .await
            .calls,
        0
    );

    for share in &env.shares[..2] {
        env.seal.unseal(share, false).await.unwrap();
    }
    env.put("billing/app/db", "v2").await.unwrap();
    let back = agent.poll(t0 + INTERVAL + Duration::from_secs(2)).await;
    assert!(!back.transient, "{back:?}");
    assert_eq!(read(&out, "db").as_deref(), Some("v2"));
    assert!(status(&out).unwrap()["last_error"].is_null());

    for serving in &env.serving {
        serving.abort();
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let unreachable = agent.poll(t0 + 2 * INTERVAL).await;
    assert!(unreachable.transient);
    assert_eq!(read(&out, "db").as_deref(), Some("v2"));
    env.destroy().await.unwrap();
}

/// Revoked access: `keep` keeps the last value in its file (the
/// application still has it), `remove` takes the file away; both come back
/// once access is granted again.
#[tokio::test]
async fn revoked_secrets_follow_on_revoked() {
    let env = Env::new().await.unwrap();
    env.grants.allow(AGENT, Action::Read, "billing/app");
    env.put("billing/app/kept", "k").await.unwrap();
    env.put("billing/app/removed", "r").await.unwrap();
    let out = env.out("app");
    let mut agent = env
        .agent(
            "",
            &output(
                &out,
                "",
                &[
                    "path = \"billing/app/kept\"",
                    "path = \"billing/app/removed\"\non_revoked = \"remove\"",
                ],
            ),
        )
        .unwrap();
    let t0 = Instant::now();
    agent.poll(t0).await;
    env.grants.revoke(AGENT, Action::Read, "billing/app");
    let revoked = agent.poll(t0 + INTERVAL).await;
    assert_eq!(revoked.written, 1);
    assert_eq!(read(&out, "kept").as_deref(), Some("k"));
    assert!(read(&out, "removed").is_none());
    assert_eq!(
        status(&out).unwrap()["secrets"][0]["refused"],
        "permission_denied"
    );

    env.grants.allow(AGENT, Action::Read, "billing/app");
    agent.poll(t0 + 2 * INTERVAL).await;
    assert_eq!(read(&out, "removed").as_deref(), Some("r"));
    assert!(status(&out).unwrap()["secrets"][0]["refused"].is_null());
    env.destroy().await.unwrap();
}

/// A certificate replaced on disk (renewed, here for another identity, to
/// tell them apart) is used from the next round on.
#[tokio::test]
async fn a_replaced_certificate_is_picked_up() {
    let env = Env::new().await.unwrap();
    env.grants.allow(AGENT, Action::Read, "billing/app");
    env.grants
        .allow("apps/renewed", Action::Read, "billing/app");
    env.put("billing/app/db", "v1").await.unwrap();
    let out = env.out("app");
    let mut agent = env
        .agent("", &output(&out, "", &["path = \"billing/app/db\""]))
        .unwrap();
    let t0 = Instant::now();
    agent.poll(t0).await;
    // A file's modification time can stay in one clock tick: wait one out.
    tokio::time::sleep(Duration::from_millis(20)).await;
    env.identity("apps/renewed").unwrap();
    agent.poll(t0 + INTERVAL).await;
    let callers: Vec<String> = env.decisions("read").into_iter().map(|(c, _)| c).collect();
    assert_eq!(callers, [AGENT, "apps/renewed"]);
    env.destroy().await.unwrap();
}

/// Twenty replicas of one identity, starting together with a path they may
/// not read (optional, so the rest renders): each tries it once per
/// backoff step, so their shared denial budget (10/s, a burst of 50) is
/// never drained and their allowed reads are never refused; once granted,
/// every one has it.
#[tokio::test]
async fn replicas_sharing_an_identity_never_drain_its_denial_budget() {
    let env = Env::new().await.unwrap();
    let cap = std::num::NonZeroU32::new(64).unwrap();
    env.gate.use_limits(
        Limits::new(
            cap,
            Quota {
                rate: None,
                max_in_flight: Some(cap),
                max_watch_streams: None,
            },
            Vec::new(),
        ),
        Duration::from_secs(5),
    );
    env.grants.allow(AGENT, Action::Read, "billing/app");
    env.put("billing/app/ok", "fine").await.unwrap();
    env.put("billing/secret/db", "late").await.unwrap();
    let mut agents = Vec::new();
    for i in 0..20 {
        let out = env.out(&format!("replica-{i}"));
        agents.push((
            env.agent(
                "",
                &output(
                    &out,
                    "",
                    &[
                        "path = \"billing/app/ok\"",
                        "path = \"billing/secret/db\"\nrequired = false",
                    ],
                ),
            )
            .unwrap(),
            out,
        ));
    }
    let t0 = Instant::now();
    // A second apart, for 50 s: a 1 s retry would be 1,000 denials.
    for second in 0..50 {
        for (agent, _) in &mut agents {
            let round = agent.poll(t0 + Duration::from_secs(second)).await;
            assert!(!round.transient, "second {second}: {round:?}");
        }
    }
    for (_, out) in &agents {
        assert_eq!(read(out, "ok").as_deref(), Some("fine"));
        assert!(read(out, "db").is_none());
    }
    let denied = env
        .decisions("read")
        .into_iter()
        .filter(|(_, decision)| decision == "denied")
        .count();
    assert_eq!(denied, 20);

    env.grants.allow(AGENT, Action::Read, "billing/secret");
    for (agent, _) in &mut agents {
        agent.poll(t0 + INTERVAL).await;
    }
    for (_, out) in &agents {
        assert_eq!(read(out, "db").as_deref(), Some("late"));
    }
    env.destroy().await.unwrap();
}

/// After a change (not the first render), the application is signalled
/// through its pid file, or a command runs.
#[tokio::test]
async fn the_application_is_told_of_a_change() {
    let env = Env::new().await.unwrap();
    env.grants.allow(AGENT, Action::Read, "billing/app");
    env.put("billing/app/db", "v1").await.unwrap();
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let pid_file = env.dir.join("app.pid");
    std::fs::write(&pid_file, child.id().to_string()).unwrap();
    let touched = env.dir.join("touched");
    let signalled = env.out("signalled");
    let commanded = env.out("commanded");
    let outputs = format!(
        "{}{}",
        output(
            &signalled,
            &format!(
                "on_change = {{ signal = \"TERM\", pid_file = \"{}\" }}",
                pid_file.display()
            ),
            &["path = \"billing/app/db\""],
        ),
        output(
            &commanded,
            &format!(
                "on_change = {{ command = [\"touch\", \"{}\"] }}",
                touched.display()
            ),
            &["path = \"billing/app/db\""],
        ),
    );
    let mut agent = env.agent("", &outputs).unwrap();
    let t0 = Instant::now();
    agent.poll(t0).await;
    // The first render tells nobody.
    assert!(child.try_wait().unwrap().is_none());
    env.put("billing/app/db", "v2").await.unwrap();
    agent.poll(t0 + INTERVAL).await;
    let status = child.wait().unwrap();
    assert_eq!(status.signal(), Some(15));
    for _ in 0..100 {
        if touched.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(touched.exists());
    env.destroy().await.unwrap();
}

/// A `keep` secret refused, then readable again with the same version: its
/// file never changed, so nothing is rewritten and the application isn't
/// told (no spurious reload); a new version afterwards is.
#[tokio::test]
async fn a_refusal_ending_is_no_change() {
    let env = Env::new().await.unwrap();
    env.grants.allow(AGENT, Action::Read, "billing/app");
    env.put("billing/app/db", "v1").await.unwrap();
    let touched = env.dir.join("touched");
    let out = env.out("app");
    let mut agent = env
        .agent(
            "",
            &output(
                &out,
                &format!(
                    "on_change = {{ command = [\"touch\", \"{}\"] }}",
                    touched.display()
                ),
                &["path = \"billing/app/db\""],
            ),
        )
        .unwrap();
    let t0 = Instant::now();
    agent.poll(t0).await;
    env.grants.revoke(AGENT, Action::Read, "billing/app");
    assert_eq!(agent.poll(t0 + INTERVAL).await.written, 0);
    env.grants.allow(AGENT, Action::Read, "billing/app");
    assert_eq!(agent.poll(t0 + 2 * INTERVAL).await.written, 0);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!touched.exists(), "told of a change that isn't one");

    env.put("billing/app/db", "v2").await.unwrap();
    assert_eq!(agent.poll(t0 + 3 * INTERVAL).await.written, 1);
    for _ in 0..100 {
        if touched.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(touched.exists());
    env.destroy().await.unwrap();
}

/// Workload identity: the agent exchanges its token for a certificate,
/// reads as the identity it maps to, and exchanges again two thirds into
/// the certificate's life, reading the token file anew (the platform
/// replaces it); a failed renewal keeps the current certificate while it's
/// valid.
#[tokio::test]
async fn a_token_is_exchanged_and_the_certificate_renewed() {
    // Real certificates, checked on the real clock: each step waits until
    // a renewal is due (two thirds of LIFETIME), and the refused renewal
    // must still find the current certificate valid, which leaves a third
    // of LIFETIME for the work in between. 3 s gave too little on a busy
    // runner (CI); 9 s leaves 3.
    const LIFETIME: Duration = Duration::from_secs(9);
    let due = LIFETIME * 2 / 3 + Duration::from_millis(100);
    let env = Env::start(Some(LIFETIME)).await.unwrap();
    env.grants
        .allow("ci/acme/agent", Action::Read, "billing/app");
    env.grants
        .allow("ci/other/agent", Action::Read, "billing/app");
    env.put("billing/app/db", "v1").await.unwrap();
    env.token("acme").unwrap();
    let out = env.out("app");
    let mut agent = Agent::new(
        env.exchange_config(&output(&out, "", &["path = \"billing/app/db\""]))
            .unwrap(),
    )
    .unwrap();
    let t0 = Instant::now();
    agent.poll(t0).await;
    assert_eq!(read(&out, "db").as_deref(), Some("v1"));
    assert_eq!(env.exchanged(), ["ci/acme/agent"]);

    // Not due yet: the same certificate.
    agent.poll(t0 + INTERVAL).await;
    assert_eq!(env.exchanged(), ["ci/acme/agent"]);

    // Two thirds in: exchanged again, with the new token.
    env.token("other").unwrap();
    tokio::time::sleep(due).await;
    env.put("billing/app/db", "v2").await.unwrap();
    agent.poll(t0 + INTERVAL * 2).await;
    assert_eq!(env.exchanged(), ["ci/acme/agent", "ci/other/agent"]);
    assert_eq!(read(&out, "db").as_deref(), Some("v2"));
    let callers: Vec<String> = env.decisions("read").into_iter().map(|(c, _)| c).collect();
    assert_eq!(callers.last().map(String::as_str), Some("ci/other/agent"));

    // A token the exchange refuses: the current certificate stays in use.
    std::fs::write(env.dir.join("token"), "not a token").unwrap();
    tokio::time::sleep(due).await;
    agent.poll(t0 + INTERVAL * 3).await;
    assert_eq!(env.exchanged().len(), 2);
    let status = status(&out).unwrap();
    assert!(status["last_error"].is_null(), "{status}");

    // The issuing key revoked: the round is refused, and the next one
    // exchanges again (due or not) and reads with the new CA's certificate.
    env.token("acme").unwrap();
    env.seal.identity_rotate(true).await.unwrap();
    env.put("billing/app/db", "v3").await.unwrap();
    let refused = agent.poll(t0 + INTERVAL * 4).await;
    assert!(refused.transient, "{refused:?}");
    let back = agent.poll(t0 + INTERVAL * 5).await;
    assert!(!back.transient, "{back:?}");
    assert_eq!(env.exchanged().len(), 3);
    assert_eq!(read(&out, "db").as_deref(), Some("v3"));
    env.destroy().await.unwrap();
}

/// `run` keeps a watch stream open: a new version reaches the file within
/// seconds, though the regular rounds are an hour apart; a secret whose
/// version doesn't change isn't read again.
#[tokio::test]
async fn run_hears_of_a_change_at_once() {
    let env = Env::new().await.unwrap();
    env.grants.allow(AGENT, Action::Read, "billing/app");
    env.put("billing/app/db", "v1").await.unwrap();
    env.put("billing/app/other", "o1").await.unwrap();
    let out = env.out("app");
    let mut agent = env
        .agent(
            "interval_secs = 3600",
            &output(
                &out,
                "",
                &["path = \"billing/app/db\"", "path = \"billing/app/other\""],
            ),
        )
        .unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let running = tokio::spawn(async move {
        ferritor_agent::run::run(&mut agent, async {
            stopped.await.ok();
        })
        .await;
    });
    let wait_for = |file: &'static str, value: &'static str| {
        let out = out.clone();
        async move {
            for _ in 0..100 {
                if read(&out, file).as_deref() == Some(value) {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            false
        }
    };
    assert!(wait_for("db", "v1").await);
    // The stream is open once its round (after `ready`) is done.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let reads_before = env.decisions("read").len();
    env.put("billing/app/db", "v2").await.unwrap();
    assert!(wait_for("db", "v2").await, "the change didn't arrive");
    let reads: Vec<String> = env.decisions("read")[reads_before..]
        .iter()
        .map(|(caller, _)| caller.clone())
        .collect();
    // One read: db's, not other's.
    assert_eq!(reads, [AGENT]);
    stop.send(()).ok();
    running.await.unwrap();
    env.destroy().await.unwrap();
}

/// While a watch stream vouches for every secret, the rounds stretch to ten
/// intervals (at most ten minutes, never below the interval); losing it
/// brings the next round back within an interval.
#[tokio::test]
async fn rounds_stretch_while_watched() {
    let env = Env::new().await.unwrap();
    env.grants.allow(AGENT, Action::Read, "billing/app");
    env.put("billing/app/db", "v1").await.unwrap();
    let out = env.out("app");
    let mut agent = env
        .agent(
            "interval_secs = 60",
            &output(&out, "", &["path = \"billing/app/db\""]),
        )
        .unwrap();
    let t0 = Instant::now();
    let within = |at: Instant, from: Instant, secs: u64| {
        let nominal = Duration::from_secs(secs);
        at >= from + nominal.mul_f64(0.89) && at <= from + nominal.mul_f64(1.11)
    };
    agent.poll(t0).await;
    assert!(within(agent.next_wake(t0), t0, 60));

    agent.set_watched(true, t0);
    assert_eq!(agent.round_interval(), Duration::from_secs(600));
    let t1 = t0 + Duration::from_secs(1);
    agent.poll(t1).await;
    assert!(within(agent.next_wake(t1), t1, 600));

    let t2 = t1 + Duration::from_secs(5);
    agent.set_watched(false, t2);
    assert!(within(agent.next_wake(t2), t2, 60));
    assert_eq!(agent.round_interval(), Duration::from_secs(60));

    // A long interval isn't stretched past itself, nor shortened.
    let mut slow = env
        .agent(
            "interval_secs = 3600",
            &output(&env.out("slow"), "", &["path = \"billing/app/db\""]),
        )
        .unwrap();
    slow.set_watched(true, t0);
    assert_eq!(slow.round_interval(), Duration::from_secs(3600));
    env.destroy().await.unwrap();
}
