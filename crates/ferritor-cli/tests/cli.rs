//! The real `ferritor` binary against an in-process server (keys and data
//! databases from `ferritor-testkit`), with shares and values piped through
//! stdin the way an operator's script would.

use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::sync::Arc;
use std::time::Duration;

use ferritor_core::proto::v1::system_service_server::SystemServiceServer;
use ferritor_datastore::Datastore;
use ferritor_keystore::Keystore;
use ferritor_server::audit::{AuditLog, Gate};
use ferritor_server::authz::{Action, AllowAll, Authorizer, Caller, StoredPolicies, Target};
use ferritor_server::destroy::Destroy;
use ferritor_server::health::Readiness;
use ferritor_server::identity::exchange::Exchange;
use ferritor_server::identity::mapping::{Mapping, Template};
use ferritor_server::identity::{
    DEFAULT_EXCHANGE_BURST, DEFAULT_MAX_TOKEN_AGE, Identity, Issuer, JwksSource,
};
use ferritor_server::namespaces::{NamespaceError, Namespaces};
use ferritor_server::policies::Policies;
use ferritor_server::policy::{Policy, Rule};
use ferritor_server::purge::Purge;
use ferritor_server::rewrap::Rewrap;
use ferritor_server::seal::Seal;
use ferritor_server::secrets::Secrets;
use ferritor_server::{grpc, tls};
use ferritor_testkit::jwt::{AUDIENCE, ISS, TokenIssuer};
use ferritor_testkit::pki::{Ca, Pem};
use ferritor_testkit::{Captured, TestDatabase, TestResult};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::task::JoinHandle;
use tonic::service::Routes;

/// The namespaces the tests store under (see [`Server::create_namespaces`]).
const NAMESPACES: [&str; 3] = ["app", "billing", "payroll"];

struct Server {
    keys: TestDatabase,
    data: TestDatabase,
    addr: String,
    /// The server's own handle, for setting up data without the CLI.
    secrets: Arc<Secrets>,
    namespaces: Arc<Namespaces>,
    gate: Arc<Gate>,
    /// The token exchange's address, if started with one.
    exchange: Option<String>,
    serving: Vec<JoinHandle<()>>,
}

impl Server {
    async fn start() -> TestResult<Self> {
        Self::start_with(None, Arc::new(AllowAll), None).await
    }

    /// With TLS: a server certificate from `ca`, client certificates required.
    async fn start_tls(ca: &Ca) -> TestResult<Self> {
        Self::start_secured(ca, Arc::new(AllowAll)).await
    }

    /// With TLS and the given authorizer (a `Policy` for real tests).
    async fn start_secured(ca: &Ca, authz: Arc<dyn Authorizer>) -> TestResult<Self> {
        let pem = ca.server()?;
        let tls = tls::server_tls(
            pem.cert.as_bytes(),
            pem.key.as_bytes(),
            ca.cert.as_bytes(),
            None,
        )?;
        Self::start_with(Some(tls), authz, None).await
    }

    /// With TLS and the token exchange: tokens from `issuer` for
    /// `ci/{repository_owner}/job`.
    async fn start_exchanging(ca: &Ca, issuer: &TokenIssuer) -> TestResult<Self> {
        let pem = ca.server()?;
        let tls = tls::server_tls(
            pem.cert.as_bytes(),
            pem.key.as_bytes(),
            ca.cert.as_bytes(),
            None,
        )?;
        let identity = Identity {
            // Set once bound.
            listen_addr: "127.0.0.1:0".parse()?,
            lifetime: Duration::from_secs(3600),
            issuers: vec![Issuer {
                name: "ci".to_owned(),
                iss: ISS.to_owned(),
                audience: AUDIENCE.to_owned(),
                max_token_age: DEFAULT_MAX_TOKEN_AGE,
                exchange_burst: DEFAULT_EXCHANGE_BURST,
                jwks: JwksSource::File(issuer.jwks.clone()),
                mappings: vec![Mapping {
                    template: Template::parse("ci/{repository_owner}/job", "ci")?,
                    require: Vec::new(),
                }],
                not_before: None,
            }],
            revoked: Vec::new(),
        };
        Self::start_with(Some(tls), Arc::new(AllowAll), Some(identity)).await
    }

    async fn start_with(
        tls_config: Option<tls::ServerTls>,
        authz: Arc<dyn Authorizer>,
        identity: Option<Identity>,
    ) -> TestResult<Self> {
        let keys = TestDatabase::new(
            "KEYS_DATABASE_URL",
            "ferritor_cli_test",
            &ferritor_keystore::MIGRATOR,
        )
        .await?;
        let data = TestDatabase::new(
            "DATA_DATABASE_URL",
            "ferritor_cli_test",
            &ferritor_datastore::MIGRATOR,
        )
        .await?;
        let seal = Arc::new(Seal::new(Keystore::new(keys.pool().clone())));
        let rewrap = Arc::new(Rewrap::new(
            Arc::clone(&seal),
            Datastore::new(data.pool().clone()),
        ));
        // Deletions purgeable at once.
        let purge = Arc::new(Purge::new(
            Arc::clone(&seal),
            Datastore::new(data.pool().clone()),
            Duration::ZERO,
        ));
        let gate = Arc::new(Gate::new(
            authz,
            AuditLog::new(std::io::sink(), Duration::from_secs(5))?,
        ));
        let secrets = Arc::new(Secrets::new(
            Arc::clone(&seal),
            Datastore::new(data.pool().clone()),
            Arc::clone(&gate),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let addr = match &tls_config {
            Some(_) => format!("https://localhost:{port}"),
            None => format!("http://127.0.0.1:{port}"),
        };
        let age = Duration::from_secs(600);
        let destroy = Arc::new(Destroy::new(
            Arc::clone(&seal),
            Datastore::new(data.pool().clone()),
        ));
        let namespaces = Arc::new(Namespaces::new(
            Arc::clone(&seal),
            Datastore::new(data.pool().clone()),
        ));
        gate.use_stored_policies(Arc::clone(&seal) as Arc<dyn StoredPolicies>);
        let policies = Arc::new(Policies::new(Arc::clone(&seal), Arc::clone(&gate)));
        let mut serving = Vec::new();
        let mut exchange_addr = None;
        if let (Some(mut identity), Some(tls_config)) = (identity, &tls_config) {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            identity.listen_addr = listener.local_addr()?;
            exchange_addr = Some(format!("https://localhost:{}", identity.listen_addr.port()));
            let exchange =
                Arc::new(Exchange::new(Arc::clone(&seal), Arc::clone(&gate), identity).await?);
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
        }
        let routes = Routes::new(Readiness::new(Arc::clone(&seal)).grpc().await)
            .add_service(SystemServiceServer::new(grpc::System::new(
                seal,
                rewrap,
                purge,
                destroy,
                Arc::clone(&namespaces),
                Datastore::new(data.pool().clone()),
                Arc::clone(&gate),
            )))
            .add_service(grpc::secrets_service(Arc::clone(&secrets)))
            .add_service(grpc::policy_service(policies));
        serving.push(tokio::spawn(async move {
            tls::serve(
                tls::server(age, age),
                routes,
                listener,
                tls_config,
                std::future::pending(),
            )
            .await
            .ok();
        }));
        Ok(Self {
            keys,
            data,
            addr,
            secrets,
            namespaces,
            gate,
            exchange: exchange_addr,
            serving,
        })
    }

    /// Creates [`NAMESPACES`] through the server's own handle (once
    /// unsealed; ones already there are fine).
    async fn create_namespaces(&self) -> TestResult<()> {
        for name in NAMESPACES {
            match self.namespaces.create(name, &Default::default()).await {
                Ok(_) | Err(NamespaceError::Exists(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    /// Runs `ferritor <args>` with `stdin` piped in.
    async fn ferritor(&self, args: &[&str], stdin: &[u8]) -> TestResult<Run> {
        run_ferritor(&self.addr, args, stdin).await
    }

    async fn stop(self) -> TestResult<()> {
        for serving in &self.serving {
            serving.abort();
        }
        self.keys.destroy().await?;
        self.data.destroy().await
    }
}

/// One run of the binary.
struct Run {
    success: bool,
    /// The exit status (`None`: killed by a signal).
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: String,
}

impl Run {
    fn out(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
}

async fn run_ferritor(addr: &str, args: &[&str], stdin: &[u8]) -> TestResult<Run> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ferritor"))
        .args(args)
        .env("FERRITOR_ADDR", addr)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut pipe = child.stdin.take().ok_or("no stdin")?;
    pipe.write_all(stdin).await?;
    drop(pipe);
    let Output {
        status,
        stdout,
        stderr,
    } = child.wait_with_output().await?;
    Ok(Run {
        success: status.success(),
        code: status.code(),
        stdout,
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    })
}

/// The hex shares in `share <id> (generation <g>): <hex>` lines.
fn shares(run: &Run) -> Vec<String> {
    run.out()
        .lines()
        .filter_map(|line| line.rsplit_once(": ").map(|(_, hex)| hex.to_owned()))
        .collect()
}

fn line(share: &str) -> Vec<u8> {
    format!("{share}\n").into_bytes()
}

#[tokio::test]
async fn operator_walkthrough() {
    let server = Server::start().await.unwrap();
    let status = server.ferritor(&["status"], &[]).await.unwrap();
    assert_eq!(status.out(), "not initialized\n");

    let init = server
        .ferritor(&["init", "--shares", "3", "--threshold", "2"], &[])
        .await
        .unwrap();
    assert!(init.success, "{}", init.stderr);
    let old = shares(&init);
    assert_eq!(old.len(), 3);
    assert!(init.out().contains("(generation 1)"));
    assert!(init.stderr.contains("shown only once"));

    let first = server.ferritor(&["unseal"], &line(&old[0])).await.unwrap();
    assert!(
        first.out().contains("unseal progress: 1/2"),
        "{}",
        first.out()
    );
    let second = server.ferritor(&["unseal"], &line(&old[2])).await.unwrap();
    assert!(second.out().starts_with("unsealed\n"), "{}", second.out());

    // Nothing is stored outside a namespace, and there's none yet.
    let status = server.ferritor(&["status"], &[]).await.unwrap();
    assert!(
        status.out().ends_with("namespaces: 0\n"),
        "{}",
        status.out()
    );
    assert!(
        status.stderr.contains("namespace create"),
        "{}",
        status.stderr
    );
    let homeless = server.ferritor(&["put", "app/db"], b"x").await.unwrap();
    assert!(!homeless.success);
    assert!(
        homeless
            .stderr
            .contains("hint: a secret's path starts with its namespace"),
        "{}",
        homeless.stderr
    );
    let created = server
        .ferritor(&["namespace", "create", "app", "--label", "team=core"], &[])
        .await
        .unwrap();
    assert_eq!(
        created.out(),
        "created namespace app\nactive KEK version: 1\n"
    );

    // Binary bytes and a trailing newline survive the round trip.
    let value = b"s3cr\x00et\n";
    let put = server.ferritor(&["put", "app/db"], value).await.unwrap();
    assert_eq!(put.out(), "app/db version 1\n");
    let get = server.ferritor(&["get", "app/db"], &[]).await.unwrap();
    assert_eq!(get.stdout, value);
    let list = server.ferritor(&["list", "app"], &[]).await.unwrap();
    assert_eq!(list.out(), "app/db\tversion 1\n");
    let rotate = server
        .ferritor(&["rotate", "--namespace", "app"], &[])
        .await
        .unwrap();
    assert_eq!(rotate.out(), "active KEK version: 2\n");

    // Rekey: authorize with old shares, verify with new ones.
    let start = server
        .ferritor(
            &["rekey", "start", "--shares", "2", "--threshold", "2"],
            &[],
        )
        .await
        .unwrap();
    let nonce = start.out().trim().trim_start_matches("nonce: ").to_owned();
    let submit = ["rekey", "submit", "--nonce", nonce.as_str()];
    let partial = server.ferritor(&submit, &line(&old[1])).await.unwrap();
    assert_eq!(partial.out(), "authorizing: 1/2\n");
    let authorized = server.ferritor(&submit, &line(&old[0])).await.unwrap();
    let new = shares(&authorized);
    assert_eq!(new.len(), 2);
    assert!(authorized.out().contains("(generation 2)"));
    assert!(authorized.stderr.contains("Nothing has changed yet"));
    let verify = ["rekey", "verify", "--nonce", nonce.as_str()];
    let partial = server.ferritor(&verify, &line(&new[0])).await.unwrap();
    assert_eq!(partial.out(), "verifying: 1/2\n");
    let done = server.ferritor(&verify, &line(&new[1])).await.unwrap();
    assert_eq!(done.out(), "rekey complete: generation 2\n");

    let seal = server.ferritor(&["seal"], &[]).await.unwrap();
    assert_eq!(seal.out(), "sealed\ngeneration: 2\n");

    // The old shares are dead; the new ones unseal, and the secret is intact.
    let stale = server.ferritor(&["unseal"], &line(&old[0])).await.unwrap();
    assert!(!stale.success);
    assert!(
        stale.stderr.contains("share is from generation 1"),
        "{}",
        stale.stderr
    );
    for share in &new {
        server.ferritor(&["unseal"], &line(share)).await.unwrap();
    }
    server.create_namespaces().await.unwrap();
    let get = server.ferritor(&["get", "app/db"], &[]).await.unwrap();
    assert_eq!(get.stdout, value);

    let delete = server.ferritor(&["delete", "app/db"], &[]).await.unwrap();
    assert_eq!(delete.out(), "deleted app/db\n");
    let gone = server.ferritor(&["get", "app/db"], &[]).await.unwrap();
    assert!(!gone.success);
    assert!(gone.stderr.contains("error: secret `app/db` not found"));
    server.stop().await.unwrap();
}

#[tokio::test]
async fn errors_come_with_hints() {
    let server = Server::start().await.unwrap();
    let init = server
        .ferritor(&["init", "--shares", "3", "--threshold", "2"], &[])
        .await
        .unwrap();
    let old = shares(&init);

    let sealed = server.ferritor(&["put", "app/db"], b"x").await.unwrap();
    assert!(!sealed.success);
    assert_eq!(
        sealed.stderr,
        "error: the server is sealed\nhint: unseal it first: `ferritor unseal`, once per share.\n"
    );

    let garbage = server.ferritor(&["unseal"], b"not hex\n").await.unwrap();
    assert!(!garbage.success);
    assert!(
        garbage.stderr.contains("not a valid hex share"),
        "{}",
        garbage.stderr
    );

    for share in &old[..2] {
        server.ferritor(&["unseal"], &line(share)).await.unwrap();
    }
    server.create_namespaces().await.unwrap();
    let bad_path = server.ferritor(&["put", "/app/db"], b"x").await.unwrap();
    assert!(
        bad_path.stderr.contains("error: invalid secret path"),
        "{}",
        bad_path.stderr
    );

    // Sealing mid-rekey reports what happened to it.
    let start = server
        .ferritor(
            &["rekey", "start", "--shares", "2", "--threshold", "2"],
            &[],
        )
        .await
        .unwrap();
    let nonce = start.out().trim().trim_start_matches("nonce: ").to_owned();
    for share in &old[..2] {
        server
            .ferritor(&["rekey", "submit", "--nonce", &nonce], &line(share))
            .await
            .unwrap();
    }
    let seal = server.ferritor(&["seal"], &[]).await.unwrap();
    assert!(
        seal.stderr
            .contains("discarded; the current shares still work"),
        "{}",
        seal.stderr
    );
    server.stop().await.unwrap();
}

#[tokio::test]
async fn an_unreachable_server_is_reported_with_a_hint() {
    // Port 1: nothing listens there.
    let run = run_ferritor("http://127.0.0.1:1", &["status"], &[])
        .await
        .unwrap();
    assert!(!run.success);
    assert!(
        run.stderr
            .starts_with("error: can't reach the server at http://127.0.0.1:1"),
        "{}",
        run.stderr
    );
    assert!(run.stderr.contains("hint: is the server running?"));
}

/// `ferritor init` with stdout already closed (`| head` after its line, a full
/// disk, a closed terminal). The server is initialized by then, so the shares
/// must reach the operator anyway: on stderr, with a failing exit status.
#[tokio::test]
async fn init_with_a_broken_stdout_still_delivers_the_shares() {
    let server = Server::start().await.unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ferritor"))
        .args(["init", "--shares", "3", "--threshold", "2"])
        .env("FERRITOR_ADDR", &server.addr)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Close the read end before ferritor writes anything.
    drop(child.stdout.take());
    let output = child.wait_with_output().await.unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    assert!(!output.status.success());
    assert!(stderr.contains("they are on stderr above"), "{stderr}");
    let rescued: Vec<String> = stderr
        .lines()
        .filter(|line| line.starts_with("share "))
        .filter_map(|line| line.rsplit_once(": ").map(|(_, hex)| hex.to_owned()))
        .collect();
    assert_eq!(rescued.len(), 3, "{stderr}");

    // They're the real shares: two of them unseal.
    for share in &rescued[..2] {
        let unseal = server.ferritor(&["unseal"], &line(share)).await.unwrap();
        assert!(unseal.success, "{}", unseal.stderr);
    }
    let status = server.ferritor(&["status"], &[]).await.unwrap();
    assert!(status.out().starts_with("unsealed\n"), "{}", status.out());
    server.stop().await.unwrap();
}

/// A seal that couldn't even connect must say plainly it sealed nothing.
#[tokio::test]
async fn an_unreachable_seal_says_it_did_not_seal() {
    let run = run_ferritor("http://127.0.0.1:1", &["seal"], &[])
        .await
        .unwrap();
    assert!(!run.success);
    assert!(
        run.stderr.contains("this did NOT seal it"),
        "{}",
        run.stderr
    );
}

/// Empty stdin (a script with stdin closed, `< /dev/null`) is refused before
/// anything is sent, unless asked for.
#[tokio::test]
async fn put_refuses_empty_input_unless_allowed() {
    let server = Server::start().await.unwrap();
    let init = server
        .ferritor(&["init", "--shares", "3", "--threshold", "2"], &[])
        .await
        .unwrap();
    for share in &shares(&init)[..2] {
        server.ferritor(&["unseal"], &line(share)).await.unwrap();
    }
    server.create_namespaces().await.unwrap();

    let empty = server.ferritor(&["put", "app/db"], &[]).await.unwrap();
    assert!(!empty.success);
    assert!(
        empty.stderr.contains("refusing to store an empty value"),
        "{}",
        empty.stderr
    );
    let nothing = server.ferritor(&["get", "app/db"], &[]).await.unwrap();
    assert!(nothing.stderr.contains("not found"), "{}", nothing.stderr);

    let allowed = server
        .ferritor(&["put", "app/db", "--allow-empty"], &[])
        .await
        .unwrap();
    assert_eq!(allowed.out(), "app/db version 1\n");
    let get = server.ferritor(&["get", "app/db"], &[]).await.unwrap();
    assert!(get.success && get.stdout.is_empty());

    // A non-empty value needs no flag.
    let value = server.ferritor(&["put", "app/db"], b"x").await.unwrap();
    assert_eq!(value.out(), "app/db version 2\n");
    server.stop().await.unwrap();
}

/// Only leaving `--version` out means latest; 0 is a usage error, caught
/// before anything is sent.
#[tokio::test]
async fn get_rejects_version_zero() {
    let run = run_ferritor(
        "http://127.0.0.1:1",
        &["get", "app/db", "--version", "0"],
        &[],
    )
    .await
    .unwrap();
    assert!(!run.success);
    assert!(run.stderr.contains("--version"), "{}", run.stderr);
    assert!(
        !run.stderr.contains("can't reach the server"),
        "{}",
        run.stderr
    );
}

/// The sealed hint works for admin calls too (a different server error
/// type with the same shared message), not only for secret operations.
#[tokio::test]
async fn an_admin_call_while_sealed_gets_the_unseal_hint() {
    let server = Server::start().await.unwrap();
    server
        .ferritor(&["init", "--shares", "3", "--threshold", "2"], &[])
        .await
        .unwrap();
    let rotate = server
        .ferritor(&["rotate", "--namespace", "app"], &[])
        .await
        .unwrap();
    assert!(!rotate.success);
    assert_eq!(
        rotate.stderr,
        "error: the server is sealed\nhint: unseal it first: `ferritor unseal`, once per share.\n"
    );
    server.stop().await.unwrap();
}

#[tokio::test]
async fn an_empty_share_says_so() {
    let server = Server::start().await.unwrap();
    server
        .ferritor(&["init", "--shares", "3", "--threshold", "2"], &[])
        .await
        .unwrap();
    let empty = server.ferritor(&["unseal"], &[]).await.unwrap();
    assert!(!empty.success);
    assert!(
        empty.stderr.contains("no share given (stdin was empty)"),
        "{}",
        empty.stderr
    );
    server.stop().await.unwrap();
}

/// The nonce printed by `rekey start` got lost: `status` shows it, and it
/// works to carry on.
#[tokio::test]
async fn a_lost_rekey_nonce_is_recovered_from_status() {
    let server = Server::start().await.unwrap();
    let init = server
        .ferritor(&["init", "--shares", "3", "--threshold", "2"], &[])
        .await
        .unwrap();
    let old = shares(&init);
    for share in &old[..2] {
        server.ferritor(&["unseal"], &line(share)).await.unwrap();
    }
    server.create_namespaces().await.unwrap();
    // Its output discarded.
    server
        .ferritor(
            &["rekey", "start", "--shares", "2", "--threshold", "2"],
            &[],
        )
        .await
        .unwrap();

    let status = server.ferritor(&["status"], &[]).await.unwrap();
    assert!(
        status
            .out()
            .contains("rekey: authorizing (current shares), 0/2\n"),
        "{}",
        status.out()
    );
    assert!(
        status.stderr.contains("ferritor rekey submit --nonce"),
        "{}",
        status.stderr
    );
    let nonce = status
        .out()
        .lines()
        .find_map(|l| l.strip_prefix("rekey nonce: "))
        .unwrap()
        .to_owned();

    for share in &old[..2] {
        server
            .ferritor(&["rekey", "submit", "--nonce", &nonce], &line(share))
            .await
            .unwrap();
    }
    let status = server.ferritor(&["status"], &[]).await.unwrap();
    assert!(
        status
            .out()
            .contains("rekey: verifying (new shares, generation 2), 0/2\n"),
        "{}",
        status.out()
    );
    assert!(
        status.stderr.contains("ferritor rekey verify --nonce"),
        "{}",
        status.stderr
    );

    let cancel = server
        .ferritor(&["rekey", "cancel", "--nonce", &nonce], &[])
        .await
        .unwrap();
    assert!(cancel.success, "{}", cancel.stderr);
    let status = server.ferritor(&["status"], &[]).await.unwrap();
    assert!(!status.out().contains("rekey"), "{}", status.out());
    server.stop().await.unwrap();
}

#[tokio::test]
async fn list_fetches_every_page() {
    let server = Server::start().await.unwrap();
    let init = server
        .ferritor(&["init", "--shares", "3", "--threshold", "2"], &[])
        .await
        .unwrap();
    for share in &shares(&init)[..2] {
        server.ferritor(&["unseal"], &line(share)).await.unwrap();
    }
    server.create_namespaces().await.unwrap();
    // Three pages at the default size, the last with one secret.
    let n = 2 * ferritor_server::secrets::DEFAULT_PAGE_SIZE + 1;
    let expected: String = (0..n).map(|i| format!("app/{i:04}\tversion 1\n")).collect();
    for i in 0..n {
        server
            .secrets
            .put(&Caller::Unauthenticated, &format!("app/{i:04}"), b"x")
            .await
            .unwrap();
    }
    let list = server.ferritor(&["list", "app"], &[]).await.unwrap();
    assert!(list.success, "{}", list.stderr);
    assert_eq!(list.out(), expected);
    server.stop().await.unwrap();
}

async fn put_expecting(server: &Server, expected: &str, value: &[u8]) -> TestResult<Run> {
    server
        .ferritor(&["put", "app/db", "--expected-version", expected], value)
        .await
}

/// `--expected-version`: create only (0), or only over the version read;
/// a stale one is refused with the server's message and stores nothing.
#[tokio::test]
async fn put_with_an_expected_version() {
    let server = Server::start().await.unwrap();
    let init = server
        .ferritor(&["init", "--shares", "3", "--threshold", "2"], &[])
        .await
        .unwrap();
    for share in &shares(&init)[..2] {
        server.ferritor(&["unseal"], &line(share)).await.unwrap();
    }
    server.create_namespaces().await.unwrap();
    let created = put_expecting(&server, "0", b"one").await.unwrap();
    assert_eq!(created.out(), "app/db version 1\n");
    let exists = put_expecting(&server, "0", b"two").await.unwrap();
    assert!(!exists.success);
    assert!(
        exists
            .stderr
            .contains("its latest version is 1, expected none (create only)"),
        "{}",
        exists.stderr
    );
    assert_eq!(
        put_expecting(&server, "1", b"two").await.unwrap().out(),
        "app/db version 2\n"
    );
    let stale = put_expecting(&server, "1", b"lost").await.unwrap();
    assert!(!stale.success);
    assert!(stale.stderr.contains("read it again"), "{}", stale.stderr);

    let get = server.ferritor(&["get", "app/db"], &[]).await.unwrap();
    assert_eq!(get.stdout, b"two");
    server.stop().await.unwrap();
}

/// `ferritor purge` removes deleted versions (the test server keeps none),
/// and the path's numbering carries on.
#[tokio::test]
async fn purge_removes_deleted_versions() {
    let server = Server::start().await.unwrap();
    let init = server
        .ferritor(&["init", "--shares", "3", "--threshold", "2"], &[])
        .await
        .unwrap();
    for share in &shares(&init)[..2] {
        server.ferritor(&["unseal"], &line(share)).await.unwrap();
    }
    server.create_namespaces().await.unwrap();
    server.ferritor(&["put", "app/db"], b"x").await.unwrap();
    server.ferritor(&["put", "app/db"], b"y").await.unwrap();
    server.ferritor(&["delete", "app/db"], &[]).await.unwrap();

    let purge = server
        .ferritor(&["purge", "--max-rows", "1"], &[])
        .await
        .unwrap();
    assert!(purge.success, "{}", purge.stderr);
    assert_eq!(purge.out(), "purged: 2\n");
    assert!(purge.stderr.contains("so far"), "{}", purge.stderr);
    let again = server.ferritor(&["purge"], &[]).await.unwrap();
    assert_eq!(again.out(), "purged: 0\n");

    let put = server.ferritor(&["put", "app/db"], b"z").await.unwrap();
    assert_eq!(put.out(), "app/db version 3\n");
    server.stop().await.unwrap();
}

/// `ferritor versions` shows the history, newest first, live and deleted,
/// with times; never a value.
#[tokio::test]
async fn versions_shows_the_history() {
    let server = Server::start().await.unwrap();
    let init = server
        .ferritor(&["init", "--shares", "3", "--threshold", "2"], &[])
        .await
        .unwrap();
    for share in &shares(&init)[..2] {
        server.ferritor(&["unseal"], &line(share)).await.unwrap();
    }
    server.create_namespaces().await.unwrap();
    server.ferritor(&["put", "app/db"], b"one").await.unwrap();
    server.ferritor(&["delete", "app/db"], &[]).await.unwrap();
    server.ferritor(&["put", "app/db"], b"two").await.unwrap();

    let history = server.ferritor(&["versions", "app/db"], &[]).await.unwrap();
    assert!(history.success, "{}", history.stderr);
    let out = history.out();
    let lines: Vec<Vec<&str>> = out.lines().map(|l| l.split('\t').collect()).collect();
    assert_eq!(lines.len(), 2, "{out}");
    assert_eq!((lines[0][0], lines[0][2]), ("version 2", "live"));
    assert_eq!(lines[1][0], "version 1");
    assert!(
        lines[1][1].starts_with("created ") && lines[1][1].ends_with('Z'),
        "{out}"
    );
    assert!(
        lines[1][2].starts_with("deleted ") && lines[1][2].ends_with('Z'),
        "{out}"
    );
    assert!(!out.contains("one") && !out.contains("two"), "{out}");

    let missing = server
        .ferritor(&["versions", "app/none"], &[])
        .await
        .unwrap();
    assert!(!missing.success);
    server.stop().await.unwrap();
}

/// `ferritor restore` brings a deleted secret back: the newest deleted
/// version (only while none is live), or the one named.
#[tokio::test]
async fn restore_brings_a_deleted_secret_back() {
    let server = Server::start().await.unwrap();
    let init = server
        .ferritor(&["init", "--shares", "3", "--threshold", "2"], &[])
        .await
        .unwrap();
    for share in &shares(&init)[..2] {
        server.ferritor(&["unseal"], &line(share)).await.unwrap();
    }
    server.create_namespaces().await.unwrap();
    server.ferritor(&["put", "app/db"], b"one").await.unwrap();
    server.ferritor(&["put", "app/db"], b"two").await.unwrap();
    server.ferritor(&["delete", "app/db"], &[]).await.unwrap();

    let restored = server.ferritor(&["restore", "app/db"], &[]).await.unwrap();
    assert!(restored.success, "{}", restored.stderr);
    assert_eq!(restored.out(), "app/db version 2 restored\n");
    assert_eq!(
        server
            .ferritor(&["get", "app/db"], &[])
            .await
            .unwrap()
            .stdout,
        b"two"
    );
    // Version 2 is live: without --version, nothing more comes back.
    let live = server.ferritor(&["restore", "app/db"], &[]).await.unwrap();
    assert!(!live.success);
    assert!(live.stderr.contains("--version N"), "{}", live.stderr);
    let older = server
        .ferritor(&["restore", "app/db", "--version", "1"], &[])
        .await
        .unwrap();
    assert_eq!(older.out(), "app/db version 1 restored\n");
    let nothing = server
        .ferritor(&["restore", "app/db", "--version", "1"], &[])
        .await
        .unwrap();
    assert!(!nothing.success);
    assert!(
        nothing
            .stderr
            .contains("no deleted version 1 of `app/db` to restore"),
        "{}",
        nothing.stderr
    );
    server.stop().await.unwrap();
}

/// Rotate, rewrap (retires the old KEK), then destroy it: secrets still
/// read. The active KEK can't be destroyed, and the hint says what to do.
#[tokio::test]
async fn rotate_then_rewrap_retires_the_old_kek_and_destroy_kek_destroys_it() {
    let server = Server::start().await.unwrap();
    let init = server
        .ferritor(&["init", "--shares", "3", "--threshold", "2"], &[])
        .await
        .unwrap();
    for share in &shares(&init)[..2] {
        server.ferritor(&["unseal"], &line(share)).await.unwrap();
    }
    server.create_namespaces().await.unwrap();
    for path in ["app/a", "app/b", "app/c"] {
        server.ferritor(&["put", path], b"x").await.unwrap();
    }
    server
        .ferritor(&["rotate", "--namespace", "app"], &[])
        .await
        .unwrap();

    // One row per call: the CLI keeps going until the server says done.
    let rewrap = server
        .ferritor(&["rewrap", "--max-rows", "1"], &[])
        .await
        .unwrap();
    assert!(rewrap.success, "{}", rewrap.stderr);
    assert_eq!(rewrap.out(), "rewrapped: 3\nretired KEKs: app/1\n");
    assert!(rewrap.stderr.contains("so far"), "{}", rewrap.stderr);

    let again = server.ferritor(&["rewrap"], &[]).await.unwrap();
    assert_eq!(again.out(), "rewrapped: 0\nretired KEKs: none\n");
    let get = server.ferritor(&["get", "app/b"], &[]).await.unwrap();
    assert_eq!(get.stdout, b"x");

    // The namespace tells which version is retired, so may be destroyed.
    let get = server
        .ferritor(&["namespace", "get", "app"], &[])
        .await
        .unwrap();
    assert!(
        get.out()
            .contains("KEK versions: 1 retired, 2 active\nKEK floor: 1\n"),
        "{}",
        get.out()
    );
    let destroy = |version| ["destroy-kek", "--namespace", "app", version];
    let active = server.ferritor(&destroy("2"), &[]).await.unwrap();
    assert!(!active.success);
    assert!(
        active.stderr.contains("`app`'s active one") && active.stderr.contains("ferritor rotate"),
        "{}",
        active.stderr
    );
    let destroyed = server.ferritor(&destroy("1"), &[]).await.unwrap();
    assert!(destroyed.success, "{}", destroyed.stderr);
    assert_eq!(destroyed.out(), "destroyed KEK app/1\nKEK floor: 2\n");
    let again = server.ferritor(&destroy("1"), &[]).await.unwrap();
    assert_eq!(
        again.out(),
        "KEK app/1 was already destroyed\nKEK floor: 2\n"
    );
    let get = server.ferritor(&["get", "app/c"], &[]).await.unwrap();
    assert_eq!(get.stdout, b"x");
    let get = server
        .ferritor(&["namespace", "get", "app"], &[])
        .await
        .unwrap();
    assert!(
        get.out()
            .contains("KEK versions: 1 destroyed, 2 active\nKEK floor: 2\n"),
        "{}",
        get.out()
    );
    server.stop().await.unwrap();
}

/// PEM files for `--ca`/`--cert`/`--key`, in a fresh directory.
struct TlsFiles {
    dir: PathBuf,
}

impl TlsFiles {
    fn new(ca: &Ca, client: &Pem) -> TestResult<Self> {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ferritor-cli-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("ca.pem"), &ca.cert)?;
        std::fs::write(dir.join("cert.pem"), &client.cert)?;
        std::fs::write(dir.join("key.pem"), &client.key)?;
        Ok(Self { dir })
    }

    fn path(&self, name: &str) -> String {
        Path::new(&self.dir).join(name).display().to_string()
    }

    fn args<'a>(&'a self, args: &[&'a str], owned: &'a [String; 3]) -> Vec<&'a str> {
        let mut all = vec![
            "--ca",
            owned[0].as_str(),
            "--cert",
            owned[1].as_str(),
            "--key",
            owned[2].as_str(),
        ];
        all.extend_from_slice(args);
        all
    }

    fn paths(&self) -> [String; 3] {
        [
            self.path("ca.pem"),
            self.path("cert.pem"),
            self.path("key.pem"),
        ]
    }
}

impl Drop for TlsFiles {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).ok();
    }
}

/// `ferritor audit verify` checks a log the server wrote, offline (no server
/// settings needed: an https address without a certificate is ignored).
/// Its exit status is the verdict: 0 proven (every chain complete), 2
/// unproven (an open chain: a running server, a crash, a cut), 1 broken;
/// and a log spanning a key change needs both keys.
#[tokio::test]
async fn audit_verify_checks_a_log_offline() {
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::EncodePublicKey;
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;

    /// A server run: three decisions, and the shutdown drain unless
    /// `crashed`.
    async fn run(key: &SigningKey, crashed: bool) -> Vec<u8> {
        let audit = Captured::default();
        let (log, drain) =
            AuditLog::signed(audit.clone(), Duration::from_secs(5), key.clone()).unwrap();
        let gate = Gate::new(Arc::new(AllowAll), log);
        for _ in 0..3 {
            gate.check(&Caller::Unauthenticated, Action::Read, Target::System)
                .await
                .unwrap();
        }
        if !crashed {
            assert!(drain.wait(Duration::from_secs(5)).await);
        }
        audit.raw()
    }

    let key = SigningKey::from_bytes(&[3; 32]);
    let next_key = SigningKey::from_bytes(&[4; 32]);
    let clean = run(&key, false).await;

    let dir = std::env::temp_dir().join(format!("ferritor-cli-audit-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let public = |name: &str, key: &SigningKey| {
        let path = dir.join(name);
        std::fs::write(
            &path,
            key.verifying_key()
                .to_public_key_pem(LineEnding::LF)
                .unwrap(),
        )
        .unwrap();
        path.display().to_string()
    };
    let first = public("audit.pub.pem", &key);
    let second = public("next.pub.pem", &next_key);
    let verify = |keys: Vec<String>, input: Vec<u8>| async move {
        let mut args = vec!["audit".to_owned(), "verify".to_owned()];
        for key in keys {
            args.extend(["--public-key".to_owned(), key]);
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        run_ferritor("https://nowhere.invalid", &args, &input)
            .await
            .unwrap()
    };

    let proven = verify(vec![first.clone()], clean.clone()).await;
    assert_eq!(proven.code, Some(0), "{}", proven.stderr);
    assert!(
        proven
            .out()
            .contains(": 5 entries, complete: every entry signed"),
        "{}",
        proven.out()
    );

    // A crashed run (or one still running): open, its tail unsigned.
    let open = verify(vec![first.clone()], run(&key, true).await).await;
    assert_eq!(open.code, Some(2), "{}", open.stderr);
    assert!(
        open.out().contains("OPEN: no chain_end yet"),
        "{}",
        open.out()
    );
    assert!(
        open.out().contains("its last 4 entries are not signed"),
        "{}",
        open.out()
    );

    let edited = String::from_utf8(clean.clone())
        .unwrap()
        .replacen("\"read\"", "\"list\"", 1);
    let edited = verify(vec![first.clone()], edited.into_bytes()).await;
    assert_eq!(edited.code, Some(1));
    assert!(
        edited.out().contains("BROKEN at line 3"),
        "{}",
        edited.out()
    );

    // Across a key change: proven with both keys, unproven with one.
    let mut both = clean;
    both.extend(run(&next_key, false).await);
    let rotated = verify(vec![first.clone(), second], both.clone()).await;
    assert_eq!(rotated.code, Some(0), "{}{}", rotated.out(), rotated.stderr);
    let one = verify(vec![first], both).await;
    assert_eq!(one.code, Some(2));
    assert!(
        one.out()
            .contains("UNVERIFIABLE: signed by a key not given"),
        "{}",
        one.out()
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn the_cli_talks_tls_with_a_client_certificate() {
    let ca = Ca::new().unwrap();
    let server = Server::start_tls(&ca).await.unwrap();
    let files = TlsFiles::new(&ca, &ca.client("ops/alice").unwrap()).unwrap();
    let paths = files.paths();

    let status = server
        .ferritor(&files.args(&["status"], &paths), &[])
        .await
        .unwrap();
    assert!(status.success, "{}", status.stderr);
    assert_eq!(status.out(), "not initialized\n");
    server.stop().await.unwrap();
}

/// A short rate limit is waited out, once: the call is sent again after the
/// time the server gave, and its real answer comes through.
#[tokio::test]
async fn a_short_rate_limit_is_waited_out() {
    use ferritor_server::ratelimit::{Limits, Quota, Rate};
    use std::num::NonZeroU32;

    let ca = Ca::new().unwrap();
    let server = Server::start_tls(&ca).await.unwrap();
    let one = NonZeroU32::MIN;
    server.gate.use_limits(
        Limits::new(
            NonZeroU32::new(16).unwrap(),
            Quota {
                rate: Some(Rate::new(one, one)),
                max_in_flight: None,
                max_watch_streams: None,
            },
            Vec::new(),
        ),
        Duration::from_secs(5),
    );
    let files = TlsFiles::new(&ca, &ca.client("apps/web").unwrap()).unwrap();
    let paths = files.paths();
    let args = files.args(&["get", "app/db"], &paths);
    let get = || server.ferritor(&args, &[]);

    // Sealed, so refused either way; the first takes the only token.
    let first = get().await.unwrap();
    assert!(!first.stderr.contains("rate limited"), "{}", first.stderr);
    let second = get().await.unwrap();
    assert!(!second.success);
    assert!(
        second
            .stderr
            .contains("rate limited by the server (rate): retrying in"),
        "{}",
        second.stderr
    );
    assert!(
        second.stderr.contains("unseal it first"),
        "{}",
        second.stderr
    );
    server.stop().await.unwrap();
}

/// Mismatched options are caught before anything is sent.
#[tokio::test]
async fn tls_options_must_fit_the_address() {
    let ca = Ca::new().unwrap();
    let files = TlsFiles::new(&ca, &ca.client("ops/alice").unwrap()).unwrap();
    let [ca_path, cert_path, key_path] = files.paths();

    let plain_with_tls = run_ferritor("http://127.0.0.1:1", &["--ca", &ca_path, "status"], &[])
        .await
        .unwrap();
    assert!(
        plain_with_tls.stderr.contains("use an https:// address"),
        "{}",
        plain_with_tls.stderr
    );
    let https_without_cert =
        run_ferritor("https://localhost:1", &["--ca", &ca_path, "status"], &[])
            .await
            .unwrap();
    assert!(
        https_without_cert.stderr.contains("needs --cert and --key"),
        "{}",
        https_without_cert.stderr
    );
    let https_without_ca = run_ferritor(
        "https://localhost:1",
        &["--cert", &cert_path, "--key", &key_path, "status"],
        &[],
    )
    .await
    .unwrap();
    assert!(
        https_without_ca.stderr.contains("needs --ca"),
        "{}",
        https_without_ca.stderr
    );
    // --cert without --key is a usage error from the argument parser.
    let half = run_ferritor(
        "https://localhost:1",
        &["--cert", &cert_path, "status"],
        &[],
    )
    .await
    .unwrap();
    assert!(
        !half.success && half.stderr.contains("--key"),
        "{}",
        half.stderr
    );
}

/// A certificate from another CA is refused by the server.
#[tokio::test]
async fn a_client_certificate_from_another_ca_is_refused() {
    let ca = Ca::new().unwrap();
    let server = Server::start_tls(&ca).await.unwrap();
    let stranger = Ca::new().unwrap();
    // Trusts the right server CA, but presents a stranger's certificate.
    let files = TlsFiles::new(&ca, &stranger.client("ops/alice").unwrap()).unwrap();
    let paths = files.paths();
    let refused = server
        .ferritor(&files.args(&["status"], &paths), &[])
        .await
        .unwrap();
    assert!(!refused.success);
    assert!(
        refused
            .stderr
            .starts_with("error: can't reach the server at https://localhost:"),
        "{}",
        refused.stderr
    );
    assert!(
        refused.stderr.contains("the TLS handshake failed"),
        "{}",
        refused.stderr
    );
    server.stop().await.unwrap();
}

/// Over TLS (checked with a health call first), an unreachable server still gets the
/// unreachable hint, and a seal says plainly it didn't happen.
#[tokio::test]
async fn an_unreachable_tls_server_is_reported_as_unreachable() {
    let ca = Ca::new().unwrap();
    let files = TlsFiles::new(&ca, &ca.client("ops/alice").unwrap()).unwrap();
    let paths = files.paths();
    let status = run_ferritor("https://localhost:1", &files.args(&["status"], &paths), &[])
        .await
        .unwrap();
    assert!(
        status.stderr.contains(
            "hint: is the server running (--addr / FERRITOR_ADDR)? If it is, the TLS handshake failed"
        ),
        "{}",
        status.stderr
    );
    let seal = run_ferritor("https://localhost:1", &files.args(&["seal"], &paths), &[])
        .await
        .unwrap();
    assert!(seal.stderr.contains("did NOT seal"), "{}", seal.stderr);
}

/// A refused certificate must never look like a seal that may have
/// happened: the preflight makes "nothing was sent" certain.
#[tokio::test]
async fn a_seal_with_a_refused_certificate_did_not_seal() {
    let ca = Ca::new().unwrap();
    let server = Server::start_tls(&ca).await.unwrap();
    let stranger = Ca::new().unwrap();
    let files = TlsFiles::new(&ca, &stranger.client("ops/alice").unwrap()).unwrap();
    let paths = files.paths();
    let seal = server
        .ferritor(&files.args(&["seal"], &paths), &[])
        .await
        .unwrap();
    assert!(seal.stderr.contains("did NOT seal"), "{}", seal.stderr);
    assert!(
        !seal.stderr.contains("may already be sealed"),
        "{}",
        seal.stderr
    );
    server.stop().await.unwrap();
}

/// A real policy over TLS: an operator, and an application that may only
/// read under `billing`. Everything the application isn't granted is
/// refused, a seal included, and a rekey's nonce is hidden from it.
#[tokio::test]
async fn a_policy_decides_per_identity() {
    use ferritor_server::authz::Action as A;
    let rules = [
        Rule {
            name: None,
            identity: "ops/alice".to_owned(),
            actions: vec![
                A::Status,
                A::Init,
                A::Unseal,
                A::Seal,
                A::Rekey,
                A::Namespace,
                A::Read,
                A::Write,
                A::List,
            ],
            paths: vec![],
            all_paths: true,
        },
        Rule {
            name: None,
            identity: "apps/billing".to_owned(),
            actions: vec![A::Status, A::Read, A::List],
            paths: vec!["billing".to_owned()],
            all_paths: false,
        },
    ];
    let ca = Ca::new().unwrap();
    let server = Server::start_secured(&ca, Arc::new(Policy::new(&rules).unwrap()))
        .await
        .unwrap();
    let alice = TlsFiles::new(&ca, &ca.client("ops/alice").unwrap()).unwrap();
    let billing = TlsFiles::new(&ca, &ca.client("apps/billing").unwrap()).unwrap();
    let (alice_paths, billing_paths) = (alice.paths(), billing.paths());

    let init = server
        .ferritor(
            &alice.args(&["init", "--shares", "3", "--threshold", "2"], &alice_paths),
            &[],
        )
        .await
        .unwrap();
    for share in &shares(&init)[..2] {
        server
            .ferritor(&alice.args(&["unseal"], &alice_paths), &line(share))
            .await
            .unwrap();
    }
    for name in ["billing", "payroll"] {
        let create = server
            .ferritor(
                &alice.args(&["namespace", "create", name], &alice_paths),
                &[],
            )
            .await
            .unwrap();
        assert!(create.success, "{}", create.stderr);
    }
    // Managing namespaces is admin: not for the application.
    let create = server
        .ferritor(
            &billing.args(&["namespace", "create", "mine"], &billing_paths),
            &[],
        )
        .await
        .unwrap();
    assert!(
        create.stderr.contains("may not manage"),
        "{}",
        create.stderr
    );
    for path in ["billing/db", "payroll/db"] {
        let put = server
            .ferritor(&alice.args(&["put", path], &alice_paths), b"x")
            .await
            .unwrap();
        assert!(put.success, "{}", put.stderr);
    }

    // Billing reads its own secrets, and nothing else.
    let own = server
        .ferritor(&billing.args(&["get", "billing/db"], &billing_paths), &[])
        .await
        .unwrap();
    assert_eq!(own.stdout, b"x");
    let other = server
        .ferritor(&billing.args(&["get", "payroll/db"], &billing_paths), &[])
        .await
        .unwrap();
    assert!(
        other
            .stderr
            .contains("caller `apps/billing` may not read `payroll/db`"),
        "{}",
        other.stderr
    );
    let write = server
        .ferritor(&billing.args(&["put", "billing/db"], &billing_paths), b"y")
        .await
        .unwrap();
    assert!(write.stderr.contains("may not write"), "{}", write.stderr);
    let list_all = server
        .ferritor(&billing.args(&["list"], &billing_paths), &[])
        .await
        .unwrap();
    assert!(
        list_all.stderr.contains("may not list all secrets"),
        "{}",
        list_all.stderr
    );

    // Nor seal: refused, and the server stays unsealed.
    let seal = server
        .ferritor(&billing.args(&["seal"], &billing_paths), &[])
        .await
        .unwrap();
    assert!(seal.stderr.contains("did NOT seal"), "{}", seal.stderr);
    let status = server
        .ferritor(&alice.args(&["status"], &alice_paths), &[])
        .await
        .unwrap();
    assert!(status.out().starts_with("unsealed\n"), "{}", status.out());

    // A rekey's nonce: shown to the operator, hidden from the application.
    server
        .ferritor(
            &alice.args(
                &["rekey", "start", "--shares", "2", "--threshold", "2"],
                &alice_paths,
            ),
            &[],
        )
        .await
        .unwrap();
    let operator_view = server
        .ferritor(&alice.args(&["status"], &alice_paths), &[])
        .await
        .unwrap();
    assert!(
        operator_view.out().contains("rekey nonce: "),
        "{}",
        operator_view.out()
    );
    let app_view = server
        .ferritor(&billing.args(&["status"], &billing_paths), &[])
        .await
        .unwrap();
    assert!(
        app_view.out().contains("rekey: authorizing"),
        "{}",
        app_view.out()
    );
    assert!(
        !app_view.out().contains("rekey nonce"),
        "{}",
        app_view.out()
    );
    assert!(
        app_view
            .stderr
            .contains("shown only to callers allowed to rekey"),
        "{}",
        app_view.stderr
    );
    server.stop().await.unwrap();
}

/// Labels and metadata through the CLI: `put --label`, `metadata get`,
/// `set` and `unset`, `list --label`. A malformed label is refused before
/// anything is sent.
#[tokio::test]
async fn metadata_and_labels_from_the_cli() {
    let server = Server::start().await.unwrap();
    let init = server
        .ferritor(&["init", "--shares", "3", "--threshold", "2"], &[])
        .await
        .unwrap();
    for share in &shares(&init)[..2] {
        server.ferritor(&["unseal"], &line(share)).await.unwrap();
    }
    server.create_namespaces().await.unwrap();
    let put = server
        .ferritor(
            &["put", "app/a", "--label", "team=a", "--label", "env=prod"],
            b"x",
        )
        .await
        .unwrap();
    assert!(put.success, "{}", put.stderr);
    server.ferritor(&["put", "app/b"], b"y").await.unwrap();

    let get = server
        .ferritor(&["metadata", "get", "app/a"], &[])
        .await
        .unwrap();
    assert!(get.success, "{}", get.stderr);
    let out = get.out();
    assert!(out.starts_with("path: app/a\ncreated: "), "{out}");
    assert!(
        out.contains("current version: 1\noldest version: 1\nversions stored: 1\nlabels:\n  env=prod\n  team=a\nlabels updated: "),
        "{out}"
    );

    let set = server
        .ferritor(
            &["metadata", "set", "app/b", "team=a", "tier=v1.2_rc-3"],
            &[],
        )
        .await
        .unwrap();
    assert_eq!(set.out(), "labels:\n  team=a\n  tier=v1.2_rc-3\n");
    let unset = server
        .ferritor(&["metadata", "unset", "app/b", "tier"], &[])
        .await
        .unwrap();
    assert_eq!(unset.out(), "labels:\n  team=a\n");

    let listed = server
        .ferritor(&["list", "app", "--label", "team=a"], &[])
        .await
        .unwrap();
    assert_eq!(listed.out(), "app/a\tversion 1\napp/b\tversion 1\n");
    let prod = server
        .ferritor(&["list", "--label", "team=a", "--label", "env=prod"], &[])
        .await
        .unwrap();
    assert_eq!(prod.out(), "app/a\tversion 1\n");

    let bad = server
        .ferritor(&["metadata", "set", "app/b", "team"], &[])
        .await
        .unwrap();
    assert!(!bad.success);
    assert!(
        bad.stderr.contains("`team` is not a `key=value` label"),
        "{}",
        bad.stderr
    );
    let twice = server
        .ferritor(&["list", "--label", "t=a", "--label", "t=b"], &[])
        .await
        .unwrap();
    assert!(
        twice.stderr.contains("label `t` is given twice"),
        "{}",
        twice.stderr
    );
    server.stop().await.unwrap();
}

/// Namespaces from the CLI: create with labels, list, get, label and
/// unlabel; deleting one is refused while it has any secret, deleted ones
/// included (with the hint saying what to do), and goes through once they're
/// purged, destroying its KEK.
#[tokio::test]
async fn namespaces_from_the_cli() {
    let server = Server::start().await.unwrap();
    let init = server
        .ferritor(&["init", "--shares", "3", "--threshold", "2"], &[])
        .await
        .unwrap();
    for share in &shares(&init)[..2] {
        server.ferritor(&["unseal"], &line(share)).await.unwrap();
    }
    let created = server
        .ferritor(
            &["namespace", "create", "team-a", "--label", "owner=ops"],
            &[],
        )
        .await
        .unwrap();
    assert!(created.success, "{}", created.stderr);
    let again = server
        .ferritor(&["namespace", "create", "team-a"], &[])
        .await
        .unwrap();
    assert!(
        again.stderr.contains("namespace `team-a` already exists"),
        "{}",
        again.stderr
    );
    let labelled = server
        .ferritor(&["namespace", "label", "team-a", "tier=1"], &[])
        .await
        .unwrap();
    assert_eq!(labelled.out(), "labels:\n  owner=ops\n  tier=1\n");
    let unlabelled = server
        .ferritor(&["namespace", "unlabel", "team-a", "owner"], &[])
        .await
        .unwrap();
    assert_eq!(unlabelled.out(), "labels:\n  tier=1\n");
    // Recovery is only for a lost namespace with secrets left behind.
    let not_lost = server
        .ferritor(&["namespace", "create", "ghost", "--past-lost-keks"], &[])
        .await
        .unwrap();
    assert!(
        !not_lost.success && not_lost.stderr.contains("nothing was lost"),
        "{}",
        not_lost.stderr
    );
    let list = server.ferritor(&["namespace", "list"], &[]).await.unwrap();
    assert_eq!(list.out(), "team-a\tactive\tKEKs: 1 active; floor 1\n");
    let status = server.ferritor(&["status"], &[]).await.unwrap();
    assert!(
        status.out().ends_with("namespaces: 1\n"),
        "{}",
        status.out()
    );

    server.ferritor(&["put", "team-a/db"], b"x").await.unwrap();
    server
        .ferritor(&["delete", "team-a/db"], &[])
        .await
        .unwrap();
    let busy = server
        .ferritor(&["namespace", "delete", "team-a"], &[])
        .await
        .unwrap();
    assert!(!busy.success);
    assert!(
        busy.stderr.contains("1 rows, of which 1 deleted")
            && busy.stderr.contains("hint: nothing was deleted"),
        "{}",
        busy.stderr
    );
    // This server's retention is zero: purgeable at once.
    server.ferritor(&["purge"], &[]).await.unwrap();
    let deleted = server
        .ferritor(&["namespace", "delete", "team-a"], &[])
        .await
        .unwrap();
    assert_eq!(
        deleted.out(),
        "deleted namespace team-a\ndestroyed KEK versions: 1\nKEK floor: 2\n"
    );
    let again = server
        .ferritor(&["namespace", "delete", "team-a"], &[])
        .await
        .unwrap();
    assert_eq!(
        again.out(),
        "namespace team-a was already deleted\nKEK floor: 2\n"
    );
    let get = server
        .ferritor(&["namespace", "get", "team-a"], &[])
        .await
        .unwrap();
    assert!(
        get.out().contains("state: deleted\n") && get.out().contains("KEK versions: 1 destroyed\n"),
        "{}",
        get.out()
    );
    server.stop().await.unwrap();
}

/// A file in a fresh directory, for `ferritor policy apply -f`.
fn policy_file(name: &str, contents: &str) -> TestResult<PathBuf> {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ferritor-cli-policy-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(name);
    std::fs::write(&path, contents)?;
    Ok(path)
}

/// `ferritor policy`: apply from a TOML file and from JSON on stdin (a dry run
/// first), list, get, put, delete and check. A typo or an admin action in a
/// file is refused locally, before anything is sent. In dev mode nothing is
/// enforced, and check says so.
#[tokio::test]
async fn stored_policies_from_the_cli() {
    let server = Server::start().await.unwrap();
    let init = server
        .ferritor(&["init", "--shares", "3", "--threshold", "2"], &[])
        .await
        .unwrap();
    for share in &shares(&init)[..2] {
        server.ferritor(&["unseal"], &line(share)).await.unwrap();
    }
    server.create_namespaces().await.unwrap();

    let toml = policy_file(
        "policies.toml",
        r#"
[[policy]]
name = "apps/billing-read"
identity = "apps/billing"
actions = ["read", "list"]
paths = ["billing"]
description = "billing app, read only"
"#,
    )
    .unwrap();
    let toml = toml.display().to_string();
    let dry = server
        .ferritor(&["policy", "apply", "-f", &toml, "--dry-run"], &[])
        .await
        .unwrap();
    assert!(dry.success, "{}", dry.stderr);
    assert_eq!(
        dry.out(),
        "dry run: nothing was changed\ncreated: apps/billing-read\nupdated: none\n\
         deleted: none\nunchanged: 0\nrevision: 1\n"
    );
    let applied = server
        .ferritor(&["policy", "apply", "-f", &toml], &[])
        .await
        .unwrap();
    assert!(
        applied.out().starts_with("created: apps/billing-read\n"),
        "{}",
        applied.out()
    );

    let list = server.ferritor(&["policy", "list"], &[]).await.unwrap();
    assert_eq!(
        list.out(),
        "apps/billing-read\tstored\tapps/billing\tread,list\tbilling\n"
    );
    let get = server
        .ferritor(&["policy", "get", "apps/billing-read"], &[])
        .await
        .unwrap();
    assert!(
        get.out()
            .contains("description: billing app, read only\nversion: 1\n"),
        "{}",
        get.out()
    );

    // JSON on stdin, the JSON API's apply body: a change, and a new one.
    let json = br#"{"policies": [
        {"name": "apps/billing-read", "identity": "apps/billing",
         "actions": ["read"], "paths": ["billing"]},
        {"name": "apps/other", "identity": "apps/other", "actions": ["read"], "all_paths": true}
    ]}"#;
    let applied = server
        .ferritor(&["policy", "apply", "-f", "-", "--prune"], json)
        .await
        .unwrap();
    assert!(applied.success, "{}", applied.stderr);
    assert!(
        applied
            .out()
            .starts_with("created: apps/other\nupdated: apps/billing-read\n"),
        "{}",
        applied.out()
    );

    // Refused here, before anything is sent: nothing changes.
    for (contents, expected) in [
        (
            "[[policy]]\nname = \"a\"\nidentity = \"a\"\nactions = [\"read\"]\npathz = [\"x\"]\n",
            "unknown field",
        ),
        (
            "[[policy]]\nname = \"a\"\nidentity = \"a\"\nactions = [\"rotate\"]\nall_paths = true\n",
            "admin action",
        ),
        (
            "[[policy]]\nname = \"a\"\nidentity = \"a\"\nactions = [\"read\"]\n",
            "no scope",
        ),
    ] {
        let file = policy_file("bad.toml", contents).unwrap();
        let refused = server
            .ferritor(
                &[
                    "policy",
                    "apply",
                    "-f",
                    &file.display().to_string(),
                    "--prune",
                ],
                &[],
            )
            .await
            .unwrap();
        assert!(!refused.success);
        assert!(refused.stderr.contains(expected), "{}", refused.stderr);
    }
    let list = server.ferritor(&["policy", "list"], &[]).await.unwrap();
    assert_eq!(list.out().lines().count(), 2, "{}", list.out());

    let put = server
        .ferritor(
            &[
                "policy",
                "put",
                "apps/x",
                "--identity",
                "apps/x",
                "--action",
                "read",
                "--path",
                "billing",
            ],
            &[],
        )
        .await
        .unwrap();
    assert_eq!(put.out(), "created apps/x version 1\nrevision: 3\n");
    let refused = server
        .ferritor(
            &[
                "policy",
                "put",
                "apps/x",
                "--identity",
                "apps/x",
                "--action",
                "read",
                "--path",
                "billing",
                "--expected-version",
                "0",
            ],
            &[],
        )
        .await
        .unwrap();
    assert!(!refused.success);
    assert!(refused.stderr.contains("not 0"), "{}", refused.stderr);
    let deleted = server
        .ferritor(&["policy", "delete", "apps/x"], &[])
        .await
        .unwrap();
    assert_eq!(deleted.out(), "deleted apps/x\nrevision: 4\n");

    let allowed = server
        .ferritor(
            &[
                "policy",
                "check",
                "--identity",
                "apps/billing",
                "--action",
                "read",
                "--path",
                "billing/db",
            ],
            &[],
        )
        .await
        .unwrap();
    assert!(allowed.success);
    assert_eq!(allowed.out(), "allowed by apps/billing-read\n");
    assert!(
        allowed.stderr.contains("Not enforced (dev mode)"),
        "{}",
        allowed.stderr
    );
    let denied = server
        .ferritor(
            &[
                "policy",
                "check",
                "--identity",
                "apps/billing",
                "--action",
                "write",
                "--path",
                "billing/db",
            ],
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        (denied.code, denied.out()),
        (Some(1), "not allowed\n".to_owned())
    );
    server.stop().await.unwrap();
}

/// `ferritor identity`: no issuing CA, then one; a second init is refused;
/// rotate adds a key (the old one retired, or every old one revoked with
/// --now, saying so); status lists them all.
#[tokio::test]
async fn identity_creates_and_rotates_the_issuing_ca() {
    let server = Server::start().await.unwrap();
    let init = server
        .ferritor(&["init", "--shares", "3", "--threshold", "2"], &[])
        .await
        .unwrap();
    for share in &shares(&init)[..2] {
        server.ferritor(&["unseal"], &line(share)).await.unwrap();
    }
    let none = server.ferritor(&["identity", "status"], &[]).await.unwrap();
    assert!(none.success, "{}", none.stderr);
    assert!(none.out().starts_with("no issuing CA"), "{}", none.out());

    let created = server.ferritor(&["identity", "init"], &[]).await.unwrap();
    assert!(created.success, "{}", created.stderr);
    assert!(
        created.out().starts_with("issuing key 1: active, created "),
        "{}",
        created.out()
    );
    let again = server.ferritor(&["identity", "init"], &[]).await.unwrap();
    assert!(!again.success);
    assert!(again.stderr.contains("already exists"), "{}", again.stderr);

    let rotated = server.ferritor(&["identity", "rotate"], &[]).await.unwrap();
    assert!(
        rotated.out().starts_with("issuing key 2: active"),
        "{}",
        rotated.out()
    );
    let revoked = server
        .ferritor(&["identity", "rotate", "--now"], &[])
        .await
        .unwrap();
    assert!(
        revoked.out().starts_with("issuing key 3: active"),
        "{}",
        revoked.out()
    );
    assert!(revoked.stderr.contains("revoked"), "{}", revoked.stderr);

    let status = server.ferritor(&["identity", "status"], &[]).await.unwrap();
    let lines: Vec<String> = status.out().lines().map(str::to_owned).collect();
    assert_eq!(lines.len(), 3, "{lines:?}");
    // --now revoked the retired key too.
    assert!(lines[0].starts_with("issuing key 1: revoked, created "));
    assert!(lines[0].contains(", retired "));
    assert!(lines[1].starts_with("issuing key 2: revoked"));
    assert!(lines[2].contains("sha256 "));
    server.stop().await.unwrap();
}

/// Workload identity from the CLI: `--token-file` on a command exchanges
/// the token first, in memory; `ferritor login` writes the certificate and a
/// key only its user may read, for later commands; a refused token says
/// why, with a hint.
#[tokio::test]
async fn a_token_file_stands_in_for_a_certificate() {
    use std::os::unix::fs::PermissionsExt as _;

    let ca = Ca::new().unwrap();
    let files = TlsFiles::new(&ca, &ca.client("ops/alice").unwrap()).unwrap();
    let issuer = TokenIssuer::new(&files.dir).unwrap();
    let server = Server::start_exchanging(&ca, &issuer).await.unwrap();
    let paths = files.paths();
    let init = server
        .ferritor(
            &files.args(&["init", "--shares", "3", "--threshold", "2"], &paths),
            &[],
        )
        .await
        .unwrap();
    for share in &shares(&init)[..2] {
        let unseal = server
            .ferritor(&files.args(&["unseal"], &paths), &line(share))
            .await
            .unwrap();
        assert!(unseal.success, "{}", unseal.stderr);
    }
    let created = server
        .ferritor(&files.args(&["identity", "init"], &paths), &[])
        .await
        .unwrap();
    assert!(created.success, "{}", created.stderr);
    server.create_namespaces().await.unwrap();

    let token = files.path("token");
    std::fs::write(
        &token,
        issuer
            .token(&serde_json::json!({"repository_owner": "acme"}))
            .unwrap(),
    )
    .unwrap();
    let exchange = server.exchange.clone().unwrap();
    let with_token = |args: &[&'static str]| {
        let mut all = vec![
            "--ca".to_owned(),
            paths[0].clone(),
            "--token-file".to_owned(),
            token.clone(),
            "--exchange".to_owned(),
            exchange.clone(),
        ];
        all.extend(args.iter().map(|a| (*a).to_owned()));
        all
    };
    let put = with_token(&["put", "app/db"]);
    let put = server
        .ferritor(
            &put.iter().map(String::as_str).collect::<Vec<_>>(),
            b"hunter2",
        )
        .await
        .unwrap();
    assert!(put.success, "{}", put.stderr);

    let (cert, key) = (files.path("job.pem"), files.path("job-key.pem"));
    let login = with_token(&["login"]);
    let mut login: Vec<&str> = login.iter().map(String::as_str).collect();
    login.extend(["--cert-out", &cert, "--key-out", &key]);
    let logged_in = server.ferritor(&login, &[]).await.unwrap();
    assert!(logged_in.success, "{}", logged_in.stderr);
    assert!(
        logged_in
            .out()
            .starts_with("identity: ci/acme/job\nexpires: "),
        "{}",
        logged_in.out()
    );
    let mode = std::fs::metadata(&key).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    let get = server
        .ferritor(
            &[
                "--ca", &paths[0], "--cert", &cert, "--key", &key, "get", "app/db",
            ],
            &[],
        )
        .await
        .unwrap();
    assert!(get.success, "{}", get.stderr);
    assert_eq!(get.stdout, b"hunter2");

    std::fs::write(&token, "not a token").unwrap();
    let refused = with_token(&["get", "app/db"]);
    let refused = server
        .ferritor(&refused.iter().map(String::as_str).collect::<Vec<_>>(), &[])
        .await
        .unwrap();
    assert!(!refused.success);
    assert!(
        refused.stderr.contains("token exchange refused the token"),
        "{}",
        refused.stderr
    );
    server.stop().await.unwrap();
}
