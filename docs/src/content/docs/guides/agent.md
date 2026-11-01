---
title: 'The agent'
description: 'ferritor-agent keeps an application''s secrets current as files: its settings, the directory, notifications, refusals, and running it in Kubernetes or systemd.'
seo:
  title: 'ferritor-agent: keeping secrets current as files'
---

`ferritor-agent` reads an application's secrets and keeps them current as
plain files, one per secret, for applications that read their
configuration from files (most do) and shouldn't have to talk to ferritor
themselves. It runs next to the application: as a sidecar in Kubernetes,
or as a service on its host.

```
/run/secrets/app/
  db-password       the value, byte for byte
  tls.crt
  tls.key
```

In Kubernetes, [the CSI provider](/guides/csi) does the same once per node,
for every pod there, through the Secrets Store CSI Driver, instead of an
agent per pod; each pod still reads with its own identity.

It's an ordinary ferritor client: it reads with its own client certificate,
under that identity's policies, rate limits and audit log, and needs only
`read` on the paths it renders (and `list` with `detect = "list"`, below).
The certificate comes from files, or from the server's token exchange for
a platform token ([workload identity](/guides/workload-identity)), which the agent
renews itself.

## Running it

```sh
ferritor-agent once --config /etc/ferritor-agent/app.toml   # render, then exit
ferritor-agent run  --config /etc/ferritor-agent/app.toml   # render, then keep current
```

| Mode | Does | Exits |
|---|---|---|
| `once` | renders every output once | 0 when every required secret is written; 1 at once if the server refuses a required one for good (permission denied, not found), or after `--wait-secs` (default 60) of transient failures (unreachable, sealed, rate-limited) |
| `run` | renders, then polls every interval (and watches, below) and rewrites what changed | 0 on SIGTERM or SIGINT; the files stay as they are |

`--config` can also come from `FERRITOR_AGENT_CONFIG`. A configuration
mistake refuses to start, saying what and where. Logs go to stderr
(`FERRITOR_AGENT_LOG`, an `EnvFilter`, default `info`), never a value: paths,
versions and refusals only. Like the server, the agent marks itself
undumpable before reading anything, so the application next to it can't
read its memory or its key through `/proc`, even as the same user.

## Configuration

```toml
server = "https://ferritor.internal:7070"
ca = "/etc/ferritor/ca.pem"                       # to verify the server with
cert = "/var/run/ferritor-identity/tls.crt"       # the agent's ferritor://<name> certificate
key = "/var/run/ferritor-identity/tls.key"
interval_secs = 60
detect = "get"

[[output]]
dir = "/run/secrets/app"
on_change = { signal = "HUP", pid_file = "/run/app/app.pid" }

[[output.secret]]
path = "billing/app/db-password"               # the file is `db-password`

[[output.secret]]
path = "billing/app/tls/cert"
file = "tls.crt"

[[output.secret]]
path = "billing/app/tls/key"
file = "tls.key"
mode = 0o400
```

Top level:

| Key | Default | |
|---|---|---|
| `server` | (required) | `https://…`, or `http://…` for a dev-mode server on loopback |
| `ca` | (required with https) | PEM: the CA that signed the server's certificate. Watched |
| `cert`, `key` | (with https: these, or `token_file` and `exchange`) | PEM files: the agent's client certificate and key. Watched: replaced on disk (a renewal), they're used from the next round on |
| `token_file` | | [Workload identity](/guides/workload-identity): a platform token (a projected service account token), read anew at each exchange |
| `exchange` | | with `token_file`: the server's token exchange (its `[identity] listen_addr`), `https://`, verified with `ca` |
| `interval_secs` | 60 | between rounds, 5 to 86,400, spread by ±10 % so agents started together don't poll in step |
| `detect` | `get` | how changes are found (below): `get` or `list` |
| `watch` | true | keep a watch stream open beside the rounds, to hear of a change at once (below) |

`[[output]]`, one directory swapped as a set:

| Key | Default | |
|---|---|---|
| `dir` | (required) | absolute; created (`0750`) if missing; must be in memory (tmpfs, ramfs) |
| `allow_disk` | false | allow a directory that isn't in memory: the values then reach a disk |
| `group` | the directory's | the files' and directories' group (numeric). The agent must be a member: it has no `CAP_CHOWN`. In Kubernetes, leave it unset and use the pod's `fsGroup` |
| `mode` | `0o440` | its files' mode, unless a secret gives its own. Never any permission for others (refused): share through the group |
| `on_revoked` | `keep` | its secrets' default (below) |
| `list_prefix` | the secrets' parents | with `detect = "list"`: the one prefix to list (below) |
| `on_change` | nothing | how the application learns of a change (below) |

`[[output.secret]]`, one file:

| Key | Default | |
|---|---|---|
| `path` | (required) | the secret |
| `file` | the path's last segment | the file's name: no `/`, not starting with `..` (the agent's own names) |
| `mode` | the output's | |
| `version` | the latest | pin to this version: read once, never refreshed |
| `required` | true | the first set isn't written without it, and `once` fails without it |
| `on_revoked` | the output's | `keep` or `remove` (below) |
| `detect` | the top level's | per secret, e.g. `get` for one path under `list` |

With `token_file`, the agent exchanges the token for a certificate before
its first round, keeps the certificate and its key in memory only, and
exchanges again two thirds into the certificate's life, and after any
failed round (the certificate may be what was refused: its issuing key
revoked, a cutoff). A failed exchange keeps the current certificate while
it's valid, retried every 30 s; with none valid, the round fails as
transient, and the next try waits at least as long as the server said (an
exchange rate-limited because many replicas of one identity started
together: see [workload identity](/guides/workload-identity#the-exchange)).

## The directory

```
/run/secrets/app/
  ..2026_10_24_10_02_11.123456789.3/   one generation: every file, as written
  ..data -> ..2026_10_24_10_02_11.123456789.3
  db-password -> ..data/db-password
  tls.crt -> ..data/tls.crt
  ..status.json
```

The layout of Kubernetes Secret volumes. Each write creates a new
generation (every file written and synced, with its mode and group set
before anything points at it), then swaps `..data` onto it in one rename,
then adds the names of new files and removes those no longer configured.
The previous generation stays until the next write; older ones, and
anything a stopped agent left half-written, are removed.

**Only the agent may write the directory.** The agent trusts what it
finds there: where `..data` points, which names are its own. It refuses to
follow `..data` anywhere but one of its own generations in the directory,
and removes nothing else, but a writer there can still plant names that
make its renders fail, or swap files under the application. So the
application, and anything else in the pod or on the host, reads the
directory and never writes it: mounted read-only in Kubernetes, owned by
the agent's user with only group read and enter under systemd (below).

**Reading files that must match.** Each file is always whole. A set is
consistent only for a reader that resolves `..data` once and reads every
file under that directory:

```python
base = os.path.join(dir, os.readlink(os.path.join(dir, "..data")))
cert = open(os.path.join(base, "tls.crt")).read()
key = open(os.path.join(base, "tls.key")).read()
```

Opening `tls.crt` and then `tls.key` by their visible names resolves
`..data` twice, and a write between the two gives the old certificate and
the new key. That's true of Kubernetes Secret volumes too.

**The first set** is written once every required secret has a value
(optional ones may be missing); a later write happens only when something
changed.

**`..status.json`** is written next to the set, never in it, with a mode
the files' readers share:

```json
{
  "last_success": "2026-10-24T10:02:11Z",
  "last_error": null,
  "rendered": true,
  "secrets": [
    { "path": "billing/app/db-password", "file": "db-password", "version": 4, "refused": null }
  ]
}
```

`refused` is `permission_denied`, `not_found` or `invalid` while the
server refuses that secret for good; `version` is the version in its file,
if any.

## Telling the application

An application that reads its files once at start needs telling. Per
output, after every write but the first (at the first, the application
usually hasn't started):

| `on_change` | |
|---|---|
| (unset) | nothing: the application re-reads the files itself (watching `..data`, or reading on each use) |
| `{ signal = "HUP", pid_file = "/run/app/app.pid" }` | a signal (`HUP`, `INT`, `TERM`, `USR1`, `USR2`) to the pid in the file. Whoever can write the file chooses which process gets the signal (any the agent may signal, itself included): only the application may write it |
| `{ signal = "HUP", process = "nginx" }` | the signal to every process with that name |
| `{ command = ["systemctl", "reload", "app"] }` | a command, in the background, logged if it fails or runs past 60 s |

Across containers: a signal reaches the application only with a shared
process namespace (`shareProcessNamespace: true`), and only if the agent
may signal it (the same UID, or `CAP_KILL`). A command runs in the agent's
own environment, which for a sidecar is its own container, where the
application's tools usually aren't; in the agent's image there's nothing
but the agent ([development](/contributing/development#images)), so use a
signal there.

## Finding changes

| `detect` | Each round | Needs |
|---|---|---|
| `get` (default) | reads every secret | `read` |
| `list` | lists each prefix, then reads only the secrets whose version moved | `read`, and `list` on the prefixes |

Every call is an audited decision, and with `get` every round also
transfers and decrypts every value. So for large fleets `list` costs far
less (1,000 agents with 5 secrets each, every 60 s: 83 lines per second
with `get`, 17 with `list`, plus a line per changed secret). With a watch
stream up (below), rounds come ten times less often: 8 and 2. A listing
covers everything below its prefix and is paged (up to 1,000 paths a
page, each page a call); the agent warns when one takes more than a page.

The prefixes are the secrets' parents (`billing/app/tls/cert` lists
`billing/app/tls`), or the output's `list_prefix`. A parent can be much
broader than the secrets: `billing/db-password`'s is all of `billing`.
Keep an application's secrets under a prefix of their own
(`billing/app/…`), or set `list_prefix` to the narrowest one that covers
them. A single-segment path has no parent but everything: refused with
`list` unless `list_prefix` is set or the secret uses `detect = "get"`.

With `list`, a secret missing from its listing has no live version: it's
treated as deleted. A `read` revoked while `list` stays is noticed only
when the secret's version next moves.

**Watching.** In `run`, the agent also keeps a
[watch stream](/guides/secrets#watching) open on its secrets' paths (not the
pinned ones, nor those refused), and reads a secret as soon as the stream
says its version moved: a change reaches the files within a second or so
instead of an interval. A stream's start, and a `resync`, run a round at
once (what changed before it isn't told). The rounds go on beside it as
a safety net, ten intervals apart while the stream is up (at most ten
minutes apart, never further apart than without it: an `interval_secs`
of an hour stays an hour), and back to the interval as soon as it ends.
So an interval doesn't need shortening for speed, and raising it costs no
freshness while the stream is up. A refused secret keeps its own backoff
either way. A stream that can't be opened or ends is opened again after
1 s, doubling to the interval, logged each time (`no watch stream`);
meanwhile the rounds alone keep the files current. Opening it costs an audited decision per
path; an open stream costs nothing in the log until something changes.
`once` doesn't watch; `watch = false` turns it off. Each agent's stream
counts toward its identity's `max_watch_streams` on the server it reached
(256 by default): replicas sharing an identity past that get no stream
(`WATCH_FULL`) and poll; raise it for them in the server's
[`[[rate_limit.identity]]`](/reference/configuration).

## Failures

**Transient** (the server unreachable or timing out, sealed, its stored
policies unverified, rate-limited, the client certificate refused): nobody
decided anything about the secrets. The round stops, every file stays, and
the next try comes after 1 s, doubling up to the interval, never before
the server's own retry time.

**Authoritative** (permission denied, not found, the namespace gone):
someone decided. That secret alone backs off: one interval from the first
refusal, then two, four, up to ten intervals, never back to a second, while
the other secrets carry on. Its file follows `on_revoked`:

- `keep` (default): the last value stays in its file, and the status says
  it's refused. The application keeps working, with a value its identity
  may no longer read.
- `remove`: the file goes at the next write; it comes back when the secret
  is readable again.

**Replicas share their identity's limits.** Rate limits and the budget of
denied requests are per identity, per server (see
[operations](/operations/running#rate-limits)): the replicas of a deployment
with one identity share them. The long backoff is what keeps fifty
replicas with a path they may not read from using up the shared budget of
denials, after which the server would refuse their allowed reads too (and
none would finish its first render). A rollout with a missing grant
therefore costs one denied read per replica per backoff step.

## Kubernetes

The image is a release's, `ghcr.io/ferritor/ferritor-agent:<version>`,
or your own, built with the repository's `Dockerfile` (`docker build
--target agent`, see [development](/contributing/development#images));
below it's `registry.example/ferritor-agent`.

```yaml
spec:
  securityContext:
    fsGroup: 2000                     # the files' group, for the application
  volumes:
    - name: secrets
      emptyDir:
        medium: Memory                # tmpfs: the values never reach a disk
        sizeLimit: 1Mi
    - name: ferritor-identity
      projected:                      # workload identity: a token for ferritor, rotated by the kubelet
        sources:
          - serviceAccountToken:
              audience: ferritor
              expirationSeconds: 3600
              path: token
    - name: ferritor-agent-config
      configMap:
        name: app-ferritor-agent
  initContainers:
    - name: ferritor-agent-once          # the files exist before the application starts
      image: registry.example/ferritor-agent
      args: ["once", "--config", "/etc/ferritor-agent/app.toml"]
      volumeMounts: &agent-mounts
        - { name: secrets, mountPath: /run/secrets/app }
        - { name: ferritor-identity, mountPath: /var/run/ferritor-identity, readOnly: true }
        - { name: ferritor-agent-config, mountPath: /etc/ferritor-agent, readOnly: true }
    - name: ferritor-agent               # a native sidecar (Kubernetes 1.29+): runs alongside
      image: registry.example/ferritor-agent
      restartPolicy: Always
      args: ["run", "--config", "/etc/ferritor-agent/app.toml"]
      volumeMounts: *agent-mounts
  containers:
    - name: app
      volumeMounts:
        - { name: secrets, mountPath: /run/secrets/app, readOnly: true }
```

- **The secrets volume is the agent's to write.** The application mounts
  it `readOnly: true`, and no other container mounts it writable: an
  `emptyDir` is created writable by everyone in the pod (`0777`), so the
  mount is what keeps them out (see "Only the agent may write the
  directory", above).
- **The token is mounted into the agent only**, never the application: a
  compromised application has the values it was given, not the means to
  fetch more. Its identity's policies should grant exactly what the agent
  renders. The agent's config then has `token_file =
  "/var/run/ferritor-identity/token"` and `exchange`, not `cert` and `key`
  ([workload identity](/guides/workload-identity); the identity is the service account's,
  through the issuer's mapping).
- **Or a certificate from files** (cert-manager, say): mount its Secret at
  the same place, into the agent only, and set `cert` and `key`. Renewed in
  place, it's picked up at the next round.
- **One identity per deployment** is usual: its replicas share it, and its
  limits per server (above). One per pod if each replica must be told
  apart in the audit log.
- Kubernetes nodes usually run without swap; a memory-backed `emptyDir` is
  tmpfs, whose pages could otherwise be swapped out.

## systemd

```ini
# /etc/systemd/system/app-secrets.service
[Unit]
Description=ferritor-agent for app
After=network-online.target
Wants=network-online.target

[Service]
ExecStartPre=/usr/local/bin/ferritor-agent once --config /etc/ferritor-agent/app.toml
ExecStart=/usr/local/bin/ferritor-agent run --config /etc/ferritor-agent/app.toml
User=ferritor-agent
Group=app                             # the application's group reads the files
RuntimeDirectory=secrets/app          # /run/secrets/app, a tmpfs, removed on stop
RuntimeDirectoryMode=0750
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Order the application `After=app-secrets.service` with `Requires=`, so it
starts once the first set is written (`ExecStartPre` holds the unit back
until then). The directory is owned by the agent's user, mode `0750`: the
application's group reads it and can't write it. Never run the agent and
the application as the same user, which would let the application write
the directory (and signal or read the agent, undumpable or not, as its
own user can). The no-swap and hardening advice for the server
([production](/getting-started/production#6-run-it)) applies here too: `/run` is tmpfs,
whose pages can be swapped out on a host with swap.

## Security

- **The files are the secret now.** Whoever can read them (the
  application's user or group, root, the node's or host's administrators)
  has the values; the audit log records the agent's reads, not the
  application's use of the files.
- **Revoking access doesn't take back a value already delivered.** With
  `on_revoked = "keep"`, the application keeps a value its identity may no
  longer read for as long as it runs. To cut a workload off: rotate the
  secret itself (the old value stops working where it's checked), restart
  the workload, or use `on_revoked = "remove"`.
- **In memory**: the agent's own copies of a value are wiped when dropped;
  the gRPC and TLS layers' buffers aren't (see
  [security](/concepts/security#known-gaps), gap 3).
- **The agent's certificate** grants what its identity's policies grant;
  keep them exact. From files, it's in the agent's container (in
  Kubernetes, a Secret mounted there, and so in etcd). Exchanged, only the
  token is: the key is generated in the agent and never leaves its memory,
  and the certificate lives an hour.

## Not yet

- **Templating**: several secrets in one file (a config file, a combined
  certificate and key), which would also make matching files one read.
- **Environment variables** (`exec`: start the application with its
  secrets in its environment): values fixed for the process's life, so it
  needs a freshness story of its own.
- **Metrics**: the status file and the logs are what there is.
