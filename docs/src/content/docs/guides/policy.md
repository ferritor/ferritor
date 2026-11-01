---
title: 'Policy'
description: 'Who may do what on which paths: config rules for operators, stored policies for applications, the actions, and how the stored set is protected.'
seo:
  title: 'Access policy in ferritor: config rules and stored policies'
---

In secured mode two kinds of rules decide every request. Each grants one
identity (the `<name>` of a `ferritor://<name>` client certificate, see
[TLS](/guides/tls)) a list of actions, and for secret actions, the paths they
apply to. What a caller may do is the union of both.

| | config rules (`ferritor.toml`) | stored policies (keys database) |
|---|---|---|
| For | the operators, and anything that mustn't depend on the database | the applications |
| May grant | any action | secret actions only (read, write, delete, list, label) |
| Managed by | editing the file, then SIGHUP | `ferritor policy`, the gRPC `PolicyService` or the JSON API, with the `policy` action |
| In force | always (secret grants only matter unsealed) | while unsealed, once verified |
| Required in secured mode | at least one rule | none |

Admin rights change only on the host: a stored policy can't grant an admin
action, `policy` included, so the API can never create an admin, and the
way in (and back in) is always the config. Name operators `ops/…` and
applications `apps/…` as you like; the guarantee comes from the actions,
which the server checks, not from names.

## Config rules

```toml
[[policy]]
name = "ops-admin"         # optional: shown as config:ops-admin (unnamed: config:<n>)
identity = "ops/alice"
actions = ["status", "init", "unseal", "seal", "rekey", "rotate", "rewrap", "purge", "destroy_kek", "namespace", "policy", "identity"]

[[policy]]
identity = "ops/backup"    # a backup tool: mustn't depend on the database
actions = ["list"]
all_paths = true
```

Keep them small: the operators, and whatever must work while sealed or
without the stored policies (a monitoring identity's `status`: stored
grants don't apply while sealed, which is exactly when monitoring
matters).

## Stored policies

Named policies, each one identity, secret actions, a scope (path prefixes,
or every path) and a description:

```sh
ferritor policy put apps/billing-read --identity apps/billing \
    --action read --action list --path billing --description "billing app, read only"
ferritor policy list [--identity apps/billing]          # config rules too, as config:…
ferritor policy get apps/billing-read
ferritor policy delete apps/billing-read [--expected-version 3]
ferritor policy check --identity apps/billing --action read --path billing/db   # exit 0 if allowed
```

`put` creates or replaces, with check-and-set as for secrets
(`--expected-version 0` only creates, `N` only replaces version `N`).
Several policies may name the same identity: their grants add up. A
policy's name follows the secret-path rules (`apps/billing-read`); `:` is
never part of one, so it can't collide with a config rule's `config:…`.

### Apply: the declarative path

For automation, keep the set in a source of truth (git, CI) and apply it
whole, in one atomic call:

```sh
ferritor policy apply -f policies.toml --dry-run     # what would change
ferritor policy apply -f policies.toml [--prune]     # --prune deletes what the file doesn't list
ferritor policy apply -f - < policies.json           # JSON from stdin
```

```toml
# policies.toml: ferritor.toml's [[policy]] format, plus name and description
[[policy]]
name = "apps/billing-read"
identity = "apps/billing"
actions = ["read", "list"]
paths = ["billing"]
description = "billing app, read only"
```

JSON is the JSON API's apply body: `{"policies": [{"name": …, "identity":
…, "actions": […], "paths": […]}]}`. The CLI checks the file with the
server's own rules first (unknown keys, unknown or admin actions, invalid
names or paths, a name given twice), so a typo fails locally, before
anything is sent; the server checks again. Without `--prune`, apply never
deletes. One invalid policy refuses the whole call.

### Over the API

gRPC: `PolicyService` (`PutPolicy`, `DeletePolicy`, `GetPolicy`,
`ListPolicies`, `ApplyPolicies`, `CheckAccess`; actions are an enum of the
secret actions, so an admin action can't even be sent). JSON, on the same
port as everything else:

| Method and path | |
|---|---|
| `GET /v1/policies?identity=…&page_size=…&page_token=…` | list |
| `GET /v1/policies/{name}` | get |
| `PUT /v1/policies/{name}` | put; body `{"identity", "actions", "paths" or "all_paths", "description"?, "expected_version"?}` |
| `DELETE /v1/policies/{name}?expected_version=N` | delete |
| `POST /v1/policy-apply` | apply; body `{"policies": [...], "expected_revision"?, "prune"?, "dry_run"?}` |
| `GET /v1/policy-check?identity=…&action=…&path=…` | check |

```sh
curl --cacert ca.pem --cert ci.pem --key ci-key.pem -X POST \
  -H 'content-type: application/json' https://ferritor:7070/v1/policy-apply -d '{
  "policies": [{"name": "apps/billing-read", "identity": "apps/billing",
                "actions": ["read", "list"], "paths": ["billing"]}],
  "dry_run": true
}'
```

Bodies must be `application/json` (415 otherwise); an unknown field, an
unknown action or an admin action is refused (422, naming the field), so a
misspelled key can't silently drop a restriction. Errors and caching are as
for the secret endpoints; every body and error code is in the
[HTTP API](/reference/http-api) reference and `openapi.json`.
Every call needs the `policy` action; reading stored policies needs the
server unsealed.

Limits: 10 000 stored policies, 64 paths and a 1 KiB description per
policy, and an apply of up to all of them in at most 16 MiB (so the whole
set can always be sent at once). A description is printable ASCII
(letters, digits, spaces, punctuation), newlines and tabs: people decide
by it, and plain ASCII can't hide anything (no invisible, bidirectional or
look-alike characters, no emoji).

### When they're in force

A stored policy grants only while the server is unsealed and the stored set
verified (see "Integrity"). So:

- **Sealed is not denied.** A secret request only a stored policy could
  allow gets `SEALED` from a sealed server, audited as `"decision":
  "sealed"`, not `PERMISSION_DENIED`, so nobody chases a policy problem
  that's really a sealed server. Admin actions are the config rules' alone:
  one they don't allow is a plain denial, sealed or not.
- **Unverified is not denied either.** If the stored set doesn't verify, a
  request only it could allow gets `POLICY_UNVERIFIED` (`UNAVAILABLE`,
  audited as `"unverified"`); the config rules still work.
- **Changes reach every server** within `policy_refresh_secs` (default 5 s,
  one tiny read per poll), at once on the server that made them, on SIGHUP
  and at unseal. A revocation that can't wait: seal.

## Integrity

The stored policies live in the keys database, but writing that database
must not grant anyone access: otherwise a DBA, a stolen database password or
a SQL injection elsewhere on the same Postgres, plus any application's
client certificate, would read every secret through the normal API. So every
policy, and the set as a whole (with its revision), carries an HMAC under
the **policy key**, wrapped by the root key like a KEK (see
[key management](/operations/key-management)). The server verifies the set when it
loads it and never puts into force one that doesn't verify:

- A policy changed in the database (a path widened, an action added, the
  description changed), one inserted or deleted, the key cleared or changed,
  or everything wiped (key, set MAC and rows: only revision 0, before the
  first write, is a fresh start): the set doesn't verify. A running server
  keeps the set it last verified and alarms (logged as an error, audited as
  `policy_reload` with result `integrity`); after an unseal there's none in
  force (`POLICY_UNVERIFIED`). The whole set is re-checked once a minute, on
  its own schedule (independent of the revision poll and the keyring
  refresh), so a change that leaves the revision alone is caught within a
  minute. A failure is logged and audited once, when it starts or its
  condition changes (another policy failing, another revision, nothing in
  force any more: a keys database that keeps failing with different errors
  is one condition), and again when it ends (`recovered`); every attempt is
  counted in `ferritor.reloads` (kind `policy_store`).
- An older, validly signed set put back (a restored backup, a failover, a
  keys-database writer), or everything wiped back to revision 0: a server
  refuses a revision below one it verified (across seal and unseal, for the
  life of its process) or below the **policy revision floor**, the highest
  revision any server wrote, which the data database keeps
  (`policy_revision_floor`; every write raises it after committing, and
  any server that verifies a set above it raises it to that). So a
  restarted server refuses it too, and rolling the set back takes write
  access to both databases (`rollback`).
- Nothing builds on a set that doesn't verify: puts and deletes are refused,
  and only `ferritor policy apply --prune` with the whole set from its source of
  truth replaces it (and creates a new policy key if the old one is missing
  or won't open). Then find out who changed the keys database.

## Actions

Secret actions (on paths):

| Action | Allows |
|---|---|
| `read` | reading a secret's value |
| `write` | storing a new version, restoring a deleted one (and, with `max_versions`, pushing the oldest live version out) |
| `delete` | deleting every version of a secret |
| `list` | metadata only: listing paths under a prefix, a path's history and its metadata (labels included); never values |
| `label` | changing a path's labels (see [secrets](/guides/secrets)) |

Admin actions (on the server; config rules only):

| Action | Allows |
|---|---|
| `status` | the seal status, and how many namespaces and vanished KEKs (totals, no names) |
| `init` | initializing the seal |
| `unseal` | submitting (or resetting) unseal shares |
| `seal` | sealing |
| `rekey` | starting, submitting to, verifying or cancelling a rekey; also seeing its nonce in a status |
| `rotate` | rotating a namespace's KEK |
| `rewrap` | moving DEKs to the active KEK and retiring old versions |
| `purge` | removing deleted versions past their retention |
| `destroy_kek` | destroying a retired KEK version (irreversible); also needed to delete a namespace |
| `namespace` | creating, listing, inspecting, labelling and deleting namespaces (see [key management](/operations/key-management)) |
| `policy` | managing and reading the stored policies, and checking access |
| `identity` | creating, rotating and inspecting the workload-identity issuing CA (`ferritor identity`; see [workload identity](/guides/workload-identity)) |

Things worth knowing:

- **`policy` is powerful.** It can grant any application any data access
  (that's its point), though never an admin action. Grant it as narrowly as
  `destroy_kek`: an automation identity, a few operators.
- **`label` is separate from `write`.** An inventory or CI tool can tag
  secrets without being able to read or store values, and a put that sets
  labels needs both.
- **`list` is metadata.** A dashboard needs no `read`. A path's history is
  recorded as `list` on the path, so "who read this secret?" is answered by
  the `read` entries alone.
- **`write` can remove history.** With a version limit, `max_versions` puts
  push the oldest live versions out (deleted, then purged after the
  retention). Withholding `delete` protects the current secret, not old
  versions.
- **Cancelling a rekey needs only its nonce**, so it takes the same `rekey`
  permission as starting one, and only callers who may `rekey` see the nonce.
- **`seal` also discards a rekey in progress**, so it's an operator
  permission like `rekey`.
- **Namespaces are admin.** Creating one, and seeing which exist, takes
  `namespace` on the server, not a path grant: an application allowed to
  write under `billing` can't create `billing` nor learn of other
  namespaces. A put under a namespace that doesn't exist answers
  `NO_NAMESPACE` only to a caller allowed to write there; anyone else gets
  `PERMISSION_DENIED`, as for any path they may not write.
- **Deleting a namespace needs `destroy_kek` too.** It destroys the
  namespace's KEKs, which makes every data-database backup of its secrets
  undecryptable: as irreversible as destroying a KEK.
- **A path grant covers the path itself.** `paths = ["billing"]` covers the
  secret named exactly `billing` too, so its history is visible, although a
  listing of the prefix `billing` shows only what's strictly below it.

## Strict by design

- In the config, an unknown action is a startup error, and so is anything
  ambiguous (`all_paths = true` with `paths`, no actions, an invalid
  identity, path or name, a name used twice). A stored policy is refused
  the same way when it's written.
- A config rule without `paths` grants no secret access at all; a stored
  policy needs `paths` or `all_paths`; everything is `all_paths = true`,
  never an accident.
- An unauthenticated caller is always refused, so even a handshake bug can't
  turn into access.
- Dev mode enforces nothing (everyone may do everything); stored policies
  can still be managed there, and `check` evaluates them as secured mode
  would, but says "not enforced (dev mode)".

## Reloading and the audit log

SIGHUP reloads the config rules without a restart, and reloads the stored
policies too. Each check uses the rules in force; a call already authorized
finishes under the old. An invalid new config is refused and the running
one stays. The audit log names what's in force at startup and on every
change (`policy_loaded`, `policy_reload` with `source`: `config`,
`database` with the stored set's revision, or `seal` when a seal takes the
stored set out of force), so every decision falls between entries naming
the rules it ran under. Every stored-policy write is an outcome with the
policy as written (none of it is secret).
