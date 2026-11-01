---
title: 'Secrets'
description: 'Paths, versions, check-and-set, delete and restore, labels, watching for changes, and the gRPC and JSON APIs for secrets.'
seo:
  title: 'Secrets in ferritor: versions, labels and watching'
---

A secret is a path and a series of versions. Values are bytes, at most
1 MiB, the same limit for both APIs (so a value stored through one can
always be written back through the other).

## Paths

Segments of ASCII letters, digits, `.`, `_` and `-`, joined by `/`; no
leading, trailing or doubled `/`, no `.` or `..` segment; at most 512 bytes.
Anything else is refused with `INVALID_ARGUMENT`, never normalized: the
encryption binds the exact bytes of the path.

Prefixes match **whole segments**: `billing` covers `billing/db`, not
`billing2`. Listings and policy grants alike.

The first segment is the secret's **namespace**, which must exist: a put
under one that doesn't is refused with `FAILED_PRECONDITION`, reason
`NO_NAMESPACE` (told only to a caller allowed to write the path; anyone else
gets `PERMISSION_DENIED`). Operators create namespaces (`ferritor namespace
create`, see [key management](/operations/key-management)); each has its own KEKs.

## Versions

Every put stores a **new version**, with its own data key. Version numbers
start at 1 and are **never reused**, not after a delete, not after a purge:
a client that pins version 3 can't get a different secret that happens to
have that number.

- **Check-and-set.** A put with an expected version stores only if the
  latest live version is still that one; 0 means "only if there is none"
  (create only). Otherwise `VERSION_MISMATCH` and nothing is stored: read
  again, then decide.
- **Concurrent writes to one path** (puts, deletes, restores) take turns on
  a per-path lock, so none fails for losing a race (and without
  check-and-set, the last one wins). A write that waits longer than
  `lock_timeout_ms` for its turn is refused with `BUSY` (gRPC `ABORTED`,
  HTTP 409 `busy`) and stores nothing: retry it as is.
- **Version limit.** `max_versions` (default 10, 0 keeps all) keeps only the
  newest N live versions per path: each put marks older ones deleted, in the
  same transaction, which then go the way of any deleted version. It applies
  to existing secrets on their next put, and never touches the latest
  version. Each put's audit entry says how many it trimmed.
- **Delete** is soft: every version is marked deleted and hidden.
- **Restore** makes a deleted version live again, within the retention:
  - with a version: that one, alongside any live version (an older or a
    trimmed one);
  - without: undoes a delete, restoring the newest deleted version, only
    while the path has no live version (else `LIVE_VERSION`, nothing
    restored). Older ones stay deleted.

  Either way, retrying a restore whose outcome was unclear is safe.
- **History** lists every version still stored, live or deleted (with when),
  newest first, metadata only. It needs `list` on the path, not `read`.
- **Purge** removes deleted versions for good once they're past the
  retention (`purge_deleted_after_days`, default 30, a server setting so a
  caller can't purge recent deletions). It never touches a live version and
  never frees a version number. Run it from cron or a systemd timer; see
  [operations](/operations/running).

## Metadata and labels

A path as a whole has metadata, never its values:

| Field | |
|---|---|
| created | when the path was first written |
| updated | when it was last written by a put (a new version, e.g. a rotation) |
| current version | the latest live version; none if every version is deleted |
| oldest version | the oldest version still stored (live or deleted, not purged) |
| versions stored | how many, live and deleted |
| labels | custom `key=value` metadata (`team=a`, `project=b`) |
| labels updated | when the labels last changed |

Reading it needs `list` on the path, like the history. A path with nothing
stored (never written, or every version purged) is `NOT_FOUND`.

**Labels** are free-form tags for inventory, ownership, filtering.

> [!WARNING]
> Labels are **plain metadata, not encrypted**, readable by anyone allowed
> to list the path: never put a secret in a label.

- Keys and values: ASCII letters, digits, `-`, `_` and `.`, beginning and
  ending with a letter or digit, 1 to 63 characters
  (`([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]`, never empty). So nothing
  invisible or confusable fits in a label. At most 64 per path.
  Anything else is refused, never rewritten, and so is a change that sets
  and removes nothing.
- Changing them needs the **`label`** action (see [policy](/guides/policy)): a
  tool can tag secrets without being able to read or write their values,
  and a writer can store values without being able to change tags.
- A change merges: labels to set are added or replace a value, keys to
  remove are removed. Concurrent changes compose. A put can set labels too,
  in the same transaction as the new version (needing `label` as well as
  `write`).
- Labels belong to the path, not a version: a new version keeps them, and
  they survive a delete like the history does. They're only for paths with
  something stored, and **purging a path's last version removes its labels
  too**: a purged secret is gone for good, its metadata included (only its
  version numbers stay used). A label change that lands while a purge is
  removing the path's last version is removed with it.
- Listings can filter by labels: only paths whose labels include every one
  asked for.
- The audit log records which keys were set and removed, never their
  values.

## The CLI

```sh
echo -n 'value' | ferritor put app/db             # all of stdin, byte for byte
ferritor put app/db                                # on a terminal: one hidden line
ferritor put app/db --expected-version 3 < file    # check-and-set (0: create only)
ferritor get app/db                                # the latest value, raw bytes
ferritor get app/db --version 2
ferritor list app                                  # the latest version of everything below app/
ferritor versions app/db                           # the history
ferritor delete app/db
ferritor restore app/db                            # undo a delete
ferritor restore app/db --version 2                # bring back a deleted or trimmed version

ferritor put app/db --label team=a < file          # set labels with a put (repeatable)
ferritor metadata get app/db                       # created, updated, versions, labels
ferritor metadata set app/db team=a project=b      # add or replace labels
ferritor metadata unset app/db project             # remove labels
ferritor list app --label team=a                   # only secrets with these labels
```

Values are never command-line arguments (shell history, `/proc/*/cmdline`).
`ferritor put` refuses an empty value unless `--allow-empty`: empty input from a
script is more likely an accident. `ferritor list` fetches every page.

## The gRPC API

`SecretsService` in `proto/ferritor/v1/ferritor.proto`: `GetSecret`, `PutSecret`
(with `expected_version` and `labels`), `DeleteSecret`, `RestoreSecret`,
`ListSecrets` (with a `labels` filter), `ListVersions`, `GetMetadata`,
`UpdateLabels`. Listings are paginated: page size 0 means 100, anything
above 1000 is capped, and an empty `next_page_token` is the last page. A
page token is opaque, and can never widen a listing beyond the prefix it
came from.

## Watching

`WatchSecrets` (gRPC only) streams the changes of what it names, so a
client hears of a new version without polling: up to 1,024 `paths` and
`prefixes` together, each path needing `read` and each prefix `list`
(checked, and audited, when the stream opens). A deleted path's change has
version 0 (no live version). The stream sends:

- `ready` first, once the server's change feed is live: from then on no
  change is missed. Read what you watch once after it, since anything
  before it isn't told.
- `changed` (`path`, `version`): a path's live version moved (a put, a
  delete, a restore). It carries no value: read it. A label change isn't
  told.
- `resync`: changes may have been missed (the stream fell 4,096 changes
  behind, or more than 10,000 changed at once): read everything again.

Changes come from every server, not only the one serving the stream: each
server asks the data database every 250 ms what changed since it last
asked, so a change arrives within about that. The stream ends with an error
at a seal (`SEALED`), when the client certificate expires
(`UNAUTHENTICATED`), when the server shuts down (`UNAVAILABLE`), and when a
permission it was opened with is gone. Permissions are asked again before
each change is sent, and every 30 s, with the certificate (expiry,
revocation, its issuing CA). The repeated questions aren't written to the
audit log; a refusal is, and ends the stream. Reconnect, then read again.
An identity may have 256 streams open on a server
([`max_watch_streams`](/reference/configuration)), and a server serves at most 4,096
in all; one more is `RESOURCE_EXHAUSTED` with reason `WATCH_FULL` (and
`limit`, `identity` or `server`, in its `ErrorInfo`).

A watch is a way to learn sooner, not a replacement for reading: a
stream can end at any time, and what changed meanwhile isn't told. The
[agent](/guides/agent) keeps its rounds beside it (further apart while the
stream is up); the [CSI provider](/guides/csi) trusts its cached reads
only while its stream is up.

## The JSON API

On the same port as gRPC, sharing TLS, identity, the policy, the audit log
and the seal rules: `GET`/`PUT`/`DELETE /v1/secrets/{path}`, `POST
/v1/restore/{path}`, `GET /v1/secrets` (listing), `GET /v1/versions/{path}`
and `GET`/`PATCH /v1/metadata/{path}`. Values are base64, unknown fields and
query parameters are refused, and errors carry a `code` to match on.

The full reference, with authentication (mutual TLS) and examples in curl,
Python, Node and Go, every body and every error code, is
[HTTP API](/reference/http-api); the machine-readable description is
`openapi.json`.

## While sealed

Every secret operation is refused with `SEALED` (HTTP 503 `sealed`), and a
seal stops operations in flight: they fail and keep nothing.
