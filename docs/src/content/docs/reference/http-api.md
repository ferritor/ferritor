---
title: 'HTTP API'
description: 'The JSON API: mutual TLS with curl, Python, Node and Go, every endpoint, body and error code.'
seo:
  title: 'ferritor HTTP API: JSON over mutual TLS, every endpoint'
---

A JSON API on the same port as gRPC (`listen_addr`), sharing TLS, identity,
the policy, the audit log and the seal rules: both call the same code, so
they answer alike. It covers secrets and the stored policies; everything
else admin (init, unseal, seal, rekey, rotate, rewrap, purge, namespaces) is
gRPC only, through the `ferritor` CLI.

The machine-readable description is `openapi.json`
(OpenAPI 3.1): open it in Swagger UI or Redoc, or generate a client from it.
It's generated from the server's code (the handlers and the very types it
parses and answers with), so its bodies and parameters are what the server
takes: a test fails while the file is out of date, another while an
operation in it doesn't reach a handler, and a third while a limit it states
isn't the server's.

## Authentication

**Mutual TLS, nothing else.** There are no tokens, API keys or passwords: a
caller is the identity in its client certificate, a single URI SAN
`ferritor://<name>` (`ferritor://apps/billing` is `apps/billing`), and the
[policy](/guides/policy) decides what that identity may do. The certificate must
be issued by a CA in `[tls] client_ca`, valid now, not revoked, and carry
the `clientAuth` extended key usage (see [TLS](/guides/tls); how to make one:
[production](/getting-started/production)).

What a client needs: the CA that signed the **server's** certificate (to
verify the server), and its own certificate and key (to identify itself).

- **No client certificate**: the TLS handshake fails; there's no HTTP
  answer at all (curl: exit 55 or 56; other clients: a connection or SSL
  error).
- **A certificate the handshake accepts but that names no valid identity
  now** (expired, revoked, no or several `ferritor://` SANs): `401
  unauthenticated`, audited.
- **A valid identity the policy doesn't allow**: `403 permission_denied`.

Expiry and revocation are checked on every request, not only at the
handshake, so a long-lived connection can't outlive its certificate.

**Dev mode** (no `[tls]`): plaintext, everyone may do everything, and the
server only answers requests addressed to `localhost` or a loopback IP
(`421 misdirected_request` otherwise). For development only.

### curl

```sh
curl --cacert server-ca.pem --cert apps-billing.pem --key apps-billing-key.pem \
  https://ferritor.example.internal:7070/v1/secrets/billing/db
```

### Python (standard library)

```python
import base64, json, ssl, urllib.request

BASE = "https://ferritor.example.internal:7070"

# Trust the server's CA, and present the client certificate (mTLS).
context = ssl.create_default_context(cafile="server-ca.pem")
context.load_cert_chain(certfile="apps-billing.pem", keyfile="apps-billing-key.pem")

def call(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(BASE + path, data=data, method=method,
                                     headers={"content-type": "application/json"} if data else {})
    with urllib.request.urlopen(request, context=context) as response:
        return json.load(response)

call("PUT", "/v1/secrets/billing/api-key", {"value": base64.b64encode(b"s3cret").decode()})
secret = call("GET", "/v1/secrets/billing/api-key")
print(secret["version"], base64.b64decode(secret["value"]).decode())
```

With `requests`, the same two settings: `cert=("apps-billing.pem",
"apps-billing-key.pem")` and `verify="server-ca.pem"`. Python 3.13 and later
verify strictly: the server's certificate needs an Authority Key
Identifier, which the [production](/getting-started/production) script includes.

### Node.js

```js
import { readFileSync } from "node:fs";
import https from "node:https";

const agent = new https.Agent({
  ca: readFileSync("server-ca.pem"),         // trust the server's CA
  cert: readFileSync("apps-billing.pem"),    // the client certificate (mTLS)
  key: readFileSync("apps-billing-key.pem"),
});

function call(method, path, body) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : JSON.stringify(body);
    const request = https.request(
      { host: "ferritor.example.internal", port: 7070, path, method, agent,
        headers: data ? { "content-type": "application/json" } : {} },
      (response) => {
        let text = "";
        response.on("data", (chunk) => (text += chunk));
        response.on("end", () =>
          response.statusCode < 300 ? resolve(text ? JSON.parse(text) : null)
                                    : reject(new Error(`${response.statusCode} ${text}`)));
      });
    request.on("error", reject);
    request.end(data);
  });
}

await call("PUT", "/v1/secrets/billing/api-key", { value: Buffer.from("s3cret").toString("base64") });
const secret = await call("GET", "/v1/secrets/billing/api-key");
console.log(secret.version, Buffer.from(secret.value, "base64").toString());
```

### Go

```go
ca, err := os.ReadFile("server-ca.pem")
if err != nil {
	log.Fatal(err)
}
roots := x509.NewCertPool()
roots.AppendCertsFromPEM(ca) // trust the server's CA
cert, err := tls.LoadX509KeyPair("apps-billing.pem", "apps-billing-key.pem")
if err != nil {
	log.Fatal(err)
}
client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
	RootCAs:      roots,
	Certificates: []tls.Certificate{cert}, // the client certificate (mTLS)
}}}

resp, err := client.Get("https://ferritor.example.internal:7070/v1/secrets/billing/db")
```

Every example here was run against a secured server.

## Conventions

- **JSON in, JSON out.** A body must be `application/json` (`415`
  otherwise), even where it's empty: a restore of the newest deleted version
  sends `{}`. That's deliberate: see "Browsers".
- **Values are base64** (standard, with padding) in both directions, so any
  bytes round-trip. Times are RFC 3339, UTC, to the second.
- **Typos are refused**, never ignored: an unknown body field is `422`, an
  unknown query parameter `400`, each naming it. So a misspelled
  `expected_version` can't silently skip a check-and-set.
- **Paths and names** go into the URL as they are, slashes included
  (`/v1/secrets/billing/db`). They're canonical secret paths: segments of
  letters, digits, `.`, `_` and `-`; nothing is normalized (see
  [secrets](/guides/secrets)).
- **Check-and-set**: a put with `expected_version` stores only if the latest
  version is still that one (`0`: only if there's none). A mismatch is
  `409 version_mismatch`: read again, then decide. Policies work the same
  way.
- **Paging**: listings return at most `page_size` items (default 100, at
  most 1000) and a `next_page_token`; pass it back as `page_token` until
  it's empty.
- **Every response** carries `Cache-Control: no-store`.
- **Limits**: a value at most 1 MiB; a policy apply at most 16 MiB (`413`
  past the body limit).

### Errors

Every error is `{"error": {"code": "...", "message": "..."}}`. Match on
`code`, never on the message (meant for people, it may change). New codes
may be added; treat an unknown one by its HTTP status.

```json
{"error": {"code": "version_mismatch",
           "message": "`billing/db` was changed: its latest version is 2, expected 1; read it again"}}
```

| HTTP | `code` | Meaning | What to do |
|---|---|---|---|
| 400 | `invalid_argument` | an invalid path, page token, query parameter, value or label | fix the request |
| 401 | `unauthenticated` | the certificate names no valid identity now (expired, revoked, no `ferritor://` SAN) | fix the certificate |
| 403 | `permission_denied` | the policy doesn't allow it | ask for a grant |
| 404 | `not_found` | no such secret, version or policy (or endpoint) | |
| 405 | `method_not_allowed` | the endpoint doesn't take that method | |
| 409 | `version_mismatch` | a check-and-set found another version (or revision) | read again, then decide |
| 409 | `live_version` | a restore without a version while one is live | name the version |
| 409 | `no_namespace` | the path's namespace doesn't exist | an operator creates it |
| 409 | `busy` | too many concurrent writes to one path | retry as is |
| 409 | `aborted` | a conflict that a retry resolves | retry |
| 413 | `invalid_argument` | the body is over the limit | |
| 415 | `invalid_argument` | the body isn't `application/json` | |
| 421 | `misdirected_request` | dev mode, and not addressed to loopback | |
| 422 | `invalid_argument` | the body isn't valid (an unknown field, a wrong type, an admin action in a policy) | fix the body |
| 429 | `rate_limited` | over one of the caller's [rate limits](/operations/running#rate-limits) (the message names it); nothing was done | retry after `Retry-After` (whole seconds), slower |
| 503 | `sealed` | the server is sealed | another server, or wait for the unseal |
| 503 | `unaudited` | the decision couldn't be written to the audit log; nothing was done | retry later |
| 503 | `unknown_kek` | this server can't open the secret's key (another server rekeyed) | another server |
| 503 | `policy_unverified` | the stored policies don't verify; only they would allow this | an operator repairs them |
| 503 | `failed_precondition` | a policy write this server can't make now: another server rekeyed, so its root key is out of date | another server; an operator seals and unseals this one with the new shares |
| 503 | `unavailable` | a database didn't answer in time, or the server is at its cap of calls in flight; a write's outcome is unknown | retry (a check-and-set put is safe to retry) |
| 500 | `internal` | logged on the server, never detailed here | |

### Browsers

A client certificate installed in a browser is an ambient credential, like a
cookie. Cross-site requests stay harmless because every state change needs a
CORS preflight the server never grants (`PUT`, `PATCH`, `DELETE`, and `POST`
only with a JSON body), and a cross-site `GET` can't read the response. So
the API sends no CORS headers, has no state-changing `GET`, and accepts no
form or text bodies.

## Health

### `GET /v1/health`

Whether this server should get traffic: no authorization, not audited (in
secured mode the handshake still needs a client certificate).

```json
{"ready": true, "sealed": false}
```

`200` when ready, `503` otherwise (`sealed: false` then means it's shutting
down). Point an HTTP load balancer here; gRPC load balancers use the
standard health service (see [operations](/operations/running)).

## Secrets

Each needs the action shown on the path (see [policy](/guides/policy)).

### `GET /v1/secrets/{path}` (`read`)

The latest version, or `?version=N`.

```json
{"path": "billing/db", "version": 2, "created_at": "2026-10-20T12:29:38Z", "value": "bmV3"}
```

`404 not_found` if there's no such secret or version (deleted versions
included: restore one first).

### `PUT /v1/secrets/{path}` (`write`; `label` too with `labels`)

Stores a new version.

```json
{"value": "czNjcmV0", "expected_version": 1, "labels": {"env": "prod"}}
```

`expected_version` and `labels` are optional. Answers the version stored:

```json
{"path": "billing/db", "version": 2, "created_at": "2026-10-20T12:29:38Z"}
```

### `DELETE /v1/secrets/{path}` (`delete`)

Deletes every version (restorable until purged). `204`, no body.

### `POST /v1/restore/{path}` (`write`)

Brings a deleted version back: `{}` undoes a delete (the newest deleted
version, only while none is live; `409 live_version` otherwise), `{"version":
N}` restores that one. Answers like a put.

### `GET /v1/secrets?prefix=…&label=key=value&page_size=…&page_token=…` (`list`)

The latest version of every secret below `prefix` (whole segments; empty:
everything, which needs `list` on all paths), with every `label` given
(repeatable).

```json
{"secrets": [{"path": "billing/db", "version": 2, "created_at": "2026-10-20T12:29:38Z"}],
 "next_page_token": ""}
```

### `GET /v1/versions/{path}?page_size=…&page_token=…` (`list`)

A secret's history, newest first, deleted versions included (with
`deleted_at`). Metadata only.

```json
{"versions": [{"path": "billing/db", "version": 2, "created_at": "2026-10-20T12:29:38Z", "deleted_at": null},
              {"path": "billing/db", "version": 1, "created_at": "2026-10-20T12:29:38Z", "deleted_at": null}],
 "next_page_token": ""}
```

### `GET /v1/metadata/{path}` (`list`)

```json
{"path": "billing/db", "created_at": "2026-10-20T12:29:38Z", "updated_at": "2026-10-20T12:29:38Z",
 "current_version": 2, "oldest_version": 1, "versions": 2,
 "labels": {"env": "prod"}, "labels_updated_at": "2026-10-20T12:29:38Z"}
```

`current_version` is `null` when every version is deleted.

### `PATCH /v1/metadata/{path}` (`label`)

Changes labels: `{"set": {"owner": "payments"}, "remove": ["env"]}` (either
may be left out). Answers the labels now: `{"labels": {"owner": "payments"}}`.
Labels are plain metadata, never secret.

## Policies

The stored policies (see [policy](/guides/policy)). Every endpoint needs the
`policy` action, which only config rules grant; stored policies need the
server unsealed (`503 sealed`).

### `GET /v1/policies?identity=…&page_size=…&page_token=…`

Config rules (as `config:…`, read-only) and stored policies, by name.

```json
{"policies": [
  {"name": "apps/billing", "source": "stored", "identity": "apps/billing",
   "actions": ["read", "write", "delete", "list", "label"], "paths": ["billing"], "all_paths": false,
   "description": "the billing app", "version": 1,
   "created_at": "2026-10-20T12:29:38Z", "updated_at": "2026-10-20T12:29:38Z"},
  {"name": "config:ops-admin", "source": "config", "identity": "ops/alice",
   "actions": ["status", "init", "unseal", "seal", "rekey", "rotate", "rewrap", "purge", "destroy_kek", "namespace", "policy"],
   "paths": [], "all_paths": false, "description": ""}],
 "next_page_token": "", "stored": "loaded", "revision": 1}
```

`stored` is `loaded`, `sealed` or `unverified` (then only config rules are
listed).

### `GET /v1/policies/{name}`

One rule, as in the listing.

### `PUT /v1/policies/{name}`

Creates or replaces a stored policy:

```json
{"identity": "apps/billing", "actions": ["read", "list"], "paths": ["billing"],
 "description": "billing app, read only", "expected_version": 0}
```

`actions`: secret actions only (`read`, `write`, `delete`, `list`, `label`);
an admin action is `422`. Exactly one of `paths` and `all_paths: true`.
`expected_version`: `0` only creates, `N` only replaces version `N`.

```json
{"version": 1, "revision": 1, "created": true}
```

### `DELETE /v1/policies/{name}?expected_version=N`

Idempotent: `{"deleted": false, "revision": 1}` if there was none.

### `POST /v1/policy-apply`

Makes the stored set match a list, in one atomic call: the declarative path
for automation.

```json
{"policies": [{"name": "apps/billing", "identity": "apps/billing",
               "actions": ["read", "list"], "paths": ["billing"]}],
 "prune": true, "dry_run": true, "expected_revision": 1}
```

`prune` deletes every stored policy not listed; `dry_run` changes nothing
and reports what would; `expected_revision` refuses if the set changed
since. One invalid policy refuses the whole call.

```json
{"created": [], "updated": ["apps/billing"], "deleted": [], "unchanged": [], "revision": 2,
 "dry_run": true, "replaced_unverified": false, "new_policy_key": false}
```

### `GET /v1/policy-check?identity=…&action=…&path=…`

Whether an identity may do an action (any action name; `path` for a secret
action, empty: every secret), and which rules grant it:

```json
{"allowed": true, "granted_by": ["apps/billing"], "enforced": true}
```

`enforced` is `false` in dev mode (everyone may do everything there);
`undecided` (`sealed`, `unverified`) appears when the stored policies
couldn't answer.
