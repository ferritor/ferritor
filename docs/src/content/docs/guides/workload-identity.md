---
title: 'Workload identity'
description: 'Platform tokens (Kubernetes service accounts, CI OIDC) exchanged for short-lived client certificates: issuers, mappings, revoking, the CLI and the agent.'
seo:
  title: 'Workload identity: platform tokens for ferritor certificates'
---

A workload proves who it is with a token its platform already gives it (a
Kubernetes projected service account token, a CI job's OIDC token) and gets
a short-lived client certificate from ferritor in exchange, signed by ferritor's
own issuing CA. It then uses that certificate on the main listener like
any other: the same `ferritor://<name>` identity, the same per-request checks,
the same policies. No PKI to run for applications, no certificate to
renew by hand. Operators keep their certificates from the operators' PKI
(`client_ca`): an exchanged certificate is never an admin.

Secured mode only.

```
workload                                 ferritor (exchange listener: TLS, no client certificate)
  │  key pair, CSR                          │
  │  token + CSR ─────────────────────────► │ verify the token (the issuer's keys), map its claims
  │                                         │ sign: an hour, client-auth, one ferritor:// URI SAN
  │  ◄────────────── certificate, identity  │ audited first (fails closed)
  │
  │  mTLS with the new certificate ───────► main listener, as any client
```

## Setting it up

1. **Create the issuing CA** once (the `identity` permission; unsealed):

   ```sh
   ferritor identity init
   ```

   A P-256 key and its self-signed CA certificate (five years), the key
   wrapped by the root key in the keys database, like a KEK. Every server
   picks it up at its next keyring refresh (or SIGHUP).

2. **Trust an issuer** in `ferritor.toml`, and reload (SIGHUP) or restart:

   ```toml
   [identity]
   listen_addr = "0.0.0.0:7071"   # its own listener
   lifetime_secs = 3600

   [[identity.issuer]]
   name = "k8s-prod"
   issuer = "https://kubernetes.default.svc.cluster.local"
   audience = "ferritor"
   jwks_file = "/etc/ferritor/k8s-prod-jwks.json"

   [[identity.issuer.map]]
   identity = "k8s-prod/{kubernetes.io.namespace}/{kubernetes.io.serviceaccount.name}"
   require = [{ claim = "kubernetes.io.namespace", one_of = ["billing", "shop"] }]
   ```

   Every setting is in [configuration](/reference/configuration#identity); adding
   `[identity]` to a running server, or changing `listen_addr` or
   `lifetime_secs`, needs a restart.

3. **Grant the identities** something with stored policies (`ferritor policy
   apply`, [policy](/guides/policy)): until then a token buys a certificate
   that can do nothing.

4. **Point the workload at the exchange**: the agent with `token_file` and
   `exchange` ([agent](/guides/agent#configuration)), the CLI with
   `--token-file` and `--exchange` (below), or, in Kubernetes, nothing in
   the pod: [the CSI provider](/guides/csi) exchanges each pod's token for it.

## Tokens

A token is a JWT (compact form, at most 16 KiB). It's accepted when:

- its `iss` is exactly one configured issuer's `issuer`; its `kid` names
  one of **that** issuer's keys (never another issuer's);
- its algorithm is the key's own: `RS256` (RSA, at least 2048 bits),
  `ES256` (P-256) or `EdDSA` (Ed25519). `none`, HMAC, and a header with
  `crit` are refused;
- its `aud` (a string or a list) contains the issuer's `audience`, so a
  token minted for another service is useless here;
- `exp` is in the future, `nbf` (if any) in the past, `iat` not in the
  future and not older than `max_token_age_secs`, each with 30 seconds of
  clock skew allowed.

The issuer's keys (a JWKS) come from a file, read at startup and on
SIGHUP, or from an `https://` URL, fetched at startup, every 10 minutes,
and once more (at most once a minute) when a token names a key the set
doesn't have, which is how an issuer's key rotation is picked up. A fetch
takes at most 5 seconds and 256 KiB; one that fails keeps the keys already
loaded, and until the first one succeeds that issuer's tokens are refused
(`UNAVAILABLE`). A file that doesn't load refuses to start (or to reload).

For Kubernetes, the cluster's JWKS is at its service account issuer's
`/openid/v1/jwks` (`kubectl get --raw /openid/v1/jwks > jwks.json`), and
the pod gets a token with audience `ferritor` from a projected volume:

```yaml
volumes:
  - name: ferritor-token
    projected:
      sources:
        - serviceAccountToken:
            audience: ferritor
            expirationSeconds: 3600
            path: token
```

## Mapping claims to an identity

Each issuer has one or more `[[identity.issuer.map]]`; the **first** whose
`require` all hold decides (no fall-through to the next if its template
then fails). A template is literal text with `{claim}` placeholders:

- it must start with the issuer's `name` and a `/`, literally, so an
  issuer only ever mints names under its own prefix. No `[[policy]]` may
  name an identity under an issuer's prefix, and no two issuers share a
  name, so a token can never become an operator or another issuer's
  workload;
- a claim is found by its dotted path (`kubernetes.io.namespace` reads
  `{"kubernetes.io": {"namespace": …}}`, and a key that itself has dots
  too); it must be a string;
- a claim fills **a whole segment**, with a `/` or the end on both sides:
  `k8s-prod/{kubernetes.io.namespace}/{kubernetes.io.serviceaccount.name}`,
  never `k8s-prod/{kubernetes.io.namespace}-{kubernetes.io.serviceaccount.name}`
  nor `ci/{repository_owner}-deploy`, which refuse to load. Values may
  contain `-`, `.` and `_`, so two claims sharing a segment would map
  namespace `a-b` with account `c`, and namespace `a` with account `b-c`,
  to the same `k8s-prod/a-b-c`: one identity for two tenants;
- its value must be non-empty and only `A-Z a-z 0-9 . _ -`. A value with a
  `/` (`"repository": "acme/web"`) maps to nothing rather than to two
  segments, so use claims that are single names (`repository_owner`, a
  namespace) or require exact values;
- `require`: each listed claim must equal one of `one_of` exactly.

The claims a mapping read are in the audit entry of every exchange, so the
log tells why a certificate got the name it did.

## The certificate

Built by ferritor alone: from the CSR only its public key is used (P-256,
Ed25519 or RSA of at least 3072 bits), after its signature verifies;
nothing it asks for (names, extensions, validity) is copied. The
certificate has an empty subject, one URI SAN `ferritor://<identity>`,
`clientAuth` only, a random serial, and lives `lifetime_secs` (an hour by
default, never past the token's `exp`), backdated by 30 seconds for clock
skew. Clients renew it two thirds into its life by exchanging their
(current) token again.

## Revoking

No CRLs for issued certificates: they expire within the hour. For the
hour in between, every one of these is checked on **every request**, so it
applies to open connections at once:

- **A cutoff for one identity** (`[[identity.revoke]]`, SIGHUP): its
  certificates issued before `not_before` are refused.
- **A cutoff for an issuer** (its `not_before`, SIGHUP): all of its
  certificates issued before it.
- **Removing an issuer** (SIGHUP): nothing more is exchanged for its
  tokens, and every certificate under its name is refused. Removing
  `[identity]` altogether refuses every issued certificate.
- **Rotating the issuing key**: `ferritor identity rotate` makes a new key;
  the old one is retired and its certificates stay trusted until they
  expire (at most a day after the rotation). `ferritor identity rotate --now`
  revokes the old key **and every retired one** at once: nothing they
  signed is trusted any more, and every workload exchanges again (the
  agent does at its next refused round). That's the response to a
  compromised server.

**A stolen issuing key** is ended by `rotate --now` alone: its thief signs
certificates with whatever `notBefore` suits them, after any cutoff, so
the cutoffs don't stop them (a certificate longer-lived than ferritor issues,
a day, is refused whatever signed it). Nor can a keys-database writer undo
the rotation: the issuing keys are one set, tagged under the root key at a
revision every change raises, and the highest revision written is kept in
the data database too (`issuing_revision_floor`). A key added or changed
without the root key fails the tag; the set as it was before the rotation,
written back from a backup, is below the floor. Either way the server
trusts none of the stored keys (a running server keeps the ones it has in
force; one unsealing has none) and logs it, until `ferritor identity rotate
--now`, the only rotation it allows then, revokes every key in that set
and starts a new one. Undoing a rotation takes write access to both
databases.

A certificate refused by any of these is `UNAUTHENTICATED` (reason
`revoked` in the audit entry), or refused at the handshake. Sealing refuses
them too: without the keyring nothing issued is trusted.

`ferritor identity status` lists the issuing keys in force on the server it
asks: version, state (`active`, `retired`, `revoked`), dates, and the CA
certificate's SHA-256. Each CA's name has a random part (`ferritor workload
identity CA 2 3f9c…`): certificates go to a verifier by their issuer's
name, so no operators' CA, nor another issuing CA, may share it.

## The exchange

`IdentityService.ExchangeToken` (gRPC, `ferritor.v1`), on `listen_addr`: TLS
with the server's own certificate, no client certificate asked (the token
is the credential). It isn't on the main listener, which keeps refusing
any connection without a client certificate. Answers:

| Code | Reason | When |
|---|---|---|
| OK | | the certificate (DER), the identity, `not_after_unix` |
| `UNAUTHENTICATED` | `TOKEN_REFUSED` | the token or its mapping was refused; the message says why |
| `INVALID_ARGUMENT` | | the CSR doesn't parse, verify, or has a key type refused |
| `FAILED_PRECONDITION` | `SEALED` | the server is sealed |
| `FAILED_PRECONDITION` | | no issuing CA (`ferritor identity init`) |
| `UNAVAILABLE` | `UNAUDITED` | the audit log couldn't record it: nothing issued |
| `UNAVAILABLE` | | the token's issuer's keys aren't loaded yet |
| `RESOURCE_EXHAUSTED` | `RATE_LIMITED` | too many exchanges for this identity (limit `exchanges`), with a `RetryInfo` |

Every issuance is recorded in the audit log before the certificate is
returned (`"event": "exchange"`, `"outcome": "issued"`: peer, issuer,
identity, the claims mapped, serial, `not_after`; never the token). Every
refusal too (`"outcome": "refused"`, with the reason), at most one a
second (a burst of 5) per peer address while rate limits are on, past which
they're counted as a rate-limit episode instead (`"limit":
"exchange_refused"`).

Exchanges are limited per identity they map to: one a second, with a
burst of the issuer's `exchange_burst` (10 by default) at once (`"limit":
"exchanges"`, an episode with the identity as `caller`). Each costs a
signature and an audit entry waited for. Renewals don't come near it:
they're spread across the certificate's lifetime. A rollout does:
replicas sharing an identity (one per deployment is usual) share the
limit, so 100 pods starting at once get 10 certificates at once and the
rest at one a second, the last about 90 seconds later. Every refusal says
when to retry (`RetryInfo`), and the clients wait for it (the agent before
its next round, the CLI once for a short wait), so they all get there; for
large deployments, raise the issuer's `exchange_burst` to the replica
count (at most 10,000). The key lookup is cheap
for a token that fails: an unknown `kid` fetches that token's issuer's
keys again, at most once a minute, never another issuer's.

## The CLI

Any command takes `--token-file` and `--exchange` (or `FERRITOR_TOKEN_FILE`
and `FERRITOR_EXCHANGE`) instead of `--cert` and `--key`: the token is
exchanged first and the certificate kept in memory for that one command.
For a job running many, exchange once:

```sh
ferritor login --token-file "$TOKEN_FILE" --exchange https://ferritor.internal:7071 \
  --ca ca.pem --cert-out job.pem --key-out job-key.pem
ferritor --ca ca.pem --cert job.pem --key job-key.pem get billing/db
```

`login` writes the key readable by its user alone (`0600`, replacing any
file there) and prints the identity and when the certificate expires.

On Windows, where there's no mode, the key file gets an access list of its
own instead: you, SYSTEM and Administrators, protected, so nothing the
folder passes on to new files applies, even in a shared folder like
`C:\temp`. The file is created with that list, so it never has any
other, not even for a moment. `icacls <file>` shows it.

## Several servers

Every server issues: the issuing key is in the keys database and loaded at
unseal and every keyring refresh, so a rotation on one reaches the others
within `keyring_refresh_secs` (or a SIGHUP). Until it does, a server that
hasn't seen a `--now` rotation still accepts the revoked key's certificates:
send every server SIGHUP after one. Every server raises the floor to the
newest set it verifies, so one missed raise (a failure, a data-database
failover) is caught up. Each server fetches its issuers' keys on
its own. The `[identity]` section is per server; keep it the same on every
one.
