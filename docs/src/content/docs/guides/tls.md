---
title: 'TLS and identity'
description: 'Client certificates and ferritor:// identities, the server certificate, workload certificates, and revocation with CRLs.'
seo:
  title: 'TLS and client identity in ferritor: certificates, CRLs'
---

In secured mode every connection is TLS with a client certificate from the
client CA (rustls's WebPKI verifier, which also requires the client-auth
extended key usage), or one ferritor issued itself for a platform token
([workload identity](/guides/workload-identity), below). Dev mode has no TLS; see [configuration](/reference/configuration).

ALPN offers both `h2` and `http/1.1`, so HTTP/1.1-only clients (Python
`requests`, Node `fetch`) reach the JSON API. That's why the server builds
its own rustls configuration instead of tonic's, which offers only `h2`.

## Identity

A caller is the client certificate's **single** URI SAN of the form
`ferritor://<name>`, where `<name>` follows the secret-path rules
(`ops/alice`, `apps/billing`). A certificate with no such SAN, several URI
SANs, another scheme or an invalid name is refused as `UNAUTHENTICATED`
rather than guessed at, so a SAN some other CA added for its own purposes
can't match a policy by accident. Refusals of certificates that passed the
handshake are audited (`"event": "authentication"`, with the reason).

## Checked on every request

A handshake isn't enough: an HTTP/2 connection can stay open for days, and a
TLS session resumed from a ticket reuses the original certificate chain
without the verifier seeing it again (observed: an expired certificate kept
working across a reconnect). So on **every request** the server checks:

- that every certificate the client presented (leaf and intermediates) is
  valid now: an expired one gets `not_valid_now`;
- with a CRL file, that the client certificate isn't revoked.

Connection recycling (`max_connection_age_secs`) is hygiene only; neither
check depends on it.

## Revocation (CRLs)

`[tls] crl` is one PEM file holding a CRL from each client CA. Without it,
nothing can be revoked: use short-lived client certificates.

Checked when loaded, so a bad file is refused at startup or on reload (the
current CRLs stay) instead of failing handshakes later:

- each CRL must be signed by one of the client CA certificates (every one
  of which must parse), whose key usage, if it has one, allows `cRLSign`
  (RFC 5280's rule; stricter than rustls, which checks no key usage on a
  trust anchor);
- at most one CRL per CA, and every client CA needs one (rustls refuses a
  certificate whose revocation status it can't determine);
- each CRL must be complete: no issuing distribution point (partitioned
  CRLs) and no delta CRL indicator;
- no two client CAs may share a name: CRLs are matched to CAs by name, by
  rustls too. In a CA key rollover, give the new CA a new name.

Only the client certificate itself is checked, never an intermediate, so it
must be issued directly by a CA in `client_ca`. **List in `client_ca` only
the CAs that issue client certificates**: the issuing intermediate, not the
root above it, which would otherwise need a CRL of its own renewed every
`nextUpdate` (for an offline root, a signing ceremony each time).

Revocation is checked twice, like expiry: by rustls at every full handshake,
and by the server on every request, against the same CRLs (a reload swaps
both at once). A revoked certificate on an open connection is refused at its
next request (`revoked`, audited); a new connection fails the handshake.

A CRL past its `nextUpdate` is **still used** (rustls's default): a CRL
publisher that stalls must not lock every client out. It's warned about at
load, once when one in force goes stale while serving, and visible as the
`ferritor.tls.crl.next_update` gauge. Renew the file and send SIGHUP. A
reloaded CRL with a lower CRL number than the one it replaces is warned
about (it may un-revoke certificates); removing the setting revokes nothing
from then on.

The CRLs in force are audited at startup (`revocation_loaded`) and on every
reload (`revocation_reload`): issuer, number, dates, how many certificates
each revokes, fingerprint; never the serials.

Making a CRL with OpenSSL, given an `openssl ca` configuration with a
`database` and a `crlnumber` file:

```sh
openssl ca -config ca.cnf -revoke alice.pem -keyfile ca.key -cert ca.pem
openssl ca -config ca.cnf -gencrl -keyfile ca.key -cert ca.pem -out client-ca.crl
kill -HUP "$(pidof ferritor-server)"
```

## Workload certificates

Certificates from the token exchange ([workload identity](/guides/workload-identity))
are signed by ferritor's issuing CA, not by a CA in `client_ca`, and are
trusted next to them by every server once unsealed. At the handshake a
client certificate goes to one verifier by its issuer's name: an issuing
CA's (built from the active one and the retired ones still trusted, no
CRLs), or the client CA's, as before. One whose issuing CA is revoked is
refused (`CertificateRevoked`). A sealed server trusts none of them.

On every request, the same expiry check as any certificate, and instead of
the CRLs: its issuing CA must still be trusted (active; retired, for a day
after its retirement; never revoked), its identity must be under an issuer
still configured, and it must not be issued before a cutoff for its issuer
or identity. Each is `revoked` when it fails, audited like any
authentication refusal. The CRLs never apply to them, and `client_ca`
needn't list the issuing CA (it mustn't: it would be trusted with the
operators' CRL rules, which it has no CRL for).

The exchange's own listener (`[identity] listen_addr`) presents the same
server certificate, reloaded with it, and asks for no client certificate.

## Server certificate

Reloaded on SIGHUP (see [configuration](/reference/configuration)). One that isn't valid
now is refused at startup and on reload; the `ferritor.server_certificate.expiry`
gauge tells when to renew.

## Handshakes

Each handshake runs in its own task, limited to 10 s, and at most 256 run at
once: past that, new connections wait in the kernel's backlog rather than
costing a task each. Failed handshakes are counted
(`ferritor.tls.handshake.failures`) but not audited: no request exists yet.

## The CLI

Over `https://` the CLI first makes a health call (with `--token-file`,
after the exchange). With TLS 1.3 a refused
client certificate only surfaces on the first call, indistinguishable from a
call cut off midway; the preflight makes "nothing was sent" certain before a
real (possibly destructive) call.
