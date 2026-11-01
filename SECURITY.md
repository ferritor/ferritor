# Security policy

ferritor keeps secrets, so a vulnerability in it can expose everything it
holds. Please report one privately, never in a public issue, pull request
or discussion.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:
<https://github.com/ferritor/ferritor/security/advisories/new> (the
repository's **Security** tab, **Report a vulnerability**). Only the
maintainers see the report, and the fix and the advisory are prepared
with you in the same place.

Helpful to include:

- what you run: the version (`ferritor-server --version`), the image's
  tag and digest, or, built from source, the commit; and how it runs (dev
  or secured mode, the seal provider, Kubernetes);
- what an attacker needs (which access, which identity) and what they
  gain;
- how to reproduce it, as small as you can make it.

Never include real secrets, unseal shares, keys or tokens, yours or
anyone's: a throwaway dev-mode setup shows most problems.

We'll confirm we received it, keep you informed while we fix it, and
credit you in the advisory unless you'd rather not be named. Please give
us the time to release a fix before you disclose it.

## What counts

The [security model](https://ferritor.dev/concepts/security) says what
ferritor defends against, what it doesn't, and its known gaps. Something
it claims to defend against that doesn't hold is a vulnerability; so is
anything that leaks values, shares, keys or tokens (into logs, the audit
log, error messages, metrics, files), or gets past authorization, the seal
or the audit log's fail-closed rule. A documented known gap isn't, though
a way to make it worse than described is.

Not vulnerabilities: dev mode allowing everything (that's what it's for,
on loopback only), and what an attacker can do with access the model says
grants it (root on the server host, a threshold of shares, the client CA's
key).

## Supported versions

ferritor is before 1.0: fixes go into the next release only, built from
`main`. Run the latest.

## Verifying a release

The released images are signed with cosign, keyless, by the release
workflow: see the [Kubernetes guide](https://ferritor.dev/getting-started/kubernetes#what-you-need)
for the `cosign verify` command, and deploy by the digest that verified.
