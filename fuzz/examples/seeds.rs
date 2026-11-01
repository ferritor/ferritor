//! Regenerates the committed seeds and fixtures:
//! `cargo run --manifest-path fuzz/Cargo.toml --example seeds`.
//!
//! - `seeds/audit_verify/`: genuine logs, written by `Chain` with
//!   `AUDIT_KEY` (the target treats their chains as the only genuine ones);
//! - `fixtures/ca.der`, `fixtures/crl.der` and `seeds/crl_parse/`: a
//!   throwaway CA's certificate (its key is discarded) and CRLs it signed.

use std::fs;
use std::path::Path;

use ed25519_dalek::SigningKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, CertificateRevocationListDer};
use ferritor_core::audit_chain::{Chain, Seal};
use ferritor_fuzz::AUDIT_KEY;
use ferritor_testkit::pki::Ca;

type Result<T = ()> = ferritor_testkit::TestResult<T>;

/// One chain: start, `entries` entries with a checkpoint in the middle, and
/// an end if `end`.
fn chain(key: &SigningKey, entries: usize, end: bool) -> Result<Vec<u8>> {
    let mut chain = Chain::new(Some(key.clone()))?;
    let mut out = Vec::new();
    let mut emit = |chain: &mut Chain, line: Vec<u8>, seal: Option<Seal>| {
        chain.written(&line, seal);
        out.extend_from_slice(&line);
    };
    let start = chain.start("2026-10-21T00:00:00Z")?;
    emit(&mut chain, start, None);
    for n in 0..entries {
        let entry = format!(
            "{{\"time\":\"2026-10-21T00:00:0{}Z\",\"event\":\"authorization\",\"identity\":\"apps/billing\",\"action\":\"read\",\"path\":\"billing/db\",\"decision\":\"allow\",\"n\":{n}}}\n",
            n % 10
        );
        let line = chain.link(entry.as_bytes())?;
        emit(&mut chain, line, None);
        if n == entries / 2
            && let Some(line) = chain.seal(Seal::Checkpoint, "2026-10-21T00:00:05Z")?
        {
            emit(&mut chain, line, Some(Seal::Checkpoint));
        }
    }
    if end && let Some(line) = chain.seal(Seal::End, "2026-10-21T00:01:00Z")? {
        emit(&mut chain, line, Some(Seal::End));
    }
    Ok(out)
}

fn write(path: &Path, bytes: &[u8]) -> Result {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(path, bytes)?;
    println!("wrote {}", path.display());
    Ok(())
}

fn main() -> Result {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let key = SigningKey::from_bytes(&AUDIT_KEY);

    let audit = root.join("seeds/audit_verify");
    write(&audit.join("complete.log"), &chain(&key, 6, true)?)?;
    let several = [
        chain(&key, 3, true)?,
        chain(&key, 4, false)?,
        chain(&key, 2, true)?,
    ]
    .concat();
    write(&audit.join("several.log"), &several)?;

    let ca = Ca::named("ferritor fuzz CA")?;
    let ca_der = CertificateDer::from_pem_slice(ca.cert.as_bytes())?;
    let next = time::OffsetDateTime::now_utc() + time::Duration::days(365);
    let (alice, bob) = (ca.client("ops/alice")?, ca.client("ops/bob")?);
    let crl = |pem: String| -> Result<Vec<u8>> {
        Ok(CertificateRevocationListDer::from_pem_slice(pem.as_bytes())?.to_vec())
    };
    let revoking = crl(ca.crl(&[&alice, &bob], next)?)?;
    write(&root.join("fixtures/ca.der"), ca_der.as_ref())?;
    write(&root.join("fixtures/crl.der"), &revoking)?;

    let seeds = root.join("seeds/crl_parse");
    let with_mode = |mode: u8, bytes: &[u8]| [&[mode], bytes].concat();
    write(&seeds.join("revoking"), &with_mode(0, &revoking))?;
    write(
        &seeds.join("empty"),
        &with_mode(0, &crl(ca.crl(&[], next)?)?),
    )?;
    write(
        &seeds.join("partitioned"),
        &with_mode(0, &crl(ca.partitioned_crl(next)?)?),
    )?;
    write(
        &seeds.join("file"),
        &with_mode(1, ca.crl(&[&alice], next)?.as_bytes()),
    )?;
    write(&seeds.join("ca"), &with_mode(2, ca_der.as_ref()))?;
    Ok(())
}
