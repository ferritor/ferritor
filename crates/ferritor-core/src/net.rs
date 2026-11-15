//! What counts as loopback, one rule for every binary: where plaintext may
//! listen without being asked for, and which names a request on loopback
//! may be addressed to.

use std::net::IpAddr;

/// Loopback, an IPv4-mapped IPv6 address (`::ffff:127.0.0.1`) included.
pub fn is_loopback(ip: IpAddr) -> bool {
    ip.to_canonical().is_loopback()
}

/// `localhost`, or an IP literal (IPv6 in `[ ]`) that's loopback by
/// [`is_loopback`]. Any IP literal is safe here: DNS rebinding needs a name
/// the attacker controls.
pub fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let literal = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    literal.parse().is_ok_and(is_loopback)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_names_and_addresses() {
        for host in [
            "localhost",
            "LOCALHOST",
            "127.0.0.1",
            "127.9.9.9",
            "[::1]",
            "::1",
        ] {
            assert!(is_loopback_host(host), "{host}");
        }
        for host in [
            "example.com",
            "localhost.example.com",
            "10.0.0.1",
            "[::2]",
            "",
        ] {
            assert!(!is_loopback_host(host), "{host}");
        }
        assert!(is_loopback(
            "::ffff:127.0.0.1".parse().unwrap_or(IpAddr::from([0; 4]))
        ));
    }
}
