//! Reading secrets from stdin, and the hex encoding shares are shown in.

use std::io::{self, BufRead, IsTerminal, Read};

use zeroize::Zeroizing;

/// One secret line: a hidden prompt on a terminal, else the first line of
/// stdin (trailing newline removed).
pub fn secret_line(prompt: &str) -> io::Result<Zeroizing<String>> {
    if io::stdin().is_terminal() {
        return rpassword::prompt_password(prompt).map(Zeroizing::new);
    }
    let mut line = Zeroizing::new(String::new());
    io::stdin().lock().read_line(&mut line)?;
    let trimmed = line.trim_end_matches(['\r', '\n']).len();
    line.truncate(trimmed);
    Ok(line)
}

/// A secret value: a hidden one-line prompt on a terminal, else all of
/// stdin, byte for byte (so binary values and trailing newlines survive).
pub fn secret_value(prompt: &str) -> io::Result<Zeroizing<Vec<u8>>> {
    if io::stdin().is_terminal() {
        let line = secret_line(prompt)?;
        return Ok(Zeroizing::new(line.as_bytes().to_vec()));
    }
    let mut value = Zeroizing::new(Vec::new());
    io::stdin().lock().read_to_end(&mut value)?;
    Ok(value)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("not a valid hex share")]
pub struct BadHex;

/// Decodes hex, ignoring case and any whitespace (shares get wrapped and
/// pasted).
pub fn unhex(text: &str) -> Result<Zeroizing<Vec<u8>>, BadHex> {
    let digits: Zeroizing<Vec<u8>> = Zeroizing::new(
        text.bytes()
            .filter(|b| !b.is_ascii_whitespace())
            .map(|b| match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                b'A'..=b'F' => Ok(b - b'A' + 10),
                _ => Err(BadHex),
            })
            .collect::<Result<_, _>>()?,
    );
    if digits.is_empty() || !digits.len().is_multiple_of(2) {
        return Err(BadHex);
    }
    let (pairs, _) = digits.as_chunks::<2>();
    Ok(Zeroizing::new(
        pairs.iter().map(|[high, low]| high << 4 | low).collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let bytes: Vec<u8> = (0..=255).collect();
        assert_eq!(*unhex(&hex(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn unhex_tolerates_case_and_whitespace() {
        assert_eq!(*unhex(" AB cd\n0f ").unwrap(), [0xab, 0xcd, 0x0f]);
    }

    #[test]
    fn unhex_rejects_garbage() {
        for bad in ["", "abc", "zz", "0x00"] {
            assert_eq!(unhex(bad), Err(BadHex), "{bad:?}");
        }
    }
}
