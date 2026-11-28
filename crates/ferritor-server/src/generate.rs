//! Generated secrets: values ferritor makes up itself, from a profile in
//! the config (`[[generate_profile]]`), stored as ordinary versions
//! (`ferritor generate`). Nothing rotates them on its own: that's for
//! dynamic secrets, which also change the value where it's checked.
//!
//! A profile is a length and a list of character sets, each with its own
//! minimum. Profiles live in `ferritor.toml` alone, and are checked whole
//! at load, so a bad profile fails at startup (or its SIGHUP reload), not
//! at a generate later.
//!
//! Values are uniform among those meeting the rules: every character is
//! drawn uniformly from the union of the sets (each character once, however
//! many sets hold it), by rejection sampling over `getrandom`'s bytes, and a
//! value missing a minimum is drawn again whole, up to [`MAX_DRAWS`] times.
//! Never "place the required characters, fill, shuffle", which is biased.

use std::collections::BTreeMap;
use std::sync::{Arc, PoisonError, RwLock};

use serde::Deserialize;
use zeroize::Zeroizing;

/// The profile used when a generate names none; a profile of this name in
/// the config replaces the built-in one.
pub const DEFAULT_PROFILE: &str = "default";
/// The longest value a profile may make.
pub const MAX_LENGTH: u32 = 100;
/// The fewest bits a profile's values may carry (`length × log2(alphabet)`).
pub const MIN_BITS: f64 = 80.0;
/// The most character sets in one profile.
pub const MAX_CHARSETS: usize = 16;
/// The most whole values drawn for one generated value before giving up.
pub const MAX_DRAWS: u32 = 10_000;
/// The longest profile name.
pub const MAX_NAME_LEN: usize = 63;

/// How many values the load check draws, and the fewest of them that must
/// meet the minimums: a profile whose values meet them less than one time
/// in a hundred is refused, so a generate never runs out of draws (at one
/// in a hundred, [`MAX_DRAWS`] fail together about once in e^100).
const LOAD_SAMPLE: u32 = 10_000;
const LOAD_MIN_MET: u32 = LOAD_SAMPLE / 100;

/// `[[generate_profile]]` as written in `ferritor.toml`.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProfileSettings {
    pub name: String,
    pub length: u32,
    pub charsets: Vec<CharsetSettings>,
}

/// One character set of a profile: its characters, and how many of a
/// value's characters at least must be among them (default 0).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CharsetSettings {
    pub chars: String,
    #[serde(default)]
    pub min: u32,
}

/// A profile, checked: the alphabet (the sets' union, each character once,
/// in byte order) and, for each set, which of the alphabet's characters it
/// holds and its minimum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    name: String,
    length: usize,
    alphabet: Vec<u8>,
    /// Per set: a flag per alphabet character, and the set's minimum.
    sets: Vec<(Vec<bool>, usize)>,
}

/// Why a value couldn't be made.
#[derive(Debug, thiserror::Error)]
pub enum GenerateError {
    #[error("the system's random number generator failed")]
    Random(#[source] getrandom::Error),
    /// Only if the load check let through a profile whose minimums are too
    /// rare: it shouldn't.
    #[error("no value met profile `{0}`'s minimums in {MAX_DRAWS} draws")]
    TooRare(String),
}

impl Profile {
    /// `settings` checked: a name of lowercase letters, digits, `-` and `_`
    /// (at most [`MAX_NAME_LEN`]); a length from 1 to [`MAX_LENGTH`]; from
    /// 1 to [`MAX_CHARSETS`] sets, none empty, each character printable
    /// ASCII but space (33 to 126) and in its set once; minimums adding up
    /// to no more than the length; at least [`MIN_BITS`]; and minimums
    /// that a value meets often enough (one in a hundred, by a test batch).
    pub fn new(settings: &ProfileSettings) -> Result<Self, String> {
        let name = &settings.name;
        if name.is_empty()
            || name.len() > MAX_NAME_LEN
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return Err(format!(
                "generate_profile name {name:?}: from 1 to {MAX_NAME_LEN} lowercase letters, \
                 digits, `-` and `_`"
            ));
        }
        let at = |what: String| format!("generate_profile `{name}`: {what}");
        if !(1..=MAX_LENGTH).contains(&settings.length) {
            return Err(at(format!(
                "length ({}) must be from 1 to {MAX_LENGTH}",
                settings.length
            )));
        }
        let length = settings.length as usize;
        if settings.charsets.is_empty() || settings.charsets.len() > MAX_CHARSETS {
            return Err(at(format!(
                "needs from 1 to {MAX_CHARSETS} charsets, has {}",
                settings.charsets.len()
            )));
        }
        let mut alphabet = Vec::new();
        for (i, set) in settings.charsets.iter().enumerate() {
            let n = i + 1;
            if set.chars.is_empty() {
                return Err(at(format!("charset {n} is empty")));
            }
            let mut seen = [false; 128];
            for c in set.chars.chars() {
                let Some(b) = u8::try_from(c).ok().filter(|b| (33..=126).contains(b)) else {
                    return Err(at(format!(
                        "charset {n} holds {c:?}: only printable ASCII, no space (33 to 126)"
                    )));
                };
                if std::mem::replace(&mut seen[usize::from(b)], true) {
                    return Err(at(format!("charset {n} holds {c:?} twice")));
                }
                alphabet.push(b);
            }
        }
        alphabet.sort_unstable();
        alphabet.dedup();
        let sets: Vec<(Vec<bool>, usize)> = settings
            .charsets
            .iter()
            .map(|set| {
                let held = alphabet
                    .iter()
                    .map(|b| set.chars.as_bytes().contains(b))
                    .collect();
                (held, set.min as usize)
            })
            .collect();
        let minimums: u64 = settings.charsets.iter().map(|s| u64::from(s.min)).sum();
        if minimums > u64::from(settings.length) {
            return Err(at(format!(
                "the minimums add up to {minimums}, past the length ({length})"
            )));
        }
        let bits = length as f64 * (alphabet.len() as f64).log2();
        if bits < MIN_BITS {
            return Err(at(format!(
                "{length} characters of {} carry {bits:.0} bits, under {MIN_BITS:.0}: make it \
                 longer or add characters",
                alphabet.len()
            )));
        }
        let profile = Self {
            name: name.clone(),
            length,
            alphabet,
            sets,
        };
        // Deterministic: the same profile is accepted or refused at every
        // load, on every server.
        let mut sample = SplitMix(0x6665_7272_6974_6f72);
        let mut met = 0;
        for _ in 0..LOAD_SAMPLE {
            let value = profile.draw(&mut sample).map_err(|e| at(e.to_string()))?;
            if profile.meets(&value) {
                met += 1;
            }
        }
        if met < LOAD_MIN_MET {
            return Err(at(format!(
                "its minimums are met by {met} values in {LOAD_SAMPLE}, under one in a hundred: \
                 lower them, or make the value longer"
            )));
        }
        Ok(profile)
    }

    /// The built-in `default`: 32 characters of lowercase, uppercase,
    /// digits and the 32 ASCII symbols (33 to 126 together), at least one
    /// of each.
    pub fn default_settings() -> ProfileSettings {
        let symbols: String = (33u8..=126)
            .filter(|b| !b.is_ascii_alphanumeric())
            .map(char::from)
            .collect();
        let set = |chars: &str| CharsetSettings {
            chars: chars.to_owned(),
            min: 1,
        };
        ProfileSettings {
            name: DEFAULT_PROFILE.to_owned(),
            length: 32,
            charsets: vec![
                set("abcdefghijklmnopqrstuvwxyz"),
                set("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
                set("0123456789"),
                set(&symbols),
            ],
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// A new value, from the system's random number generator.
    pub fn generate(&self) -> Result<Zeroizing<Vec<u8>>, GenerateError> {
        self.generate_from(&mut OsBytes::default())
    }

    fn generate_from(&self, bytes: &mut impl Bytes) -> Result<Zeroizing<Vec<u8>>, GenerateError> {
        for _ in 0..MAX_DRAWS {
            let value = self.draw(bytes).map_err(GenerateError::Random)?;
            if self.meets(&value) {
                return Ok(value);
            }
        }
        Err(GenerateError::TooRare(self.name.clone()))
    }

    /// `length` characters, each uniform over the alphabet.
    fn draw(&self, bytes: &mut impl Bytes) -> Result<Zeroizing<Vec<u8>>, getrandom::Error> {
        let n = self.alphabet.len();
        // The largest multiple of n a byte can be below: a byte at or past
        // it is drawn again, so every character is equally likely (never
        // `byte % n` alone).
        let limit = 256 - 256 % n;
        let mut value = Zeroizing::new(Vec::with_capacity(self.length));
        while value.len() < self.length {
            let b = usize::from(bytes.next()?);
            if b < limit
                && let Some(&c) = self.alphabet.get(b % n)
            {
                value.push(c);
            }
        }
        Ok(value)
    }

    /// Whether `value` has at least each set's minimum of its characters
    /// (a character in two sets counts toward both).
    fn meets(&self, value: &[u8]) -> bool {
        self.sets.iter().all(|(held, min)| {
            value
                .iter()
                .filter(|c| {
                    self.alphabet
                        .binary_search(c)
                        .ok()
                        .and_then(|i| held.get(i))
                        .copied()
                        .unwrap_or(false)
                })
                .count()
                >= *min
        })
    }
}

/// Random bytes, one at a time.
trait Bytes {
    fn next(&mut self) -> Result<u8, getrandom::Error>;
}

/// The system's random number generator, read 256 bytes at a time into a
/// buffer wiped when dropped.
struct OsBytes {
    buffer: Zeroizing<[u8; 256]>,
    used: usize,
}

impl Default for OsBytes {
    fn default() -> Self {
        Self {
            buffer: Zeroizing::new([0; 256]),
            used: 256,
        }
    }
}

impl Bytes for OsBytes {
    fn next(&mut self) -> Result<u8, getrandom::Error> {
        if self.used == self.buffer.len() {
            getrandom::fill(self.buffer.as_mut())?;
            self.used = 0;
        }
        let b = self.buffer.get(self.used).copied().unwrap_or(0);
        self.used += 1;
        Ok(b)
    }
}

/// SplitMix64, for the load check only: a fixed seed makes it the same
/// on every load. Never for a value.
struct SplitMix(u64);

impl Bytes for SplitMix {
    fn next(&mut self) -> Result<u8, getrandom::Error> {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        Ok((z ^ (z >> 31)).to_le_bytes()[0])
    }
}

/// Every profile, the config's and the built-in `default` (unless the
/// config has its own), checked; refused if two share a name.
pub fn profiles(settings: &[ProfileSettings]) -> Result<BTreeMap<String, Profile>, String> {
    let mut profiles = BTreeMap::new();
    for profile in settings {
        let profile = Profile::new(profile)?;
        if profiles.contains_key(profile.name()) {
            return Err(format!(
                "generate_profile `{}` is defined twice",
                profile.name()
            ));
        }
        profiles.insert(profile.name().to_owned(), profile);
    }
    if !profiles.contains_key(DEFAULT_PROFILE) {
        let default = Profile::new(&Profile::default_settings())?;
        profiles.insert(DEFAULT_PROFILE.to_owned(), default);
    }
    Ok(profiles)
}

/// The profiles in force: the config's, swapped on SIGHUP.
#[derive(Debug)]
pub struct Profiles(RwLock<Arc<BTreeMap<String, Profile>>>);

impl Default for Profiles {
    /// The built-in `default` alone.
    fn default() -> Self {
        Self::new(profiles(&[]).unwrap_or_default())
    }
}

impl Profiles {
    pub fn new(profiles: BTreeMap<String, Profile>) -> Self {
        Self(RwLock::new(Arc::new(profiles)))
    }

    /// The profile named `name`, if this server has one.
    pub fn get(&self, name: &str) -> Option<Profile> {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(name)
            .cloned()
    }

    pub fn reload(&self, profiles: BTreeMap<String, Profile>) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(profiles);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn settings(length: u32, charsets: &[(&str, u32)]) -> ProfileSettings {
        ProfileSettings {
            name: "p".to_owned(),
            length,
            charsets: charsets
                .iter()
                .map(|(chars, min)| CharsetSettings {
                    chars: (*chars).to_owned(),
                    min: *min,
                })
                .collect(),
        }
    }

    const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
    const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const DIGITS: &str = "0123456789";

    #[test]
    fn the_default_is_32_of_every_printable_character() -> TestResult {
        let profiles = profiles(&[])?;
        let default = profiles.get(DEFAULT_PROFILE).ok_or("no default")?;
        assert_eq!(default.alphabet, (33u8..=126).collect::<Vec<_>>());
        let value = default.generate()?;
        assert_eq!(value.len(), 32);
        assert!(value.iter().any(u8::is_ascii_lowercase));
        assert!(value.iter().any(u8::is_ascii_uppercase));
        assert!(value.iter().any(u8::is_ascii_digit));
        assert!(value.iter().any(u8::is_ascii_punctuation));
        Ok(())
    }

    #[test]
    fn a_profile_named_default_replaces_the_built_in_one() -> TestResult {
        let mut own = settings(24, &[(LOWER, 0), (DIGITS, 0)]);
        own.name = DEFAULT_PROFILE.to_owned();
        let profiles = profiles(&[own])?;
        let default = profiles.get(DEFAULT_PROFILE).ok_or("no default")?;
        assert_eq!(default.length, 24);
        assert_eq!(profiles.len(), 1);
        Ok(())
    }

    #[test]
    fn bad_profiles_are_refused_at_load() {
        let refused = |s: ProfileSettings, why: &str| {
            let error = Profile::new(&s).err().unwrap_or_default();
            assert!(error.contains(why), "{error:?} lacks {why:?}");
        };
        let mut bad_name = settings(20, &[(LOWER, 0)]);
        bad_name.name = "Bad Name".to_owned();
        refused(bad_name, "lowercase letters");
        let mut no_name = settings(20, &[(LOWER, 0)]);
        no_name.name = String::new();
        refused(no_name, "from 1 to 63");
        refused(settings(0, &[(LOWER, 0)]), "length (0)");
        refused(settings(101, &[(LOWER, 0)]), "length (101)");
        refused(settings(20, &[]), "from 1 to 16 charsets");
        refused(settings(20, &[(LOWER, 0), ("", 0)]), "charset 2 is empty");
        refused(settings(20, &[("abc d", 0)]), "' '");
        refused(settings(20, &[("abcé", 0)]), "'é'");
        refused(settings(20, &[("ab\tc", 0)]), "'\\t'");
        refused(settings(20, &[("abca", 0)]), "'a' twice");
        refused(
            settings(20, &[(LOWER, 10), (DIGITS, 11)]),
            "add up to 21, past the length (20)",
        );
        // 8 digits ≈ 27 bits; 16 lowercase ≈ 75.
        refused(settings(8, &[(DIGITS, 0)]), "27 bits");
        refused(settings(16, &[(LOWER, 0)]), "75 bits");
        // 30 characters of 36, 15 of them from a set of one: met far less
        // than one time in a hundred.
        refused(
            settings(30, &[(LOWER, 0), (DIGITS, 0), ("#", 15)]),
            "under one in a hundred",
        );
    }

    #[test]
    fn enough_bits_pass() -> TestResult {
        // 16 letters and digits ≈ 95 bits; 20 of 70 ≈ 122.
        Profile::new(&settings(16, &[(LOWER, 0), (UPPER, 0), (DIGITS, 0)]))?;
        Profile::new(&settings(
            20,
            &[(LOWER, 1), (UPPER, 1), (DIGITS, 1), ("!@#$%^&*", 2)],
        ))?;
        Ok(())
    }

    #[test]
    fn a_name_twice_is_refused() {
        let error = profiles(&[settings(20, &[(LOWER, 0)]), settings(20, &[(LOWER, 0)])])
            .err()
            .unwrap_or_default();
        assert!(error.contains("`p` is defined twice"), "{error}");
    }

    /// The todo's example: overlapping sets (`STUVWXYZ` in two) are one
    /// alphabet, each character once, and a shared one counts for both.
    #[test]
    fn overlapping_sets_are_one_alphabet() -> TestResult {
        let profile = Profile::new(&settings(
            20,
            &[(LOWER, 1), (UPPER, 1), (DIGITS, 1), ("!@#$%^&*STUVWXYZ", 2)],
        ))?;
        assert_eq!(profile.alphabet.len(), 26 + 26 + 10 + 8);
        assert!(profile.meets(b"aA1SSaaaaaaaaaaaaaaa"));
        assert!(!profile.meets(b"aA1Saaaaaaaaaaaaaaaa"));
        Ok(())
    }

    /// Every value meets the minimums, and over many draws the characters
    /// of a set come up about equally often (no skew from `% n` or from
    /// placing required characters). Across sets they needn't: values
    /// meeting a minimum of 2 digits hold more digits than an unconstrained
    /// draw, as uniform among the values meeting the rules implies.
    #[test]
    fn values_meet_the_rules_and_are_uniform() -> TestResult {
        let profile = Profile::new(&settings(20, &[(LOWER, 1), (UPPER, 1), (DIGITS, 2)]))?;
        let mut counts = BTreeMap::<u8, u32>::new();
        let mut source = SplitMix(7);
        for _ in 0..5_000 {
            let value = profile.generate_from(&mut source)?;
            assert_eq!(value.len(), 20);
            assert!(profile.meets(&value));
            for c in value.iter() {
                *counts.entry(*c).or_default() += 1;
            }
        }
        assert_eq!(counts.len(), 62);
        for set in [LOWER, UPPER, DIGITS] {
            let drawn: Vec<u32> = set
                .bytes()
                .map(|c| counts.get(&c).copied().unwrap_or(0))
                .collect();
            let expected = f64::from(drawn.iter().sum::<u32>()) / drawn.len() as f64;
            for (c, n) in set.chars().zip(drawn) {
                let off = (f64::from(n) - expected).abs() / expected;
                assert!(
                    off < 0.1,
                    "{c:?} drawn {n} times, expected about {expected:.0}"
                );
            }
        }
        Ok(())
    }

    /// Without minimums, every character of the alphabet is equally likely.
    #[test]
    fn without_minimums_every_character_is_equally_likely() -> TestResult {
        let profile = Profile::new(&settings(20, &[(LOWER, 0), (DIGITS, 0), ("!#%", 0)]))?;
        let mut counts = BTreeMap::<u8, u32>::new();
        let mut source = SplitMix(11);
        for _ in 0..5_000 {
            for c in profile.generate_from(&mut source)?.iter() {
                *counts.entry(*c).or_default() += 1;
            }
        }
        assert_eq!(counts.len(), 39);
        let expected = 5_000.0 * 20.0 / 39.0;
        for (c, n) in counts {
            let off = (f64::from(n) - expected).abs() / expected;
            assert!(off < 0.1, "{:?} drawn {n} times", char::from(c));
        }
        Ok(())
    }

    #[test]
    fn reloading_swaps_the_profiles() -> TestResult {
        let in_force = Profiles::default();
        assert!(in_force.get("p").is_none());
        in_force.reload(profiles(&[settings(20, &[(LOWER, 0), (DIGITS, 0)])])?);
        assert_eq!(in_force.get("p").map(|p| p.length), Some(20));
        assert!(in_force.get(DEFAULT_PROFILE).is_some());
        Ok(())
    }
}
