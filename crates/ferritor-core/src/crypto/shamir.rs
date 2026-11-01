//! Splits the root key into Shamir shares over GF(256) (via `vsss-rs`) and
//! reconstructs it.
//!
//! Encoded share: `format (1) || generation (u32 BE) || x (1) || y (32)`.
//! The generation is `seal_config.generation` when the shares were made, so
//! shares from before a rekey are rejected before reconstruction is attempted.

use std::fmt;

use getrandom::SysRng;
use getrandom::rand_core::{Infallible, TryCryptoRng, TryRng};
use vsss_rs::Gf256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::CryptoError;
use super::key::{KEY_LEN, RootKey};

const SHARE_FORMAT: u8 = 1;
/// `x || y`, the form `vsss-rs` works with.
const POINT_LEN: usize = 1 + KEY_LEN;
const SHARE_LEN: usize = 1 + 4 + POINT_LEN;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Share {
    generation: u32,
    point: [u8; POINT_LEN],
}

impl Share {
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// The share's x-coordinate, unique among shares from one split. Not secret.
    pub fn id(&self) -> u8 {
        self.point[0]
    }

    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(SHARE_LEN));
        bytes.push(SHARE_FORMAT);
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&self.point);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let [SHARE_FORMAT, g0, g1, g2, g3, point @ ..] = bytes else {
            return Err(CryptoError::MalformedShare);
        };
        if point.len() != POINT_LEN || point[0] == 0 {
            return Err(CryptoError::MalformedShare);
        }
        let mut share = Self {
            generation: u32::from_be_bytes([*g0, *g1, *g2, *g3]),
            point: [0; POINT_LEN],
        };
        share.point.copy_from_slice(point);
        Ok(share)
    }
}

impl fmt::Debug for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Share")
            .field("generation", &self.generation)
            .field("x", &self.point[0])
            .finish_non_exhaustive()
    }
}

/// Adapts a fallible RNG to the infallible one `vsss-rs` requires without
/// panicking: the first error is recorded and the failed output is zero-filled.
/// Anything produced while `error` is set must be discarded.
struct RecordingRng<R: TryCryptoRng> {
    inner: R,
    error: Option<R::Error>,
}

impl<R: TryCryptoRng> TryRng for RecordingRng<R> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        if let Err(error) = self.inner.try_fill_bytes(dst) {
            dst.fill(0);
            self.error.get_or_insert(error);
        }
        Ok(())
    }
}

impl<R: TryCryptoRng> TryCryptoRng for RecordingRng<R> {}

/// How many shares to split into and how many reconstruct: always
/// `2 <= threshold <= shares`. One type instead of two `u8`s so they can't be
/// passed in the wrong order. The constructor still takes both, but a swap
/// there is caught: swapped valid values have `threshold > shares` unless
/// they're equal, in which case the swap is harmless.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShareParams {
    shares: u8,
    threshold: u8,
}

impl ShareParams {
    pub fn new(shares: u8, threshold: u8) -> Result<Self, CryptoError> {
        if threshold < 2 || threshold > shares {
            return Err(CryptoError::InvalidShareParams { threshold, shares });
        }
        Ok(Self { shares, threshold })
    }

    pub fn shares(self) -> u8 {
        self.shares
    }

    pub fn threshold(self) -> u8 {
        self.threshold
    }
}

/// Splits `root` into `params.shares()` shares, any `params.threshold()` of
/// which reconstruct it.
pub fn split(
    root: &RootKey,
    params: ShareParams,
    generation: u32,
) -> Result<Vec<Share>, CryptoError> {
    split_with(SysRng, root, params, generation)
}

fn split_with<R>(
    rng: R,
    root: &RootKey,
    params: ShareParams,
    generation: u32,
) -> Result<Vec<Share>, CryptoError>
where
    R: TryCryptoRng<Error = getrandom::Error>,
{
    let mut rng = RecordingRng {
        inner: rng,
        error: None,
    };
    // Pass a slice: `root.0` by value would copy the key into memory that is
    // never zeroized (clippy suggests exactly that for `&root.0`).
    let result = Gf256::split_bytes(
        params.threshold.into(),
        params.shares.into(),
        root.0.as_slice(),
        &mut rng,
    )
    .map(Zeroizing::new);
    // Check the RNG before the result: an RNG failure is the root cause even
    // if `vsss-rs` then failed too. Shares built from zero-filled randomness
    // would leak the key; `result` is wiped on return.
    if let Some(error) = rng.error {
        return Err(CryptoError::Rng(error));
    }
    let points = result.map_err(CryptoError::Shamir)?;
    points
        .iter()
        .map(|point| {
            let point: &[u8; POINT_LEN] = point
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::MalformedShare)?;
            Ok(Share {
                generation,
                point: *point,
            })
        })
        .collect()
}

/// Reconstructs the root key from `shares`, rejecting any share not from
/// `generation`.
///
/// Fewer than the threshold still "succeeds" with the wrong key, so the
/// caller must pass at least `threshold` shares and confirm the result with
/// [`RootKey::verify_root_check`].
pub fn combine(shares: &[Share], generation: u32) -> Result<RootKey, CryptoError> {
    if let Some(stale) = shares.iter().find(|s| s.generation != generation) {
        return Err(CryptoError::StaleShare {
            expected: generation,
            found: stale.generation,
        });
    }
    let points: Zeroizing<Vec<Vec<u8>>> =
        Zeroizing::new(shares.iter().map(|s| s.point.to_vec()).collect());
    let secret =
        Zeroizing::new(Gf256::combine_bytes(points.as_slice()).map_err(CryptoError::Shamir)?);
    RootKey::from_slice(&secret)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn p(shares: u8, threshold: u8) -> ShareParams {
        ShareParams::new(shares, threshold).unwrap()
    }

    fn params() -> impl Strategy<Value = (u8, u8, Vec<usize>)> {
        (2u8..=8, 0u8..=4).prop_flat_map(|(threshold, extra)| {
            let shares = threshold + extra;
            let picked = prop::sample::subsequence(
                (0..usize::from(shares)).collect::<Vec<_>>(),
                usize::from(threshold)..=usize::from(shares),
            )
            .prop_shuffle();
            (Just(threshold), Just(shares), picked)
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn any_threshold_subset_reconstructs((threshold, shares, picked) in params()) {
            let root = RootKey::generate().unwrap();
            let all = split(&root, p(shares, threshold), 1).unwrap();
            let subset: Vec<Share> = picked
                .iter()
                .map(|&i| Share::from_bytes(&all[i].to_bytes()).unwrap())
                .collect();
            prop_assert_eq!(combine(&subset, 1).unwrap().0, root.0);
        }
    }

    #[test]
    fn below_threshold_gives_a_different_key() {
        let root = RootKey::generate().unwrap();
        let shares = split(&root, p(5, 3), 1).unwrap();
        assert_ne!(combine(&shares[..2], 1).unwrap().0, root.0);
    }

    #[test]
    fn ids_are_distinct_and_nonzero() {
        let root = RootKey::generate().unwrap();
        let mut ids: Vec<u8> = split(&root, p(5, 3), 1)
            .unwrap()
            .iter()
            .map(Share::id)
            .collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 5);
        assert!(!ids.contains(&0));
    }

    #[test]
    fn rejects_stale_generation() {
        let root = RootKey::generate().unwrap();
        let shares = split(&root, p(3, 2), 1).unwrap();
        assert!(matches!(
            combine(&shares, 2),
            Err(CryptoError::StaleShare {
                expected: 2,
                found: 1
            })
        ));
    }

    #[test]
    fn rejects_duplicate_shares() {
        let root = RootKey::generate().unwrap();
        let shares = split(&root, p(3, 2), 1).unwrap();
        let dup = [
            Share::from_bytes(&shares[0].to_bytes()).unwrap(),
            Share::from_bytes(&shares[0].to_bytes()).unwrap(),
        ];
        assert!(matches!(combine(&dup, 1), Err(CryptoError::Shamir(_))));
    }

    /// Succeeds for the first `remaining` calls, then fails.
    struct FlakyRng {
        remaining: usize,
    }

    impl TryRng for FlakyRng {
        type Error = getrandom::Error;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut bytes = [0; 4];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u32::from_le_bytes(bytes))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut bytes = [0; 8];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u64::from_le_bytes(bytes))
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            self.remaining = self
                .remaining
                .checked_sub(1)
                .ok_or(getrandom::Error::UNSUPPORTED)?;
            SysRng.try_fill_bytes(dst)
        }
    }

    impl TryCryptoRng for FlakyRng {}

    #[test]
    fn rng_failure_is_an_error_not_a_panic() {
        let root = RootKey::generate().unwrap();
        for remaining in [0, 1, 10] {
            assert!(matches!(
                split_with(FlakyRng { remaining }, &root, p(5, 3), 1),
                Err(CryptoError::Rng(_))
            ));
        }
    }

    #[test]
    fn rejects_invalid_params() {
        for (shares, threshold) in [(3, 1), (3, 0), (3, 4), (1, 1), (0, 0)] {
            assert!(matches!(
                ShareParams::new(shares, threshold),
                Err(CryptoError::InvalidShareParams { .. })
            ));
        }
        let params = p(5, 3);
        assert_eq!((params.shares(), params.threshold()), (5, 3));
    }

    proptest! {
        /// Swapping the constructor's arguments is either rejected or a no-op.
        #[test]
        fn swapped_params_are_rejected_or_identical(a: u8, b: u8) {
            if let (Ok(x), Ok(y)) = (ShareParams::new(a, b), ShareParams::new(b, a)) {
                prop_assert_eq!(x, y);
            }
        }
    }

    #[test]
    fn rejects_malformed_bytes() {
        let root = RootKey::generate().unwrap();
        let good = split(&root, p(2, 2), 7).unwrap()[0].to_bytes();
        assert_eq!(Share::from_bytes(&good).unwrap().generation(), 7);

        let mut wrong_format = good.to_vec();
        wrong_format[0] = 2;
        let mut zero_x = good.to_vec();
        zero_x[5] = 0;
        for bad in [&good[..SHARE_LEN - 1], &[], &wrong_format, &zero_x] {
            assert!(matches!(
                Share::from_bytes(bad),
                Err(CryptoError::MalformedShare)
            ));
        }
    }
}
