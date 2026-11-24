//! Rotation reminders: how old a secret (one flagged `ferritor.rotation`),
//! a namespace's active KEK and the root key may grow before they're due
//! for rotation, and how long before that they count as due soon. A
//! reminder only: nothing is ever refused for being old, since an outage
//! over a missed rotation would be worse than the old key. Nothing is
//! audited either: a deadline passing isn't a call (the puts and the
//! versions' times are the evidence).
//!
//! The ages are the config's (`rotation_max_age_days`, `kek_max_age_days`,
//! `root_key_max_age_days`, `rotation_warn_days`), reloaded on SIGHUP into
//! [`Rotation`], which everything that reports a due date reads.

use std::sync::{PoisonError, RwLock};

use time::{Duration, OffsetDateTime};

/// The longest any maximum may be: ten years.
pub const MAX_DAYS: u32 = 3650;

/// The four ages, in days. Checked (by [`Policy::new`]): each from 1 to
/// [`MAX_DAYS`], and the warning shorter than the shortest maximum, so
/// "due soon" always comes before "overdue".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// A secret with the rotation flag, from its current version's
    /// creation.
    pub secret_max_age_days: u32,
    /// A namespace's active KEK, from its creation.
    pub kek_max_age_days: u32,
    /// The root key, from the last rekey (or the init).
    pub root_key_max_age_days: u32,
    /// How long before its maximum something counts as due soon.
    pub warn_days: u32,
}

/// The defaults: 90 days for secrets (the usual SOX period), a year for
/// KEKs and the root key (a rekey needs the share holders), and two weeks'
/// warning.
pub const DEFAULT: Policy = Policy {
    secret_max_age_days: 90,
    kek_max_age_days: 365,
    root_key_max_age_days: 365,
    warn_days: 14,
};

impl Default for Policy {
    fn default() -> Self {
        DEFAULT
    }
}

/// What can be due for rotation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Secret,
    Kek,
    RootKey,
}

/// Where something stands against its maximum age.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Standing {
    Current,
    /// Within the warning of its maximum.
    DueSoon,
    /// Past its maximum.
    Overdue,
}

impl Policy {
    /// The four ages, checked.
    pub fn new(
        secret_max_age_days: u32,
        kek_max_age_days: u32,
        root_key_max_age_days: u32,
        warn_days: u32,
    ) -> Result<Self, String> {
        for (name, days) in [
            ("rotation_max_age_days", secret_max_age_days),
            ("kek_max_age_days", kek_max_age_days),
            ("root_key_max_age_days", root_key_max_age_days),
            ("rotation_warn_days", warn_days),
        ] {
            if !(1..=MAX_DAYS).contains(&days) {
                return Err(format!("{name} ({days}) must be from 1 to {MAX_DAYS}"));
            }
        }
        let shortest = secret_max_age_days
            .min(kek_max_age_days)
            .min(root_key_max_age_days);
        if warn_days >= shortest {
            return Err(format!(
                "rotation_warn_days ({warn_days}) must be below the shortest maximum age \
                 ({shortest} days), or nothing would be due soon before it's overdue"
            ));
        }
        Ok(Self {
            secret_max_age_days,
            kek_max_age_days,
            root_key_max_age_days,
            warn_days,
        })
    }

    fn max_age(&self, kind: Kind) -> Duration {
        let days = match kind {
            Kind::Secret => self.secret_max_age_days,
            Kind::Kek => self.kek_max_age_days,
            Kind::RootKey => self.root_key_max_age_days,
        };
        Duration::days(i64::from(days))
    }

    /// When something of `kind` made at `since` is due for rotation.
    pub fn due(&self, kind: Kind, since: OffsetDateTime) -> OffsetDateTime {
        since.saturating_add(self.max_age(kind))
    }

    /// Where something of `kind` made at `since` stands at `now`: overdue
    /// once its due date has passed, due soon within the warning of it.
    pub fn standing(&self, kind: Kind, since: OffsetDateTime, now: OffsetDateTime) -> Standing {
        let due = self.due(kind, since);
        if now >= due {
            Standing::Overdue
        } else if now >= due.saturating_sub(Duration::days(i64::from(self.warn_days))) {
            Standing::DueSoon
        } else {
            Standing::Current
        }
    }
}

/// The policy in force: the config's, swapped on SIGHUP.
#[derive(Debug, Default)]
pub struct Rotation(RwLock<Policy>);

impl Rotation {
    pub fn new(policy: Policy) -> Self {
        Self(RwLock::new(policy))
    }

    pub fn policy(&self) -> Policy {
        *self.0.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Puts `policy` in force for every due date reported from now on.
    pub fn reload(&self, policy: Policy) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = policy;
    }
}

/// How many are overdue and due soon, of one kind.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tally {
    pub overdue: u64,
    pub due_soon: u64,
}

impl Tally {
    /// Of things of `kind` made at `since`: how many stand where at `now`.
    pub fn of(
        policy: &Policy,
        kind: Kind,
        since: impl IntoIterator<Item = OffsetDateTime>,
        now: OffsetDateTime,
    ) -> Self {
        let mut tally = Self::default();
        for made in since {
            match policy.standing(kind, made, now) {
                Standing::Overdue => tally.overdue += 1,
                Standing::DueSoon => tally.due_soon += 1,
                Standing::Current => {}
            }
        }
        tally
    }
}

/// The last counts, for the gauges (`metrics::observe_rotation`): each kind
/// absent until it's been counted once, and kept as it was when a count
/// fails (the stores unreachable), so a gauge never drops to 0 for want of
/// an answer.
#[derive(Debug, Default)]
pub struct RotationCounts {
    secrets: RwLock<Option<Tally>>,
    keks: RwLock<Option<Tally>>,
    root_key: RwLock<Option<Tally>>,
}

impl RotationCounts {
    pub fn secrets(&self) -> Option<Tally> {
        *self.secrets.read().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn keks(&self) -> Option<Tally> {
        *self.keks.read().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn root_key(&self) -> Option<Tally> {
        *self.root_key.read().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn set_secrets(&self, tally: Tally) {
        *self.secrets.write().unwrap_or_else(PoisonError::into_inner) = Some(tally);
    }

    pub fn set_keks(&self, tally: Tally) {
        *self.keks.write().unwrap_or_else(PoisonError::into_inner) = Some(tally);
    }

    pub fn set_root_key(&self, tally: Tally) {
        *self
            .root_key
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(tally);
    }
}

/// The two moments the secrets' count is cut at: a version created at or
/// before the first is overdue, after it and at or before the second due
/// soon.
pub fn secret_cutoffs(policy: &Policy, now: OffsetDateTime) -> (OffsetDateTime, OffsetDateTime) {
    let max = Duration::days(i64::from(policy.secret_max_age_days));
    let warn = Duration::days(i64::from(policy.warn_days));
    (
        now.saturating_sub(max),
        now.saturating_sub(max).saturating_add(warn),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_age_is_checked_and_the_warning_comes_first() {
        assert_eq!(Policy::new(90, 365, 365, 14), Ok(DEFAULT));
        assert!(Policy::new(1, 1, 1, 1).unwrap_err().contains("below"));
        for (bad, says) in [
            (Policy::new(0, 365, 365, 14), "rotation_max_age_days (0)"),
            (Policy::new(90, 3651, 365, 14), "kek_max_age_days (3651)"),
            (Policy::new(90, 365, 0, 14), "root_key_max_age_days (0)"),
            (Policy::new(90, 365, 365, 0), "rotation_warn_days (0)"),
            (
                Policy::new(90, 30, 365, 30),
                "shortest maximum age (30 days)",
            ),
        ] {
            let error = bad.unwrap_err();
            assert!(error.contains(says), "{error}");
        }
    }

    /// Current, then due soon for the last `warn_days`, then overdue from
    /// the due date itself; each kind against its own maximum.
    #[test]
    fn standing_follows_the_due_date() {
        let policy = DEFAULT;
        let made = OffsetDateTime::UNIX_EPOCH;
        let day = |n: i64| made + Duration::days(n);
        assert_eq!(policy.due(Kind::Secret, made), day(90));
        assert_eq!(policy.due(Kind::Kek, made), day(365));
        let secret = |now| policy.standing(Kind::Secret, made, now);
        assert_eq!(secret(day(0)), Standing::Current);
        assert_eq!(secret(day(75)), Standing::Current);
        assert_eq!(secret(day(76)), Standing::DueSoon);
        assert_eq!(secret(day(89)), Standing::DueSoon);
        assert_eq!(secret(day(90)), Standing::Overdue);
        assert_eq!(
            policy.standing(Kind::RootKey, made, day(90)),
            Standing::Current
        );
        assert_eq!(
            policy.standing(Kind::RootKey, made, day(352)),
            Standing::DueSoon
        );
    }

    /// The tally sorts each age as `standing` does, and the secrets'
    /// cutoffs cut where `standing` would: the database's count and the
    /// in-memory one agree on every boundary.
    #[test]
    fn tallies_and_cutoffs_agree_with_standing() {
        let policy = DEFAULT;
        let now = OffsetDateTime::UNIX_EPOCH + Duration::days(1000);
        let ago = |days: i64| now - Duration::days(days);
        let tally = Tally::of(
            &policy,
            Kind::Kek,
            [ago(10), ago(351), ago(364), ago(365), ago(900)],
            now,
        );
        assert_eq!(
            tally,
            Tally {
                overdue: 2,
                due_soon: 2
            }
        );
        let (overdue_at, due_soon_at) = secret_cutoffs(&policy, now);
        for days in [0, 75, 76, 77, 89, 90, 91, 400] {
            let made = ago(days);
            let by_cutoff = if made <= overdue_at {
                Standing::Overdue
            } else if made <= due_soon_at {
                Standing::DueSoon
            } else {
                Standing::Current
            };
            assert_eq!(
                by_cutoff,
                policy.standing(Kind::Secret, made, now),
                "{days} days"
            );
        }
    }

    #[test]
    fn a_reload_replaces_the_policy() {
        let rotation = Rotation::default();
        assert_eq!(rotation.policy(), DEFAULT);
        let shorter = Policy::new(30, 180, 365, 7).unwrap();
        rotation.reload(shorter);
        assert_eq!(rotation.policy(), shorter);
    }
}
