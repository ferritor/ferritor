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

    #[test]
    fn a_reload_replaces_the_policy() {
        let rotation = Rotation::default();
        assert_eq!(rotation.policy(), DEFAULT);
        let shorter = Policy::new(30, 180, 365, 7).unwrap();
        rotation.reload(shorter);
        assert_eq!(rotation.policy(), shorter);
    }
}
