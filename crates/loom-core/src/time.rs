//! Bitemporal time.
//!
//! Two axes, and they move independently:
//!
//! - **valid** — when the statement holds **in the world**.
//! - **known** — when **we** believed it. Assigned by the engine, immutable, *closed* rather than
//!   overwritten.
//!
//! An observation that arrives today may describe last week: `known` starts today, `valid` starts
//! last week. A correction closes the old `known` interval and opens a new one — it never rewrites
//! the old row, because "what did we believe on 3 March" and "what do we believe now" are different
//! questions and both have to be answerable.
//!
//! # Unknown bounds are explicit
//!
//! `None` means *we do not know*. It does not mean "the epoch", and it does not mean "now". Guessing
//! a timestamp to fill a hole is how a temporal database starts lying: the guess is indistinguishable
//! from a fact the moment it is written.

use serde::{Deserialize, Serialize};

/// Milliseconds since the Unix epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Timestamp(u64);

impl Timestamp {
    /// From milliseconds since the epoch.
    pub fn from_ms(ms: u64) -> Self {
        Timestamp(ms)
    }

    /// Milliseconds since the epoch.
    pub fn as_ms(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}ms", self.0)
    }
}

/// A half-open interval `[start, end)`. `end: None` means "still true, as far as we know".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interval {
    /// When it starts. `None` means we do not know when it started — **not** "the beginning of time".
    pub start: Option<Timestamp>,
    /// When it stops. `None` means it has not stopped.
    pub end: Option<Timestamp>,
}

impl Interval {
    /// An interval that starts here and has not ended.
    pub fn from(start: Timestamp) -> Self {
        Interval {
            start: Some(start),
            end: None,
        }
    }

    /// A closed interval.
    pub fn between(start: Timestamp, end: Timestamp) -> Self {
        Interval {
            start: Some(start),
            end: Some(end),
        }
    }

    /// Entirely unknown.
    pub fn unknown() -> Self {
        Interval {
            start: None,
            end: None,
        }
    }

    /// Whether this interval contains an instant.
    ///
    /// An unknown bound does not constrain: if we do not know when something started, we cannot say
    /// it had not started. That is deliberately permissive, and it is the honest reading of "unknown".
    pub fn contains(&self, at: Timestamp) -> bool {
        let after_start = self.start.is_none_or(|s| at >= s);
        let before_end = self.end.is_none_or(|e| at < e);
        after_start && before_end
    }

    /// Whether two intervals overlap. Two claims that overlap in validity **and disagree** are a
    /// contradiction; two that do not overlap are simply a history.
    pub fn overlaps(&self, other: &Interval) -> bool {
        let self_starts_before_other_ends = match (self.start, other.end) {
            (Some(s), Some(e)) => s < e,
            _ => true,
        };
        let other_starts_before_self_ends = match (other.start, self.end) {
            (Some(s), Some(e)) => s < e,
            _ => true,
        };
        self_starts_before_other_ends && other_starts_before_self_ends
    }

    /// Close this interval at an instant. Used when a belief is superseded — the old one is *closed*,
    /// not deleted.
    pub fn closed_at(&self, end: Timestamp) -> Interval {
        Interval {
            start: self.start,
            end: Some(end),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(ms: u64) -> Timestamp {
        Timestamp::from_ms(ms)
    }

    #[test]
    fn a_half_open_interval_excludes_its_end() {
        let i = Interval::between(t(100), t(200));
        assert!(i.contains(t(100)));
        assert!(i.contains(t(199)));
        assert!(!i.contains(t(200)), "the interval is half-open");
        assert!(!i.contains(t(99)));
    }

    #[test]
    fn an_open_ended_interval_has_not_stopped() {
        let i = Interval::from(t(100));
        assert!(i.contains(t(100)));
        assert!(i.contains(t(u64::MAX)));
        assert!(!i.contains(t(99)));
    }

    #[test]
    fn an_unknown_bound_does_not_constrain() {
        // If we do not know when it started, we cannot claim it had not started. Unknown is not zero.
        let i = Interval::unknown();
        assert!(i.contains(t(0)));
        assert!(i.contains(t(u64::MAX)));
    }

    #[test]
    fn overlapping_validity_is_what_makes_a_contradiction() {
        let a = Interval::between(t(0), t(100));
        let b = Interval::between(t(50), t(150));
        let c = Interval::between(t(100), t(200));

        assert!(a.overlaps(&b), "these two can contradict each other");
        assert!(
            !a.overlaps(&c),
            "these two are just a history, not a conflict"
        );
        assert!(b.overlaps(&c));
    }

    #[test]
    fn closing_an_interval_preserves_its_start() {
        // Supersession CLOSES the old belief; it does not rewrite it.
        let open = Interval::from(t(100));
        let closed = open.closed_at(t(200));
        assert_eq!(closed.start, Some(t(100)));
        assert_eq!(closed.end, Some(t(200)));
    }
}
