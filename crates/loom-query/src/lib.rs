//! **AQL v0 — the as-of query. "What did you believe, and when?"**
//!
//! One question, asked bitemporally: for a `(subject, predicate)`, what did we believe held in the
//! world at `valid_at`, as of what we knew at `known_at`? The answer walks the append-only version
//! history (see `loom_core::ClaimVersion`) and returns the version whose *known* interval contains
//! `known_at` and whose *valid* interval contains `valid_at`.
//!
//! Two acceptance tests turn on this:
//!
//! - **AT-004 (late arrival).** Ingest today an observation that was valid last week. Asking "what did
//!   you know last week" excludes it; asking "what held last week, as of today" includes it. The two
//!   time axes are independent, and confusing them is the classic bitemporal bug.
//! - **AT-009 (as-of is reproducible).** A query with defaulted bounds **states the `valid_at` and
//!   `known_at` it actually used**, and re-issuing with those exact bounds returns an identical answer.
//!   A reproducible answer is one you can put in an audit and defend a year later.

use loom_branch::{CapabilityToken, Loom, Tree};
use loom_core::{BranchId, Claim, ClaimVersion, Result, Timestamp};
use substrate_pager::PageStore;

/// The bitemporal coordinates a query is answered at. Both default to "now"; whatever is used is
/// **recorded in the answer**, so the same question can be re-asked identically (AT-009).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AsOf {
    /// When it held **in the world**.
    pub valid_at: Timestamp,
    /// When **we** believed it.
    pub known_at: Timestamp,
}

impl AsOf {
    /// Both axes at the same instant — the common "what do we believe right now" query.
    pub fn at(now: Timestamp) -> Self {
        AsOf {
            valid_at: now,
            known_at: now,
        }
    }
}

/// An as-of answer: the claim we believed, **and the exact coordinates we answered at**.
///
/// The coordinates are the point. An answer that does not say *when* it was true and *when* it was
/// believed is an answer nobody can reproduce or defend — so every answer carries them, and re-issuing
/// [`AsOfAnswer::as_of`] returns byte-identical results.
#[derive(Clone, Debug, PartialEq)]
pub struct AsOfAnswer {
    /// The claim believed at these coordinates, or `None` if we believed nothing then.
    pub claim: Option<Claim>,
    /// The exact `(valid_at, known_at)` this was answered at — defaulted values resolved to concrete
    /// timestamps, so the query is reproducible.
    pub as_of: AsOf,
}

/// Answers as-of queries against a branch.
pub struct AsOfQuery<'a> {
    db: &'a Loom,
}

impl<'a> AsOfQuery<'a> {
    /// Wrap a database.
    pub fn new(db: &'a Loom) -> Self {
        AsOfQuery { db }
    }

    /// **What did we believe about `(subject, predicate)` at these coordinates?**
    ///
    /// Walks the version history and returns the claim whose *known* interval contains `known_at` and
    /// whose *valid* interval contains `valid_at`. When several versions qualify — which happens when
    /// their known intervals were not perfectly partitioned — the **latest by sequence** wins, so the
    /// selection is deterministic (AT-006's "preferred current is deterministic").
    pub fn as_of(
        &self,
        token: &CapabilityToken,
        branch: &BranchId,
        subject: &str,
        predicate: &str,
        as_of: AsOf,
    ) -> Result<AsOfAnswer> {
        self.db.authorize_read(token, branch)?;

        let head = self.db.head(branch)?;
        let store = self.db.pager_for_debug().fork(&head)?;
        let mut tree = Tree::open(&*store)?;

        let prefix = ClaimVersion::history_prefix(subject, predicate);
        let mut best: Option<ClaimVersion> = None;
        for (key, record) in tree.scan()? {
            if !key.starts_with(&prefix) {
                continue;
            }
            let loom_core::Record::Value(loom_core::Value::Blob(bytes)) = record else {
                continue;
            };
            let Ok(version) = ClaimVersion::decode(&bytes) else {
                continue;
            };
            // Both axes must contain the asked coordinate. Independent conditions — the whole point of
            // bitemporality is that "when it held" and "when we believed it" are different questions.
            if version.claim.known.contains(as_of.known_at)
                && version.claim.valid.contains(as_of.valid_at)
            {
                best = Some(match best {
                    Some(prev) if prev.seq >= version.seq => prev,
                    _ => version,
                });
            }
        }

        Ok(AsOfAnswer {
            claim: best.map(|v| v.claim),
            as_of,
        })
    }
}
