//! The merge engine. **Record granularity, not page granularity.**
//!
//! ```text
//! substrate.diff3(base, a, b)     →  which PAGES changed        (cheap, physical, a PREFILTER)
//!      ↓
//! decode the leaves in those pages →  which KEYS might have changed
//!      ↓
//! typed rules, per record          →  merged records, or conflicts   (semantic)
//!      ↓
//! replay as NEW commits on target  →  policy re-evaluated at merge time
//! ```
//!
//! # Why the granularity matters, and why it was a bug
//!
//! substrate's `diff3` compares **pages** — a physical 64 KiB unit. An earlier version of the
//! architecture had the merge engine consume that classification *directly*, which meant that two
//! agents writing two entirely unrelated facts that happened to land in the same page would be
//! reported as a conflict.
//!
//! A merge engine that reports conflicts between things that do not conflict is a merge engine that
//! lies, and an agent — which is the consumer here — would either escalate to a human for nothing, or
//! learn to ignore conflicts. Both outcomes are worse than not having merge at all.
//!
//! So `diff3` narrows the search, and the search is over **records**.
//!
//! # A merge is not a copy
//!
//! The result is a set of *new writes* on the target branch, not a transplant of the source's pages.
//! That matters because the world moved while the branch was off exploring: a write that was allowed
//! when the branch forked may not be allowed now, and re-validating at merge time is the only place
//! that can be caught.

use crate::tree::Tree;
use loom_core::{Claim, Key, Record, Result, Value};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use substrate_pager::{ManifestId, PageStore};

/// Keys the engine reserves for its own bookkeeping.
///
/// A leading NUL sorts before every printable key, so the engine's records live at the front of the
/// tree and out of everyone's way. They are hidden from `scan`, refused to writers, and — critically
/// — **excluded from merge candidates**, because the record of *what a branch has already merged* must
/// not itself be merged. Merging the merge bookkeeping would produce a conflict on every second merge
/// and be, on reflection, quite funny.
pub const RESERVED_PREFIX: &[u8] = b"\x00loom/";

/// The prefix every merge-bookkeeping record shares.
pub fn merged_from_prefix() -> Key {
    let mut key = RESERVED_PREFIX.to_vec();
    key.extend_from_slice(b"merged-from/");
    key
}

/// The key at which a branch records the last commit it merged from another branch.
pub fn merged_from_key(source: &str) -> Key {
    let mut key = merged_from_prefix();
    key.extend_from_slice(source.as_bytes());
    key
}

/// Whether a key belongs to the engine rather than the caller.
pub fn is_reserved(key: &[u8]) -> bool {
    key.starts_with(RESERVED_PREFIX)
}

/// What the caller wants done when the typed rules cannot decide.
pub enum MergePolicy {
    /// The source branch wins.
    TakeSource,
    /// The target branch wins.
    TakeTarget,
    /// Report it and merge nothing.
    Conflict,
    /// Decide per record.
    Custom(Box<dyn Fn(&MergeConflict) -> Resolution + Send + Sync>),
}

impl std::fmt::Debug for MergePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MergePolicy::TakeSource => f.write_str("TakeSource"),
            MergePolicy::TakeTarget => f.write_str("TakeTarget"),
            MergePolicy::Conflict => f.write_str("Conflict"),
            MergePolicy::Custom(_) => f.write_str("Custom(<callback>)"),
        }
    }
}

/// How a caller resolved one conflict.
#[derive(Clone, Debug)]
pub enum Resolution {
    /// Take the source's version.
    Source,
    /// Take the target's version.
    Target,
    /// Take this instead.
    Replace(Record),
    /// Do not merge this record; report it.
    Unresolved,
}

/// One record the engine could not merge on its own.
///
/// **Written to be read by a language model.** The consumer of a merge conflict in this system is very
/// often a model deciding what to do next, and a report it cannot understand produces a bad decision.
/// So every field carries a human-readable description, not a page number and a hash.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MergeConflict {
    /// The key, as text if it is text.
    pub key: String,
    /// What the merge base held. `None` if neither branch's ancestor had it.
    pub base: Option<String>,
    /// What the source branch says.
    pub source: Option<String>,
    /// What the target branch says.
    pub target: Option<String>,
    /// Why the engine could not decide, in a sentence.
    pub reason: String,
    /// The records themselves, for a caller that wants to resolve programmatically.
    #[serde(skip)]
    pub records: ConflictRecords,
}

/// The actual records behind a conflict.
#[derive(Clone, Debug, Default)]
pub struct ConflictRecords {
    /// The merge base's record.
    pub base: Option<Record>,
    /// The source's record.
    pub source: Option<Record>,
    /// The target's record.
    pub target: Option<Record>,
}

/// Everything the engine could not merge.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MergeConflictReport {
    /// The conflicts.
    pub conflicts: Vec<MergeConflict>,
}

impl MergeConflictReport {
    /// True if there is nothing to report.
    pub fn is_empty(&self) -> bool {
        self.conflicts.is_empty()
    }
}

impl std::fmt::Display for MergeConflictReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.conflicts.is_empty() {
            return f.write_str("no conflicts");
        }
        writeln!(f, "{} conflict(s):", self.conflicts.len())?;
        for c in &self.conflicts {
            writeln!(f, "  • {}", c.key)?;
            writeln!(
                f,
                "      base:   {}",
                c.base.as_deref().unwrap_or("(absent)")
            )?;
            writeln!(
                f,
                "      source: {}",
                c.source.as_deref().unwrap_or("(deleted)")
            )?;
            writeln!(
                f,
                "      target: {}",
                c.target.as_deref().unwrap_or("(deleted)")
            )?;
            writeln!(f, "      {}", c.reason)?;
        }
        Ok(())
    }
}

/// What a merge did.
#[derive(Debug)]
pub enum MergeOutcome {
    /// Everything merged. These records must be written to the target.
    Merged {
        /// The records to apply.
        writes: Vec<(Key, Record)>,
        /// How many merged without anyone having to decide.
        automatic: usize,
    },
    /// Some records could not be merged.
    Conflict(Box<MergeConflictReport>),
}

/// Plan a three-way merge of `source` into `target`.
///
/// Reads only. Nothing is written — the caller applies the result, so that a merge can be inspected,
/// re-validated against policy, and rejected before it touches anything.
pub fn plan_merge(
    store: &dyn PageStore,
    base: &ManifestId,
    source: &ManifestId,
    target: &ManifestId,
    policy: &MergePolicy,
) -> Result<MergeOutcome> {
    // 1. THE PREFILTER. Which pages did either branch touch?
    let diff = store.diff3(base, source, target)?;
    let changed: Vec<u64> = diff.entries.iter().map(|(page_no, _)| *page_no).collect();

    // 2. Turn changed pages into candidate keys. A superset — extra keys cost a comparison, and a
    //    missing key would cost a silently dropped merge.
    let base_store = store.fork(base)?;
    let source_store = store.fork(source)?;
    let target_store = store.fork(target)?;

    let mut base_tree = Tree::open(&*base_store)?;
    let mut source_tree = Tree::open(&*source_store)?;
    let mut target_tree = Tree::open(&*target_store)?;

    let mut candidates: BTreeSet<Key> = BTreeSet::new();
    candidates.extend(source_tree.keys_in_pages(&changed)?);
    candidates.extend(target_tree.keys_in_pages(&changed)?);
    candidates.extend(base_tree.keys_in_pages(&changed)?);

    // The engine's own bookkeeping is not the caller's data, and must not be merged as though it
    // were — see `RESERVED_PREFIX`.
    candidates.retain(|k| !is_reserved(k));

    // 3. Decide, per record.
    let mut writes = Vec::new();
    let mut report = MergeConflictReport::default();
    let mut automatic = 0usize;

    for key in candidates {
        let b = base_tree.get(&key)?;
        let s = source_tree.get(&key)?;
        let t = target_tree.get(&key)?;

        match decide(&key, b.as_ref(), s.as_ref(), t.as_ref(), policy)? {
            Decision::Nothing => {}
            Decision::Write(record) => {
                automatic += 1;
                writes.push((key, record));
            }
            Decision::Resolved(record) => writes.push((key, record)),
            Decision::Conflict(conflict) => report.conflicts.push(conflict),
        }
    }

    if !report.is_empty() {
        return Ok(MergeOutcome::Conflict(Box::new(report)));
    }
    Ok(MergeOutcome::Merged { writes, automatic })
}

enum Decision {
    /// The target already has the right answer. Write nothing.
    Nothing,
    /// The engine decided on its own.
    Write(Record),
    /// The caller's policy decided.
    Resolved(Record),
    /// Nobody could decide.
    Conflict(MergeConflict),
}

fn decide(
    key: &[u8],
    base: Option<&Record>,
    source: Option<&Record>,
    target: Option<&Record>,
    policy: &MergePolicy,
) -> Result<Decision> {
    // Both sides agree.
    if source == target {
        // Either nobody touched it, or both made the SAME change — which is convergence, not
        // conflict. Two agents deriving the same fact from the same source is a normal, common,
        // *good* thing, and reporting it as a conflict would generate an enormous amount of
        // pointless work.
        return Ok(Decision::Nothing);
    }

    // Only one side moved.
    if source == base {
        return Ok(Decision::Nothing); // the target is the only author; it already has its answer
    }
    if target == base {
        return match source {
            Some(record) => Ok(Decision::Write(record.clone())),
            // The source deleted it and the target never touched it.
            None => Ok(Decision::Nothing),
        };
    }

    // Both moved, and they disagree. Try the typed rules.
    if let (Some(s), Some(t)) = (source, target) {
        if let Some(merged) = merge_typed(base, s, t) {
            return Ok(Decision::Write(merged));
        }
    }

    // The typed rules could not decide. Ask the policy.
    let conflict = MergeConflict {
        key: describe_key(key),
        base: base.map(|r| r.describe()),
        source: source.map(|r| r.describe()),
        target: target.map(|r| r.describe()),
        reason: reason_for(source, target),
        records: ConflictRecords {
            base: base.cloned(),
            source: source.cloned(),
            target: target.cloned(),
        },
    };

    let resolution = match policy {
        MergePolicy::TakeSource => Resolution::Source,
        MergePolicy::TakeTarget => Resolution::Target,
        MergePolicy::Conflict => Resolution::Unresolved,
        MergePolicy::Custom(f) => f(&conflict),
    };

    Ok(match resolution {
        Resolution::Source => match source {
            Some(r) => Decision::Resolved(r.clone()),
            None => Decision::Conflict(conflict),
        },
        Resolution::Target => Decision::Nothing,
        Resolution::Replace(r) => Decision::Resolved(r),
        Resolution::Unresolved => Decision::Conflict(conflict),
    })
}

/// The typed rules (docs/03 §3.3). `None` means "this one needs a human, or a policy".
fn merge_typed(base: Option<&Record>, source: &Record, target: &Record) -> Option<Record> {
    match (source, target) {
        // --- ADDITIVE: this is most agent concurrency, and it must not be a conflict ---
        (Record::Value(Value::Counter(s)), Record::Value(Value::Counter(t))) => {
            // Merge the *deltas*, not the values. Two branches each incrementing by 3 from a base of
            // 10 must yield 16, not 13 — taking either side's absolute value would silently discard
            // the other agent's work while looking perfectly successful.
            let b = match base {
                Some(Record::Value(Value::Counter(b))) => *b,
                _ => 0,
            };
            Some(Record::Value(Value::Counter(
                b.saturating_add(s.saturating_sub(b))
                    .saturating_add(t.saturating_sub(b)),
            )))
        }

        (Record::Value(Value::Set(s)), Record::Value(Value::Set(t))) => {
            let mut merged = s.clone();
            merged.extend(t.iter().cloned());
            Some(Record::Value(Value::Set(merged)))
        }

        // --- TEMPORAL FACTS: resolve by validity, then by provenance rank ---
        (Record::Claim(s), Record::Claim(t)) => merge_claims(s, t),

        // Everything else needs someone to decide.
        _ => None,
    }
}

/// Two claims about the same thing, from two branches.
fn merge_claims(source: &Claim, target: &Claim) -> Option<Record> {
    // If their validity windows do not overlap, they are not in conflict at all — they are a
    // *history*. Two claims that were true at different times are both true.
    if !source.valid.overlaps(&target.valid) {
        // Keep the one that is valid later; the other remains in history and is not lost, because
        // claims are superseded rather than deleted.
        let winner = match (source.valid.start, target.valid.start) {
            (Some(s), Some(t)) if s >= t => source,
            (Some(_), Some(_)) => target,
            _ => return None, // unknown bounds: we will not guess
        };
        return Some(Record::Claim(Box::new(winner.clone())));
    }

    // They overlap and disagree. Provenance rank decides: a claim derived directly from a verified
    // system outranks one a language model inferred, and that should not be controversial.
    let s_rank = source.provenance_rank();
    let t_rank = target.provenance_rank();

    if s_rank == t_rank {
        // Equal provenance, overlapping validity, different content. There is no principled way to
        // choose, and inventing one would be worse than admitting it.
        return None;
    }

    Some(Record::Claim(Box::new(
        if s_rank > t_rank { source } else { target }.clone(),
    )))
}

fn reason_for(source: Option<&Record>, target: Option<&Record>) -> String {
    match (source, target) {
        (None, Some(_)) => "the source branch DELETED this record while the target modified it. \
                            Deleting and editing are very different intentions, and the engine will \
                            not guess which one you meant."
            .to_string(),
        (Some(_), None) => "the target branch DELETED this record while the source modified it. \
                            Deleting and editing are very different intentions, and the engine will \
                            not guess which one you meant."
            .to_string(),
        (Some(Record::Claim(s)), Some(Record::Claim(t))) => format!(
            "both branches assert a claim about {:?} with OVERLAPPING validity and EQUAL provenance \
             rank (both {:?}, confidence {:.2} vs {:.2}). There is no principled way to choose \
             between them; decide, or supersede one with a better-evidenced claim.",
            s.subject, s.confidence.method, s.confidence.value, t.confidence.value
        ),
        (Some(_), Some(_)) => "both branches changed this record to different values, and its type \
                               is not one the engine knows how to combine (a counter adds, a set \
                               unions, a claim resolves by validity and provenance — an opaque value \
                               does none of those). Choose one, or supply a merged value."
            .to_string(),
        (None, None) => "both branches deleted this record".to_string(),
    }
}

fn describe_key(key: &[u8]) -> String {
    match std::str::from_utf8(key) {
        Ok(s) => s.to_string(),
        Err(_) => format!("<{} bytes of binary key>", key.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_core::{
        ActorId, ClaimId, ClaimStatus, Confidence, Interval, Method, SourceRef, Timestamp,
    };

    fn counter(n: i64) -> Record {
        Record::Value(Value::Counter(n))
    }

    fn set(items: &[&str]) -> Record {
        Record::Value(Value::Set(
            items.iter().map(|s| s.as_bytes().to_vec()).collect(),
        ))
    }

    fn claim(method: Method, confidence: f64, valid: Interval, object: Value) -> Record {
        Record::Claim(Box::new(Claim {
            id: ClaimId::new(),
            predicate: "identity.compromised".into(),
            subject: "user-4471".into(),
            object,
            valid,
            known: Interval::from(Timestamp::from_ms(0)),
            confidence: Confidence::new(confidence, method, "risk-v4"),
            evidence: vec![SourceRef::new("idp", "signin-847")],
            status: ClaimStatus::Asserted,
            policy: None,
            actor: ActorId::new("agent-1"),
        }))
    }

    #[test]
    fn two_agents_incrementing_a_counter_do_not_conflict() {
        // The single most common shape of agent concurrency. If this is a conflict, the database is
        // unusable — and, worse, taking either side's absolute value would silently DISCARD the other
        // agent's work while reporting a clean merge.
        let base = counter(10);
        let source = counter(13); // +3
        let target = counter(15); // +5

        let merged = merge_typed(Some(&base), &source, &target).expect("counters must merge");
        assert_eq!(merged, counter(18), "10 + 3 + 5, not 13 or 15");
    }

    #[test]
    fn a_counter_with_no_base_still_merges() {
        let merged = merge_typed(None, &counter(3), &counter(5)).expect("must merge");
        assert_eq!(merged, counter(8));
    }

    #[test]
    fn sets_merge_by_union() {
        let merged = merge_typed(Some(&set(&["a"])), &set(&["a", "b"]), &set(&["a", "c"]))
            .expect("sets must merge");
        assert_eq!(merged, set(&["a", "b", "c"]));
    }

    #[test]
    fn a_verified_claim_outranks_one_a_language_model_inferred() {
        let overlapping = Interval::from(Timestamp::from_ms(100));

        let from_llm = claim(Method::LanguageModel, 0.95, overlapping, Value::Bool(true));
        let from_system = claim(Method::Direct, 0.60, overlapping, Value::Bool(false));

        let merged = merge_typed(None, &from_llm, &from_system).expect("must resolve");
        let Record::Claim(winner) = merged else {
            panic!("expected a claim");
        };
        assert_eq!(
            winner.confidence.method,
            Method::Direct,
            "a confident language model must not beat a verified system record"
        );
        assert_eq!(winner.object, Value::Bool(false));
    }

    #[test]
    fn claims_whose_validity_does_not_overlap_are_a_history_not_a_conflict() {
        let earlier = claim(
            Method::Rule,
            0.9,
            Interval::between(Timestamp::from_ms(0), Timestamp::from_ms(100)),
            Value::Bool(false),
        );
        let later = claim(
            Method::Rule,
            0.9,
            Interval::from(Timestamp::from_ms(100)),
            Value::Bool(true),
        );

        let merged =
            merge_typed(None, &earlier, &later).expect("non-overlapping is not a conflict");
        let Record::Claim(winner) = merged else {
            panic!("expected a claim");
        };
        assert_eq!(winner.object, Value::Bool(true), "the later belief wins");
    }

    #[test]
    fn equal_provenance_and_overlapping_validity_is_an_honest_conflict() {
        // Two claims, same method, same confidence, overlapping validity, opposite conclusions.
        // There is genuinely no principled way to choose, and inventing one would be worse than
        // admitting it.
        let overlapping = Interval::from(Timestamp::from_ms(100));
        let a = claim(Method::Rule, 0.9, overlapping, Value::Bool(true));
        let b = claim(Method::Rule, 0.9, overlapping, Value::Bool(false));

        assert!(
            merge_typed(None, &a, &b).is_none(),
            "the engine must not fabricate a resolution it has no basis for"
        );
    }

    #[test]
    fn opaque_blobs_do_not_merge_themselves() {
        let a = Record::Value(Value::Blob(vec![1, 2, 3]));
        let b = Record::Value(Value::Blob(vec![4, 5, 6]));
        assert!(merge_typed(None, &a, &b).is_none());
    }

    #[test]
    fn a_conflict_report_reads_like_something_a_model_can_act_on() {
        let overlapping = Interval::from(Timestamp::from_ms(100));
        let source = claim(Method::Rule, 0.9, overlapping, Value::Bool(true));
        let target = claim(Method::Rule, 0.9, overlapping, Value::Bool(false));

        let decision = decide(
            b"claim/user-4471/compromised",
            None,
            Some(&source),
            Some(&target),
            &MergePolicy::Conflict,
        )
        .expect("decide");

        let Decision::Conflict(conflict) = decision else {
            panic!("expected a conflict");
        };

        assert_eq!(conflict.key, "claim/user-4471/compromised");
        assert!(conflict.reason.contains("OVERLAPPING validity"));
        assert!(conflict.reason.contains("EQUAL provenance"));
        // It must say what to DO.
        assert!(conflict.reason.contains("decide, or supersede"));
        // And the human-readable descriptions must actually describe something.
        assert!(conflict
            .source
            .as_ref()
            .is_some_and(|s| s.contains("claim")));
    }

    #[test]
    fn delete_versus_edit_is_a_conflict_the_engine_refuses_to_guess() {
        let decision = decide(
            b"k",
            Some(&counter(1)),
            None,              // source deleted it
            Some(&counter(5)), // target edited it
            &MergePolicy::Conflict,
        )
        .expect("decide");

        let Decision::Conflict(conflict) = decision else {
            panic!("delete-vs-edit must be a conflict");
        };
        assert!(conflict.reason.contains("DELETED"));
        assert!(conflict.reason.contains("will not guess"));
    }

    #[test]
    fn convergent_edits_are_not_a_conflict() {
        // Two agents derived the SAME fact from the same source, in separate branches. That is
        // convergence, and calling it a conflict would generate an enormous amount of pointless work.
        let same = counter(7);
        let decision = decide(
            b"k",
            Some(&counter(1)),
            Some(&same),
            Some(&same),
            &MergePolicy::Conflict,
        )
        .expect("decide");

        assert!(matches!(decision, Decision::Nothing));
    }

    #[test]
    fn a_policy_can_break_a_tie() {
        let decision = decide(
            b"k",
            Some(&Record::Value(Value::Blob(vec![0]))),
            Some(&Record::Value(Value::Blob(vec![1]))),
            Some(&Record::Value(Value::Blob(vec![2]))),
            &MergePolicy::TakeSource,
        )
        .expect("decide");

        let Decision::Resolved(record) = decision else {
            panic!("the policy should have resolved it");
        };
        assert_eq!(record, Record::Value(Value::Blob(vec![1])));
    }
}
