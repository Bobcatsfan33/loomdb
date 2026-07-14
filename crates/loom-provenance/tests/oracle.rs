//! **The taint oracle.** docs/05 §4 calls this the load-bearing one, and it is.
//!
//! # Why this test matters more than the others
//!
//! An incomplete recall plan tells a customer their poisoned data is contained **when it is not**.
//! That is the worst thing this system can do — worse than crashing, worse than refusing to start —
//! because the customer acts on it, and nothing complains.
//!
//! Precision matters almost as much. A plan that proposes reverting four hundred unrelated writes
//! will not be run by anyone, and then the poisoned data stays. A taint that cries wolf is a taint
//! that gets ignored.
//!
//! So: **exactly** the right set. Not a superset. Not a subset.
//!
//! # What makes this an oracle rather than a mirror
//!
//! The model does not use the engine's DAG, its source index, its branches, or its storage. It is a
//! plain `BTreeMap` of "this write read these things", built by the *test* as it drives the engine,
//! and flooded downstream with the most obvious algorithm anyone could write.
//!
//! The engine, meanwhile, has to get there through: read-set capture on a session, derivation nodes
//! written into a B+tree, a source index, branch inheritance through forks, and a reverse-edge walk.
//! Any one of those can be silently wrong. If it is, the two answers differ.
//!
//! (The engine's own commit ordering was silently wrong when this suite was written — provenance was
//! being committed *before* the data commit took the head, so every derivation node was overwritten
//! and the DAG was empty. `taint()` cheerfully reported "nothing is contaminated". The acceptance
//! tests caught it in seconds. This is what that class of bug looks like from the inside.)

use loom_branch::Loom;
use loom_core::{
    ActorId, BranchId, Claim, ClaimId, ClaimStatus, Confidence, Interval, Method, Observation,
    ObservationId, Record, SessionId, SourceRef, TenantId, Timestamp, TrustClass, Value,
    WriteEnvelope,
};
use loom_provenance::Provenance;
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

const NOW: u64 = 1_700_000_000_000;
const SOURCES: usize = 3;

/// The model: a flat list of writes, each recording what it was derived from.
///
/// # Why it tracks WRITES and not KEYS
///
/// The first version of this model kept `key → parents` and unioned across writes. It reported a
/// contamination the engine did not, and the **engine was right**: a key can be *overwritten*, and a
/// conclusion built on a re-derived, clean version of a claim is genuinely clean. Treating a key as
/// permanently tainted because one *historical* version of it was would over-report — and a plan that
/// over-reports is a plan nobody runs.
///
/// So the model does what the engine does, from first principles: one record per write, edges to the
/// specific *versions* that were read. It still uses no part of the engine — no node ids, no source
/// index, no branch inheritance, no B+tree. Just a list and a loop.
#[derive(Clone, Debug)]
struct Write {
    key: String,
    sources: BTreeSet<String>,
    parents: BTreeSet<usize>,
}

#[derive(Default, Debug)]
struct Model {
    writes: Vec<Write>,
    /// (branch, key) → the index of the write that most recently produced it *on that branch*.
    ///
    /// Per-branch, because a fork inherits its parent's view and then diverges. Getting this wrong is
    /// how a taint stops at a fork boundary.
    latest: BTreeMap<(String, String), usize>,
}

impl Model {
    fn write(
        &mut self,
        branch: &str,
        key: &str,
        sources: BTreeSet<String>,
        parents: BTreeSet<usize>,
    ) {
        let idx = self.writes.len();
        self.writes.push(Write {
            key: key.to_string(),
            sources,
            parents,
        });
        self.latest
            .insert((branch.to_string(), key.to_string()), idx);
    }

    /// What a read of `key` on `branch` sees: the write that produced it there, if any.
    fn visible(&self, branch: &str, key: &str) -> Option<usize> {
        self.latest
            .get(&(branch.to_string(), key.to_string()))
            .copied()
    }

    /// A fork inherits everything its parent could see, and then diverges.
    fn fork(&mut self, from: &str, to: &str) {
        let inherited: Vec<((String, String), usize)> = self
            .latest
            .iter()
            .filter(|((b, _), _)| b == from)
            .map(|((_, k), v)| ((to.to_string(), k.clone()), *v))
            .collect();
        self.latest.extend(inherited);
    }

    /// Everything downstream of a source. Flood-fill, written the dumbest way possible.
    fn contaminated_keys(&self, source: &str) -> BTreeSet<String> {
        let mut hit: BTreeSet<usize> = self
            .writes
            .iter()
            .enumerate()
            .filter(|(_, w)| w.sources.contains(source))
            .map(|(i, _)| i)
            .collect();

        // Repeat until nothing changes. No reverse index, no bounds, no cleverness.
        loop {
            let mut grew = false;
            for (i, w) in self.writes.iter().enumerate() {
                if hit.contains(&i) {
                    continue;
                }
                if w.parents.iter().any(|p| hit.contains(p)) {
                    hit.insert(i);
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }

        hit.into_iter()
            .map(|i| self.writes[i].key.clone())
            .collect()
    }
}

#[derive(Clone, Debug)]
enum Op {
    /// Ingest an observation citing a source.
    Observe { branch: u8, source: u8 },
    /// Read some keys, then write a claim derived from whatever was read.
    Derive { branch: u8, reads: Vec<u8>, key: u8 },
    /// Fork a branch.
    Fork { from: u8 },
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0u8..5, 0u8..(SOURCES as u8)).prop_map(|(branch, source)| Op::Observe { branch, source }),
        5 => (0u8..5, prop::collection::vec(0u8..8, 0..3), 0u8..8)
            .prop_map(|(branch, reads, key)| Op::Derive { branch, reads, key }),
        2 => (0u8..5).prop_map(|from| Op::Fork { from }),
    ]
}

fn envelope(session: &SessionId, branch: &BranchId) -> WriteEnvelope {
    WriteEnvelope::new(
        ActorId::new("agent"),
        session.clone(),
        branch.clone(),
        "property test",
    )
}

fn observation(source: &str) -> Record {
    Record::Observation(Box::new(Observation {
        id: ObservationId::of(source.as_bytes()),
        source: SourceRef::new("web", source),
        trust: TrustClass::Untrusted,
        observed_at: None,
        ingested_at: Timestamp::from_ms(NOW),
        payload: source.as_bytes().to_vec(),
    }))
}

fn claim(key: &str) -> Record {
    Record::Claim(Box::new(Claim {
        id: ClaimId::of(key.as_bytes()),
        predicate: "p".into(),
        subject: key.into(),
        object: Value::Bool(true),
        valid: Interval::from(Timestamp::from_ms(NOW)),
        known: Interval::from(Timestamp::from_ms(NOW)),
        confidence: Confidence::new(0.9, Method::Rule, "v1"),
        evidence: vec![SourceRef::new("web", "s0")],
        status: ClaimStatus::Asserted,
        policy: None,
        actor: ActorId::new("agent"),
    }))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("TAINT_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(400)
    ))]

    /// **The plan names EXACTLY what is downstream of the source. No more, no less.**
    #[test]
    fn taint_names_exactly_the_contaminated_set(ops in prop::collection::vec(op(), 1..30)) {
        let db = Loom::in_memory(TenantId::new("acme"))
            .map_err(|e| TestCaseError::fail(e.to_string()))?
            .with_clock(|| NOW);

        let session = SessionId::new("s");
        let (handle, mut token) = db
            .open_session_named(session.clone())
            .map_err(|e| TestCaseError::fail(e.to_string()))?;

        let mut branches: Vec<BranchId> = vec![handle.branch.clone()];
        let mut model = Model::default();

        for (step, op) in ops.iter().enumerate() {
            match op {
                Op::Observe { branch, source } => {
                    let branch = branches[*branch as usize % branches.len()].clone();
                    let source_name = format!("s{source}");
                    let key = format!("obs/{source_name}");

                    db.write(
                        &token,
                        &branch,
                        key.clone().into_bytes(),
                        observation(&source_name),
                        &envelope(&session, &branch),
                    )
                    .map_err(|e| TestCaseError::fail(format!("step {step}: observe: {e}")))?;

                    model.write(
                        branch.as_str(),
                        &key,
                        [source_name].into_iter().collect(),
                        BTreeSet::new(),
                    );
                }

                Op::Derive { branch, reads, key } => {
                    let branch = branches[*branch as usize % branches.len()].clone();
                    let key = format!("claim/{key}");

                    // Read some keys. Whatever actually EXISTS on this branch is what the engine
                    // captures — and it is what the model records too.
                    let mut parents: BTreeSet<usize> = BTreeSet::new();
                    for r in reads {
                        // Candidate keys: observations and claims, by name.
                        for candidate in [format!("obs/s{}", r % SOURCES as u8), format!("claim/{r}")] {
                            let found = db
                                .read(&token, &branch, candidate.as_bytes())
                                .map_err(|e| TestCaseError::fail(format!("step {step}: read: {e}")))?;
                            if found.is_some() {
                                // The model links to the SPECIFIC VERSION that was visible, not to
                                // the key — because a later, clean re-derivation of that key does not
                                // retroactively clean this write, and an earlier poisoned one does
                                // not retroactively taint a write that never saw it.
                                if let Some(idx) = model.visible(branch.as_str(), &candidate) {
                                    parents.insert(idx);
                                }
                            }
                        }
                    }

                    db.write(
                        &token,
                        &branch,
                        key.clone().into_bytes(),
                        claim(&key),
                        &envelope(&session, &branch),
                    )
                    .map_err(|e| TestCaseError::fail(format!("step {step}: derive: {e}")))?;

                    // The model records what was read. Note it unions nothing the caller declared —
                    // because the caller declared nothing, which is the whole point of AT-002.
                    model.write(branch.as_str(), &key, BTreeSet::new(), parents);
                }

                Op::Fork { from } => {
                    let parent = branches[*from as usize % branches.len()].clone();
                    let name = format!("fork-{step}");
                    let (branch, new_token) = db
                        .branch(&token, &parent, &name)
                        .map_err(|e| TestCaseError::fail(format!("step {step}: fork: {e}")))?;
                    token = new_token;
                    model.fork(parent.as_str(), branch.as_str());
                    branches.push(branch);
                }
            }
        }

        // ── the check ────────────────────────────────────────────────────
        let prov = Provenance::new(&db);

        for s in 0..SOURCES {
            let source_name = format!("s{s}");
            let source = SourceRef::new("web", &source_name);

            let (plan, _) = prov
                .taint(&source)
                .map_err(|e| TestCaseError::fail(format!("taint: {e}")))?;

            // What the ENGINE says is contaminated — by logical key.
            let engine: BTreeSet<String> = plan
                .reversible
                .iter()
                .filter_map(|item| {
                    // The description is "<actor> wrote \"<key>\" — ..."
                    let start = item.description.find('"')? + 1;
                    let end = item.description[start..].find('"')? + start;
                    Some(item.description[start..end].to_string())
                })
                .collect();

            // What the MODEL says, computed by the dumbest flood-fill anyone could write.
            let expected = model.contaminated_keys(&source_name);

            let missed: Vec<_> = expected.difference(&engine).collect();
            prop_assert!(
                missed.is_empty(),
                "INCOMPLETE. taint({source_name}) MISSED {missed:?}.\n\
                 An incomplete recall plan tells a customer their poisoned data is contained when it \
                 is not. This is the worst thing this system can do.\n\
                 engine: {engine:?}\n  model: {expected:?}"
            );

            let excess: Vec<_> = engine.difference(&expected).collect();
            prop_assert!(
                excess.is_empty(),
                "IMPRECISE. taint({source_name}) proposes reverting {excess:?}, which are NOT \
                 downstream of it.\n\
                 A plan that reverts too much will not be run by anyone, and then the poisoned data \
                 stays.\n  engine: {engine:?}\n  model: {expected:?}"
            );
        }
    }
}
