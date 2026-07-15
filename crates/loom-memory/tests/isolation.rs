//! **AT-040 — branch-aware indexes, and the oracle that a sibling never leaks.**
//!
//! # Why this is the load-bearing test of L3
//!
//! The spec calls an index leak "a correctness bug wearing a performance costume", and it is exactly
//! the bug a global-index-with-a-branch-filter invites: the filter is one forgotten `WHERE`, one
//! mis-scoped join, one query-planner reordering away from returning another tenant's or another
//! hypothesis's data. This engine does not have that filter, because index entries live in the
//! branch's own tree and a sibling branch — a different head manifest — cannot address them. This
//! test is what proves the claim rather than asserting it.
//!
//! The oracle is a plain model of "what a branch can see": the writes on the branch itself, plus
//! everything it inherited from its parent at the moment it forked. It is built by the test as it
//! drives the engine, uses none of the engine's storage, and floods forward the dumbest way. The
//! engine reaches the same set through fork isolation, index storage, and retrieval. If they ever
//! disagree — in particular if the engine returns a *sibling's* write the model does not — the test
//! fails, and that disagreement is the leak.

use std::collections::{BTreeMap, BTreeSet};

use loom_branch::{Loom, MAIN};
use loom_core::{
    ActorId, BranchId, Embedding, IndexHint, Observation, ObservationId, Record, SessionId,
    SourceRef, TenantId, Timestamp, TrustClass, WriteEnvelope,
};
use loom_memory::{RetrievalQuery, Retriever};
use proptest::prelude::*;

const NOW: u64 = 1_700_000_000_000;

fn envelope(session: &SessionId, branch: &BranchId) -> WriteEnvelope {
    WriteEnvelope::new(
        ActorId::new("agent"),
        session.clone(),
        branch.clone(),
        "index a fact",
    )
}

fn observation(fact: &str) -> Record {
    Record::Observation(Box::new(Observation {
        id: ObservationId::of(fact.as_bytes()),
        source: SourceRef::new("web", fact),
        trust: TrustClass::Untrusted,
        observed_at: None,
        ingested_at: Timestamp::from_ms(NOW),
        payload: fact.as_bytes().to_vec(),
    }))
}

/// A toy deterministic embedding: term presence over a tiny fixed vocabulary. Deterministic so replay
/// is exact; it is an oracle's embedding, not a model's. What matters is that the *engine* stores and
/// compares whatever vector it is handed — not how good the vector is.
fn embed(text: &str) -> Embedding {
    const VOCAB: [&str; 6] = ["risk", "cfo", "revenue", "fraud", "dana", "emea"];
    let lower = text.to_lowercase();
    Embedding::new(
        VOCAB
            .iter()
            .map(|w| if lower.contains(w) { 1.0f32 } else { 0.0 })
            .collect::<Vec<_>>(),
    )
}

/// **The concrete story, spelled out: a fork's write is invisible to its sibling.**
#[test]
fn at_040_a_siblings_write_is_never_retrieved() -> loom_core::Result<()> {
    let db = Loom::in_memory(TenantId::new("acme"))?.with_clock(|| NOW);
    let (root, token) = db.open_session()?;

    // Two sibling hypotheses off main.
    let (left, left_tok) = db.branch(&token, &root.branch, "left")?;
    let (right, right_tok) = db.branch(&token, &root.branch, "right")?;

    // Each writes a distinct, indexed fact.
    db.write_indexed(
        &left_tok,
        &left,
        b"claim/cfo".to_vec(),
        observation("the CFO is Dana"),
        IndexHint::text("the CFO is Dana").with_embedding(embed("cfo dana")),
        &envelope(&root.id, &left),
    )?;
    db.write_indexed(
        &right_tok,
        &right,
        b"claim/cfo".to_vec(),
        observation("the CFO is Morgan"),
        IndexHint::text("the CFO is Morgan").with_embedding(embed("cfo")),
        &envelope(&root.id, &right),
    )?;

    let retr = Retriever::new(&db);
    let query = RetrievalQuery::text("who is the cfo", 1000).with_embedding(embed("cfo"));

    // Retrieve from LEFT. It must see its own fact and NOT right's.
    let from_left = retr.retrieve(&left_tok, &left, &query)?;
    let left_texts: Vec<&str> = from_left.items.iter().map(|i| i.text.as_str()).collect();
    assert!(
        left_texts.contains(&"the CFO is Dana"),
        "left must see its own fact"
    );
    assert!(
        !left_texts.contains(&"the CFO is Morgan"),
        "LEAK: left retrieved right's fact. A sibling's write must be invisible — this is AT-040."
    );

    // And symmetrically from RIGHT.
    let from_right = retr.retrieve(&right_tok, &right, &query)?;
    let right_texts: Vec<&str> = from_right.items.iter().map(|i| i.text.as_str()).collect();
    assert!(
        right_texts.contains(&"the CFO is Morgan"),
        "right must see its own fact"
    );
    assert!(
        !right_texts.contains(&"the CFO is Dana"),
        "LEAK: right retrieved left's fact."
    );

    // Every packed item is cited (AT-041), in passing.
    for item in from_left.items.iter().chain(&from_right.items) {
        assert!(
            !item.citations.is_empty(),
            "AT-041: no packed item may be uncited"
        );
    }
    Ok(())
}

// ── the oracle ──────────────────────────────────────────────────────────────────────────────────

/// The model of "what a branch can see": its own writes, plus what it inherited at fork time.
#[derive(Default, Clone)]
struct Model {
    /// branch → (key → fact text) currently visible on it.
    visible: BTreeMap<String, BTreeMap<String, String>>,
}

impl Model {
    fn write(&mut self, branch: &str, key: &str, fact: &str) {
        self.visible
            .entry(branch.to_string())
            .or_default()
            .insert(key.to_string(), fact.to_string());
    }

    /// A fork inherits exactly what its parent can see at this instant, and then diverges.
    fn fork(&mut self, from: &str, to: &str) {
        let inherited = self.visible.get(from).cloned().unwrap_or_default();
        self.visible.insert(to.to_string(), inherited);
    }

    fn visible_facts(&self, branch: &str) -> BTreeSet<String> {
        self.visible
            .get(branch)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }
}

#[derive(Clone, Debug)]
enum Op {
    Write { branch: u8, key: u8, fact: u8 },
    Fork { from: u8 },
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0u8..5, 0u8..6, 0u8..12).prop_map(|(branch, key, fact)| Op::Write { branch, key, fact }),
        1 => (0u8..5).prop_map(|from| Op::Fork { from }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("ISOLATION_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(400)
    ))]

    /// **What the engine retrieves from a branch equals what the model says is visible there — and no
    /// more.** The "no more" is the leak check: any branch returning a fact the model does not place
    /// there is a sibling (or unrelated-branch) leak.
    #[test]
    fn retrieval_sees_exactly_the_branch_and_never_a_sibling(ops in prop::collection::vec(op(), 1..40)) {
        let db = Loom::in_memory(TenantId::new("acme"))
            .map_err(|e| TestCaseError::fail(e.to_string()))?
            .with_clock(|| NOW);
        let session = SessionId::new("s");
        let (root, mut token) = db
            .open_session_named(session.clone())
            .map_err(|e| TestCaseError::fail(e.to_string()))?;

        let mut branches: Vec<BranchId> = vec![root.branch.clone()];
        let mut tokens = vec![token.clone()];
        let mut model = Model::default();
        // main starts empty; give the model the branch name.
        model.visible.insert(MAIN.to_string(), BTreeMap::new());

        for (step, op) in ops.iter().enumerate() {
            match op {
                Op::Write { branch, key, fact } => {
                    let i = *branch as usize % branches.len();
                    let b = branches[i].clone();
                    let tok = tokens[i].clone();
                    let key_s = format!("k{key}");
                    let fact_s = format!("fact-{fact}");

                    db.write_indexed(
                        &tok,
                        &b,
                        key_s.clone().into_bytes(),
                        observation(&fact_s),
                        IndexHint::text(&fact_s).with_embedding(embed(&fact_s)),
                        &envelope(&session, &b),
                    )
                    .map_err(|e| TestCaseError::fail(format!("step {step}: write: {e}")))?;

                    model.write(b.as_str(), &key_s, &fact_s);
                }
                Op::Fork { from } => {
                    let i = *from as usize % branches.len();
                    let parent = branches[i].clone();
                    let parent_tok = tokens[i].clone();
                    let name = format!("b-{step}");
                    let (child, child_tok) = db
                        .branch(&parent_tok, &parent, &name)
                        .map_err(|e| TestCaseError::fail(format!("step {step}: fork: {e}")))?;
                    token = child_tok.clone();
                    model.fork(parent.as_str(), child.as_str());
                    branches.push(child);
                    tokens.push(child_tok);
                }
            }
        }
        let _ = &token;

        // A broad query — every candidate matches the FTS on "fact", so retrieval returns everything
        // visible, which is exactly what lets us compare the *sets*.
        let retr = Retriever::new(&db);
        for (b, tok) in branches.iter().zip(&tokens) {
            let packed = retr
                .retrieve(tok, b, &RetrievalQuery::text("fact", 100_000))
                .map_err(|e| TestCaseError::fail(format!("retrieve {b:?}: {e}")))?;

            let engine: BTreeSet<String> = packed.items.iter().map(|i| i.text.clone()).collect();
            let expected = model.visible_facts(b.as_str());

            let leaked: Vec<_> = engine.difference(&expected).collect();
            prop_assert!(
                leaked.is_empty(),
                "LEAK on {b:?}: retrieved {leaked:?} which the model does not place on this branch. \
                 An index that returns another branch's facts is the exact bug AT-040 forbids.\n\
                 engine: {engine:?}\n  model: {expected:?}"
            );

            let missed: Vec<_> = expected.difference(&engine).collect();
            prop_assert!(
                missed.is_empty(),
                "INCOMPLETE on {b:?}: the branch should see {missed:?} but retrieval did not return it.\n\
                 engine: {engine:?}\n  model: {expected:?}"
            );
        }
    }
}
