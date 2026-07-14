//! The model oracle for branch and merge.
//!
//! # What this actually proves, and what it does not
//!
//! The model reimplements the *merge rules* on plain `BTreeMap`s — no pages, no B-tree, no `diff3`,
//! no prefilter. So it does **not** independently verify that "a counter merges arithmetically" is
//! the right rule; both implementations believe the same thing about that, and if the rule is wrong
//! they are wrong together.
//!
//! What it verifies is everything **underneath** the rule, which is where the bugs actually live:
//!
//! - the **prefilter**. `plan_merge` narrows candidate keys using substrate's page-level `diff3`. If
//!   that prefilter ever misses a key, a record silently fails to merge — the merge reports success,
//!   the data is quietly wrong, and nothing complains. The model has no prefilter: it considers every
//!   key. If the two ever disagree, the prefilter dropped something.
//! - the **B-tree**. Splits, child selection, the dirty-page cache.
//! - **branch isolation** through a real storage engine with real shared pages.
//! - **merge-base computation** over a real commit DAG.
//!
//! That is the honest scope, and it is worth stating, because an oracle whose scope is overstated is
//! a false sense of security dressed up as rigour.

use loom_branch::{Loom, MergePolicy, MergeResult};
use loom_core::{ActorId, BranchId, Key, Record, SessionId, TenantId, Value, WriteEnvelope};
use proptest::prelude::*;
use std::collections::BTreeMap;

const NOW: u64 = 1_700_000_000_000;
const MAX_KEY: u8 = 6;

type State = BTreeMap<Key, Record>;

/// The naive model — and it is deliberately built on the thing substrate does **not** have.
///
/// # Why the model keeps a two-parent DAG
///
/// substrate's manifests have exactly one parent. Git's merge commits have two, and that is not a
/// stylistic difference: it is what makes a merge base correct the *second* time you merge. LoomDB
/// therefore has to *reconstruct* two-parent ancestry from bookkeeping it keeps in its own tree
/// (see `Loom::best_merge_base`), and the whole question is whether that reconstruction is right.
///
/// So the model does the honest thing and keeps a real DAG with real merge commits, and computes a
/// real lowest common ancestor over it. If the engine's bookkeeping trick ever disagrees with an
/// actual two-parent LCA, this is what says so — which it did, twice, on the way to this version.
#[derive(Clone, Debug)]
struct Commit {
    parents: Vec<usize>,
    state: State,
}

#[derive(Clone, Debug, Default)]
struct Model {
    commits: Vec<Commit>,
    heads: BTreeMap<String, usize>,
}

impl Model {
    fn new() -> Self {
        let mut model = Model::default();
        model.commits.push(Commit {
            parents: vec![],
            state: State::new(),
        });
        model.heads.insert("session".to_string(), 0);
        model
    }

    fn head_state(&self, branch: &str) -> State {
        self.heads
            .get(branch)
            .and_then(|c| self.commits.get(*c))
            .map(|c| c.state.clone())
            .unwrap_or_default()
    }

    fn commit(&mut self, branch: &str, parents: Vec<usize>, state: State) {
        let id = self.commits.len();
        self.commits.push(Commit { parents, state });
        self.heads.insert(branch.to_string(), id);
    }

    fn write(&mut self, branch: &str, key: Key, record: Record) {
        let Some(head) = self.heads.get(branch).copied() else {
            return;
        };
        let mut state = self.head_state(branch);
        state.insert(key, record);
        self.commit(branch, vec![head], state);
    }

    fn fork(&mut self, from: &str, name: &str) {
        if let Some(head) = self.heads.get(from).copied() {
            self.heads.insert(name.to_string(), head);
        }
    }

    /// Every commit reachable backwards from `c`, including itself.
    fn ancestors(&self, c: usize) -> std::collections::BTreeSet<usize> {
        let mut seen = std::collections::BTreeSet::new();
        let mut stack = vec![c];
        while let Some(id) = stack.pop() {
            if !seen.insert(id) {
                continue;
            }
            if let Some(commit) = self.commits.get(id) {
                stack.extend(commit.parents.iter().copied());
            }
        }
        seen
    }

    /// **All** lowest common ancestors over a real DAG. There can be more than one — that is the
    /// criss-cross case, and it is exactly what the engine must detect and refuse.
    fn merge_bases(&self, a: usize, b: usize) -> Vec<usize> {
        let (a_anc, b_anc) = (self.ancestors(a), self.ancestors(b));
        let common: Vec<usize> = a_anc.intersection(&b_anc).copied().collect();

        common
            .iter()
            .copied()
            .filter(|&c| {
                !common
                    .iter()
                    .any(|&other| other != c && self.ancestors(other).contains(&c))
            })
            .collect()
    }

    fn merge(&mut self, source: &str, target: &str) -> bool {
        let (Some(sh), Some(th)) = (
            self.heads.get(source).copied(),
            self.heads.get(target).copied(),
        ) else {
            return false;
        };

        // More than one merge base is ambiguous, and the model refuses exactly as the engine does.
        let bases = self.merge_bases(sh, th);
        if bases.len() > 1 {
            return false;
        }
        let base = bases
            .first()
            .map(|c| self.commits[*c].state.clone())
            .unwrap_or_default();
        let s = self.head_state(source);
        let t = self.head_state(target);

        let mut merged = t.clone();
        let keys: std::collections::BTreeSet<&Key> =
            base.keys().chain(s.keys()).chain(t.keys()).collect();

        for key in keys {
            let (b, sv, tv) = (base.get(key), s.get(key), t.get(key));

            if sv == tv || sv == b {
                continue; // agreement, or only the target moved
            }
            if tv == b {
                if let Some(v) = sv {
                    merged.insert(key.clone(), v.clone());
                }
                continue;
            }

            // Both moved. The property test only generates counters, and they merge by delta.
            match (b, sv, tv) {
                (
                    Some(Record::Value(Value::Counter(bc))),
                    Some(Record::Value(Value::Counter(sc))),
                    Some(Record::Value(Value::Counter(tc))),
                ) => {
                    merged.insert(
                        key.clone(),
                        Record::Value(Value::Counter(
                            bc.saturating_add(sc.saturating_sub(*bc))
                                .saturating_add(tc.saturating_sub(*bc)),
                        )),
                    );
                }
                (
                    None,
                    Some(Record::Value(Value::Counter(sc))),
                    Some(Record::Value(Value::Counter(tc))),
                ) => {
                    merged.insert(
                        key.clone(),
                        Record::Value(Value::Counter(sc.saturating_add(*tc))),
                    );
                }
                _ => return false,
            }
        }

        // A MERGE COMMIT: two parents. This is the whole point of the model.
        self.commit(target, vec![th, sh], merged);
        true
    }

    fn head(&self, branch: &str) -> State {
        self.head_state(branch)
    }
}

#[derive(Clone, Debug)]
enum Op {
    Write { branch: u8, key: u8, value: i8 },
    Fork { from: u8, name: u8 },
    Merge { source: u8, target: u8 },
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        5 => (0u8..6, 0u8..MAX_KEY, any::<i8>())
            .prop_map(|(branch, key, value)| Op::Write { branch, key, value }),
        2 => (0u8..6, 0u8..6).prop_map(|(from, name)| Op::Fork { from, name }),
        2 => (0u8..6, 0u8..6).prop_map(|(source, target)| Op::Merge { source, target }),
    ]
}

fn key_of(n: u8) -> Key {
    format!("key-{n}").into_bytes()
}

fn counter(v: i8) -> Record {
    Record::Value(Value::Counter(v as i64))
}

fn envelope(branch: &BranchId) -> WriteEnvelope {
    WriteEnvelope::new(
        ActorId::new("agent"),
        SessionId::new("s"),
        branch.clone(),
        "property test",
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// The real engine and the model agree about the contents of every branch, under any sequence of
    /// writes, forks, and merges.
    #[test]
    fn the_engine_agrees_with_the_model(ops in prop::collection::vec(op(), 1..40)) {
        let db = Loom::in_memory(TenantId::new("acme"))
            .map_err(|e| TestCaseError::fail(e.to_string()))?
            .with_clock(|| NOW);

        let (session, mut token) = db
            .open_session_named(SessionId::new("session"))
            .map_err(|e| TestCaseError::fail(e.to_string()))?;

        let mut real: Vec<BranchId> = vec![session.branch.clone()];
        let mut model = Model::new();
        let mut model_names: Vec<String> = vec!["session".to_string()];

        for (step, op) in ops.iter().enumerate() {
            match op {
                Op::Write { branch, key, value } => {
                    let idx = *branch as usize % real.len();
                    let branch_id = real[idx].clone();
                    let name = model_names[idx].clone();

                    db.write(
                        &token,
                        &branch_id,
                        key_of(*key),
                        counter(*value),
                        &envelope(&branch_id),
                    )
                    .map_err(|e| TestCaseError::fail(format!("step {step}: write: {e}")))?;

                    model.write(&name, key_of(*key), counter(*value));
                }

                Op::Fork { from, name } => {
                    let idx = *from as usize % real.len();
                    let parent = real[idx].clone();
                    let parent_name = model_names[idx].clone();

                    let new_name = format!("fork-{step}-{name}");
                    let (new_branch, new_token) = db
                        .branch(&token, &parent, &new_name)
                        .map_err(|e| TestCaseError::fail(format!("step {step}: fork: {e}")))?;
                    token = new_token;

                    model.fork(&parent_name, &new_name);
                    real.push(new_branch);
                    model_names.push(new_name);
                }

                Op::Merge { source, target } => {
                    let s = *source as usize % real.len();
                    let t = *target as usize % real.len();
                    if s == t {
                        continue;
                    }

                    let (src, tgt) = (real[s].clone(), real[t].clone());
                    let (src_name, tgt_name) = (model_names[s].clone(), model_names[t].clone());

                    let result = db
                        .merge(&token, &src, &tgt, &MergePolicy::Conflict, &envelope(&tgt))
                        .map_err(|e| TestCaseError::fail(format!("step {step}: merge: {e}")))?;

                    let model_merged = model.merge(&src_name, &tgt_name);

                    // The engine and the model must agree about WHETHER it merged, not only about
                    // what came out. An engine that conflicts where the model merges is dropping
                    // work; an engine that merges where the model conflicts is inventing an answer.
                    prop_assert_eq!(
                        result.is_merged(),
                        model_merged,
                        "step {}: engine says merged={}, model says merged={}",
                        step,
                        result.is_merged(),
                        model_merged
                    );

                    if let MergeResult::Conflict(_) = result {
                        // A conflicting merge must change nothing.
                    }
                }
            }

            // After EVERY op: every branch's full contents must match.
            for (idx, branch) in real.iter().enumerate() {
                let engine: BTreeMap<Key, Record> = db
                    .scan(&token, branch)
                    .map_err(|e| TestCaseError::fail(format!("step {step}: scan: {e}")))?
                    .into_iter()
                    .collect();

                let expected = model.head(&model_names[idx]);

                prop_assert_eq!(
                    &engine,
                    &expected,
                    "step {}: branch {:?} disagrees with the model.\n  engine: {:?}\n  model:  {:?}",
                    step,
                    model_names[idx],
                    engine,
                    expected
                );
            }
        }
    }
}

/// The prefilter, on its own, because it is the thing most likely to be silently wrong.
///
/// `plan_merge` uses substrate's page-level `diff3` to narrow the keys it examines. If that narrowing
/// ever *misses* a key, the merge reports success and quietly drops a record — the worst kind of bug,
/// because nothing complains.
///
/// So: enough records to span many pages, changes scattered across the whole key range, and a check
/// that every single one arrives.
#[test]
fn the_prefilter_never_drops_a_record() -> loom_core::Result<()> {
    let db = Loom::in_memory(TenantId::new("acme"))?.with_clock(|| NOW);
    let (session, token) = db.open_session()?;

    // A database big enough that a merge genuinely has to prefilter — many pages, many leaves.
    let seed: Vec<_> = (0..2_000u64)
        .map(|n| (format!("key-{n:08}").into_bytes(), counter(0)))
        .collect();
    db.write_many(&token, &session.branch, seed, &envelope(&session.branch))?;

    let (a, token) = db.branch(&token, &session.branch, "a")?;
    let (b, token) = db.branch(&token, &session.branch, "b")?;

    // Scatter changes across the whole key range, in both branches, on disjoint keys.
    // Every value must DIFFER from the seed, or the engine correctly skips it as a no-op and the
    // test accuses the prefilter of dropping records it never had to merge.
    //
    // The first version of this test used `n as i8`, which wraps at 256 — so two of the 286 "changes"
    // wrote counter(0), the seed value, and were rightly ignored. The oracle reported a dropped
    // record, and the bug was in the test. Values that cannot collide with the seed, please.
    let a_changes: Vec<_> = (0..2_000u64)
        .filter(|n| n % 7 == 0)
        .map(|n| {
            (
                format!("key-{n:08}").into_bytes(),
                Record::Value(Value::Counter(n as i64 + 1)),
            )
        })
        .collect();
    let b_changes: Vec<_> = (0..2_000u64)
        .filter(|n| n % 11 == 0 && n % 7 != 0)
        .map(|n| {
            (
                format!("key-{n:08}").into_bytes(),
                Record::Value(Value::Counter(n as i64 + 1)),
            )
        })
        .collect();

    let expected_from_a = a_changes.len();
    db.write_many(&token, &a, a_changes.clone(), &envelope(&a))?;
    db.write_many(&token, &b, b_changes.clone(), &envelope(&b))?;

    let result = db.merge(&token, &a, &b, &MergePolicy::Conflict, &envelope(&b))?;
    let MergeResult::Merged { records, .. } = result else {
        panic!("disjoint keys must not conflict: {result:?}");
    };

    assert_eq!(
        records, expected_from_a,
        "the prefilter dropped records: it merged {records} of a's {expected_from_a} changes. \
         A merge that silently loses a record is the worst bug this engine can have, because it \
         reports success."
    );

    // And every single one of a's changes is really there, alongside b's.
    for (key, value) in &a_changes {
        assert_eq!(
            db.read(&token, &b, key)?.as_ref(),
            Some(value),
            "a's change to {:?} was lost in the merge",
            String::from_utf8_lossy(key)
        );
    }
    for (key, value) in &b_changes {
        assert_eq!(db.read(&token, &b, key)?.as_ref(), Some(value));
    }
    Ok(())
}
