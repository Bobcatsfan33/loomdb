//! **AT-042 — adversarial budgets, and AT-043 — stale claims down-ranked.**
//!
//! AT-042 is a robustness claim: a *well-formed* `PackedContext` under any budget and any candidate
//! count, with no panic, no item truncated mid-evidence, and no uncited item. The two named extremes —
//! 50 tokens against 100,000 candidates, and an unbounded budget against three — are the corners, and
//! the property test fills in everything between.

use loom_core::{Embedding, IndexEntry, SourceRef};
use loom_memory::{pack, score_candidate, RetrievalQuery, ScoredCandidate};
use proptest::prelude::*;

fn entry(i: usize, text: &str, stale: bool) -> IndexEntry {
    IndexEntry::new(
        format!("k{i}").into_bytes(),
        text,
        Some(Embedding::new([0.1, 0.2, 0.3])),
        vec![SourceRef::new("web", format!("src-{i}"))],
        stale,
        loom_core::TrustClass::Untrusted,
    )
    .expect("cited")
}

/// **50 tokens against 100,000 candidates: a well-formed context, whole items only.**
#[test]
fn at_042_a_tiny_budget_against_a_huge_candidate_set() {
    let candidates: Vec<ScoredCandidate> = (0..100_000)
        .map(|i| ScoredCandidate {
            entry: entry(
                i,
                "a fact about something that takes several tokens to state",
                false,
            ),
            score: (i % 7) as f32,
        })
        .collect();

    let packed = pack(candidates, 50);

    assert!(packed.used_tokens <= 50, "must not exceed the budget");
    assert!(packed.considered == 100_000);
    assert!(
        packed.dropped_for_budget > 0,
        "most of 100k cannot fit in 50 tokens"
    );
    for item in &packed.items {
        assert!(
            !item.citations.is_empty(),
            "AT-041 holds even under a starving budget"
        );
        assert!(!item.text.is_empty());
        // Whole items: the packed text is exactly an original, never a prefix of one.
        assert_eq!(
            item.text,
            "a fact about something that takes several tokens to state"
        );
    }
}

/// **A huge budget against three candidates: all three, still well-formed.**
#[test]
fn at_042_a_huge_budget_against_a_tiny_candidate_set() {
    let candidates: Vec<ScoredCandidate> = (0..3)
        .map(|i| ScoredCandidate {
            entry: entry(i, "short fact", false),
            score: i as f32,
        })
        .collect();

    let packed = pack(candidates, u32::MAX);
    assert_eq!(packed.items.len(), 3, "a huge budget fits all three");
    assert_eq!(packed.dropped_for_budget, 0);
}

/// **Zero budget: an empty, well-formed context. Not a panic.**
#[test]
fn at_042_a_zero_budget_is_empty_not_a_crash() {
    let candidates = vec![ScoredCandidate {
        entry: entry(0, "anything", false),
        score: 1.0,
    }];
    let packed = pack(candidates, 0);
    assert!(packed.items.is_empty());
    assert_eq!(packed.used_tokens, 0);
    assert_eq!(packed.dropped_for_budget, 1);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// **Whatever the budget and whatever the candidates, the context is well-formed.**
    ///
    /// Never over budget, never an uncited item, never a truncated one, never a panic. Items in
    /// non-increasing score order. This is AT-042 as an invariant rather than two examples.
    #[test]
    fn pack_is_always_well_formed(
        budget in 0u32..500,
        specs in prop::collection::vec((0usize..50, any::<bool>()), 0..200),
    ) {
        let candidates: Vec<ScoredCandidate> = specs
            .iter()
            .enumerate()
            .map(|(i, (len, stale))| {
                let text = "x ".repeat(*len);
                ScoredCandidate { entry: entry(i, text.trim(), *stale), score: (i % 11) as f32 }
            })
            .collect();
        let original_texts: std::collections::BTreeSet<String> =
            candidates.iter().map(|c| c.entry.text.clone()).collect();

        let packed = pack(candidates.clone(), budget);

        prop_assert!(packed.used_tokens <= budget, "over budget: {} > {}", packed.used_tokens, budget);
        prop_assert_eq!(packed.considered, candidates.len());
        prop_assert_eq!(packed.items.len() + packed.dropped_for_budget, candidates.len(),
            "every candidate is either packed or dropped — none vanish");

        let mut last = f32::INFINITY;
        for item in &packed.items {
            prop_assert!(item.score <= last, "items must be in non-increasing score order");
            last = item.score;
            prop_assert!(!item.citations.is_empty(), "AT-041: no uncited item");
            // Whole items only: every packed text is verbatim one of the originals.
            prop_assert!(original_texts.contains(&item.text), "an item was truncated or fabricated");
        }
    }
}

// ── AT-043 — stale claims are down-ranked and marked ──────────────────────────────────────────────

/// **A stale claim that is a stronger match than a fresh one is still ranked below it, and marked.**
#[test]
fn at_043_a_stale_claim_is_penalised_and_flagged() {
    let query = RetrievalQuery::text("cfo dana revenue", 1000);

    // The stale claim is a BETTER text match (all three terms) than the fresh one (one term).
    let stale = entry(1, "cfo dana revenue", true);
    let fresh = entry(2, "cfo", false);

    let stale_score = score_candidate(&query, &stale);
    let fresh_score = score_candidate(&query, &fresh);

    assert!(
        stale_score < fresh_score,
        "AT-043: a stale claim must lose to a fresh one even when it matches better. \
         stale={stale_score}, fresh={fresh_score}"
    );

    // And when it is packed, it is marked so the model knows not to lean on it.
    let packed = pack(
        vec![
            ScoredCandidate {
                entry: stale,
                score: stale_score,
            },
            ScoredCandidate {
                entry: fresh,
                score: fresh_score,
            },
        ],
        1000,
    );
    let stale_item = packed
        .items
        .iter()
        .find(|i| i.key == b"k1")
        .expect("packed");
    assert!(
        stale_item.stale,
        "the stale item must be marked in the packed context"
    );
    assert!(packed.contains_stale());
}
