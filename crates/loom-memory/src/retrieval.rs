//! Scoring candidates, and packing them into a budget.
//!
//! The retrieval reads a branch's index entries — through `pager.fork(head)`, exactly as `Loom::read`
//! does, so a sibling branch's entries are unreachable (AT-040) — scores each against the query,
//! penalises the stale ones (AT-043), and packs the best into the token budget whole-item-at-a-time
//! (AT-042), every packed item carrying the real citation it was indexed with (AT-041).

use std::sync::Arc;

use loom_branch::{CapabilityToken, Loom, Tree};
use loom_core::{
    BranchId, Embedding, IndexEntry, Key, LoomError, Record, Result, SourceRef,
    RESERVED_INDEX_PREFIX,
};
use substrate_pager::PageStore;

use crate::tokens::{estimate, Budget};

/// How much a stale claim's score is multiplied by. Less than one, so a stale claim can still surface
/// when it is the only relevant thing — but it loses every tie to a fresh claim, and it arrives marked.
///
/// AT-043 says down-ranked *and marked*, not dropped: a stale claim is still the best evidence we have
/// until it is recomputed, and hiding it entirely would be its own kind of lie. So we penalise and
/// flag, and let the model see both the content and the warning.
pub const STALE_PENALTY: f32 = 0.25;

/// A query against a branch's memory.
#[derive(Clone, Debug)]
pub struct RetrievalQuery {
    /// The semantic vector, if the caller embedded their query. Compared by cosine to each entry's
    /// embedding.
    pub embedding: Option<Embedding>,
    /// The full-text query. Tokenised and matched against each entry's text.
    pub text: String,
    /// The token budget the packed context must fit inside.
    pub budget: u32,
}

impl RetrievalQuery {
    /// A text-only query.
    pub fn text(text: impl Into<String>, budget: u32) -> Self {
        RetrievalQuery {
            embedding: None,
            text: text.into(),
            budget,
        }
    }

    /// Attach a semantic vector.
    pub fn with_embedding(mut self, embedding: Embedding) -> Self {
        self.embedding = Some(embedding);
        self
    }
}

/// One candidate, with the score it earned.
#[derive(Clone, Debug)]
pub struct ScoredCandidate {
    /// The entry.
    pub entry: IndexEntry,
    /// Its score against the query, after any stale penalty. Higher is better.
    pub score: f32,
}

/// **Score one candidate against a query.** Pure, so it can be tested exhaustively.
///
/// The score blends two signals a caller might have asked with — a semantic vector and full-text terms
/// — and applies the stale penalty last. A candidate that matches neither signal scores zero and will
/// be packed only if nothing better competes for the budget.
///
/// Blending, not choosing: an entry that matches the text *and* is semantically close should beat one
/// that only does one, and summing the two normalised signals gives exactly that without a tuning knob
/// nobody will ever set correctly.
pub fn score_candidate(query: &RetrievalQuery, entry: &IndexEntry) -> f32 {
    let mut score = 0.0f32;

    // Semantic: cosine, mapped from [-1, 1] into [0, 1] so it cannot cancel out a text match with a
    // negative. An incomparable pair (missing embedding, mismatched dimension) simply contributes
    // nothing, rather than a guessed zero-similarity — see `Embedding::cosine`.
    if let (Some(q), Some(e)) = (&query.embedding, &entry.embedding) {
        if let Some(cos) = q.cosine(e) {
            score += (cos + 1.0) / 2.0;
        }
    }

    // Full-text: the fraction of the query's terms that appear in the entry's text. Boring on purpose
    // — the clever answer is BM25 over an inverted index, and when this needs to be fast that is what
    // it becomes; for correctness under a budget, term overlap is enough and obviously right.
    let terms = tokenize(&query.text);
    if !terms.is_empty() {
        let text = entry.text.to_lowercase();
        let hits = terms.iter().filter(|t| text.contains(*t)).count();
        score += hits as f32 / terms.len() as f32;
    }

    // Stale last, so it discounts the whole score (AT-043).
    if entry.stale {
        score *= STALE_PENALTY;
    }

    score
}

/// One item in a packed context, ready for a model to read.
#[derive(Clone, Debug, PartialEq)]
pub struct PackedItem {
    /// The record this came from.
    pub key: Key,
    /// The text placed in the context.
    pub text: String,
    /// **Where it came from.** Never empty — the index refused to store an uncited entry, so a packed
    /// item cannot be uncited (AT-041).
    pub citations: Vec<SourceRef>,
    /// Its score.
    pub score: f32,
    /// Whether it is a stale claim. When true, the model is being told: here is the best we have, and
    /// it is out of date (AT-043).
    pub stale: bool,
    /// What it cost the budget.
    pub tokens: u32,
}

/// The result of a retrieval: what fit, and an honest account of what did not.
#[derive(Clone, Debug, PartialEq)]
pub struct PackedContext {
    /// The packed items, best first.
    pub items: Vec<PackedItem>,
    /// The budget it was packed against.
    pub budget: u32,
    /// Tokens actually used.
    pub used_tokens: u32,
    /// How many candidates were scored.
    pub considered: usize,
    /// How many scored candidates did not fit the budget. Reported rather than hidden — "we retrieved
    /// 5 of 100,000 relevant things" is something the caller needs to know, not something to bury.
    pub dropped_for_budget: usize,
}

impl PackedContext {
    /// Whether any stale claim made it into the context. A caller that forbids acting on stale
    /// evidence can check this without walking the items.
    pub fn contains_stale(&self) -> bool {
        self.items.iter().any(|i| i.stale)
    }
}

/// **Pack scored candidates into a budget.** Pure and total — the load-bearing robustness of AT-042.
///
/// Greedy by score, **whole items only**. It never truncates a fact to fit, because half a fact is a
/// fact with its evidence cut off; it stops adding when the next item will not fit and keeps scanning
/// in case a smaller later item still does. It never panics, on any budget from zero to unbounded and
/// any candidate count from none to a hundred thousand. Every item it emits carries the citation it
/// was indexed with.
pub fn pack(mut scored: Vec<ScoredCandidate>, budget_tokens: u32) -> PackedContext {
    let considered = scored.len();

    // Best first. A stable tiebreak on the record key keeps the result deterministic — two runs of the
    // same retrieval must pack the same items in the same order, or "reproducible" is a word we do not
    // get to use.
    scored.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.entry.key.cmp(&b.entry.key))
    });

    let mut budget = Budget::new(budget_tokens);
    let mut items = Vec::new();
    let mut dropped = 0usize;

    for cand in scored {
        let cost = estimate(&cand.entry.text);
        if budget.spend(cost) {
            items.push(PackedItem {
                key: cand.entry.key,
                text: cand.entry.text,
                citations: cand.entry.citations,
                score: cand.score,
                stale: cand.entry.stale,
                tokens: cost,
            });
        } else {
            // Did not fit. Keep going — a smaller, lower-ranked item may still fit the remainder, and
            // dropping the rest wholesale would waste budget an item could have used.
            dropped += 1;
        }
    }

    PackedContext {
        items,
        budget: budget_tokens,
        used_tokens: budget.spent(),
        considered,
        dropped_for_budget: dropped,
    }
}

/// Reads a branch's memory and answers retrievals.
pub struct Retriever<'a> {
    db: &'a Loom,
}

impl<'a> Retriever<'a> {
    /// Wrap a database.
    pub fn new(db: &'a Loom) -> Self {
        Retriever { db }
    }

    /// Every index entry visible on a branch.
    ///
    /// Reads the branch tree directly through a fork of its head — the same path `Loom::read` takes,
    /// which is what makes AT-040 structural: a sibling branch has a different head and literally
    /// cannot address these pages. Nothing here filters by branch, because nothing has to.
    fn entries_on(&self, token: &CapabilityToken, branch: &BranchId) -> Result<Vec<IndexEntry>> {
        // Authorise against the token, so retrieval obeys capability scope like every other surface
        // (AT-019). A read outside your scope is refused here too.
        self.db.authorize_read(token, branch)?;

        let head = self.db.head(branch)?;
        let store = self.db.pager_for_debug().fork(&head)?;
        let mut tree = Tree::open(&*store)?;

        let mut entries = Vec::new();
        for (key, record) in tree.scan()? {
            if !key.starts_with(RESERVED_INDEX_PREFIX) {
                continue;
            }
            let Record::Value(loom_core::Value::Blob(bytes)) = record else {
                continue;
            };
            let entry = IndexEntry::decode(&bytes).map_err(|source| LoomError::Codec {
                op: "decode",
                what: "index entry",
                source,
            })?;
            entries.push(entry);
        }
        Ok(entries)
    }

    /// **Retrieve, and pack into the query's budget.**
    ///
    /// The whole L3 contract in one call: branch-isolated candidates, scored, stale ones penalised and
    /// marked, packed whole-item into the budget, every item cited.
    pub fn retrieve(
        &self,
        token: &CapabilityToken,
        branch: &BranchId,
        query: &RetrievalQuery,
    ) -> Result<PackedContext> {
        let scored: Vec<ScoredCandidate> = self
            .entries_on(token, branch)?
            .into_iter()
            .map(|entry| {
                let score = score_candidate(query, &entry);
                ScoredCandidate { entry, score }
            })
            .collect();

        Ok(pack(scored, query.budget))
    }
}

/// Lowercase word tokens. The dumbest thing that could possibly work, and it is enough for term
/// overlap; a real deployment swaps in the model's tokeniser.
fn tokenize(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_string())
        .collect()
}

/// So `Arc<Loom>` and `&Loom` both work at call sites.
impl<'a> From<&'a Arc<Loom>> for Retriever<'a> {
    fn from(db: &'a Arc<Loom>) -> Self {
        Retriever::new(db)
    }
}
