//! What is stored to make a record retrievable, and **where** — which is the whole ballgame for
//! branch isolation.
//!
//! # Isolation is structural, not a filter
//!
//! AT-040 says a query from a sibling branch must not return this branch's facts, and calls a leak
//! "a correctness bug wearing a performance costume." The costume is the temptation: a single global
//! vector index is faster to build and comes with a `WHERE branch = ?` you can forget, mis-scope, or
//! have a query planner reorder around. So we do not build one.
//!
//! An index entry is written **into the branch's own tree**, at a reserved key. Retrieval scans that
//! tree — through `pager.fork(head)`, exactly as `read` does — so a sibling branch, which has a
//! different head manifest, cannot address these bytes at all. Isolation is inherited from substrate's
//! content-addressed forks; it is not something this crate remembers to enforce. A fork *inherits* the
//! parent's entries (the tree is inherited), which is what makes a freshly-forked session immediately
//! searchable.
//!
//! The prefix is reserved (`\x00loom/`), so entries are hidden from `scan` and **excluded from merge**
//! — the same treatment as the latest-node pointer, and for the same reason: an index entry is a
//! *derived representation* of a record, not history, and merging two branches' opaque index blobs
//! would be a conflict nobody can resolve. When a record merges, its entry is recomputed on the
//! target, not transplanted.

use crate::value::{SourceRef, TrustClass};
use crate::Key;
use serde::{Deserialize, Serialize};

use crate::Embedding;

/// The reserved prefix under which every index entry lives. Reserved, so: hidden from `scan`,
/// excluded from merge, inherited on fork.
pub const RESERVED_INDEX_PREFIX: &[u8] = b"\x00loom/idx/";

/// What a query matches against, and what a hit carries back.
///
/// It is a *representation* of a record, derived from it — the text a full-text query scans, the
/// vector a semantic query compares against, and the **citations** that make a retrieved item
/// traceable (AT-041). The record key ties it back to the thing itself.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IndexEntry {
    /// The key of the record this represents.
    pub key: Key,
    /// The text a full-text query scans.
    pub text: String,
    /// The vector a semantic query compares against. `None` for a text-only entry — a fact can be
    /// full-text searchable without anyone having embedded it.
    pub embedding: Option<Embedding>,
    /// **Where this came from.** Never empty for a stored entry — see [`IndexEntry::new`]. This is
    /// what AT-041 means by "no item is uncited": an item that cannot say where it came from is not
    /// allowed into the index, because it could not be allowed into a packed context.
    pub citations: Vec<SourceRef>,
    /// Whether the underlying claim is `Stale`. Cached here so the ranker can penalise it (AT-043)
    /// without re-reading the record, and so the packed context can mark it for the model.
    pub stale: bool,
    /// **The effective trust label of this record's information** — the most restrictive trust of
    /// everything it was derived from (AT-035). Cached here so the influence filter (AT-036) can drop a
    /// restricted candidate *before* packing, without walking the DAG for every candidate.
    pub label: TrustClass,
}

impl IndexEntry {
    /// Build an entry, refusing one with no citations.
    ///
    /// The refusal is the point. AT-041 is enforced *here*, at write time, not hoped for at read
    /// time: if nothing can say where a fact came from, it never enters the index, so no retrieval
    /// can ever pack an uncited item. Returns `None`, and the caller must decide — but the caller
    /// cannot decide to store one anyway, because there is no other constructor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key: Key,
        text: impl Into<String>,
        embedding: Option<Embedding>,
        citations: Vec<SourceRef>,
        stale: bool,
        label: TrustClass,
    ) -> Option<Self> {
        if citations.is_empty() {
            return None;
        }
        Some(IndexEntry {
            key,
            text: text.into(),
            embedding,
            citations,
            stale,
            label,
        })
    }

    /// The reserved key this entry is stored at, derived from the record key so that re-indexing the
    /// same record overwrites its entry rather than accreting duplicates.
    pub fn storage_key(record_key: &[u8]) -> Key {
        let mut k = RESERVED_INDEX_PREFIX.to_vec();
        k.extend_from_slice(record_key);
        k
    }

    /// Encode for storage.
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Decode from storage.
    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_with_no_citation_cannot_be_built() {
        let none = IndexEntry::new(
            b"claim/x".to_vec(),
            "text",
            None,
            vec![],
            false,
            TrustClass::Untrusted,
        );
        assert!(
            none.is_none(),
            "AT-041: an uncited entry must not exist, or a retrieval could pack an uncited item"
        );
    }

    #[test]
    fn a_cited_entry_round_trips() {
        let e = IndexEntry::new(
            b"claim/x".to_vec(),
            "the CFO is Dana",
            Some(Embedding::new([0.1, 0.2])),
            vec![SourceRef::new("web", "page-1")],
            false,
            TrustClass::Untrusted,
        )
        .expect("has a citation");
        let bytes = e.encode().unwrap();
        assert_eq!(IndexEntry::decode(&bytes).unwrap(), e);
    }

    #[test]
    fn storage_keys_are_reserved_and_derived_from_the_record() {
        let k = IndexEntry::storage_key(b"claim/x");
        assert!(k.starts_with(RESERVED_INDEX_PREFIX));
        assert_eq!(
            k,
            IndexEntry::storage_key(b"claim/x"),
            "same record → same slot, so re-index overwrites"
        );
    }
}

/// The caller-supplied half of an index entry: the searchable text and, optionally, a vector.
///
/// The *other* half — the citations and the stale flag — is not the caller's to give. It is derived
/// from the record itself at write time (an observation cites its source, a claim cites its evidence),
/// which is what guarantees AT-041: a packed item's citation is the same `SourceRef` the provenance
/// DAG records, not a string the caller typed and we hoped was true.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IndexHint {
    /// The text a full-text query scans.
    pub text: String,
    /// The vector a semantic query compares against, if the caller embedded it.
    pub embedding: Option<Embedding>,
}

impl IndexHint {
    /// A text-only hint.
    pub fn text(text: impl Into<String>) -> Self {
        IndexHint {
            text: text.into(),
            embedding: None,
        }
    }

    /// Attach a vector.
    pub fn with_embedding(mut self, embedding: Embedding) -> Self {
        self.embedding = Some(embedding);
        self
    }
}
