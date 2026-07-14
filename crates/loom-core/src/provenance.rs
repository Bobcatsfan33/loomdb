//! The derivation DAG.
//!
//! Every write records what it was derived from. Those edges, taken together, are the only structure
//! in this system that can answer the question the whole product exists for:
//!
//! > *A source you trusted turns out to have been poisoned. Which of your agent's conclusions are
//! > downstream of it?*
//!
//! An audit log cannot answer that. It records **that** a write happened, not **what it was derived
//! from**. That is the entire difference, and it is why this is a DAG and not a log.
//!
//! # Where the nodes live, and the honest deviation from the architecture
//!
//! `docs/03` §3.4 says the derivation DAG lives in "a dedicated system store per tenant (on substrate,
//! its own pool)". **It does not. It lives in the tenant's own tree**, under a hidden key prefix.
//!
//! The reason is branch-awareness, and it is not a shortcut — it is the thing that makes AT-020 work.
//! A fork inherits the whole tree, so a derivation node written *before* a fork automatically appears
//! in **both children**. A separate system store would have to reimplement branching, and would get it
//! subtly wrong at exactly the moment it mattered: taint has to cross forks, and a taint that stops at
//! a fork boundary is a taint that misses the contamination.
//!
//! The cost is that provenance shares a tree with data. Nodes are hidden from `scan`, and they are
//! **immutable and content-addressed**, so a merge carries them across as new keys and two branches
//! that derived the same node converge on it rather than conflicting.
//!
//! (They are *not* in the `\x00loom/` reserved space, because reserved keys are excluded from merge
//! candidates — and provenance must **merge**. Merging a branch that must not carry its provenance
//! with it would be a hole you could drive a poisoned document through.)

use crate::ids::{ActorId, BranchId, CommitId};
use crate::value::SourceRef;
use crate::{Key, LoomError, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

/// The key prefix every derivation node lives under.
///
/// `\x01` sorts after the engine's reserved `\x00` space and before every printable key. Hidden from
/// `scan`; **included** in merge, because provenance has to travel with the branch that produced it.
pub const PROV_PREFIX: &[u8] = b"\x01prov/";

/// The prefix for the source index: which nodes cite a given external source.
pub const SRC_PREFIX: &[u8] = b"\x01src/";

/// Whether a key belongs to the provenance layer rather than the caller.
pub fn is_provenance(key: &[u8]) -> bool {
    key.starts_with(PROV_PREFIX) || key.starts_with(SRC_PREFIX)
}

/// A node in the derivation DAG: one write, and what it came from.
///
/// **Content-addressed.** Two agents that perform genuinely the same derivation — same actor, same
/// branch, same commit, same key, same inputs — produce the same node. That makes the DAG idempotent
/// under retries and convergent under merge, which are both things you want very much at 3am.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeId([u8; 32]);

impl NodeId {
    /// Hex.
    pub fn to_hex(self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The key this node *used* to be stored at, and why it no longer is.
    ///
    /// # The write-amplification bug, in one paragraph
    ///
    /// A `NodeId` is a content hash, so storing a node **at** its id meant every provenance write went
    /// to a **uniformly random** point in the keyspace. Once the tree held more leaves than a commit
    /// held records, a commit's random keys touched *nearly every leaf* — so nearly every leaf was
    /// dirtied, re-encoded, re-hashed and rewritten. **Each commit rewrote a large fraction of the
    /// database.** The same 100,000 records cost 36.9 s in ten commits and 9.4 s in one; the only
    /// variable was the number of commits.
    ///
    /// The fix is to notice that **nothing ever looks a node up by id from storage.** `taint()` scans
    /// the provenance range and builds the `id → node` map in memory; the source index answers "who
    /// cites this source". So the id never needed to be the *storage key* — it only needs to be the
    /// *identity*, and it still is, inside the node.
    ///
    /// Nodes now live at [`node_storage_key`]: an **append-ordered** `(branch, sequence)`. A batch of
    /// writes lands at the tail of the tree instead of all over it.
    #[deprecated(note = "use node_storage_key: content-addressed keys rewrite the whole tree")]
    pub fn key(&self) -> Key {
        let mut key = PROV_PREFIX.to_vec();
        key.extend_from_slice(self.to_hex().as_bytes());
        key
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "der_{}", &self.to_hex()[..12])
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// One derivation: a write, and everything it was derived from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivationNode {
    /// This node's id.
    pub id: NodeId,
    /// The branch the write landed on.
    pub branch: BranchId,
    /// The commit that contains it.
    pub commit: CommitId,
    /// The logical key that was written.
    pub key: Key,
    /// Who wrote it.
    pub actor: ActorId,
    /// The chain of authority. `A → B → C`, not just the last hop.
    pub delegation: Vec<ActorId>,
    /// Why, in the agent's own words.
    pub intent: String,

    /// **Other derivation nodes this write is downstream of.**
    ///
    /// Engine-captured from the session's read-set. A caller cannot remove one.
    pub derived_from: Vec<NodeId>,

    /// **External sources this write is downstream of.**
    ///
    /// Engine-captured when a read touches an `Observation` (its source), plus anything the caller
    /// chose to *add*. Callers may add; they may not omit.
    pub sources: Vec<SourceRef>,
}

impl DerivationNode {
    /// Build a node, computing its content-addressed id.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        branch: BranchId,
        commit: CommitId,
        key: Key,
        actor: ActorId,
        delegation: Vec<ActorId>,
        intent: String,
        mut derived_from: Vec<NodeId>,
        mut sources: Vec<SourceRef>,
    ) -> Self {
        // Sorted and deduplicated before hashing, so that the id does not depend on the order a
        // HashSet happened to iterate in. An id that varies run to run is not an id.
        derived_from.sort_unstable();
        derived_from.dedup();
        sources.sort();
        sources.dedup();

        let mut hasher = blake3::Hasher::new();
        hasher.update(branch.as_str().as_bytes());
        hasher.update(commit.as_bytes());
        hasher.update(&key);
        hasher.update(actor.as_str().as_bytes());
        for parent in &derived_from {
            hasher.update(&parent.0);
        }
        for source in &sources {
            hasher.update(source.to_string().as_bytes());
        }

        let id = NodeId(*hasher.finalize().as_bytes());

        DerivationNode {
            id,
            branch,
            commit,
            key,
            actor,
            delegation,
            intent,
            derived_from,
            sources,
        }
    }

    /// Encode for storage.
    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|source| LoomError::Codec {
            op: "encode",
            what: "derivation node",
            source,
        })
    }

    /// Decode.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|source| LoomError::Codec {
            op: "decode",
            what: "derivation node",
            source,
        })
    }

    /// A human-readable line, for a recall report someone has to read at 3am.
    pub fn describe(&self) -> String {
        let key = String::from_utf8_lossy(&self.key);
        format!(
            "{} wrote {:?} — {:?}",
            self.actor,
            key,
            if self.intent.len() > 60 {
                format!("{}…", &self.intent[..60])
            } else {
                self.intent.clone()
            }
        )
    }
}

/// The key at which a source's index entry lives.
///
/// The index answers "which derivation nodes cite this source" without scanning the DAG. Without it,
/// `taint()` would have to read every node in every branch just to find where to start, and a taint
/// that is too slow to run is a taint nobody runs.
pub fn source_index_key(source: &SourceRef, branch: &str, seq: u64) -> Key {
    let mut key = SRC_PREFIX.to_vec();
    key.extend_from_slice(source.to_string().as_bytes());
    key.push(b'/');
    key.extend_from_slice(&branch_seq(branch, seq));
    key
}

/// `<u16 branch length><branch><u64 sequence, big-endian>`.
///
/// **Big-endian on purpose.** These keys are compared as bytes, so the sequence must sort numerically
/// when it sorts lexicographically, or "append-ordered" is a lie and appends scatter again.
///
/// The branch is length-prefixed rather than delimited so that no branch name — whatever characters it
/// contains — can be confused with another one's sequence bytes.
fn branch_seq(branch: &str, seq: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + branch.len() + 8);
    out.extend_from_slice(&(branch.len() as u16).to_be_bytes());
    out.extend_from_slice(branch.as_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out
}

/// **Where a derivation node is stored: append-ordered, not content-addressed.**
///
/// Keyed by `(branch, sequence)`, so a commit's provenance lands at the **tail** of its branch's range
/// rather than scattered across every leaf in the tree. See [`NodeId::key`] for the bug this fixes.
///
/// The branch is part of the key, and that is load-bearing: without it, two branches that diverged
/// would both write sequence `N` — different nodes, same key — and merging them would produce a
/// **conflict on the provenance itself**. With it, each branch appends into its own range and a merge
/// simply carries the source's range across.
pub fn node_storage_key(branch: &str, seq: u64) -> Key {
    let mut key = PROV_PREFIX.to_vec();
    key.extend_from_slice(&branch_seq(branch, seq));
    key
}

/// The reserved key holding a branch's next provenance sequence number.
///
/// Reserved, so it is hidden from `scan` and **excluded from merge** — it is mutable per-branch
/// bookkeeping, not history. A fork inherits its parent's counter, which is harmless: the branch name
/// is in the node key, so two branches at the same sequence number cannot collide.
pub fn prov_seq_key(branch: &str) -> Key {
    let mut key = RESERVED_PROV_SEQ_PREFIX.to_vec();
    key.extend_from_slice(branch.as_bytes());
    key
}

/// See [`prov_seq_key`].
pub const RESERVED_PROV_SEQ_PREFIX: &[u8] = b"\x00loom/provseq/";

/// The prefix that matches every index entry for one source.
pub fn source_index_prefix(source: &SourceRef) -> Key {
    let mut key = SRC_PREFIX.to_vec();
    key.extend_from_slice(source.to_string().as_bytes());
    key.push(b'/');
    key
}

/// Pull the node id back out of a source-index **value**.
///
/// It used to come out of the *key* — which is precisely what forced the key to contain a content
/// hash, and therefore to be random. The id now rides in the value, and the key is free to be ordered.
pub fn node_from_index_value(value: &[u8]) -> Option<NodeId> {
    let bytes: [u8; 32] = value.try_into().ok()?;
    Some(NodeId(bytes))
}

impl NodeId {
    /// Rebuild from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes: [u8; 32] = bytes.try_into().ok()?;
        Some(NodeId(bytes))
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The key at which a branch records **which derivation node most recently wrote a logical key**.
///
/// Without this, linking a read to the write that produced it would mean scanning the whole DAG. With
/// it, it is one lookup — and a provenance layer too slow to run on every read is a provenance layer
/// that gets turned off.
///
/// # Why this is *reserved* bookkeeping and not *provenance*
///
/// Derivation nodes are immutable and content-addressed, so they merge cleanly: two branches simply
/// bring their nodes across as different keys, and the DAG is the union.
///
/// This pointer is the opposite. It is **mutable state** — "which node most recently wrote this key
/// *on this branch*" — and two branches that both wrote the same key hold two different, equally
/// valid pointers. Handing that to the merge engine as data produced a conflict on an opaque blob,
/// with a report telling the caller to pick one, which is a question nobody can answer and which the
/// caller never asked.
///
/// So it lives in the **reserved space**: hidden, and *excluded from merge*. The merge recomputes it,
/// and carries the source's derivation nodes forward as parents of the merged write — which is the
/// honest answer, because a merged record genuinely is derived from both sides.
pub fn latest_node_key(key: &[u8]) -> Key {
    let mut out = RESERVED_LATEST_PREFIX.to_vec();
    out.extend_from_slice(key);
    out
}

/// The reserved prefix the latest-node pointers live under. Never merged.
pub const RESERVED_LATEST_PREFIX: &[u8] = b"\x00loom/latest/";

#[cfg(test)]
mod tests {
    use super::*;

    fn node(key: &[u8], parents: Vec<NodeId>, sources: Vec<SourceRef>) -> DerivationNode {
        DerivationNode::new(
            BranchId::new("h2"),
            CommitId::from_bytes([1; 32]),
            key.to_vec(),
            ActorId::new("agent-1"),
            vec![],
            "investigating".into(),
            parents,
            sources,
        )
    }

    #[test]
    fn the_same_derivation_produces_the_same_node() {
        // Content-addressed, so a retry is idempotent and two branches that derived the same thing
        // converge rather than conflicting.
        let a = node(b"claim/x", vec![], vec![SourceRef::new("idp", "signin-1")]);
        let b = node(b"claim/x", vec![], vec![SourceRef::new("idp", "signin-1")]);
        assert_eq!(a.id, b.id);

        let c = node(b"claim/y", vec![], vec![SourceRef::new("idp", "signin-1")]);
        assert_ne!(a.id, c.id);
    }

    #[test]
    fn input_order_does_not_change_a_nodes_identity() {
        // The read-set arrives from a set, whose iteration order is not a promise. An id that varies
        // run to run is not an id, and a DAG whose node ids move is a DAG that cannot be walked.
        let p1 = node(b"a", vec![], vec![]).id;
        let p2 = node(b"b", vec![], vec![]).id;

        let forward = node(b"claim/x", vec![p1, p2], vec![]);
        let backward = node(b"claim/x", vec![p2, p1], vec![]);
        assert_eq!(forward.id, backward.id);
    }

    #[test]
    fn a_different_input_is_a_different_node() {
        // The property taint depends on: if what you derived from changed, this is not the same
        // derivation, and it must not be mistaken for one.
        let p1 = node(b"a", vec![], vec![]).id;
        let clean = node(b"claim/x", vec![], vec![]);
        let derived = node(b"claim/x", vec![p1], vec![]);
        assert_ne!(clean.id, derived.id);
    }

    #[test]
    fn round_trips_through_bytes() -> Result<()> {
        let n = node(
            b"claim/x",
            vec![node(b"a", vec![], vec![]).id],
            vec![SourceRef::new("web", "poisoned")],
        );
        assert_eq!(DerivationNode::decode(&n.encode()?)?, n);
        Ok(())
    }

    #[test]
    fn provenance_keys_are_recognised_and_hidden() {
        assert!(is_provenance(&node_storage_key("main", 0)));
        assert!(is_provenance(&source_index_key(
            &SourceRef::new("web", "p"),
            "main",
            0
        )));
        assert!(!is_provenance(b"claim/x"), "user data must not be hidden");
    }

    #[test]
    fn a_source_index_entry_leads_back_to_its_node() {
        let n = node(b"claim/x", vec![], vec![]);
        let source = SourceRef::new("idp", "signin-847223");
        let key = source_index_key(&source, "main", 7);

        assert!(
            key.starts_with(&source_index_prefix(&source)),
            "the index must still be scannable by source, or taint has nowhere to start"
        );
        assert_eq!(
            node_from_index_value(n.id.as_bytes()),
            Some(n.id),
            "the index must lead back to the node — now through the VALUE, not the key"
        );
    }

    /// **Append-ordered keys must actually sort in append order.**
    ///
    /// They are compared as bytes. If the sequence number were little-endian, key 256 would sort
    /// before key 1, appends would scatter across the tree, and the whole point of the change — that a
    /// commit's provenance lands at the *tail* rather than everywhere — would be quietly lost. Nothing
    /// would fail; writes would just go on rewriting the database.
    #[test]
    fn node_storage_keys_sort_in_sequence_order() {
        let mut keys: Vec<Key> = (0u64..300).map(|i| node_storage_key("main", i)).collect();
        let expected = keys.clone();

        keys.sort();

        assert_eq!(
            keys, expected,
            "storage keys do not sort in sequence order, so provenance writes are NOT appends"
        );
    }

    /// Two branches at the same sequence number must not collide.
    ///
    /// Without the branch in the key, two branches that diverged would both write sequence `N` — the
    /// same key, different nodes — and merging them would produce a conflict *on the provenance
    /// itself*, which is not a question any caller can answer.
    #[test]
    fn two_branches_at_the_same_sequence_do_not_collide() {
        assert_ne!(
            node_storage_key("hypothesis-a", 4),
            node_storage_key("hypothesis-b", 4)
        );
    }

    /// A branch name cannot be confused with another branch's sequence bytes.
    #[test]
    fn a_branch_name_cannot_be_confused_with_a_sequence() {
        assert_ne!(node_storage_key("ab", 1), node_storage_key("a", 1));
    }
}
