//! Taint, and the walk downstream.
//!
//! # The rules this obeys, and why each one is not negotiable
//!
//! **It crosses forks** (AT-020). A node written *before* a fork is inherited by both children, and
//! every conclusion either child built on it is downstream. A taint that stops at a fork boundary is
//! a taint that misses the contamination — which is worse than no taint at all, because it produces a
//! report that says "contained" when it is not.
//!
//! **It is exact** (AT-021). Completeness *and* precision. A plan that reverts too much is as unusable
//! as one that reverts too little: an operator who is told to roll back four hundred unrelated writes
//! will not run the plan, and then the poisoned data stays.
//!
//! **It never executes** (AT-024). `taint()` returns a dry run. A system that can silently delete a
//! tenant's data on a signal is a system that can be turned into a weapon.
//!
//! **It refuses cycles** (AT-025). The walk is bounded, and a derivation cycle is rejected rather than
//! chased. An unbounded provenance walk is a denial of service against ourselves.
//!
//! **It says what it cannot undo.** The `RecallPlan`'s `irreversible` section stays empty until the
//! action gateway lands — but the shape is there, the report already leads with it, and it already
//! says out loud that rewinding a branch does not un-suspend an account.

use loom_branch::{CapabilityToken, Loom, Tree};
use loom_core::{
    node_from_index_value, source_index_prefix, BranchId, ClaimStatus, Compensation,
    DerivationNode, LoomError, NodeId, RecallPlan, Record, Result, ReversibleItem, SourceRef,
    Value,
};
use std::collections::{BTreeMap, BTreeSet};
use substrate_pager::PageStore;

/// How deep the walk may go before it decides something is wrong.
///
/// Derivation chains in a real agent are shallow — an observation, a claim, a conclusion. A chain
/// this long is a cycle, or a bug, and either way chasing it is a denial of service against
/// ourselves.
pub const MAX_DERIVATION_DEPTH: usize = 64;

/// What a taint walk did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TaintStats {
    /// Branches searched.
    pub branches: usize,
    /// Derivation nodes examined.
    pub nodes_examined: usize,
    /// Nodes found to be downstream of the source.
    pub contaminated: usize,
}

/// The provenance layer, over a database.
pub struct Provenance<'a> {
    db: &'a Loom,
}

impl<'a> Provenance<'a> {
    /// Wrap a database.
    pub fn new(db: &'a Loom) -> Self {
        Provenance { db }
    }

    /// Every derivation node on a branch, by id.
    ///
    /// Reads the branch's tree directly rather than through `Loom::read`, deliberately: walking the
    /// DAG must not itself enter the read-set, or the auditor becomes a derivation of everything it
    /// inspected.
    fn nodes_on(&self, branch: &BranchId) -> Result<BTreeMap<NodeId, DerivationNode>> {
        let head = self.db.head(branch)?;
        let store = self.db.pager_for_debug().fork(&head)?;
        let mut tree = Tree::open(&*store)?;

        let mut nodes = BTreeMap::new();
        for (key, record) in tree.scan()? {
            if !key.starts_with(loom_core::PROV_PREFIX) {
                continue;
            }
            // The `latest/` pointers share the prefix and are not nodes.
            let Record::Value(Value::Blob(bytes)) = record else {
                continue;
            };
            let Ok(node) = DerivationNode::decode(&bytes) else {
                continue;
            };
            nodes.insert(node.id, node);
        }
        Ok(nodes)
    }

    /// The nodes on a branch that cite a source directly.
    fn seeds_on(&self, branch: &BranchId, source: &SourceRef) -> Result<BTreeSet<NodeId>> {
        let head = self.db.head(branch)?;
        let store = self.db.pager_for_debug().fork(&head)?;
        let mut tree = Tree::open(&*store)?;

        let prefix = source_index_prefix(source);
        let mut seeds = BTreeSet::new();

        for (key, record) in tree.scan()? {
            if !key.starts_with(&prefix) {
                continue;
            }
            // The node id is in the VALUE. It used to be in the key — which is exactly what forced the
            // key to carry a content hash, and therefore to be random, and therefore to rewrite the
            // whole tree on every commit.
            let Record::Value(Value::Blob(bytes)) = record else {
                continue;
            };
            if let Some(node) = node_from_index_value(&bytes) {
                seeds.insert(node);
            }
        }
        Ok(seeds)
    }

    /// **Everything downstream of a source, across every branch of the tenant.**
    ///
    /// Returns a dry-run [`RecallPlan`]. **Nothing is mutated.**
    pub fn taint(&self, source: &SourceRef) -> Result<(RecallPlan, TaintStats)> {
        let mut stats = TaintStats::default();
        let mut plan = RecallPlan {
            source: Some(source.clone()),
            ..Default::default()
        };

        for branch_name in self.db.branch_names() {
            let branch = BranchId::new(branch_name.as_str());
            stats.branches += 1;

            let nodes = self.nodes_on(&branch)?;
            stats.nodes_examined += nodes.len();

            // Where the contamination enters this branch: nodes that cite the source directly.
            //
            // Because a fork inherits the whole tree, a node written BEFORE a fork appears in both
            // children — so this seeds correctly in every branch that descends from the poisoned
            // write, without any special handling. That is AT-020, and it is free.
            let seeds = self.seeds_on(&branch, source)?;
            if seeds.is_empty() {
                continue;
            }

            let contaminated = flood_downstream(&nodes, &seeds)?;
            stats.contaminated += contaminated.len();

            for id in &contaminated {
                let Some(node) = nodes.get(id) else { continue };

                // Never propose reverting the provenance layer's own records. Rewinding the audit
                // trail as part of an audit action would be a very funny way to destroy the evidence.
                if loom_core::is_provenance(&node.key) {
                    continue;
                }

                plan.reversible.push(ReversibleItem {
                    branch: node.branch.clone(),
                    commit: node.commit,
                    actor: node.actor.clone(),
                    description: node.describe(),
                    derived_via: path_to_source(&nodes, *id, source),
                    compensation: Compensation::Tombstone {
                        branch: node.branch.clone(),
                        claims: vec![],
                    },
                });
            }
        }

        // Deterministic order. A plan that lists the same contamination in a different order on every
        // run is a plan nobody can diff, and "did anything change since yesterday" is a question an
        // incident responder will ask.
        plan.reversible.sort_by(|a, b| {
            (a.branch.as_str(), &a.description).cmp(&(b.branch.as_str(), &b.description))
        });
        plan.reversible.dedup_by(|a, b| {
            a.branch == b.branch && a.description == b.description && a.commit == b.commit
        });

        Ok((plan, stats))
    }

    /// **Mark everything downstream of an invalidated source as `Stale`.**
    ///
    /// The scalpel, not the sledgehammer (AT-023). Stale claims remain readable and auditable — but
    /// they are **not action-eligible** until re-derived. Most of the time the right answer to "an
    /// input changed" is not "revert history", it is "stop letting that conclusion authorize anything
    /// until you have looked at it again".
    ///
    /// Returns the claims it marked.
    pub fn mark_stale(
        &self,
        token: &CapabilityToken,
        branch: &BranchId,
        source: &SourceRef,
        envelope: &loom_core::WriteEnvelope,
    ) -> Result<Vec<Vec<u8>>> {
        let nodes = self.nodes_on(branch)?;
        let seeds = self.seeds_on(branch, source)?;
        let contaminated = flood_downstream(&nodes, &seeds)?;

        let head = self.db.head(branch)?;
        let store = self.db.pager_for_debug().fork(&head)?;
        let mut tree = Tree::open(&*store)?;

        let mut marked = Vec::new();
        let mut writes = Vec::new();

        for id in &contaminated {
            let Some(node) = nodes.get(id) else { continue };
            if loom_core::is_provenance(&node.key) {
                continue;
            }

            let Some(Record::Claim(mut claim)) = tree.get(&node.key)? else {
                continue; // only claims go stale; an observation is what a source SAID, and that
                          // remains true even when the source turns out to be a liar
            };
            if claim.status != ClaimStatus::Asserted {
                continue;
            }

            claim.status = ClaimStatus::Stale;
            writes.push((node.key.clone(), Record::Claim(claim)));
            marked.push(node.key.clone());
        }

        if !writes.is_empty() {
            self.db.write_many(token, branch, writes, envelope)?;
        }
        Ok(marked)
    }
}

/// **The walk.** Everything reachable downstream of the seeds.
///
/// This is the load-bearing function in the whole crate, and it has exactly one job: name the correct
/// set. Not a superset — a plan that reverts four hundred unrelated writes will not be run. Not a
/// subset — a plan that misses one contaminated conclusion tells a customer their poisoned data is
/// contained when it is not, which is the worst thing this system can do.
pub fn flood_downstream(
    nodes: &BTreeMap<NodeId, DerivationNode>,
    seeds: &BTreeSet<NodeId>,
) -> Result<BTreeSet<NodeId>> {
    // Invert the edges once: a node stores what it was derived FROM, and we need to walk the other
    // way. Doing this per-seed instead would turn an O(E) walk into an O(V·E) one, and a taint too
    // slow to run is a taint nobody runs.
    let mut children: BTreeMap<NodeId, Vec<NodeId>> = BTreeMap::new();
    for node in nodes.values() {
        for parent in &node.derived_from {
            children.entry(*parent).or_default().push(node.id);
        }
    }

    let mut contaminated: BTreeSet<NodeId> = BTreeSet::new();
    let mut stack: Vec<(NodeId, usize)> = seeds.iter().map(|id| (*id, 0usize)).collect();

    while let Some((id, depth)) = stack.pop() {
        // AT-025. A derivation chain this deep is a cycle or a bug, and chasing it is a denial of
        // service against ourselves. `contaminated` already prevents revisiting a node, so this is a
        // second line of defence against a DAG that is not one.
        if depth > MAX_DERIVATION_DEPTH {
            return Err(LoomError::DerivationCycle {
                depth: MAX_DERIVATION_DEPTH,
            });
        }
        if !contaminated.insert(id) {
            continue;
        }
        for child in children.get(&id).into_iter().flatten() {
            stack.push((*child, depth + 1));
        }
    }

    Ok(contaminated)
}

/// The path from a contaminated node back to the source, for a human who wants to *check* the claim
/// rather than take it on faith.
fn path_to_source(
    nodes: &BTreeMap<NodeId, DerivationNode>,
    from: NodeId,
    source: &SourceRef,
) -> Vec<String> {
    let mut path = Vec::new();
    let mut current = Some(from);
    let mut hops = 0;

    while let Some(id) = current {
        hops += 1;
        if hops > MAX_DERIVATION_DEPTH {
            path.push("… (path truncated)".to_string());
            break;
        }
        let Some(node) = nodes.get(&id) else { break };

        path.push(String::from_utf8_lossy(&node.key).to_string());

        if node.sources.contains(source) {
            path.push(source.to_string());
            break;
        }
        current = node.derived_from.first().copied();
    }

    path.reverse();
    path
}
