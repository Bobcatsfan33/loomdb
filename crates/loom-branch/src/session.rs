//! Sessions, branches, and the write path.
//!
//! **A session is a branch.** `open_session()` forks the tenant's base image — an O(1) substrate fork
//! that copies nothing — and hands back a handle and a capability token. A million idle sessions are a
//! million manifests: bytes in object storage, no compute.
//!
//! That is what makes speculation affordable. An agent branches three hypotheses, writes freely in
//! each, merges the one that worked, and rewinds the two that did not — and the rewound ones remain
//! readable and auditable, because nothing was destroyed, only unreferenced.
//!
//! # The write path rejects any write without an envelope
//!
//! Enforced *here*, at the entry point — not as middleware, not as a decorator someone can forget.
//! A bypassable audit trail is worse than none, because it is believed.

use crate::merge::{
    is_reserved, merged_from_key, merged_from_prefix, plan_merge, MergeOutcome, MergePolicy,
};
use crate::token::{CapabilityToken, TokenIssuer};
use crate::tree::Tree;
use loom_core::{
    BranchId, CommitId, Key, LoomError, Record, Result, SessionId, TenantId, Value, WriteEnvelope,
};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use substrate_pager::{BranchTree, ManifestId, PageStore, Pager, StoreConfig};

/// How long a session's capability lasts, by default.
pub const DEFAULT_SESSION_TTL_MS: u64 = 8 * 3_600_000; // 8 hours

/// The branch a tenant's committed state lives on.
pub const MAIN: &str = "main";

/// A handle to an open session.
#[derive(Clone, Debug)]
pub struct SessionHandle {
    /// The session.
    pub id: SessionId,
    /// The branch it forked. **This is the session** — they are the same thing.
    pub branch: BranchId,
    /// What the session was opened at.
    pub base: CommitId,
}

/// An agent-native database, for one tenant.
///
/// One tenant per store, and the tenant is the substrate *pool* — so two tenants never share a page,
/// even when their bytes are identical (substrate docs/02 §9.1). That is not a check we perform; it
/// is a property of where the bytes are written.
pub struct Loom {
    pager: Arc<Pager>,
    branches: Mutex<BranchTree>,
    issuer: TokenIssuer,
    tenant: TenantId,
    now_ms: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl std::fmt::Debug for Loom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Loom")
            .field("tenant", &self.tenant.to_string())
            .finish()
    }
}

impl Loom {
    /// Open an in-memory database for a tenant.
    pub fn in_memory(tenant: TenantId) -> Result<Self> {
        let pager = Pager::in_memory(StoreConfig {
            pool: tenant.as_str().to_string(),
            ..Default::default()
        })?;
        Loom::from_pager(Arc::new(pager), tenant)
    }

    /// Open a database on disk.
    pub fn open(path: impl AsRef<std::path::Path>, tenant: TenantId) -> Result<Self> {
        let pager = Pager::open(
            path,
            StoreConfig {
                pool: tenant.as_str().to_string(),
                ..Default::default()
            },
        )?;
        Loom::from_pager(Arc::new(pager), tenant)
    }

    fn from_pager(pager: Arc<Pager>, tenant: TenantId) -> Result<Self> {
        let root = pager.head();
        Ok(Loom {
            pager,
            branches: Mutex::new(BranchTree::rooted(MAIN, root)),
            issuer: TokenIssuer::generate(),
            tenant,
            now_ms: Box::new(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0)
            }),
        })
    }

    /// Replace the clock. Tests need time to stand still.
    pub fn with_clock(mut self, clock: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        self.now_ms = Box::new(clock);
        self
    }

    fn now(&self) -> u64 {
        (self.now_ms)()
    }

    fn branches(&self) -> std::sync::MutexGuard<'_, BranchTree> {
        self.branches.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Where a branch currently points.
    pub fn head(&self, branch: &BranchId) -> Result<CommitId> {
        self.branches()
            .head(branch.as_str())
            .ok_or_else(|| LoomError::OutOfScope {
                branch: branch.clone(),
                scope: "no such branch".to_string(),
            })
    }

    /// **Open a session.** Forks the tenant's `main` — O(1), copies nothing.
    pub fn open_session(&self) -> Result<(SessionHandle, CapabilityToken)> {
        let session = SessionId::new(format!("s-{}", self.now()));
        self.open_session_named(session)
    }

    /// Open a session with a chosen id.
    pub fn open_session_named(
        &self,
        session: SessionId,
    ) -> Result<(SessionHandle, CapabilityToken)> {
        let base = self.head(&BranchId::new(MAIN))?;
        let branch = BranchId::new(session.as_str());

        self.branches().branch(branch.as_str(), base)?;

        let scope: BTreeSet<BranchId> = [branch.clone()].into_iter().collect();
        let token =
            self.issuer
                .issue(session.clone(), scope, self.now() + DEFAULT_SESSION_TTL_MS)?;

        Ok((
            SessionHandle {
                id: session,
                branch,
                base,
            },
            token,
        ))
    }

    /// Branch from a branch the token already covers, and get a **new** token that covers both.
    ///
    /// The old token is not retroactively widened. A capability means exactly what it meant when it
    /// was issued, forever — otherwise "what could this token do" has no answer.
    pub fn branch(
        &self,
        token: &CapabilityToken,
        from: &BranchId,
        name: &str,
    ) -> Result<(BranchId, CapabilityToken)> {
        self.issuer.authorize(token, from, self.now())?;

        let head = self.head(from)?;
        let new_branch = BranchId::new(name);
        self.branches().branch(new_branch.as_str(), head)?;

        let token = self.issuer.extend(token, new_branch.clone())?;
        Ok((new_branch, token))
    }

    /// **Write.** Requires an envelope. There is no overload that does not.
    pub fn write(
        &self,
        token: &CapabilityToken,
        branch: &BranchId,
        key: Key,
        record: Record,
        envelope: &WriteEnvelope,
    ) -> Result<CommitId> {
        self.write_many(token, branch, vec![(key, record)], envelope)
    }

    /// Write several records in one commit.
    pub fn write_many(
        &self,
        token: &CapabilityToken,
        branch: &BranchId,
        records: Vec<(Key, Record)>,
        envelope: &WriteEnvelope,
    ) -> Result<CommitId> {
        // 1. THE ENVELOPE. Before anything else, and with no way around it.
        if !envelope.is_valid() {
            return Err(LoomError::MissingEnvelope);
        }

        // 2. THE TOKEN. No code path below this line touches a page outside the token's scope.
        self.issuer.authorize(token, branch, self.now())?;

        // 3. The write itself, against this branch's head — and *only* this branch's head.
        let head = self.head(branch)?;
        let store = self.pager.fork(&head)?;

        let mut txn = store.begin()?;
        let mut tree = Tree::open(&*store)?;
        for (key, record) in records {
            tree.insert(key, record)?;
        }
        tree.flush(&mut txn)?;
        let commit = store.commit(txn)?;

        self.branches().set_head(branch.as_str(), commit)?;
        Ok(commit)
    }

    /// Read a record from a branch.
    pub fn read(
        &self,
        token: &CapabilityToken,
        branch: &BranchId,
        key: &[u8],
    ) -> Result<Option<Record>> {
        self.issuer.authorize(token, branch, self.now())?;

        let head = self.head(branch)?;
        let store = self.pager.fork(&head)?;
        let mut tree = Tree::open(&*store)?;
        tree.get(key)
    }

    /// Read a record as of a specific commit — the past, exactly as it was.
    pub fn read_at(
        &self,
        token: &CapabilityToken,
        branch: &BranchId,
        commit: &CommitId,
        key: &[u8],
    ) -> Result<Option<Record>> {
        self.issuer.authorize(token, branch, self.now())?;

        let store = self.pager.fork(commit)?;
        let mut tree = Tree::open(&*store)?;
        tree.get(key)
    }

    /// Every record on a branch, in key order.
    pub fn scan(&self, token: &CapabilityToken, branch: &BranchId) -> Result<Vec<(Key, Record)>> {
        self.issuer.authorize(token, branch, self.now())?;

        let head = self.head(branch)?;
        let store = self.pager.fork(&head)?;
        let mut tree = Tree::open(&*store)?;

        // The engine's bookkeeping is not the caller's data.
        Ok(tree
            .scan()?
            .into_iter()
            .filter(|(k, _)| !is_reserved(k))
            .collect())
    }

    /// **Merge** `source` into `target`, at record granularity.
    ///
    /// The result is a set of *new commits on the target*, not a transplant of the source's pages —
    /// so a merge can be re-validated against the world as it is now, rather than as it was when the
    /// branch forked.
    pub fn merge(
        &self,
        token: &CapabilityToken,
        source: &BranchId,
        target: &BranchId,
        policy: &MergePolicy,
        envelope: &WriteEnvelope,
    ) -> Result<MergeResult> {
        if !envelope.is_valid() {
            return Err(LoomError::MissingEnvelope);
        }
        // A merge WRITES to the target and READS the source. Both need to be in scope, and forgetting
        // the source here would let a session merge in a branch it was never allowed to see.
        self.issuer.authorize(token, source, self.now())?;
        self.issuer.authorize(token, target, self.now())?;

        let source_head = self.head(source)?;
        let target_head = self.head(target)?;

        // THE MERGE BASE, and the bug this exists to fix.
        //
        // substrate's manifests have ONE parent, so a merge commit does not record that it
        // incorporated the source. Ask the commit DAG for a merge base a second time and it will
        // cheerfully hand back the original fork point — as though the first merge never happened —
        // and the merge will re-apply the source's deltas.
        //
        // For a counter, that is not a crash. It is a number that is silently, quietly wrong: merge
        // twice and a +3 becomes a +6. The model oracle caught this on its first run.
        //
        // So a branch REMEMBERS what it has already merged from every other branch, in its own tree,
        // as part of its committed state. That record is the base for the next merge, and merging
        // twice with no new work in between is now a no-op — which is what anyone would expect.
        // MORE THAN ONE MERGE BASE MEANS THE ANSWER IS AMBIGUOUS, AND WE REFUSE TO GUESS.
        //
        // When two branches have merged *each other* — a criss-cross, and the moment two agents
        // collaborate it is inevitable — their history has several equally-lowest common ancestors.
        // A three-way merge takes exactly one base, and picking one arbitrarily produces an answer
        // that is defensible, deterministic, and *wrong* in a way nobody will ever notice: for a
        // counter it silently over- or under-counts.
        //
        // git's answer is a recursive merge — merge the bases together into a virtual base and use
        // that. It is the right answer and it is not built yet. Until it is, we say so, out loud,
        // rather than returning a number we cannot justify. A database that admits it does not know
        // is worth more than one that guesses confidently.
        let bases = self.merge_bases(&source_head, &target_head)?;

        let base = match bases.len() {
            0 => source_head, // no shared history: everything in the source is new
            1 => bases[0],
            n => {
                return Ok(MergeResult::AmbiguousHistory {
                    bases: n,
                    detail: format!(
                        "branches {source} and {target} have merged each other, so their history \
                         has {n} equally-valid merge bases and a three-way merge cannot be done \
                         safely. Merge one direction only, or rebase one branch onto the other, \
                         and retry. (Recursive merge over a virtual base is not implemented.)"
                    ),
                });
            }
        };

        let outcome = plan_merge(&*self.pager, &base, &source_head, &target_head, policy)?;

        match outcome {
            MergeOutcome::Conflict(report) => Ok(MergeResult::Conflict(report)),
            MergeOutcome::Merged {
                mut writes,
                automatic,
            } => {
                let records = writes.len();

                // Record what we merged, in the same commit as the merge itself. If this were a
                // separate commit, a crash between the two would leave a branch that had applied the
                // source's changes but did not know it — and the next merge would apply them again.
                writes.push((
                    merged_from_key(source.as_str()),
                    Record::Value(Value::Blob(source_head.as_bytes().to_vec())),
                ));

                let commit = self.write_many(token, target, writes, envelope)?;
                Ok(MergeResult::Merged {
                    commit,
                    records,
                    automatic,
                })
            }
        }
    }

    /// **The merge base, and the hardest correctness problem in this file.**
    ///
    /// # The bug this exists to fix
    ///
    /// substrate's manifests have exactly **one parent**. Git's merge commits have two, and that is
    /// not a stylistic difference — it is what makes a merge base correct the *second* time you merge.
    ///
    /// Consider: branch `X` merges from `main`, absorbing `main`'s work. Later someone forks `Y` from
    /// `main` and merges `Y` into `X`. Ask the raw one-parent DAG for the merge base of `X` and `Y`
    /// and it answers with the **original fork point** — because from the DAG's point of view `X`
    /// never absorbed anything, it merely has commits of its own that happen to contain the same data.
    ///
    /// So the merge re-applies work `X` already has. For a counter that is not a crash: it is a `+3`
    /// that silently becomes a `+6`. The database reports a clean merge and the number is wrong.
    ///
    /// **The model oracle caught this, and then caught two successive half-fixes for it.** The first
    /// looked only at what the target had absorbed; the second added the source, and still failed,
    /// because absorbed-ancestry is *transitive* and a flat list of "commits I merged" cannot express
    /// that. There is no clever shortcut here — the only correct answer is to reconstruct the
    /// two-parent DAG properly.
    ///
    /// # The reconstruction
    ///
    /// Every merge writes, into the target's own tree, the commit it absorbed. Those records are
    /// inherited by every descendant, because a descendant inherits the whole tree. So the full
    /// ancestry of a commit is:
    ///
    /// ```text
    /// ancestors(c) = {c} ∪ ancestors(dag_parent(c)) ∪ ⋃ ancestors(a) for every a absorbed by c
    /// ```
    ///
    /// which is exactly the transitive closure a two-parent DAG would have given us. The merge base
    /// is then the lowest common ancestor under *that* relation: the common ancestor that is not an
    /// ancestor of any other common ancestor.
    ///
    /// It is O(history) per merge, and it is correct. Correct first, fast later (CLAUDE.md rule 10).
    fn merge_bases(&self, source_head: &CommitId, target_head: &CommitId) -> Result<Vec<CommitId>> {
        let source_ancestors = self.full_ancestors(source_head)?;
        let target_ancestors = self.full_ancestors(target_head)?;

        let common: Vec<CommitId> = source_ancestors
            .intersection(&target_ancestors)
            .copied()
            .collect();

        // The LOWEST common ancestors: those nothing else in the set descends from.
        //
        // There can be MORE THAN ONE. That is the criss-cross case — X merged Y, and Y merged X —
        // and it is not exotic: it is what happens the moment two agents merge each other's work.
        let mut lowest = Vec::new();
        for candidate in &common {
            let mut is_lowest = true;
            for other in &common {
                if other == candidate {
                    continue;
                }
                if self.full_ancestors(other)?.contains(candidate) {
                    is_lowest = false; // `other` descends from `candidate`, so `other` is lower
                    break;
                }
            }
            if is_lowest {
                lowest.push(*candidate);
            }
        }
        lowest.sort();
        Ok(lowest)
    }

    /// Every commit in a commit's history — following **both** the DAG's parent edge and the merge
    /// edges the commit recorded in its own tree.
    fn full_ancestors(&self, head: &CommitId) -> Result<BTreeSet<CommitId>> {
        let mut seen: BTreeSet<CommitId> = BTreeSet::new();
        let mut stack = vec![*head];

        while let Some(commit) = stack.pop() {
            if !seen.insert(commit) {
                continue;
            }

            // The DAG edge.
            if let Ok(manifest) = self.pager.manifest(&commit) {
                if let Some(parent) = manifest.parent {
                    stack.push(parent);
                }
            }

            // The merge edges — the second parents substrate cannot store.
            for absorbed in self.absorbed_commits(&commit)? {
                stack.push(absorbed);
            }
        }
        Ok(seen)
    }

    /// Every commit this commit's tree records having absorbed from another branch.
    fn absorbed_commits(&self, head: &CommitId) -> Result<Vec<CommitId>> {
        let store = self.pager.fork(head)?;
        let mut tree = Tree::open(&*store)?;

        let prefix = merged_from_prefix();
        let mut out = Vec::new();

        for (key, record) in tree.scan()? {
            if !key.starts_with(&prefix) {
                continue;
            }
            let Record::Value(Value::Blob(bytes)) = record else {
                continue;
            };
            let Ok(bytes) = <[u8; 32]>::try_from(bytes.as_slice()) else {
                return Err(LoomError::CorruptNode {
                    page: 0,
                    detail: "merge bookkeeping record is not a 32-byte commit id".to_string(),
                });
            };
            out.push(CommitId::from_bytes(bytes));
        }
        Ok(out)
    }

    /// **Rewind.** O(1) — a pointer move.
    ///
    /// The abandoned suffix is not destroyed. It stays readable until GC decides nothing points at it,
    /// which is what makes "explore three hypotheses and discard two" *auditable* rather than merely
    /// cheap: an agent's discarded reasoning is still there to be asked about.
    pub fn rewind(
        &self,
        token: &CapabilityToken,
        branch: &BranchId,
        to: &CommitId,
    ) -> Result<CommitId> {
        self.issuer.authorize(token, branch, self.now())?;
        let previous = self.branches().set_head(branch.as_str(), *to)?;
        Ok(previous)
    }

    /// Sweep everything no branch points at.
    ///
    /// Roots come from the branch tree — every branch and every tag. Handing GC an incomplete set of
    /// roots is how you delete a customer's data, so we never assemble one by hand.
    pub fn gc(&self) -> Result<substrate_pager::GcStats> {
        let roots: Vec<ManifestId> = self.branches().roots();
        Ok(self.pager.gc(&roots)?)
    }

    /// The underlying pager. Debug and diagnostics only.
    #[doc(hidden)]
    pub fn pager_for_debug(&self) -> &Arc<Pager> {
        &self.pager
    }

    /// The tenant this database belongs to.
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Every branch that exists.
    pub fn branch_names(&self) -> Vec<String> {
        self.branches()
            .branches()
            .map(|(name, _)| name.to_string())
            .collect()
    }
}

/// What a merge did.
#[derive(Debug)]
pub enum MergeResult {
    /// It merged.
    Merged {
        /// The new head of the target.
        commit: CommitId,
        /// How many records were written.
        records: usize,
        /// How many merged with no human or policy involved.
        automatic: usize,
    },
    /// It did not.
    Conflict(Box<crate::merge::MergeConflictReport>),
    /// The two branches have merged each other, so there is more than one merge base and a
    /// three-way merge cannot be done safely. **We refuse rather than guess.**
    AmbiguousHistory {
        /// How many equally-valid merge bases there are.
        bases: usize,
        /// What the caller should do about it.
        detail: String,
    },
}

impl MergeResult {
    /// True if the merge went through.
    pub fn is_merged(&self) -> bool {
        matches!(self, MergeResult::Merged { .. })
    }
}
