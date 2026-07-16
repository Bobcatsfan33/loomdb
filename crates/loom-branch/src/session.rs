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

use crate::merge::{is_reserved, merged_from_key, plan_merge, MergeOutcome, MergePolicy};
use crate::refs::{FileRefStore, MemRefStore, RefStore, Refs};
// Only the gated `sleep`/`wake` methods name this type; unused in an airgap build.
#[cfg(feature = "remote")]
use crate::sleep::LoomWakeToken;
use crate::token::{CapabilityToken, TokenIssuer};
use crate::tree::Tree;
use ed25519_dalek::VerifyingKey;
use loom_core::{
    is_provenance, latest_node_key, node_storage_key, prov_seq_key, source_index_key, ActorId,
    BranchId, Claim, ClaimStatus, ClaimVersion, CommitId, DerivationNode, IndexEntry, IndexHint,
    Key, LoomError, NodeId, Record, Result, SessionId, SourceRef, TenantId, TrustClass, Value,
    WriteEnvelope,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use substrate_pager::{Clock, PageStore, Pager, StoreConfig};

/// A commit clock that never hands out the same instant twice.
///
/// # Why this is not a detail
///
/// substrate's manifests are **content-addressed**: a manifest's id is the hash of its contents,
/// which includes its parent and its timestamp. So two different branches that happen to reach the
/// *same state* from the *same parent* within the *same millisecond* produce **the same commit id** —
/// and the engine, quite correctly by its own rules, treats them as the same commit.
///
/// For a storage engine that is elegant. For an **audit database** it is unacceptable: two agents
/// independently arriving at the same conclusion is two events, by two actors, and collapsing them
/// into one commit destroys exactly the history this database exists to preserve. It also corrupts
/// merge-base computation, because the commit DAG acquires edges that never happened.
///
/// The model oracle caught this the hard way: it passed locally and failed in CI, because whether
/// two commits collided depended on how fast the machine was. A test whose result depends on the
/// clock is a test that will eventually lie to you.
///
/// So every commit gets a distinct, monotonically increasing instant. Distinct events, distinct
/// commits — always, regardless of how fast the machine is.
#[derive(Debug)]
struct CommitClock {
    next: std::sync::atomic::AtomicU64,
}

impl CommitClock {
    fn new() -> Self {
        let start = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        CommitClock {
            next: std::sync::atomic::AtomicU64::new(start),
        }
    }
}

impl Clock for CommitClock {
    fn now_ms(&self) -> u64 {
        self.next.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }
}

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
///
/// # What L1 does not persist yet, said plainly
///
/// **Branch refs and the commit DAG live in memory.** The *data* is durable — every commit is a
/// substrate manifest, fsync'd, crash-safe, and every merge writes its bookkeeping into the tree. But
/// the map from branch name to head, and the multi-parent merge edges, are rebuilt only for the life
/// of the process.
///
/// So: **a restart loses your branch names.** The commits are all still there and still readable by
/// id; nothing is corrupted and nothing is lost. But you cannot yet ask "where is branch h2" after a
/// restart.
///
/// This is a real gap and it is written down here rather than discovered later. Persisting both — the
/// refs, and the DAG (which can be rebuilt from the `merged-from` records already in each tree) — is
/// a prerequisite for L2, because the provenance layer needs to walk history across restarts.
pub struct Loom {
    pager: Arc<Pager>,
    /// The public keys of the actors allowed to write, if this database authenticates its writers.
    ///
    /// # Why this is optional, and what it costs to leave it empty
    ///
    /// `None` means envelopes are **attributable but not authenticated**: a write says who it came
    /// from, and nothing checks that it is telling the truth. That is the right default for an
    /// embedded, single-process database where the only writer is the process itself — and it is the
    /// wrong default the moment more than one agent can reach the same database, because then any
    /// agent can write as any other, and the audit trail becomes a work of fiction.
    ///
    /// `Some(registry)` means **every write must be signed**, and the signature is verified against
    /// the key of the actor the envelope *claims to be*. An actor with no registered key is refused
    /// rather than trusted (`UnknownActor`) — fail closed, because failing open here means an attacker
    /// picks an actor name nobody has registered and writes as a ghost.
    actor_keys: Option<BTreeMap<ActorId, VerifyingKey>>,
    /// **Everything that must survive a restart, other than the data.**
    ///
    /// Branch heads, tags, and the commit DAG — including the *second parent* of every merge, which
    /// substrate's single-parent manifests cannot store and which, if lost, silently restores the
    /// double-counting merge bug the model oracle caught.
    ///
    /// Held in memory and written through to [`RefStore`] on every mutation. The ordering is not
    /// negotiable: the manifest is durable **before** the ref that points at it (see `refs.rs`).
    refs: Mutex<Refs>,
    store: Arc<dyn RefStore>,
    /// **The engine-captured read-set** (AT-002).
    ///
    /// Everything a session has read since its last write. The *next* write is derived from all of
    /// it, whether the caller mentions it or not.
    ///
    /// This is the difference between a provenance system and a provenance *claim*. If
    /// `derived_from` were caller-supplied, an agent — or an attacker steering one — could launder a
    /// derivation simply by declining to mention what it read. The engine watches instead.
    ///
    /// Callers may still ADD external sources. They may not OMIT what they read.
    read_sets: Mutex<BTreeMap<SessionId, ReadSet>>,
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
    /// Open an **in-memory** database. Nothing survives the process; for tests and ephemeral work.
    pub fn in_memory(tenant: TenantId) -> Result<Self> {
        let pager = Pager::in_memory_with_clock(
            StoreConfig {
                pool: tenant.as_str().to_string(),
                ..Default::default()
            },
            Arc::new(CommitClock::new()),
        )?;
        Loom::assemble(Arc::new(pager), Arc::new(MemRefStore::new()), tenant)
    }

    /// Open a **durable** database on disk.
    ///
    /// If it already exists, its branches, tags, and commit DAG are loaded — so *"where is branch
    /// h2"* has an answer after a restart, which is the whole point of this constructor existing.
    pub fn open(path: impl AsRef<std::path::Path>, tenant: TenantId) -> Result<Self> {
        let path = path.as_ref();
        let pager = Pager::open_with(
            substrate_pager::std_vfs(),
            path,
            StoreConfig {
                pool: tenant.as_str().to_string(),
                ..Default::default()
            },
            Arc::new(CommitClock::new()),
        )?;
        let refs = FileRefStore::open(path)?;
        Loom::assemble(Arc::new(pager), Arc::new(refs), tenant)
    }

    /// Build a database over a caller-supplied pager and ref store.
    ///
    /// This is the seam a tiered (object-storage) LoomDB reaches through, and the seam the
    /// kill-and-restart tests use to cut the power mid-write.
    pub fn on(pager: Arc<Pager>, store: Arc<dyn RefStore>, tenant: TenantId) -> Result<Self> {
        Loom::assemble(pager, store, tenant)
    }

    fn assemble(pager: Arc<Pager>, store: Arc<dyn RefStore>, tenant: TenantId) -> Result<Self> {
        // Load what was there. A brand-new database gets a `main` at the root manifest.
        let refs = match store.load()? {
            Some(refs) => refs,
            None => {
                let root = pager.root_manifest()?;
                let refs = Refs::rooted(MAIN, root);
                store.save(&refs)?;
                refs
            }
        };

        Ok(Loom {
            pager,
            actor_keys: None,
            refs: Mutex::new(refs),
            store,
            read_sets: Mutex::new(BTreeMap::new()),
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

    fn refs(&self) -> std::sync::MutexGuard<'_, Refs> {
        self.refs.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Persist the refs. **Called after the manifest is already durable, never before.**
    ///
    /// A crash between the two leaves the refs pointing at the old head and the new manifest
    /// unreferenced — a lost commit, which GC sweeps. The other ordering would leave a ref pointing
    /// at a manifest that does not exist, which is a corrupt database. Losing the last transaction
    /// is recoverable; dangling into the void is not.
    fn persist(&self) -> Result<()> {
        let refs = self.refs().clone();
        self.store.save(&refs)
    }

    /// Record a commit's parents. A merge has two; everything else has one.
    fn record_commit(&self, commit: CommitId, parents: Vec<CommitId>) {
        // A no-op commit returns its own base — substrate refuses to append a duplicate manifest to
        // history. Recording it as its own parent would make the ancestry walk loop forever.
        let parents: Vec<CommitId> = parents.into_iter().filter(|p| *p != commit).collect();
        if parents.is_empty() {
            return;
        }
        self.refs().commits.entry(commit).or_insert(parents);
    }

    /// Where a branch currently points.
    /// Authorise a read against a branch, exactly as `read`/`scan` do.
    ///
    /// Public so the memory layer (a separate crate) enforces capability scope through the *same*
    /// issuer, rather than inventing a second, weaker check. AT-019 is "no code path touches a page
    /// outside the token's scope, through every surface" — retrieval is a surface, so it authorises
    /// here.
    pub fn authorize_read(&self, token: &CapabilityToken, branch: &BranchId) -> Result<()> {
        self.issuer.authorize(token, branch, self.now())
    }

    /// The index entry for a key on a branch, if the record was indexed. Used by `capture_read` to
    /// inherit a read record's label, and available to the memory layer.
    pub fn index_entry_for(&self, branch: &BranchId, key: &[u8]) -> Result<Option<IndexEntry>> {
        let head = self.head(branch)?;
        let store = self.pager.fork(&head)?;
        let mut tree = Tree::open(&*store)?;
        match tree.get(&IndexEntry::storage_key(key))? {
            Some(Record::Value(Value::Blob(bytes))) => {
                let entry = IndexEntry::decode(&bytes).map_err(|source| LoomError::Codec {
                    op: "decode",
                    what: "index entry",
                    source,
                })?;
                Ok(Some(entry))
            }
            _ => Ok(None),
        }
    }

    /// **Build (or rebuild) the branch's ANN index from its current index entries.**
    ///
    /// Reads every index entry on the branch that carries an embedding, inserts each into an HNSW graph
    /// stored in the branch's OWN tree (reserved `\x00loom/hnsw/` keys), and commits — all in one
    /// transaction, so the graph is durable-or-absent, never half-built. Token-gated like every write.
    /// The graph lives in the branch, so it is isolated exactly as the data is (invariant I-11).
    ///
    /// This is the explicit build; auto-inserting on every write is deferred behind its own
    /// write-amplification measurement (see `ann.rs`). Returns how many vectors were indexed.
    pub fn build_ann_index(&self, token: &CapabilityToken, branch: &BranchId) -> Result<usize> {
        self.issuer.authorize(token, branch, self.now())?;

        let head = self.head(branch)?;
        let store = self.pager.fork(&head)?;
        let mut txn = store.begin()?;
        let tree = Tree::open(&*store)?;

        // Collect (id, embedding) first, so the graph build is not interleaved with the scan.
        let mut pairs: Vec<(Key, loom_core::Embedding)> = Vec::new();
        {
            let mut scan_tree = tree;
            for (key, record) in scan_tree.scan()? {
                if !key.starts_with(loom_core::RESERVED_INDEX_PREFIX) {
                    continue;
                }
                let Record::Value(Value::Blob(bytes)) = record else {
                    continue;
                };
                let entry = IndexEntry::decode(&bytes).map_err(|source| LoomError::Codec {
                    op: "decode",
                    what: "index entry",
                    source,
                })?;
                if let Some(emb) = entry.embedding {
                    pairs.push((entry.key, emb));
                }
            }

            let count = pairs.len();
            let mut node_store = crate::ann::TreeNodeStore::new(scan_tree);
            for (id, emb) in pairs {
                loom_core::hnsw_insert(&mut node_store, &id, emb).map_err(|e| {
                    LoomError::Index {
                        detail: format!("insert of {}: {e}", String::from_utf8_lossy(&id)),
                    }
                })?;
            }
            let tree = node_store.into_tree();
            tree.flush(&mut txn)?;
            let commit = store.commit(txn)?;
            self.record_commit(commit, vec![head]);
            self.set_head(branch, commit)?;
            Ok(count)
        }
    }

    /// **Search the branch's ANN index for the `k` nearest record keys to `query`.**
    ///
    /// Reads only the graph nodes the search traverses — the sub-linear win — and only from *this*
    /// branch's tree, so it can never return a sibling's fact (AT-040, structurally). Returns the record
    /// keys best-first; the caller loads and packs the entries. Empty if the index was never built.
    pub fn search_ann(
        &self,
        token: &CapabilityToken,
        branch: &BranchId,
        query: &loom_core::Embedding,
        k: usize,
    ) -> Result<Vec<Key>> {
        self.issuer.authorize(token, branch, self.now())?;

        let head = self.head(branch)?;
        let store = self.pager.fork(&head)?;
        let tree = Tree::open(&*store)?;
        let node_store = crate::ann::TreeNodeStore::new(tree);

        let hits =
            loom_core::hnsw_search(&node_store, query, k, loom_core::EF_DEFAULT).map_err(|e| {
                LoomError::Index {
                    detail: format!("search: {e}"),
                }
            })?;
        Ok(hits.into_iter().map(|(id, _)| id).collect())
    }

    /// The commit a branch currently points at.
    pub fn head(&self, branch: &BranchId) -> Result<CommitId> {
        self.refs()
            .branches
            .get(branch.as_str())
            .copied()
            .ok_or_else(|| LoomError::OutOfScope {
                branch: branch.clone(),
                scope: "no such branch".to_string(),
            })
    }

    /// Create a branch and persist it. Refuses to clobber an existing name.
    ///
    /// Silently moving an existing branch would discard whatever it pointed at, and `branch("main")`
    /// on a database that already has a `main` is nearly always a mistake.
    fn create_branch(&self, name: &str, at: CommitId) -> Result<()> {
        {
            let mut refs = self.refs();
            if refs.branches.contains_key(name) {
                return Err(LoomError::BranchExists {
                    name: name.to_string(),
                });
            }
            refs.branches.insert(name.to_string(), at);
        }
        self.persist()
    }

    /// Move a branch and persist it.
    fn set_head(&self, branch: &BranchId, to: CommitId) -> Result<()> {
        {
            let mut refs = self.refs();
            let Some(slot) = refs.branches.get_mut(branch.as_str()) else {
                return Err(LoomError::OutOfScope {
                    branch: branch.clone(),
                    scope: "no such branch".to_string(),
                });
            };
            *slot = to;
        }
        self.persist()
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

        self.create_branch(branch.as_str(), base)?;

        let scope: BTreeSet<BranchId> = [branch.clone()].into_iter().collect();
        let token = self.issuer.issue(
            self.tenant.clone(),
            session.clone(),
            scope,
            self.now() + DEFAULT_SESSION_TTL_MS,
        )?;

        Ok((
            SessionHandle {
                id: session,
                branch,
                base,
            },
            token,
        ))
    }

    /// **Mint a capability for branches that already exist.**
    ///
    /// This is how a caller reaches a branch after a restart, or after a session's token expired. The
    /// branches must exist; you cannot mint authority over something that is not there.
    ///
    /// # What this deliberately does not decide
    ///
    /// **Who is allowed to ask.** The database can issue a capability; deciding *whether this caller
    /// should get one* is an authorization question, and authorization over data — read, influence,
    /// disclosure, action — is `loom-policy`'s job (docs/03 §5), which is L3.5.
    ///
    /// Until it exists, this is an unguarded door, and it is one **on purpose and in writing** rather
    /// than by accident. `loomd` (L4) must not expose it to an agent, and the MCP surface will not.
    /// A capability system whose issuing endpoint is open to anyone is not a capability system.
    pub fn issue_capability(
        &self,
        session: SessionId,
        branches: &[BranchId],
        ttl_ms: u64,
    ) -> Result<CapabilityToken> {
        for branch in branches {
            // Minting authority over a branch that does not exist would hand out a capability that
            // becomes valid the moment someone creates a branch with that name — a name-squatting
            // hole, and exactly the kind of thing that looks harmless until it is not.
            self.head(branch)?;
        }
        let scope: BTreeSet<BranchId> = branches.iter().cloned().collect();
        self.issuer
            .issue(self.tenant.clone(), session, scope, self.now() + ttl_ms)
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
        self.create_branch(new_branch.as_str(), head)?;

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

    /// **Require every write to be signed, and verify it against the writer's registered key.**
    ///
    /// Turns AT-026 on. Without it, an envelope names its author and nothing checks the name.
    ///
    /// An actor that is not in this registry cannot write at all. That is deliberate: an unknown
    /// actor is refused, not trusted. The alternative — accept unsigned writes from actors we have
    /// never heard of — means an attacker writes as `"acme-compliance-bot"`, a name nobody registered,
    /// and the audit trail records it as gospel.
    pub fn with_actor_keys(
        mut self,
        keys: impl IntoIterator<Item = (ActorId, VerifyingKey)>,
    ) -> Self {
        self.actor_keys = Some(keys.into_iter().collect());
        self
    }

    /// Is this envelope actually from who it says it is?
    ///
    /// A no-op when the database has no actor registry — see the field docs for what that costs.
    fn authenticate(&self, envelope: &WriteEnvelope) -> Result<()> {
        let Some(keys) = &self.actor_keys else {
            return Ok(());
        };

        // Looked up by the actor the envelope CLAIMS to be. Sign as A, claim to be B, and we verify
        // against B's key — which fails. That is the whole mechanism: you cannot impersonate an actor
        // whose key you do not hold.
        let key = keys
            .get(&envelope.actor)
            .ok_or_else(|| LoomError::UnknownActor {
                actor: envelope.actor.as_str().to_string(),
            })?;

        envelope.verify(key)
    }

    /// Write several records in one commit.
    pub fn write_many(
        &self,
        token: &CapabilityToken,
        branch: &BranchId,
        records: Vec<(Key, Record)>,
        envelope: &WriteEnvelope,
    ) -> Result<CommitId> {
        self.write_many_derived(token, branch, records, envelope, &BTreeMap::new())
    }

    /// **Write a record and make it retrievable, in one commit.**
    ///
    /// The record, its provenance, and its index entry all land in the *same* transaction (invariant
    /// I-1) — a crash cannot leave a fact searchable but unprovenanced, or written but unsearchable.
    ///
    /// The index entry's **citations are derived from the record**, not from the hint: an observation
    /// cites its source, a claim cites its evidence. That is what makes AT-041 true by construction —
    /// a packed item's citation is the same `SourceRef` the provenance DAG holds, not a caller's
    /// assertion. A record with nothing to cite (a claim with empty evidence, a bare value) is written
    /// but **not indexed**, because an uncited item could never be packed anyway.
    pub fn write_indexed(
        &self,
        token: &CapabilityToken,
        branch: &BranchId,
        key: Key,
        record: Record,
        hint: IndexHint,
        envelope: &WriteEnvelope,
    ) -> Result<CommitId> {
        let mut hints = BTreeMap::new();
        hints.insert(key.clone(), hint);
        self.write_indexed_many(token, branch, vec![(key, record)], &hints, envelope)
    }

    /// **Forget a set of records: invalidate the claims, remove their index entries — in one commit.**
    ///
    /// The mutating half of AT-044. For each key, in a single transaction:
    /// - its index entry is **removed**, so it can no longer be retrieved. The embedding, the text, the
    ///   summary — the *governed representations* — go with it.
    /// - if it is a claim, its status becomes **`Invalidated`**. Not `Stale`: stale says "re-derive me
    ///   when you can", and forgetting is stronger than that — the input it rested on is gone, so the
    ///   conclusion is withdrawn, not merely paused.
    ///
    /// The record itself is **not deleted**. History is not rewritten; the claim remains readable and
    /// auditable with an honest `Invalidated` status, exactly as supersession and staleness do. What is
    /// removed is only the *derived representation* that made it retrievable.
    ///
    /// Returns `(invalidated, deindexed)` counts. This is a real mutation and it is token-gated — unlike
    /// `taint`, which is a dry run. Forgetting is the execution, and the caller asked for it.
    pub fn invalidate_and_deindex(
        &self,
        token: &CapabilityToken,
        branch: &BranchId,
        keys: &[Key],
        envelope: &WriteEnvelope,
    ) -> Result<(usize, usize)> {
        if !envelope.is_valid() {
            return Err(LoomError::MissingEnvelope);
        }
        self.authenticate(envelope)?;
        self.issuer.authorize(token, branch, self.now())?;

        let head = self.head(branch)?;
        let store = self.pager.fork(&head)?;
        let mut txn = store.begin()?;
        let mut tree = Tree::open(&*store)?;

        let mut invalidated = 0usize;
        let mut deindexed = 0usize;

        for key in keys {
            // Remove the representation. `remove` returns whether anything was there, which is exactly
            // the deindexed count — a key that was never indexed is not double-counted.
            if tree.remove(&IndexEntry::storage_key(key))? {
                deindexed += 1;
            }

            // Withdraw the claim, if it is one and still standing.
            if let Some(Record::Claim(mut claim)) = tree.get(key)? {
                if matches!(claim.status, ClaimStatus::Asserted | ClaimStatus::Stale) {
                    claim.status = ClaimStatus::Invalidated;
                    tree.insert(key.clone(), Record::Claim(claim))?;
                    invalidated += 1;
                }
            }
        }

        tree.flush(&mut txn)?;
        let commit = store.commit(txn)?;
        self.record_commit(commit, vec![head]);
        self.set_head(branch, commit)?;

        Ok((invalidated, deindexed))
    }

    /// `write_many`, with an index hint per key. Keys without a hint are written but not indexed.
    pub fn write_indexed_many(
        &self,
        token: &CapabilityToken,
        branch: &BranchId,
        records: Vec<(Key, Record)>,
        hints: &BTreeMap<Key, IndexHint>,
        envelope: &WriteEnvelope,
    ) -> Result<CommitId> {
        self.write_all(token, branch, records, envelope, &BTreeMap::new(), hints)
    }

    /// `write_many`, plus derivation parents the caller *knows about* but did not read.
    ///
    /// The only caller is `merge`. A merged record genuinely **is** derived from both sides — that is
    /// what merging means — but the merge engine reads through the tree rather than through
    /// `Loom::read`, so the read-set never sees it. Without this, every merge would silently sever the
    /// provenance of everything it merged, and a taint on a source would stop dead at the first merge
    /// boundary. That is not a corner case: merging the winning hypothesis back into main is the
    /// *normal* path.
    ///
    /// The parents are **per key**, and that is load-bearing. The first version handed every record in
    /// the write the union of every parent, which is wrong twice over: record `K` is not derived from
    /// record `J`'s ancestors, so the taint over-reports — and the node blob grows with the size of the
    /// merge, so a 2,000-key merge produced an 18KB derivation node *per record* and blew past the
    /// page size. The oracle caught it as `PageTooLarge`. Precision and size are the same bug here.
    ///
    /// It is `pub(crate)` on purpose. This is the one seam that lets a caller add a derivation edge it
    /// did not read, and it is not for agents.
    pub(crate) fn write_many_derived(
        &self,
        token: &CapabilityToken,
        branch: &BranchId,
        records: Vec<(Key, Record)>,
        envelope: &WriteEnvelope,
        extra_parents: &BTreeMap<Key, Vec<NodeId>>,
    ) -> Result<CommitId> {
        self.write_all(
            token,
            branch,
            records,
            envelope,
            extra_parents,
            &BTreeMap::new(),
        )
    }

    /// The one write path. Everything else is a convenience over this.
    fn write_all(
        &self,
        token: &CapabilityToken,
        branch: &BranchId,
        records: Vec<(Key, Record)>,
        envelope: &WriteEnvelope,
        extra_parents: &BTreeMap<Key, Vec<NodeId>>,
        index_hints: &BTreeMap<Key, IndexHint>,
    ) -> Result<CommitId> {
        // 1. THE ENVELOPE. Before anything else, and with no way around it.
        if !envelope.is_valid() {
            return Err(LoomError::MissingEnvelope);
        }
        self.authenticate(envelope)?;

        // 2. THE TOKEN. No code path below this line touches a page outside the token's scope.
        self.issuer.authorize(token, branch, self.now())?;

        // 3. THE READ-SET. Engine-captured, and consumed here (AT-002).
        //
        //    This is the difference between a provenance system and a provenance *claim*. The caller
        //    supplied `envelope.derived_from`; we take that as an ADDITION, not as the truth. What
        //    the session actually read goes in regardless.
        //
        //    An agent — or an attacker steering one — must not be able to launder a derivation by
        //    declining to mention what it read.
        let captured = self.take_read_set(&envelope.session);

        // 4. The write, and its provenance, **in one commit**.
        //
        // # Why one commit and not two
        //
        // The first version wrote the data, then wrote the derivation nodes in a *second* commit —
        // because a node names the commit it describes and therefore, it seemed, could not be inside
        // it. Two bugs followed immediately.
        //
        // The ordering bug: writing provenance first produced a commit on the *old* head, which the
        // data commit's `set_head` then overwrote — silently discarding every derivation node, on
        // every write. `taint()` cheerfully reported that nothing was contaminated.
        //
        // And a subtler one: two commits per write means two nodes in the commit DAG per write, and
        // the branch model oracle caught the divergence within seconds.
        //
        // The fix is to stop needing the commit id. A node records the commit its write was **based
        // on** — the head it was derived against — which is *more* useful anyway: it is exactly the
        // rewind boundary a recall plan wants ("move the branch back to before this write"). So
        // provenance goes in the same transaction as the data, atomically, and a crash can no longer
        // separate a write from its provenance.
        let head = self.head(branch)?;
        let store = self.pager.fork(&head)?;

        let mut txn = store.begin()?;
        let mut tree = Tree::open(&*store)?;

        let written: Vec<(Key, Record)> = records.clone();
        for (key, record) in records {
            tree.insert(key, record)?;
        }

        if written
            .iter()
            .any(|(k, _)| !is_provenance(k) && !is_reserved(k))
        {
            let nodes =
                self.derivation_nodes(branch, head, &written, envelope, &captured, extra_parents);

            // **Append-ordered provenance.** Nodes used to be stored AT their content hash, which put
            // every provenance write at a uniformly random point in the keyspace — so each commit
            // dirtied nearly every leaf and rewrote a large fraction of the database. They now append
            // to the tail of this branch's range. See `NodeId::key` for the full story.
            let mut seq = match tree.get(&prov_seq_key(branch.as_str()))? {
                Some(Record::Value(Value::Counter(n))) => n as u64,
                _ => 0,
            };

            for node in &nodes {
                tree.insert(
                    node_storage_key(branch.as_str(), seq),
                    Record::Value(Value::Blob(node.encode()?)),
                )?;

                // "Which node last wrote this key" — one lookup instead of a scan of the whole DAG.
                // Reserved, and therefore never merged: it is mutable per-branch bookkeeping, not
                // history, and handing it to the merge engine produced a conflict on an opaque blob
                // with a report asking the caller to pick one. Nobody can answer that.
                //
                // This one is keyed by the DATA key, so it already had the locality the others lacked.
                tree.insert(
                    latest_node_key(&node.key),
                    Record::Value(Value::Blob(node.id.as_bytes().to_vec())),
                )?;

                // "Which nodes cite this source" — so `taint()` has somewhere to start without
                // reading every node in every branch. A taint too slow to run is a taint nobody runs.
                //
                // Append-ordered too, within each source's range. The node id rides in the VALUE now;
                // putting it in the KEY is what made this random in the first place.
                for source in &node.sources {
                    tree.insert(
                        source_index_key(source, branch.as_str(), seq),
                        Record::Value(Value::Blob(node.id.as_bytes().to_vec())),
                    )?;
                }

                seq += 1;
            }

            // The branch's next sequence number. Reserved, so it never merges: each branch counts for
            // itself, and the branch name is inside the node key, so two branches sitting at the same
            // sequence cannot collide.
            tree.insert(
                prov_seq_key(branch.as_str()),
                Record::Value(Value::Counter(seq as i64)),
            )?;
        }

        // Index entries — in this same commit, so a fact is never searchable before it is durable, or
        // durable before it is searchable. The entry's citations are derived from the record, never
        // from the hint (AT-041): a record with nothing to cite is written but not indexed.
        for (key, record) in &written {
            let Some(hint) = index_hints.get(key) else {
                continue;
            };
            let citations = citations_of(record);
            // The effective label: the most restrictive of what this write READ (captured.min_label)
            // and what it IS (an observation's own trust; a claim contributes only the identity, so it
            // inherits its evidence's label). This is AT-035 — the restriction rides the derivation.
            let label = captured.min_label.most_restrictive(own_trust(record));
            let Some(entry) = IndexEntry::new(
                key.clone(),
                hint.text.clone(),
                hint.embedding.clone(),
                citations,
                is_stale(record),
                label,
            ) else {
                // No citation to be had — a bare value, or a claim with empty evidence. It is written,
                // but it does not enter the index, because an uncited item could never be packed.
                continue;
            };
            tree.insert(
                IndexEntry::storage_key(key),
                Record::Value(Value::Blob(entry.encode().map_err(|source| {
                    LoomError::Codec {
                        op: "encode",
                        what: "index entry",
                        source,
                    }
                })?)),
            )?;
        }

        // Bitemporal history — a claim assertion APPENDS a version and CLOSES the prior open one's
        // known interval (AT-005/AT-006). Never an overwrite: "what did you believe last week" stays
        // answerable forever. In this same commit, so a belief and its history cannot diverge.
        for (_, record) in &written {
            if let Record::Claim(claim) = record {
                append_claim_version(&mut tree, claim)?;
            }
        }

        tree.flush(&mut txn)?;
        let commit = store.commit(txn)?;

        self.record_commit(commit, vec![head]);
        self.set_head(branch, commit)?;
        Ok(commit)
    }

    /// Take a session's read-set, clearing it. The next write starts fresh.
    fn take_read_set(&self, session: &SessionId) -> ReadSet {
        self.read_sets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(session)
            .unwrap_or_default()
    }

    /// Build one derivation node per key written.
    fn derivation_nodes(
        &self,
        branch: &BranchId,
        commit: CommitId,
        written: &[(Key, Record)],
        envelope: &WriteEnvelope,
        captured: &ReadSet,
        extra_parents: &BTreeMap<Key, Vec<NodeId>>,
    ) -> Vec<DerivationNode> {
        // The union of what the ENGINE saw and what the CALLER declared. The caller can only ever
        // make this set bigger.
        let mut base_sources: Vec<SourceRef> = captured.sources.iter().cloned().collect();
        base_sources.extend(envelope.derived_from.iter().cloned());

        let base_parents: Vec<NodeId> = captured.nodes.iter().copied().collect();

        written
            .iter()
            .filter(|(key, _)| !is_provenance(key))
            .map(|(key, record)| {
                let mut sources = base_sources.clone();

                // What the engine saw this session read, plus — for a merge, and only a merge — the
                // node that produced *this key* on each side. See `write_many_derived`.
                let mut derived_from = base_parents.clone();
                if let Some(extra) = extra_parents.get(key) {
                    derived_from.extend(extra.iter().copied());
                }
                derived_from.sort();
                derived_from.dedup();

                // **An observation IS the arrival of a source.** Its node must cite it, or the DAG
                // has no bottom: `taint("that scraped page")` would have nothing to match against and
                // would confidently report that nothing is contaminated.
                //
                // This is not the caller telling us where it came from. It is the record itself.
                if let Record::Observation(obs) = record {
                    sources.push(obs.source.clone());
                }

                DerivationNode::new(
                    branch.clone(),
                    commit,
                    key.clone(),
                    envelope.actor.clone(),
                    envelope.delegation.clone(),
                    envelope.intent.clone(),
                    derived_from.clone(),
                    sources,
                )
            })
            .collect()
    }

    /// Like `write_many`, but records a **second parent** — the merge edge.
    fn write_merge(
        &self,
        token: &CapabilityToken,
        branch: &BranchId,
        records: Vec<(Key, Record)>,
        envelope: &WriteEnvelope,
        second_parent: CommitId,
        derivation_parents: &BTreeMap<Key, Vec<NodeId>>,
    ) -> Result<CommitId> {
        let before = self.head(branch)?;
        let commit =
            self.write_many_derived(token, branch, records, envelope, derivation_parents)?;

        // THE SECOND PARENT. This is the whole reason merges are correct on the second pass — and
        // why it must be durable: losing it across a restart silently restores the double-counting
        // bug (merge twice, and a +3 becomes a +6, and the merge reports success).
        self.record_commit(commit, vec![before, second_parent]);
        {
            let mut refs = self.refs();
            if let Some(parents) = refs.commits.get_mut(&commit) {
                if !parents.contains(&second_parent) {
                    parents.push(second_parent);
                }
            }
        }
        self.persist()?;
        Ok(commit)
    }

    /// Read a record from a branch.
    ///
    /// **The read is captured.** Whatever this returns becomes part of the session's read-set, and the
    /// session's next write will be recorded as derived from it — whether the caller says so or not
    /// (AT-002).
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
        let record = tree.get(key)?;

        if let Some(record) = &record {
            self.capture_read(token.session(), branch, key, record)?;
        }
        Ok(record)
    }

    /// Record what a read saw, into the session's read-set.
    ///
    /// Two things get captured, and they are different in kind:
    ///
    /// - the **derivation node** that produced this record, if one exists — so the DAG links write to
    ///   write, and taint can walk downstream through conclusions built on conclusions;
    /// - the **external source**, if the record is an `Observation` — so the DAG bottoms out somewhere
    ///   real, and `taint("that scraped page")` has something to match against.
    fn capture_read(
        &self,
        session: &SessionId,
        branch: &BranchId,
        key: &[u8],
        record: &Record,
    ) -> Result<()> {
        // The provenance layer's own records are not evidence. Reading a derivation node while
        // walking the DAG must not make the walker a derivation of everything it inspected.
        if is_provenance(key) {
            return Ok(());
        }

        let mut sets = self.read_sets.lock().unwrap_or_else(|e| e.into_inner());
        let set = sets.entry(session.clone()).or_default();

        // Which node produced this key on this branch?
        if let Some(node) = self.node_for_key(branch, key)? {
            set.nodes.insert(node);
        }

        // An observation's source is where the DAG bottoms out — and its trust is where the label
        // does. Reading an `Untrusted` scrape makes the reader's read-set `Untrusted`, and anything it
        // then writes inherits that (AT-035).
        if let Record::Observation(obs) = record {
            set.sources.insert(obs.source.clone());
            set.min_label = set.min_label.most_restrictive(obs.trust);
        }

        // Reading a *derived* record carries its label forward too, so a restriction propagates through
        // a summary or a re-derived claim, not only through a directly-read observation. The label was
        // cached on the record's index entry when it was written; if it was never indexed there is
        // nothing to inherit, which is correct — an un-indexed value carries no evidence.
        if let Some(entry) = self.index_entry_for(branch, key)? {
            set.min_label = set.min_label.most_restrictive(entry.label);
        }
        Ok(())
    }

    /// The derivation node that most recently wrote this key on this branch, if any.
    fn node_for_key(&self, branch: &BranchId, key: &[u8]) -> Result<Option<NodeId>> {
        let head = self.head(branch)?;
        let store = self.pager.fork(&head)?;
        let mut tree = Tree::open(&*store)?;

        let Some(Record::Value(Value::Blob(bytes))) = tree.get(&latest_node_key(key))? else {
            return Ok(None);
        };
        Ok(NodeId::from_bytes(&bytes))
    }

    /// The current read-set for a session. Diagnostics, and the tests that prove AT-002.
    pub fn read_set(&self, session: &SessionId) -> ReadSet {
        self.read_sets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(session)
            .cloned()
            .unwrap_or_default()
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

        // Neither the engine's bookkeeping nor the provenance layer is the caller's data.
        //
        // Note the asymmetry, and it is deliberate: reserved keys are hidden AND excluded from merge;
        // provenance keys are hidden but **merged**. Merging a branch without carrying its provenance
        // would be a hole you could drive a poisoned document through.
        Ok(tree
            .scan()?
            .into_iter()
            .filter(|(k, _)| !is_reserved(k) && !is_provenance(k))
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
        // No information-flow policy check — every merged write is permitted.
        self.merge_checked(token, source, target, policy, envelope, &|_, _| None)
    }

    /// `merge`, but each merged write is re-evaluated against a policy **at merge time** (AT-016).
    ///
    /// `forbids(key, record)` returns `Some(reason)` if the *current* policy forbids this write landing
    /// on the target. It is called for every caller-facing write the merge would make — a merge is a
    /// new write on the target, and it is evaluated against the world as it is *now*, not as it was
    /// when the source branched. If any write is forbidden, the whole merge is refused and **nothing is
    /// written** (a partial merge would be its own kind of corruption). The predicate is injected so
    /// this crate stays free of the policy engine, exactly as retrieval's filter is.
    pub fn merge_checked(
        &self,
        token: &CapabilityToken,
        source: &BranchId,
        target: &BranchId,
        policy: &MergePolicy,
        envelope: &WriteEnvelope,
        forbids: &dyn Fn(&Key, &Record) -> Option<String>,
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
                // The caller's facts, not the engine's bookkeeping. Provenance nodes ride along in
                // the merge — they must, or a taint would stop dead at the first merge boundary — but
                // nobody asked for a count of them, and reporting "we merged 3 records" when the user
                // wrote 1 fact is a number that means nothing.
                let records = writes
                    .iter()
                    .filter(|(k, _)| !is_reserved(k) && !is_provenance(k))
                    .count();

                // POLICY, RE-EVALUATED AT MERGE TIME (AT-016). Each caller-facing write the merge would
                // make is checked against the CURRENT policy. If one is now forbidden, refuse the whole
                // merge — a merge that applied some writes and refused others would leave the target in
                // a state neither branch ever had.
                for (key, record) in &writes {
                    if is_reserved(key) || is_provenance(key) {
                        continue;
                    }
                    if let Some(reason) = forbids(key, record) {
                        return Ok(MergeResult::PolicyRefused {
                            key: String::from_utf8_lossy(key).to_string(),
                            reason,
                        });
                    }
                }

                // Record what we merged, in the same commit as the merge itself. If this were a
                // separate commit, a crash between the two would leave a branch that had applied the
                // source's changes but did not know it — and the next merge would apply them again.
                writes.push((
                    merged_from_key(source.as_str()),
                    Record::Value(Value::Blob(source_head.as_bytes().to_vec())),
                ));

                // Carry the provenance across. Every key this merge writes is derived from the
                // node that produced it on the SOURCE (and, where it existed, on the TARGET) — and
                // saying so is the difference between a taint that crosses a merge and one that
                // stops dead at it.
                let mut parents: BTreeMap<Key, Vec<NodeId>> = BTreeMap::new();
                for (key, _) in &writes {
                    if is_reserved(key) || is_provenance(key) {
                        continue;
                    }
                    let mut per_key = Vec::new();
                    for from in [source, target] {
                        if let Ok(Some(node)) = self.node_for_key(from, key) {
                            per_key.push(node);
                        }
                    }
                    if !per_key.is_empty() {
                        parents.insert(key.clone(), per_key);
                    }
                }

                let commit =
                    self.write_merge(token, target, writes, envelope, source_head, &parents)?;
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

    /// Every commit in a commit's history, over the **recorded multi-parent DAG**.
    fn full_ancestors(&self, head: &CommitId) -> Result<BTreeSet<CommitId>> {
        let mut seen: BTreeSet<CommitId> = BTreeSet::new();
        let mut stack = vec![*head];

        while let Some(commit) = stack.pop() {
            if !seen.insert(commit) {
                continue;
            }

            // The parents we recorded — including a merge's second parent, which substrate cannot
            // store and which is the entire point of keeping this DAG.
            if let Some(parents) = self.refs().commits.get(&commit) {
                stack.extend(parents.iter().copied());
                continue;
            }

            // A commit we did not record (the root, or one made before this process started). Fall
            // back to substrate's single parent edge.
            if let Ok(manifest) = self.pager.manifest(&commit) {
                if let Some(parent) = manifest.parent {
                    stack.push(parent);
                }
            }
        }
        Ok(seen)
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
        let previous = self.head(branch)?;
        self.set_head(branch, *to)?;
        Ok(previous)
    }

    /// Sweep everything no branch points at.
    ///
    /// Roots come from the branch tree — every branch and every tag. Handing GC an incomplete set of
    /// roots is how you delete a customer's data, so we never assemble one by hand.
    pub fn gc(&self) -> Result<substrate_pager::GcStats> {
        // Roots come from the refs — every branch AND every tag. Handing GC an incomplete set of
        // roots is how you delete a customer's data, so we never assemble one by hand.
        let roots = self.refs().roots();
        Ok(self.pager.gc(&roots)?)
    }

    /// The underlying pager. Debug and diagnostics only.
    #[doc(hidden)]
    pub fn pager_for_debug(&self) -> &Arc<Pager> {
        &self.pager
    }

    /// How many merge bases two branches have. Diagnostics and the oracle.
    #[doc(hidden)]
    pub fn merge_base_count(&self, a: &BranchId, b: &BranchId) -> Result<usize> {
        let (ah, bh) = (self.head(a)?, self.head(b)?);
        Ok(self.merge_bases(&ah, &bh)?.len())
    }

    /// **Sleep the whole tenant** into object storage.
    ///
    /// Only compiled with the `remote` feature (on by default). An airgap build
    /// (`--no-default-features`) has no object-storage client, so there is nothing to sleep *to* — the
    /// method does not exist rather than existing and failing at runtime.
    ///
    /// Every branch is a head, and every head's pages *and its full manifest ancestry* must be durable
    /// before a single local byte is dropped. Putting a tenant to sleep must not quietly discard the
    /// branches nobody happened to be looking at.
    #[cfg(feature = "remote")]
    ///
    /// The returned token carries the refs — branch heads, tags, and the commit DAG. A token that
    /// carried only data would restore the database and lose the branch names, and *"where is branch
    /// h2"* is exactly the question this has to answer.
    pub async fn sleep(&self, tiered: &substrate_store::TieredStore) -> Result<LoomWakeToken> {
        let refs = self.refs().clone();

        // EVERY branch head, not just one. And `ensure_durable` uploads each head's whole manifest
        // ancestry — the overlay bases it needs to be readable, and the parents that are its history.
        let heads = refs.roots();
        tiered
            .ensure_durable(&heads)
            .await
            .map_err(|e| LoomError::CorruptNode {
                page: 0,
                detail: format!("cannot make the tenant durable: {e}"),
            })?;

        // Only now is it safe to throw the local copy away. If anything above failed we drop nothing
        // and the tenant stays awake — a sleep that loses data is a bug with good marketing.
        tiered.drop_local().map_err(|e| LoomError::CorruptNode {
            page: 0,
            detail: format!("cannot drop local state: {e}"),
        })?;

        Ok(LoomWakeToken {
            tenant: self.tenant.clone(),
            page_size: self.pager.page_size(),
            refs,
        })
    }

    /// **Wake a sleeping tenant.** Branch names and all.
    ///
    /// Only compiled with the `remote` feature (on by default) — see [`sleep`](Self::sleep).
    #[cfg(feature = "remote")]
    pub fn wake(tiered: &substrate_store::TieredStore, token: &LoomWakeToken) -> Result<Self> {
        let store = Arc::new(MemRefStore::new());
        store.save(&token.refs)?;
        Loom::assemble(Arc::clone(tiered.pager()), store, token.tenant.clone())
    }

    /// The tenant this database belongs to.
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Every branch that exists.
    pub fn branch_names(&self) -> Vec<String> {
        self.refs().branches.keys().cloned().collect()
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
    /// **Policy, re-evaluated at merge time, forbids one of the writes (AT-016).** The branch's write
    /// was allowed when it forked, but the policy has changed since, and a merge is a *new* write on
    /// the target evaluated against the world as it is *now* — not as it was when the branch forked.
    /// Nothing is written.
    PolicyRefused {
        /// The key whose merge the current policy forbids.
        key: String,
        /// Why, in words the caller can act on.
        reason: String,
    },
}

impl MergeResult {
    /// True if the merge went through.
    pub fn is_merged(&self) -> bool {
        matches!(self, MergeResult::Merged { .. })
    }
}

/// What a session has read since its last write.
///
/// Two kinds, because they are two kinds of thing: **derivation nodes** (things this database
/// produced, which have their own upstream) and **external sources** (things the world told us,
/// which are where the DAG bottoms out).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadSet {
    /// Derivation nodes whose output this session has read.
    pub nodes: BTreeSet<NodeId>,
    /// External sources this session has read — the `source` of every `Observation` it touched.
    pub sources: BTreeSet<SourceRef>,
    /// **The most restrictive trust label of everything this session has read.** A write derived from
    /// this read-set inherits it (AT-035): the weakest link in what you read sets the label of what you
    /// write. Starts at the least-restrictive identity and only ever climbs.
    pub min_label: TrustClass,
}

impl Default for ReadSet {
    fn default() -> Self {
        // min_label starts at the LEAST restrictive — an empty read-set has read nothing, so it imposes
        // no restriction. This is not `TrustClass::default()` on purpose: a security label must never
        // have a global "trusted" default that some other code path could pick up by accident.
        ReadSet {
            nodes: BTreeSet::new(),
            sources: BTreeSet::new(),
            min_label: TrustClass::least_restrictive(),
        }
    }
}

impl ReadSet {
    /// True if nothing has been read.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty() && self.sources.is_empty()
    }
}

/// The sources a record cites — the same `SourceRef`s the provenance DAG records.
///
/// This is what makes an index entry's citation *real* (AT-041) rather than a caller's claim: an
/// observation is the arrival of a source and cites it; a claim cites its evidence. A bare value cites
/// nothing, and a claim with empty evidence cites nothing — both are stored, neither is retrievable,
/// because an item that cannot say where it came from must never appear in a packed context.
fn citations_of(record: &Record) -> Vec<SourceRef> {
    match record {
        Record::Observation(obs) => vec![obs.source.clone()],
        Record::Claim(claim) => claim.evidence.clone(),
        Record::Value(_) => Vec::new(),
    }
}

/// Whether a record is a claim whose evidence has been invalidated. Cached into the index entry so the
/// ranker can penalise it (AT-043) without re-reading the record.
fn is_stale(record: &Record) -> bool {
    matches!(record, Record::Claim(c) if c.status == ClaimStatus::Stale)
}

/// A record's own trust label, before anything it was derived from is folded in.
///
/// An observation *is* a trust statement — it carries the trust of its source. A claim carries none of
/// its own; its label comes entirely from its evidence (the read-set), so it contributes the
/// least-restrictive identity here and inherits the rest. A bare value likewise imposes no restriction.
fn own_trust(record: &Record) -> TrustClass {
    match record {
        Record::Observation(obs) => obs.trust,
        Record::Claim(_) | Record::Value(_) => TrustClass::least_restrictive(),
    }
}

/// Append a claim version, closing the prior open version of the same `(subject, predicate)`.
///
/// The heart of the bitemporal history (AT-005/AT-006). Reads the existing versions for this claim's
/// subject+predicate, closes whichever is still open (its `known.end` becomes the new version's
/// `known.start` — we believed the old thing right up until we believed the new one), marks it
/// `Superseded`, and appends the new version at the next sequence. Nothing is overwritten; the log
/// only grows.
fn append_claim_version(tree: &mut Tree<'_>, claim: &Claim) -> Result<()> {
    let subject = &claim.subject;
    let predicate = &claim.predicate;
    let prefix = ClaimVersion::history_prefix(subject, predicate);

    // Find the existing versions, and the highest sequence.
    let mut max_seq: Option<u64> = None;
    let mut open: Vec<(Key, ClaimVersion)> = Vec::new();
    for (key, record) in tree.scan()? {
        if !key.starts_with(&prefix) {
            continue;
        }
        let Record::Value(Value::Blob(bytes)) = record else {
            continue;
        };
        let Ok(version) = ClaimVersion::decode(&bytes) else {
            continue;
        };
        max_seq = Some(max_seq.map_or(version.seq, |m| m.max(version.seq)));
        // An "open" version is one whose known interval has not been closed.
        if version.claim.known.end.is_none() {
            open.push((key, version));
        }
    }

    // Close every still-open prior version at the moment the new belief begins.
    let now = claim.known.start;
    for (key, mut version) in open {
        if let Some(start) = now {
            version.claim.known = version.claim.known.closed_at(start);
        }
        version.claim.status = ClaimStatus::Superseded;
        tree.insert(
            key,
            Record::Value(Value::Blob(version.encode().map_err(|source| {
                LoomError::Codec {
                    op: "encode",
                    what: "claim version",
                    source,
                }
            })?)),
        )?;
    }

    // Append the new version.
    let seq = max_seq.map_or(0, |m| m + 1);
    let version = ClaimVersion {
        claim: claim.clone(),
        seq,
    };
    tree.insert(
        ClaimVersion::storage_key(subject, predicate, seq),
        Record::Value(Value::Blob(version.encode().map_err(|source| {
            LoomError::Codec {
                op: "encode",
                what: "claim version",
                source,
            }
        })?)),
    )?;
    Ok(())
}
