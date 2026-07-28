//! Durable refs: where branches live, and the commit DAG.
//!
//! # Why this exists, and why it is the first thing in L2 rather than an afterthought
//!
//! Before this, LoomDB's *data* was durable — every commit is a substrate manifest, fsync'd and
//! content-addressed — but the map from **branch name to head**, and the **multi-parent merge edges**,
//! lived in memory. So a restart lost your branch names. Every commit was still there and still
//! readable by id; nothing corrupted. But *"where is branch h2"* had no answer.
//!
//! Everything in L2 stacks on durable history. A derivation DAG built on refs that vanish is a
//! derivation DAG that vanishes, and a taint report that cannot walk the history it is taunting is
//! not a report, it is a guess.
//!
//! # The commit DAG is not optional
//!
//! substrate's manifests have exactly **one parent**. Git's merge commits have two, and that is what
//! makes a merge base correct the *second* time you merge. LoomDB records the second parent itself —
//! and it has to survive a restart, or the merge-base computation silently reverts to the
//! double-counting bug the model oracle caught. (Merge twice, and a `+3` becomes a `+6`. The merge
//! reports success.)
//!
//! # The write ordering, and why it is this way round
//!
//! ```text
//! 1. pages + manifest → durable    (substrate: fsync'd, content-addressed)
//! 2. refs → durable                (a fsync'd append to the ref log)
//! ```
//!
//! A crash **between** them leaves the refs pointing at the *old* head, and the new manifest
//! unreferenced — garbage, which GC sweeps. That is a **lost commit**, and it is the failure we
//! choose: the alternative ordering would leave a ref pointing at a manifest that does not exist,
//! which is a **corrupt database**. Losing the last transaction is recoverable. Dangling into the
//! void is not.
//!
//! This is the same discipline as substrate's commit protocol (docs/02 §3.1), for the same reason.
//!
//! # Log-structured, so a commit is O(1) — not O(branches) (Phase 2)
//!
//! The refs used to be one file that was serialized and atomic-written **in full on every commit**. That
//! is O(branches + commits) per commit — invisible at ten branches, 41 ms and a 12.4 MB rewrite at a
//! hundred thousand (`benches/refs_scaling.rs`). It is now **log-structured** (design: `docs/refs-design.md`):
//!
//! - a **snapshot** (`refs.snapshot`) — a full [`Refs`], atomic-written, the compaction baseline;
//! - a **log** (`refs.log`) — an append-only sequence of [`RefEdit`] deltas, each a checksummed frame,
//!   appended (fsync'd) on every commit. One small append, flat regardless of branch count.
//!
//! `load` replays the log on the snapshot **in append order**, stopping at the first torn frame (a crash
//! mid-append — detected by its BLAKE3 checksum — is the recoverable lost-last-commit above). Compaction
//! folds the log back into a fresh snapshot when it grows past the snapshot's own size; because every
//! [`RefEdit`] is idempotent/last-write-wins and replay is chronological, a crash *mid-compaction* (new
//! snapshot written, old log not yet truncated) simply replays already-incorporated edits as no-ops — so
//! **no sequence numbers are needed**. The manifest-before-ref ordering above is unchanged: the append
//! happens exactly where the full write did, after the manifest is durable.

use loom_core::{CommitId, LoomError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use substrate_pager::{std_vfs, Vfs};

/// The on-disk format version for the refs file.
pub const REFS_FORMAT_VERSION: u32 = 1;

/// Everything that must survive a restart, other than the data itself.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refs {
    /// Format version.
    pub format_version: u32,
    /// Branch name → head commit. These move.
    pub branches: BTreeMap<String, CommitId>,
    /// Tag name → commit. These do not.
    pub tags: BTreeMap<String, CommitId>,
    /// **The commit DAG.** A merge commit has two parents; everything else has one.
    ///
    /// This is the second parent substrate cannot store, and losing it across a restart would
    /// silently restore the double-counting merge bug.
    ///
    /// Serialized as **pairs**, not as a map: a `CommitId` is 32 bytes, not a string, and JSON has no
    /// such thing as a non-string key. A wake token has to survive being written into a registry as
    /// JSON, so the wire form is a list.
    #[serde(with = "commits_as_pairs")]
    pub commits: BTreeMap<CommitId, Vec<CommitId>>,
}

/// The commit DAG, on the wire, as pairs — see [`Refs::commits`].
mod commits_as_pairs {
    use super::{BTreeMap, CommitId};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        map: &BTreeMap<CommitId, Vec<CommitId>>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let pairs: Vec<(&CommitId, &Vec<CommitId>)> = map.iter().collect();
        pairs.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<BTreeMap<CommitId, Vec<CommitId>>, D::Error> {
        let pairs: Vec<(CommitId, Vec<CommitId>)> = Vec::deserialize(d)?;
        Ok(pairs.into_iter().collect())
    }
}

impl Refs {
    /// An empty ref set with a single branch at a root commit.
    pub fn rooted(branch: &str, at: CommitId) -> Self {
        let mut refs = Refs {
            format_version: REFS_FORMAT_VERSION,
            ..Default::default()
        };
        refs.branches.insert(branch.to_string(), at);
        refs
    }

    /// Every commit any branch or tag points at. **These are GC's roots.**
    ///
    /// Handing GC an incomplete set of roots is how you delete a customer's data, so this is the only
    /// place that assembles them, and it takes both branches *and* tags — a tagged release that gets
    /// garbage collected is a very bad afternoon.
    pub fn roots(&self) -> Vec<CommitId> {
        let mut roots: Vec<CommitId> = self.branches.values().copied().collect();
        roots.extend(self.tags.values().copied());
        roots.sort_unstable();
        roots.dedup();
        roots
    }

    /// Serialize.
    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|source| LoomError::Codec {
            op: "encode",
            what: "refs",
            source,
        })
    }

    /// Deserialize.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let refs: Refs = bincode::deserialize(bytes).map_err(|source| LoomError::Codec {
            op: "decode",
            what: "refs",
            source,
        })?;

        // A refs file from a future version is not something to guess at. Refusing to open is
        // recoverable; opening and misreading a commit DAG is not.
        if refs.format_version > REFS_FORMAT_VERSION {
            return Err(LoomError::CorruptNode {
                page: 0,
                detail: format!(
                    "refs file is format version {}, but this build understands at most {}. \
                     Upgrade LoomDB, or restore an older refs file.",
                    refs.format_version, REFS_FORMAT_VERSION
                ),
            });
        }
        Ok(refs)
    }

    /// Apply one [`RefEdit`] to this in-memory `Refs`. **Every variant is idempotent / last-write-wins**,
    /// which is the whole reason the log can be replayed on a fresher snapshot after a mid-compaction
    /// crash without corrupting anything (see the module docs).
    pub fn apply_edit(&mut self, edit: &RefEdit) {
        match edit {
            RefEdit::SetHead { branch, to } => {
                self.branches.insert(branch.clone(), *to);
            }
            RefEdit::CreateBranch { name, at } => {
                self.branches.insert(name.clone(), *at);
            }
            RefEdit::RemoveBranch { name } => {
                self.branches.remove(name);
            }
            RefEdit::SetTag { tag, to } => {
                self.tags.insert(tag.clone(), *to);
            }
            RefEdit::RemoveTag { tag } => {
                self.tags.remove(tag);
            }
            RefEdit::RecordCommit { commit, parents } => {
                self.commits.insert(*commit, parents.clone());
            }
            RefEdit::AddParent { commit, parent } => {
                let entry = self.commits.entry(*commit).or_default();
                if !entry.contains(parent) {
                    entry.push(*parent);
                }
            }
        }
    }
}

/// A single durable change to the refs — the unit the log appends, so a commit costs O(1), not
/// O(branches). Each variant is **idempotent / last-write-wins** (see [`Refs::apply_edit`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefEdit {
    /// Move an existing branch to a new head — the ordinary per-commit edit.
    SetHead {
        /// The branch being moved.
        branch: String,
        /// Its new head commit.
        to: CommitId,
    },
    /// Create a branch at a commit (the session refuses to clobber; on replay it is a plain insert).
    CreateBranch {
        /// The new branch name.
        name: String,
        /// The commit it starts at.
        at: CommitId,
    },
    /// Delete a branch.
    RemoveBranch {
        /// The branch to remove.
        name: String,
    },
    /// Set (or move) a tag.
    SetTag {
        /// The tag name.
        tag: String,
        /// The commit it points at.
        to: CommitId,
    },
    /// Delete a tag.
    RemoveTag {
        /// The tag to remove.
        tag: String,
    },
    /// Record a commit's parents — the DAG edge substrate cannot store. Overwrites, so replaying an
    /// older single-parent record before an `AddParent` still converges to the full parent set.
    RecordCommit {
        /// The commit whose parents are recorded.
        commit: CommitId,
        /// Its parent commits (one normally, two for a merge).
        parents: Vec<CommitId>,
    },
    /// Add a second parent to an already-recorded commit — the merge edge (a set-union, idempotent).
    AddParent {
        /// The commit gaining a parent.
        commit: CommitId,
        /// The parent to add.
        parent: CommitId,
    },
}

/// How many bytes of a frame's BLAKE3 payload checksum are stored. Eight bytes is ample to catch a torn
/// tail (a crash mid-append); this is corruption detection, not an adversary, so it need not be the full
/// 32 bytes.
const FRAME_CHECKSUM_LEN: usize = 8;

/// Encode one edit as a self-describing frame: `[u32 len][payload][8-byte BLAKE3(payload)]`. The length
/// bounds the read and the checksum proves the payload is whole — together they make a torn trailing
/// frame unmistakable on replay.
fn frame_encode(edit: &RefEdit) -> Result<Vec<u8>> {
    let payload = bincode::serialize(edit).map_err(|source| LoomError::Codec {
        op: "encode",
        what: "ref edit",
        source,
    })?;
    let mut out = Vec::with_capacity(4 + payload.len() + FRAME_CHECKSUM_LEN);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&payload);
    out.extend_from_slice(&blake3::hash(&payload).as_bytes()[..FRAME_CHECKSUM_LEN]);
    Ok(out)
}

/// Parse every **complete, checksum-valid** frame from a log buffer, in order, stopping at the first
/// torn/short/undecodable frame — that is the tail a crash left, and everything after it is discarded.
/// A malformed length that would run past the buffer is a torn tail too, not an error.
fn frames_decode(buf: &[u8]) -> Vec<RefEdit> {
    let mut edits = Vec::new();
    let mut pos = 0usize;
    while pos + 4 <= buf.len() {
        let len = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as usize;
        let start = pos + 4;
        let Some(end) = start.checked_add(len) else {
            break;
        };
        let Some(sum_end) = end.checked_add(FRAME_CHECKSUM_LEN) else {
            break;
        };
        if sum_end > buf.len() {
            break; // torn tail: the frame is not all here
        }
        let payload = &buf[start..end];
        if blake3::hash(payload).as_bytes()[..FRAME_CHECKSUM_LEN] != buf[end..sum_end] {
            break; // torn/corrupt tail: the payload is not whole
        }
        match bincode::deserialize::<RefEdit>(payload) {
            Ok(edit) => edits.push(edit),
            Err(_) => break, // an undecodable frame is treated as the tail, never guessed at
        }
        pos = sum_end;
    }
    edits
}

/// Where refs are persisted.
///
/// Two implementations: a local file (log-structured), and — for a database that has been put to sleep in
/// object storage — in memory, because the refs travel with the data (see `Loom::sleep`).
pub trait RefStore: Send + Sync + std::fmt::Debug {
    /// Read the refs. `None` if this is a brand-new database.
    fn load(&self) -> Result<Option<Refs>>;

    /// Replace the persisted refs with a **full snapshot**, atomically — and reset the delta log. This
    /// is the O(branches) path: it seeds a fresh store (root init, sleep-resume) and is what compaction
    /// folds the log back into. A half-written snapshot must never be observable, so it is atomic.
    fn save(&self, refs: &Refs) -> Result<()>;

    /// Append a batch of [`RefEdit`] deltas durably — the **O(edits) per-commit path**. All edits in the
    /// batch land in one fsync'd append (so a commit pays one fsync, not one per edit). A crash mid-append
    /// leaves a torn trailing frame that `load` discards — the recoverable lost-last-commit.
    fn apply(&self, edits: &[RefEdit]) -> Result<()>;
}

/// The name of the legacy single-file refs, read once and migrated to a snapshot if a pre-Phase-2
/// database is opened by this build (so `"where is branch main"` never silently returns nothing).
const LEGACY_REFS_FILE: &str = "refs.bin";
/// The full-snapshot file — the compaction baseline.
const SNAPSHOT_FILE: &str = "refs.snapshot";
/// The append-only delta log.
const LOG_FILE: &str = "refs.log";
/// Compact once the log outgrows the snapshot, with this floor so a tiny database never churns: below it,
/// replaying the whole log on load costs well under a millisecond, so compaction buys nothing.
const COMPACT_FLOOR_BYTES: u64 = 256 * 1024;

/// Refs in files on disk, **log-structured**: a full `refs.snapshot` plus an append-only `refs.log` of
/// deltas since it. A commit appends one small frame; compaction folds the log back into a new snapshot
/// when it outgrows the snapshot. See the module docs for the crash-safety argument.
#[derive(Debug)]
pub struct FileRefStore {
    vfs: Arc<dyn Vfs>,
    snapshot_path: PathBuf,
    log_path: PathBuf,
    legacy_path: PathBuf,
    /// The log-size floor below which compaction is skipped. Defaults to [`COMPACT_FLOOR_BYTES`]; the
    /// crash suite lowers it so a compaction can be provoked (and crash-swept) after a handful of edits
    /// rather than a quarter-megabyte of them. The compaction *logic* is identical either way.
    compact_floor: u64,
    /// Guards the log file and compaction, and caches the sizes that drive the compaction trigger.
    state: std::sync::Mutex<FileState>,
}

#[derive(Debug, Default)]
struct FileState {
    snapshot_bytes: u64,
    log_bytes: u64,
}

impl FileRefStore {
    /// Open (creating the directory if absent) a ref store under a database root.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        FileRefStore::open_with_vfs(std_vfs(), root)
    }

    /// Open on a caller-supplied filesystem — which is how the kill-and-restart tests get to cut the
    /// power in the middle of a ref write.
    pub fn open_with_vfs(vfs: Arc<dyn Vfs>, root: impl AsRef<Path>) -> Result<Self> {
        let dir = root.as_ref().join("loom");
        vfs.create_dir_all(&dir)
            .map_err(|e| LoomError::CorruptNode {
                page: 0,
                detail: format!("cannot create the refs directory {}: {e}", dir.display()),
            })?;
        let store = FileRefStore {
            snapshot_path: dir.join(SNAPSHOT_FILE),
            log_path: dir.join(LOG_FILE),
            legacy_path: dir.join(LEGACY_REFS_FILE),
            vfs,
            compact_floor: COMPACT_FLOOR_BYTES,
            state: std::sync::Mutex::new(FileState::default()),
        };
        // Prime the cached sizes from whatever is on disk, so the first commit's compaction decision is
        // right without a stat per append.
        let mut st = store.lock();
        st.snapshot_bytes = store.file_len(&store.snapshot_path);
        st.log_bytes = store.file_len(&store.log_path);
        drop(st);
        Ok(store)
    }

    /// Lower (or raise) the log-size floor at which compaction kicks in. Mainly for the crash suite,
    /// which needs a compaction to happen after a few edits so it can be crash-swept without writing a
    /// quarter-megabyte of them first.
    pub fn with_compact_floor(mut self, bytes: u64) -> Self {
        self.compact_floor = bytes;
        self
    }

    /// Where the snapshot lives (the durable baseline the tests inspect).
    pub fn path(&self) -> &Path {
        &self.snapshot_path
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FileState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn file_len(&self, path: &Path) -> u64 {
        if !self.vfs.exists(path) {
            return 0;
        }
        self.vfs.read(path).map(|b| b.len() as u64).unwrap_or(0)
    }

    /// Read the snapshot, or migrate a legacy single-file refs into one. `None` if neither exists.
    fn read_snapshot(&self) -> Result<Option<Refs>> {
        if self.vfs.exists(&self.snapshot_path) {
            let bytes = self.read_file(&self.snapshot_path)?;
            return Ok(Some(Refs::decode(&bytes)?));
        }
        // A pre-Phase-2 database has only `refs.bin`. Read it as the snapshot; the first `save` will
        // rewrite it into `refs.snapshot` form and this path stops being taken.
        if self.vfs.exists(&self.legacy_path) {
            let bytes = self.read_file(&self.legacy_path)?;
            return Ok(Some(Refs::decode(&bytes)?));
        }
        Ok(None)
    }

    fn read_file(&self, path: &Path) -> Result<Vec<u8>> {
        self.vfs.read(path).map_err(|e| LoomError::CorruptNode {
            page: 0,
            detail: format!("cannot read {}: {e}", path.display()),
        })
    }

    /// Reconstruct the live refs from snapshot + replayed log. Assumes the lock is held.
    fn reconstruct(&self) -> Result<Option<Refs>> {
        let snapshot = self.read_snapshot()?;
        let log = if self.vfs.exists(&self.log_path) {
            frames_decode(&self.read_file(&self.log_path)?)
        } else {
            Vec::new()
        };
        match (snapshot, log.is_empty()) {
            (None, true) => Ok(None),
            (base, _) => {
                let mut refs = base.unwrap_or_default();
                for edit in &log {
                    refs.apply_edit(edit);
                }
                Ok(Some(refs))
            }
        }
    }

    /// Write a fresh snapshot atomically, then truncate the log — the compaction step, and `save`. The
    /// order is load-bearing: the snapshot is durable *before* the log is cut, so a crash between them
    /// replays the old (already-incorporated) log on the new snapshot as no-ops. Assumes the lock is held.
    fn write_snapshot_and_reset_log(&self, refs: &Refs, st: &mut FileState) -> Result<()> {
        let bytes = refs.encode()?;
        self.vfs
            .atomic_write(&self.snapshot_path, &bytes)
            .map_err(|e| LoomError::CorruptNode {
                page: 0,
                detail: format!("cannot write {}: {e}", self.snapshot_path.display()),
            })?;
        if self.vfs.exists(&self.log_path) {
            self.vfs
                .truncate(&self.log_path, 0)
                .map_err(|e| LoomError::CorruptNode {
                    page: 0,
                    detail: format!("cannot truncate {}: {e}", self.log_path.display()),
                })?;
        }
        st.snapshot_bytes = bytes.len() as u64;
        st.log_bytes = 0;
        Ok(())
    }
}

impl RefStore for FileRefStore {
    fn load(&self) -> Result<Option<Refs>> {
        let _st = self.lock();
        self.reconstruct()
    }

    fn save(&self, refs: &Refs) -> Result<()> {
        let mut st = self.lock();
        self.write_snapshot_and_reset_log(refs, &mut st)
    }

    fn apply(&self, edits: &[RefEdit]) -> Result<()> {
        if edits.is_empty() {
            return Ok(());
        }
        let mut st = self.lock();

        // One append for the whole batch → one fsync per commit, not one per edit.
        let mut frame_bytes = Vec::new();
        for edit in edits {
            frame_bytes.extend_from_slice(&frame_encode(edit)?);
        }
        self.vfs
            .append(&self.log_path, &frame_bytes)
            .map_err(|e| LoomError::CorruptNode {
                page: 0,
                detail: format!("cannot append to {}: {e}", self.log_path.display()),
            })?;
        st.log_bytes += frame_bytes.len() as u64;

        // Compact once the log has outgrown the snapshot (past a floor), so recovery replay stays bounded
        // by ~one snapshot and write amplification stays ~2×. Reconstruct from our own durable state —
        // the store is the source of truth, it does not need the session's in-memory copy.
        if st.log_bytes > st.snapshot_bytes.max(self.compact_floor) {
            drop(st);
            let refs = self.reconstruct()?.unwrap_or_default();
            let mut st = self.lock();
            self.write_snapshot_and_reset_log(&refs, &mut st)?;
        }
        Ok(())
    }
}

/// Refs held only in memory. For `Loom::in_memory`, and for a store whose refs live elsewhere.
#[derive(Debug, Default)]
pub struct MemRefStore {
    refs: std::sync::Mutex<Option<Refs>>,
}

impl MemRefStore {
    /// A new, empty in-memory ref store.
    pub fn new() -> Self {
        MemRefStore::default()
    }
}

impl RefStore for MemRefStore {
    fn load(&self) -> Result<Option<Refs>> {
        Ok(self.refs.lock().unwrap_or_else(|e| e.into_inner()).clone())
    }

    fn save(&self, refs: &Refs) -> Result<()> {
        *self.refs.lock().unwrap_or_else(|e| e.into_inner()) = Some(refs.clone());
        Ok(())
    }

    fn apply(&self, edits: &[RefEdit]) -> Result<()> {
        let mut guard = self.refs.lock().unwrap_or_else(|e| e.into_inner());
        let refs = guard.get_or_insert_with(Refs::default);
        for edit in edits {
            refs.apply_edit(edit);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commit(n: u8) -> CommitId {
        CommitId::from_bytes([n; 32])
    }

    #[test]
    fn round_trips_through_bytes() -> Result<()> {
        let mut refs = Refs::rooted("main", commit(1));
        refs.branches.insert("h2".into(), commit(2));
        refs.tags.insert("v1.0".into(), commit(3));
        refs.commits.insert(commit(2), vec![commit(1), commit(9)]); // a merge: TWO parents

        let decoded = Refs::decode(&refs.encode()?)?;
        assert_eq!(decoded, refs);
        assert_eq!(
            decoded.commits[&commit(2)],
            vec![commit(1), commit(9)],
            "the merge's second parent must survive the round trip, or the double-counting bug \
             comes back the moment the process restarts"
        );
        Ok(())
    }

    #[test]
    fn roots_include_tags_as_well_as_branches() -> Result<()> {
        // GC's correctness depends on this being complete. A tag left out of roots() is a tagged
        // release that gets garbage collected.
        let mut refs = Refs::rooted("main", commit(1));
        refs.tags.insert("v1.0".into(), commit(7));

        let roots = refs.roots();
        assert!(roots.contains(&commit(1)));
        assert!(roots.contains(&commit(7)), "a tag is a GC root too");
        Ok(())
    }

    #[test]
    fn a_refs_file_from_the_future_is_refused_not_guessed_at() -> Result<()> {
        let mut refs = Refs::rooted("main", commit(1));
        refs.format_version = REFS_FORMAT_VERSION + 1;

        let err = Refs::decode(&refs.encode()?);
        assert!(
            err.is_err(),
            "refusing to open is recoverable; misreading a commit DAG is not"
        );
        assert!(err.unwrap_err().to_string().contains("Upgrade LoomDB"));
        Ok(())
    }

    #[test]
    fn a_file_ref_store_survives_being_dropped_and_reopened() -> Result<()> {
        let dir = tempfile::tempdir().expect("tempdir");

        {
            let store = FileRefStore::open(dir.path())?;
            assert_eq!(store.load()?, None, "a fresh database has no refs yet");

            let mut refs = Refs::rooted("main", commit(1));
            refs.branches.insert("h2".into(), commit(2));
            store.save(&refs)?;
        }

        // A different process, a different handle. The branch is still there.
        let store = FileRefStore::open(dir.path())?;
        let refs = store.load()?.expect("refs must survive");
        assert_eq!(refs.branches.get("h2"), Some(&commit(2)));
        Ok(())
    }

    #[test]
    fn saving_twice_replaces_rather_than_appends() -> Result<()> {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileRefStore::open(dir.path())?;

        store.save(&Refs::rooted("main", commit(1)))?;
        store.save(&Refs::rooted("main", commit(2)))?;

        assert_eq!(
            store.load()?.expect("refs").branches.get("main"),
            Some(&commit(2))
        );
        Ok(())
    }

    #[test]
    fn apply_edits_are_durable_and_replay_on_the_snapshot() -> Result<()> {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let store = FileRefStore::open(dir.path())?;
            store.save(&Refs::rooted("main", commit(1)))?; // snapshot: main@1
            store.apply(&[
                RefEdit::CreateBranch {
                    name: "h2".into(),
                    at: commit(1),
                },
                RefEdit::RecordCommit {
                    commit: commit(2),
                    parents: vec![commit(1)],
                },
                RefEdit::SetHead {
                    branch: "h2".into(),
                    to: commit(2),
                },
            ])?;
        }
        // A fresh handle (a restart): snapshot + replayed log.
        let store = FileRefStore::open(dir.path())?;
        let refs = store.load()?.expect("refs survive");
        assert_eq!(refs.branches.get("main"), Some(&commit(1)));
        assert_eq!(
            refs.branches.get("h2"),
            Some(&commit(2)),
            "the log replayed"
        );
        assert_eq!(refs.commits.get(&commit(2)), Some(&vec![commit(1)]));
        Ok(())
    }

    #[test]
    fn a_torn_trailing_frame_is_discarded_not_guessed_at() -> Result<()> {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileRefStore::open(dir.path())?;
        store.save(&Refs::rooted("main", commit(1)))?;
        store.apply(&[RefEdit::SetHead {
            branch: "main".into(),
            to: commit(2),
        }])?;

        // Simulate a crash mid-append: corrupt the tail of the log by appending a partial frame's worth
        // of bytes (a plausible length prefix, then not enough payload). Replay must stop at the last
        // WHOLE frame and keep main@2 — never invent a commit from a half-written record.
        let log = dir.path().join("loom").join(LOG_FILE);
        let mut bytes = std::fs::read(&log).expect("log exists");
        bytes.extend_from_slice(&1024u32.to_le_bytes()); // claims 1024 bytes...
        bytes.extend_from_slice(&[0u8; 4]); // ...but only 4 follow
        std::fs::write(&log, &bytes).expect("write torn log");

        let refs = FileRefStore::open(dir.path())?.load()?.expect("refs");
        assert_eq!(
            refs.branches.get("main"),
            Some(&commit(2)),
            "the last whole frame survived; the torn tail was discarded"
        );
        Ok(())
    }

    #[test]
    fn compaction_is_transparent_and_keeps_the_log_bounded() -> Result<()> {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileRefStore::open(dir.path())?;
        store.save(&Refs::rooted("main", commit(1)))?;

        // Blow past the compaction floor several times over. Moving ONE branch's head repeatedly keeps
        // the reconstructed refs tiny, so if compaction did not truncate the log it would grow without
        // bound; if it does, load stays correct and the file stays small. Applied in a few large batches
        // (one fsync each) rather than 20k single appends, so the test is fast — the log-size math is the
        // same either way.
        let mut last = 0u32;
        for batch in 0..4u32 {
            let edits: Vec<RefEdit> = (0..6_000u32)
                .map(|j| {
                    last = batch * 6_000 + j;
                    RefEdit::SetHead {
                        branch: "main".into(),
                        to: CommitId::from_bytes([(last % 251) as u8; 32]),
                    }
                })
                .collect();
            store.apply(&edits)?;
        }
        let final_head = CommitId::from_bytes([(last % 251) as u8; 32]);

        let log_len = std::fs::metadata(dir.path().join("loom").join(LOG_FILE))
            .map(|m| m.len())
            .unwrap_or(0);
        assert!(
            log_len <= COMPACT_FLOOR_BYTES,
            "compaction should keep the log within the floor, but it is {log_len} bytes"
        );
        assert_eq!(
            FileRefStore::open(dir.path())?
                .load()?
                .expect("refs")
                .branches
                .get("main"),
            Some(&final_head),
            "compaction preserved the latest head exactly"
        );
        Ok(())
    }

    #[test]
    fn a_legacy_refs_bin_is_read_so_an_upgraded_database_is_not_empty() -> Result<()> {
        let dir = tempfile::tempdir().expect("tempdir");
        // Write a pre-Phase-2 database: a single `loom/refs.bin`, no snapshot, no log.
        let loom = dir.path().join("loom");
        std::fs::create_dir_all(&loom).expect("mkdir");
        let mut legacy = Refs::rooted("main", commit(1));
        legacy.branches.insert("h2".into(), commit(2));
        std::fs::write(loom.join(LEGACY_REFS_FILE), legacy.encode()?).expect("write legacy");

        let store = FileRefStore::open(dir.path())?;
        let refs = store.load()?.expect("legacy refs are read, not ignored");
        assert_eq!(refs.branches.get("h2"), Some(&commit(2)));
        Ok(())
    }
}
