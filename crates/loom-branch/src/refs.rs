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
//! 2. refs → durable                (atomic_write: temp → fsync → rename → fsync dir)
//! ```
//!
//! A crash **between** them leaves the refs pointing at the *old* head, and the new manifest
//! unreferenced — garbage, which GC sweeps. That is a **lost commit**, and it is the failure we
//! choose: the alternative ordering would leave a ref pointing at a manifest that does not exist,
//! which is a **corrupt database**. Losing the last transaction is recoverable. Dangling into the
//! void is not.
//!
//! This is the same discipline as substrate's commit protocol (docs/02 §3.1), for the same reason.

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
}

/// Where refs are persisted.
///
/// Two implementations: a local file, and — for a database that has been put to sleep in object
/// storage — nowhere at all, because the refs travel with the data (see `Loom::sleep`).
pub trait RefStore: Send + Sync + std::fmt::Debug {
    /// Read the refs. `None` if this is a brand-new database.
    fn load(&self) -> Result<Option<Refs>>;

    /// Write the refs, **atomically**. Either the whole file is there, or the old one is.
    ///
    /// A half-written refs file is a database whose branches point at nothing, so this must never
    /// produce one — hence `atomic_write` (temp → fsync → rename → fsync the directory), and not a
    /// truncate-and-write.
    fn save(&self, refs: &Refs) -> Result<()>;
}

/// Refs in a file on disk.
#[derive(Debug)]
pub struct FileRefStore {
    vfs: Arc<dyn Vfs>,
    path: PathBuf,
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
        Ok(FileRefStore {
            vfs,
            path: dir.join("refs.bin"),
        })
    }

    /// Where the refs file lives.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl RefStore for FileRefStore {
    fn load(&self) -> Result<Option<Refs>> {
        if !self.vfs.exists(&self.path) {
            return Ok(None);
        }
        let bytes = self
            .vfs
            .read(&self.path)
            .map_err(|e| LoomError::CorruptNode {
                page: 0,
                detail: format!("cannot read {}: {e}", self.path.display()),
            })?;
        Ok(Some(Refs::decode(&bytes)?))
    }

    fn save(&self, refs: &Refs) -> Result<()> {
        self.vfs
            .atomic_write(&self.path, &refs.encode()?)
            .map_err(|e| LoomError::CorruptNode {
                page: 0,
                detail: format!("cannot write {}: {e}", self.path.display()),
            })
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
}
