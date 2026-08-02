//! **Recovery exercises.** Take a backup while the database is being written to, lose the database,
//! and get it back — measuring what that cost.
//!
//! # What this crate does, and what it refuses to do
//!
//! It drives the *real* mechanisms rather than reimplementing them: `Loom::backup_to_signed` takes
//! the backup, `loom-keys` decides which trust root may verify it, `restore_signed_backup` puts it
//! somewhere new, and `Loom::open_production_attested` opens the result. If any of those changes,
//! the drill changes with it or fails — which is the point of a drill that is code rather than a
//! runbook.
//!
//! It does **not** simulate anything it cannot do. The point-in-time clone is made by copying the
//! store directory, because that is what a developer machine can honestly provide, and the receipt
//! records the topology as `local-filesystem-copy-clone` along with the list of things that topology
//! does not exercise. A CSI driver, a storage array, a backup product, and an object-lock target are
//! all absent, and the receipt says so rather than leaving a reader to assume otherwise.
//!
//! # The shape of a drill
//!
//! ```text
//!   seed ──► clone ──────────────────────────► FAILURE
//!             │         (writes continue)          │
//!             ▼                                    │
//!          backup-signed                           │  recovery point = failure - clone
//!             │                                    │
//!             ▼                                    ▼
//!          verify (separate trust domain) ──► restore to a NEW path ──► attested reopen
//!                                                                       │
//!                                            recovery time ─────────────┘
//! ```
//!
//! The clone is taken *before* the last writes, so the recovery point is a real measured gap and not
//! a zero that proves nothing. Everything after the clone is work the restore is expected to have
//! lost, and the known-answer checks assert exactly that boundary: what was written before the clone
//! must come back, and what was written after it must not.

#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![warn(rust_2018_idioms)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod incident;
pub mod receipt;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use loom_branch::{BackupManifest, Loom, BACKUP_MANIFEST_FILE, BACKUP_SIGNATURE_FILE};
use loom_core::TenantId;
use loom_keys::{KeyDirectory, KeyRole};

pub use receipt::{
    human_bytes, human_duration, BackupConsumed, DrillReceipt, FaultOutcome, KnownAnswer, Measured,
    Topology, RECEIPT_SCHEMA_VERSION, RPO_TARGET_SECONDS, RTO_TARGET_SECONDS,
};

/// The largest `Message` AWS KMS `Sign` accepts, in bytes.
///
/// Pure Ed25519 (`ED25519_SHA_512`) requires `MessageType: RAW`, so a signing payload above this
/// cannot go through KMS unmodified. Recorded per backup rather than assumed — see
/// `docs/key-custody.md` §5.
pub const KMS_RAW_SIGN_LIMIT_BYTES: u64 = 4096;

/// Anything a drill step can refuse to do.
#[derive(Debug)]
pub struct DrillError(pub String);

impl std::fmt::Display for DrillError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for DrillError {}

/// This crate's result type.
pub type Result<T> = std::result::Result<T, DrillError>;

fn fail(detail: impl Into<String>) -> DrillError {
    DrillError(detail.into())
}

/// Unix seconds now.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// **Take the point-in-time clone the backup will be read from.**
///
/// `loomd` holds an exclusive advisory lock on a store it is serving, so a backup cannot read the
/// live volume — that constraint is what the whole P7 scheduling design is built around. In
/// production the platform provides the clone (a CSI volume snapshot, a storage-array clone, a
/// filesystem snapshot). Here it is a directory copy, and the topology records that.
///
/// The `store.lock` file is deliberately copied like any other file and then ignored: a clone of a
/// live volume contains whatever was on disk, including a lock file nobody holds, and the restore
/// path has to cope with that rather than being handed a tidied-up input.
pub fn take_clone(live: &Path, clone: &Path) -> Result<u64> {
    if clone.exists() {
        return Err(fail(format!(
            "clone destination {} already exists; a clone is taken fresh so it cannot silently \
             carry a previous run's bytes",
            clone.display()
        )));
    }
    copy_tree(live, clone)?;
    Ok(now_unix())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<u64> {
    std::fs::create_dir_all(destination)
        .map_err(|error| fail(format!("cannot create {}: {error}", destination.display())))?;
    let mut bytes = 0;
    let entries = std::fs::read_dir(source)
        .map_err(|error| fail(format!("cannot list {}: {error}", source.display())))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| fail(format!("cannot list {}: {error}", source.display())))?;
        let from = entry.path();
        let to = destination.join(entry.file_name());
        let metadata = std::fs::symlink_metadata(&from)
            .map_err(|error| fail(format!("cannot inspect {}: {error}", from.display())))?;
        if metadata.is_dir() {
            bytes += copy_tree(&from, &to)?;
        } else if metadata.is_file() {
            bytes += std::fs::copy(&from, &to)
                .map_err(|error| fail(format!("cannot copy {}: {error}", from.display())))?;
        }
    }
    Ok(bytes)
}

/// Total bytes under a directory tree.
pub fn tree_bytes(root: &Path) -> Result<u64> {
    let mut bytes = 0;
    let entries = std::fs::read_dir(root)
        .map_err(|error| fail(format!("cannot list {}: {error}", root.display())))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| fail(format!("cannot list {}: {error}", root.display())))?;
        let metadata = std::fs::symlink_metadata(entry.path())
            .map_err(|error| fail(format!("cannot inspect {:?}: {error}", entry.path())))?;
        if metadata.is_dir() {
            bytes += tree_bytes(&entry.path())?;
        } else if metadata.is_file() {
            bytes += metadata.len();
        }
    }
    Ok(bytes)
}

/// **Verify a backup the way the independent verifier job does.**
///
/// Through trust-root custody, so the key id, role, and algorithm are all bound — and a revoked key
/// is refused by name rather than passing a check it would mathematically pass. The caller supplies
/// a directory built from the *verifier's* register, which in the reference deployment is a
/// different mount held by a different identity than the writer's signing key.
pub fn verify_from_separate_trust_domain(
    backup: &Path,
    verifier: &KeyDirectory,
) -> Result<(BackupManifest, String)> {
    if verifier.role() != KeyRole::BackupRoot {
        return Err(fail(format!(
            "the verifier directory speaks for the {} role, not backup-root",
            verifier.role()
        )));
    }
    loom_branch::verify_signed_backup_with(backup, verifier).map_err(|error| {
        fail(format!(
            "independent verification refused the backup: {error}"
        ))
    })
}

/// What the signature over this backup's manifest actually covers, in bytes.
///
/// The payload is the domain separator, the key id, and the whole manifest, so it grows with the
/// store. Measured rather than assumed, because it decides whether this role can be signed by AWS
/// KMS unmodified (`Sign` takes at most 4096 bytes and pure Ed25519 needs `MessageType: RAW`).
pub fn signed_payload_bytes(backup: &Path) -> Result<u64> {
    let manifest = std::fs::read(backup.join(BACKUP_MANIFEST_FILE))
        .map_err(|error| fail(format!("cannot read the backup manifest: {error}")))?;
    let record = std::fs::read_to_string(backup.join(BACKUP_SIGNATURE_FILE))
        .map_err(|error| fail(format!("cannot read the signature record: {error}")))?;
    let record: serde_json::Value = serde_json::from_str(&record)
        .map_err(|error| fail(format!("the signature record is not JSON: {error}")))?;
    let key_id = record["key_id"]
        .as_str()
        .ok_or_else(|| fail("the signature record has no key_id"))?;
    // domain separator + key id + one separator byte + the manifest bytes (backup.rs).
    const SIGNATURE_DOMAIN_BYTES: u64 = 36;
    Ok(SIGNATURE_DOMAIN_BYTES + key_id.len() as u64 + 1 + manifest.len() as u64)
}

/// The manifest digest a signature record commits to.
pub fn manifest_blake3(backup: &Path) -> Result<String> {
    let record = std::fs::read_to_string(backup.join(BACKUP_SIGNATURE_FILE))
        .map_err(|error| fail(format!("cannot read the signature record: {error}")))?;
    let record: serde_json::Value = serde_json::from_str(&record)
        .map_err(|error| fail(format!("the signature record is not JSON: {error}")))?;
    record["manifest_blake3"]
        .as_str()
        .map(ToString::to_string)
        .ok_or_else(|| fail("the signature record has no manifest_blake3"))
}

/// **Restore to a new path, and refuse to go anywhere near a live store.**
///
/// `restore_signed_backup` already refuses an existing destination, so a restore cannot overwrite.
/// This adds the check that belongs to a *drill*: the destination must not be, or sit inside, any
/// store this drill knows to be live. A rehearsal that lands on production is the failure a
/// rehearsal exists to avoid.
pub fn restore_beside_production(
    backup: &Path,
    destination: &Path,
    live_stores: &[&Path],
    expected_tenant: &str,
    verifier: &KeyDirectory,
) -> Result<BackupManifest> {
    for live in live_stores {
        if destination == *live || destination.starts_with(live) {
            return Err(fail(format!(
                "refusing to restore into {}: it is, or is inside, the live store {}. A drill \
                 restores beside production, never onto it",
                destination.display(),
                live.display()
            )));
        }
    }
    let (manifest, key_id) = verify_from_separate_trust_domain(backup, verifier)?;
    if manifest.tenant != expected_tenant {
        return Err(fail(format!(
            "backup belongs to tenant {:?}, not the expected {expected_tenant:?}; refusing restore",
            manifest.tenant
        )));
    }
    let _ = key_id;
    loom_branch::restore_signed_backup(
        backup,
        destination,
        &signature_key_id(backup)?,
        &verifier
            .resolve(&signature_key_id(backup)?)
            .map_err(|error| fail(error.to_string()))?
            .verifying_key()
            .map_err(|error| fail(error.to_string()))?,
    )
    .map_err(|error| fail(format!("restore refused: {error}")))
}

fn signature_key_id(backup: &Path) -> Result<String> {
    let record = std::fs::read_to_string(backup.join(BACKUP_SIGNATURE_FILE))
        .map_err(|error| fail(format!("cannot read the signature record: {error}")))?;
    let record: serde_json::Value = serde_json::from_str(&record)
        .map_err(|error| fail(format!("the signature record is not JSON: {error}")))?;
    record["key_id"]
        .as_str()
        .map(ToString::to_string)
        .ok_or_else(|| fail("the signature record has no key_id"))
}

/// The branch heads of a store, for the receipt and for known-answer comparison.
pub fn heads(store: &Loom) -> Result<BTreeMap<String, String>> {
    let mut heads = BTreeMap::new();
    for name in store.branch_names() {
        let head = store
            .head(&loom_core::BranchId::new(&name))
            .map_err(|error| fail(format!("cannot read head of {name}: {error}")))?;
        heads.insert(name, head.to_string());
    }
    Ok(heads)
}

/// Materialize a directory path, for callers assembling a drill.
pub fn ensure_dir(path: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(path)
        .map_err(|error| fail(format!("cannot create {}: {error}", path.display())))?;
    Ok(path.to_path_buf())
}

/// Open a restored store through the attested constructor, exactly as the daemon would.
///
/// This is the step that proves a restored store is *servable*, not merely present: the governance
/// signature, the tenant binding, the rollback floor, and the registry fingerprint are all checked
/// before any store file is opened.
#[allow(clippy::too_many_arguments)]
pub fn open_restored_attested(
    path: &Path,
    tenant: &str,
    actors: Vec<(loom_core::ActorId, ed25519_dalek::VerifyingKey)>,
    attestation: &loom_branch::ActorRegistryAttestation,
    governance: &KeyDirectory,
    minimum_generation: u64,
) -> Result<Loom> {
    let trusted = governance
        .verify_any(&attestation.signed_bytes(), attestation.signature())
        .map_err(|error| {
            fail(format!(
                "the restored store's actor registry attestation is not signed by a trusted \
                 governance key: {error}"
            ))
        })?;
    let governance_key = trusted
        .verifying_key()
        .map_err(|error| fail(error.to_string()))?;
    Loom::open_production_attested(
        path,
        TenantId::new(tenant),
        actors,
        attestation,
        &governance_key,
        minimum_generation,
    )
    .map_err(|error| fail(format!("the restored store did not open attested: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clone_refuses_an_existing_destination(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let live = dir.path().join("live");
        let clone = dir.path().join("clone");
        std::fs::create_dir_all(&live)?;
        std::fs::create_dir_all(&clone)?;
        let error = take_clone(&live, &clone).expect_err("must refuse");
        assert!(format!("{error}").contains("already exists"), "{error}");
        Ok(())
    }

    #[test]
    fn a_clone_copies_the_whole_tree() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let live = dir.path().join("live");
        std::fs::create_dir_all(live.join("loom"))?;
        std::fs::write(live.join("loom").join("a"), b"hello")?;
        std::fs::write(live.join("b"), b"world!")?;
        let clone = dir.path().join("clone");
        take_clone(&live, &clone)?;
        assert_eq!(std::fs::read(clone.join("loom").join("a"))?, b"hello");
        assert_eq!(tree_bytes(&clone)?, 11);
        Ok(())
    }
}
