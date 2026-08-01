//! The operational receipt written beside a backup.
//!
//! # Why beside, and never inside
//!
//! `verify_backup` refuses a backup directory that contains a file the signed manifest does not
//! allow-list — that strictness is the point of the allow-list. So a receipt cannot live inside the
//! backup without either breaking verification or being smuggled into the signed set. It is written
//! as a sibling, `<backup>.receipt.json`.
//!
//! # What a receipt is, and what it is emphatically not
//!
//! It is an **operational record**: when this backup was taken, how long it took, how much it
//! covered, and which trust-root key id signed it. It is what lets verification, later and from
//! another trust domain, report a *recovery point* rather than merely "something verified".
//!
//! It is **not** an authenticity claim, and it is deliberately unsigned. The authenticity check is
//! and remains the loomDB trust-root Ed25519 signature over the exact manifest bytes. A receipt an
//! attacker rewrote changes a number on a dashboard; it cannot make a tampered backup verify. This
//! is the same rule the deployment applies to a storage vendor's checksum: it may coexist, it never
//! substitutes.

use std::path::{Path, PathBuf};

/// Where the receipt for `backup` lives.
pub fn path_for(backup: &Path) -> PathBuf {
    let mut name = backup.file_name().unwrap_or_default().to_os_string();
    name.push(".receipt.json");
    backup.with_file_name(name)
}

/// An operational record of one signed backup.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BackupReceipt {
    /// Receipt format version.
    pub schema_version: u32,
    /// The tenant the backup belongs to, copied from the signed manifest.
    pub tenant: String,
    /// The operator-selected trust-root id bound into the signature.
    pub key_id: String,
    /// BLAKE3 of the exact signed manifest bytes, for correlating a receipt with a backup.
    pub manifest_blake3: String,
    /// When the backup completed, in Unix seconds. This is the recovery point.
    pub created_unix: u64,
    /// How long the backup took.
    pub duration_seconds: f64,
    /// Bytes covered by the manifest allow-list.
    pub bytes: u64,
    /// Files covered by the manifest allow-list.
    pub files: u64,
}

impl BackupReceipt {
    /// Current receipt format version.
    pub const SCHEMA_VERSION: u32 = 1;

    /// Write the receipt beside `backup`, atomically.
    pub fn write_beside(&self, backup: &Path) -> Result<PathBuf, String> {
        let target = path_for(backup);
        let partial = target.with_extension("partial");
        let body = serde_json::to_vec_pretty(self)
            .map_err(|error| format!("cannot encode the backup receipt: {error}"))?;
        std::fs::write(&partial, &body)
            .map_err(|error| format!("cannot write {}: {error}", partial.display()))?;
        std::fs::rename(&partial, &target)
            .map_err(|error| format!("cannot publish {}: {error}", target.display()))?;
        Ok(target)
    }

    /// Read the receipt beside `backup`, if there is one.
    ///
    /// A missing receipt is **not** an error. It means the recovery point is unknown to us, and the
    /// caller reports it as unknown rather than inventing one — a backup taken by an older revision,
    /// or copied without its sibling, is still a backup whose signature verifies.
    pub fn read_beside(backup: &Path) -> Result<Option<Self>, String> {
        let target = path_for(backup);
        let bytes = match std::fs::read(&target) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("cannot read {}: {error}", target.display())),
        };
        let receipt: BackupReceipt = serde_json::from_slice(&bytes).map_err(|error| {
            format!(
                "{} is not a valid backup receipt: {error}",
                target.display()
            )
        })?;
        if receipt.schema_version != Self::SCHEMA_VERSION {
            return Err(format!(
                "{} has receipt schemaVersion {}, expected {}",
                target.display(),
                receipt.schema_version,
                Self::SCHEMA_VERSION
            ));
        }
        Ok(Some(receipt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> BackupReceipt {
        BackupReceipt {
            schema_version: BackupReceipt::SCHEMA_VERSION,
            tenant: "acme".into(),
            key_id: "backup-root-2026-q3".into(),
            manifest_blake3: "abc123".into(),
            created_unix: 1_750_000_000,
            duration_seconds: 1.5,
            bytes: 4096,
            files: 7,
        }
    }

    #[test]
    fn the_receipt_is_a_sibling_never_a_member_of_the_backup() {
        let backup = Path::new("/backups/acme-2026-07-29");
        assert_eq!(
            path_for(backup),
            Path::new("/backups/acme-2026-07-29.receipt.json")
        );
    }

    #[test]
    fn a_receipt_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let backup = dir.path().join("acme-2026-07-29");
        std::fs::create_dir(&backup)?;
        sample().write_beside(&backup)?;
        assert_eq!(BackupReceipt::read_beside(&backup)?, Some(sample()));
        Ok(())
    }

    #[test]
    fn a_missing_receipt_is_an_unknown_recovery_point_not_an_error(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let backup = dir.path().join("never-receipted");
        std::fs::create_dir(&backup)?;
        assert_eq!(BackupReceipt::read_beside(&backup)?, None);
        Ok(())
    }

    #[test]
    fn a_receipt_from_another_format_version_is_refused() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = tempfile::tempdir()?;
        let backup = dir.path().join("acme");
        std::fs::create_dir(&backup)?;
        let mut receipt = sample();
        receipt.schema_version = 99;
        receipt.write_beside(&backup)?;
        assert!(BackupReceipt::read_beside(&backup).is_err());
        Ok(())
    }
}
