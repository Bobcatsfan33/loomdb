//! Consistent, content-verified backups for file-backed LoomDB stores.
//!
//! A backup is a directory containing the database files plus [`BACKUP_MANIFEST_FILE`]. The manifest
//! is an allow-list: every file has a byte length and BLAKE3 digest, extra files are refused, symlinks
//! are refused, and restore publishes through an atomic directory rename. [`Loom::backup_to`] holds
//! the database mutation lock while this module copies the files, so the refs and content-addressed
//! pages describe one committed prefix.

use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Current on-disk backup manifest version.
pub const BACKUP_FORMAT_VERSION: u32 = 1;
/// Manifest stored at the root of every completed backup.
pub const BACKUP_MANIFEST_FILE: &str = "loom-backup-manifest.json";

const PROCESS_LOCK_RELATIVE: &str = "loom/store.lock";
const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
const MAX_BACKUP_FILES: usize = 1_000_000;
static PARTIAL_NONCE: AtomicU64 = AtomicU64::new(0);

/// One file covered by a backup manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupFile {
    /// Slash-separated path relative to the database root.
    pub path: String,
    /// Exact file length.
    pub bytes: u64,
    /// Lowercase BLAKE3 digest of the complete file.
    pub blake3: String,
}

/// Allow-list and integrity metadata for one LoomDB backup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupManifest {
    /// Backup format version.
    pub format_version: u32,
    /// Tenant identifier without its display prefix.
    pub tenant: String,
    /// Files in lexicographic relative-path order.
    pub files: Vec<BackupFile>,
}

/// Backup or restore refusal with an operator-actionable reason.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BackupError {
    /// A filesystem operation failed.
    #[error("backup {operation} failed for {path}: {source}")]
    Io {
        /// Operation being attempted.
        operation: &'static str,
        /// Affected path.
        path: String,
        /// Underlying filesystem error.
        #[source]
        source: std::io::Error,
    },
    /// The backup manifest is not valid JSON.
    #[error("backup manifest cannot be decoded: {0}")]
    ManifestDecode(#[from] serde_json::Error),
    /// The backup is incomplete, altered, unsafe, or from an unsupported format.
    #[error("backup integrity check failed: {0}")]
    Integrity(String),
    /// This storage composition has no safe online snapshot boundary.
    #[error("backup is unsupported: {0}")]
    Unsupported(String),
    /// Refuse to overwrite any existing destination.
    #[error("backup destination already exists: {0}")]
    DestinationExists(String),
    /// The engine could not flush its durable refs before the backup.
    #[error("backup could not establish a committed prefix: {0}")]
    Engine(String),
}

fn io(operation: &'static str, path: &Path, source: std::io::Error) -> BackupError {
    BackupError::Io {
        operation,
        path: path.display().to_string(),
        source,
    }
}

fn relative_string(root: &Path, path: &Path) -> Result<String, BackupError> {
    let relative = path.strip_prefix(root).map_err(|_| {
        BackupError::Integrity(format!(
            "{} is outside backup root {}",
            path.display(),
            root.display()
        ))
    })?;
    let value = relative.to_str().ok_or_else(|| {
        BackupError::Unsupported(format!(
            "path {} is not valid UTF-8 and cannot be represented portably",
            relative.display()
        ))
    })?;
    Ok(value.replace('\\', "/"))
}

fn checked_relative(value: &str) -> Result<PathBuf, BackupError> {
    if value.is_empty() || value.contains('\\') {
        return Err(BackupError::Integrity(format!(
            "manifest path {value:?} is not a portable relative path"
        )));
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(BackupError::Integrity(format!(
            "manifest path {value:?} escapes the backup root"
        )));
    }
    Ok(path.to_path_buf())
}

fn walk_files(
    root: &Path,
    directory: &Path,
    exclude_manifest: bool,
    exclude_process_lock: bool,
    output: &mut Vec<PathBuf>,
) -> Result<(), BackupError> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| io("read directory", directory, error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io("read directory entry", directory, error))?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| io("stat", &path, error))?;
        if metadata.file_type().is_symlink() {
            return Err(BackupError::Integrity(format!(
                "symlinks are forbidden in a backup boundary: {}",
                path.display()
            )));
        }
        if metadata.is_dir() {
            walk_files(root, &path, exclude_manifest, exclude_process_lock, output)?;
        } else if metadata.is_file() {
            let relative = relative_string(root, &path)?;
            if (exclude_manifest && relative == BACKUP_MANIFEST_FILE)
                || (exclude_process_lock && relative == PROCESS_LOCK_RELATIVE)
            {
                continue;
            }
            output.push(path);
            if output.len() > MAX_BACKUP_FILES {
                return Err(BackupError::Integrity(format!(
                    "backup contains more than {MAX_BACKUP_FILES} files"
                )));
            }
        } else {
            return Err(BackupError::Integrity(format!(
                "only regular files and directories are allowed: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn copy_hashed(source: &Path, destination: &Path) -> Result<BackupFile, BackupError> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|error| io("create directory", parent, error))?;
    }
    let mut input = File::open(source).map_err(|error| io("open source", source, error))?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .map_err(|error| io("create destination", destination, error))?;
    let mut hasher = blake3::Hasher::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|error| io("read source", source, error))?;
        if read == 0 {
            break;
        }
        output
            .write_all(&buffer[..read])
            .map_err(|error| io("write destination", destination, error))?;
        hasher.update(&buffer[..read]);
        bytes = bytes.checked_add(read as u64).ok_or_else(|| {
            BackupError::Integrity(format!("file length overflows u64: {}", source.display()))
        })?;
    }
    output
        .sync_all()
        .map_err(|error| io("sync destination", destination, error))?;
    let permissions = fs::metadata(source)
        .map_err(|error| io("stat source", source, error))?
        .permissions();
    fs::set_permissions(destination, permissions)
        .map_err(|error| io("set permissions", destination, error))?;
    Ok(BackupFile {
        path: String::new(),
        bytes,
        blake3: hasher.finalize().to_hex().to_string(),
    })
}

fn partial_path(destination: &Path) -> Result<PathBuf, BackupError> {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(BackupError::Unsupported(format!(
            "destination parent does not exist: {}",
            parent.display()
        )));
    }
    let name = destination
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            BackupError::Unsupported(format!(
                "destination {} has no portable file name",
                destination.display()
            ))
        })?;
    let nonce = PARTIAL_NONCE.fetch_add(1, Ordering::Relaxed);
    Ok(parent.join(format!(".{name}.partial-{}-{nonce}", std::process::id())))
}

fn reject_nested_destination(source: &Path, destination: &Path) -> Result<(), BackupError> {
    let source =
        fs::canonicalize(source).map_err(|error| io("canonicalize source", source, error))?;
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent)
        .map_err(|error| io("canonicalize destination parent", parent, error))?;
    if parent.starts_with(&source) {
        return Err(BackupError::Unsupported(format!(
            "destination {} is inside source {}; choose a separate backup volume",
            destination.display(),
            source.display()
        )));
    }
    Ok(())
}

fn write_manifest(root: &Path, manifest: &BackupManifest) -> Result<(), BackupError> {
    let path = root.join(BACKUP_MANIFEST_FILE);
    let mut bytes = serde_json::to_vec_pretty(manifest)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .map_err(|error| io("create manifest", &path, error))?;
    file.write_all(&bytes)
        .map_err(|error| io("write manifest", &path, error))?;
    file.sync_all()
        .map_err(|error| io("sync manifest", &path, error))
}

fn publish_partial(partial: &Path, destination: &Path) -> Result<(), BackupError> {
    File::open(partial)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io("sync backup directory", partial, error))?;
    fs::rename(partial, destination).map_err(|error| io("publish backup", destination, error))?;
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io("sync destination parent", parent, error))
}

pub(crate) fn create_backup(
    source: &Path,
    destination: &Path,
    tenant: &str,
) -> Result<BackupManifest, BackupError> {
    if destination.exists() {
        return Err(BackupError::DestinationExists(
            destination.display().to_string(),
        ));
    }
    reject_nested_destination(source, destination)?;
    let partial = partial_path(destination)?;
    fs::create_dir(&partial).map_err(|error| io("create partial backup", &partial, error))?;

    let result = (|| {
        let mut source_files = Vec::new();
        walk_files(source, source, true, true, &mut source_files)?;
        let mut files = Vec::with_capacity(source_files.len());
        for source_file in source_files {
            let relative = relative_string(source, &source_file)?;
            let target = partial.join(checked_relative(&relative)?);
            let mut record = copy_hashed(&source_file, &target)?;
            record.path = relative;
            files.push(record);
        }
        files.sort_by(|left, right| left.path.cmp(&right.path));
        let manifest = BackupManifest {
            format_version: BACKUP_FORMAT_VERSION,
            tenant: tenant.to_string(),
            files,
        };
        write_manifest(&partial, &manifest)?;
        publish_partial(&partial, destination)?;
        Ok(manifest)
    })();

    if result.is_err() && partial.exists() {
        let _ = fs::remove_dir_all(&partial);
    }
    result
}

fn load_manifest(root: &Path) -> Result<BackupManifest, BackupError> {
    let path = root.join(BACKUP_MANIFEST_FILE);
    let metadata =
        fs::symlink_metadata(&path).map_err(|error| io("stat manifest", &path, error))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(BackupError::Integrity(
            "backup manifest must be a regular file".into(),
        ));
    }
    if metadata.len() > MAX_MANIFEST_BYTES {
        return Err(BackupError::Integrity(format!(
            "backup manifest is {} bytes, over the {MAX_MANIFEST_BYTES}-byte cap",
            metadata.len()
        )));
    }
    let bytes = fs::read(&path).map_err(|error| io("read manifest", &path, error))?;
    let manifest: BackupManifest = serde_json::from_slice(&bytes)?;
    if manifest.format_version != BACKUP_FORMAT_VERSION {
        return Err(BackupError::Integrity(format!(
            "backup format {} is unsupported; this build accepts {}",
            manifest.format_version, BACKUP_FORMAT_VERSION
        )));
    }
    if manifest.tenant.is_empty() {
        return Err(BackupError::Integrity(
            "backup manifest has an empty tenant identifier".into(),
        ));
    }
    if manifest.files.len() > MAX_BACKUP_FILES {
        return Err(BackupError::Integrity(format!(
            "backup manifest declares more than {MAX_BACKUP_FILES} files"
        )));
    }
    Ok(manifest)
}

fn hash_file(path: &Path) -> Result<(u64, String), BackupError> {
    let mut file = File::open(path).map_err(|error| io("open backup file", path, error))?;
    let mut hasher = blake3::Hasher::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| io("read backup file", path, error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        bytes = bytes.checked_add(read as u64).ok_or_else(|| {
            BackupError::Integrity(format!("file length overflows u64: {}", path.display()))
        })?;
    }
    Ok((bytes, hasher.finalize().to_hex().to_string()))
}

/// Verify a completed backup without modifying it.
///
/// Verification refuses missing, additional, altered, non-regular, or symlinked files before a
/// restore can publish them.
pub fn verify_backup(root: impl AsRef<Path>) -> Result<BackupManifest, BackupError> {
    let root = root.as_ref();
    let manifest = load_manifest(root)?;
    let mut declared_paths = std::collections::BTreeSet::new();
    for record in &manifest.files {
        checked_relative(&record.path)?;
        if !declared_paths.insert(record.path.clone()) {
            return Err(BackupError::Integrity(format!(
                "manifest declares {} more than once",
                record.path
            )));
        }
    }

    let mut actual_files = Vec::new();
    walk_files(root, root, true, false, &mut actual_files)?;
    let actual_paths = actual_files
        .iter()
        .map(|path| relative_string(root, path))
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    if actual_paths != declared_paths {
        let missing = declared_paths
            .difference(&actual_paths)
            .cloned()
            .collect::<Vec<_>>();
        let extra = actual_paths
            .difference(&declared_paths)
            .cloned()
            .collect::<Vec<_>>();
        return Err(BackupError::Integrity(format!(
            "manifest/file-set mismatch; missing={missing:?}, extra={extra:?}"
        )));
    }

    for record in &manifest.files {
        let path = root.join(checked_relative(&record.path)?);
        let metadata =
            fs::symlink_metadata(&path).map_err(|error| io("stat backup file", &path, error))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(BackupError::Integrity(format!(
                "{} is not a regular file",
                record.path
            )));
        }
        let (bytes, digest) = hash_file(&path)?;
        if bytes != record.bytes || digest != record.blake3 {
            return Err(BackupError::Integrity(format!(
                "{} changed: expected {} bytes / {}, found {} bytes / {}",
                record.path, record.bytes, record.blake3, bytes, digest
            )));
        }
    }
    Ok(manifest)
}

/// Restore a verified backup into a new, empty destination.
///
/// The destination is never overwritten. Files are copied into a private sibling directory and the
/// complete restore is made visible with one rename only after every source digest has been checked.
/// The returned manifest lets the caller compare the tenant before opening the restored database with
/// [`crate::Loom::open_production`] or another production constructor.
pub fn restore_backup(
    backup: impl AsRef<Path>,
    destination: impl AsRef<Path>,
) -> Result<BackupManifest, BackupError> {
    let backup = backup.as_ref();
    let destination = destination.as_ref();
    if destination.exists() {
        return Err(BackupError::DestinationExists(
            destination.display().to_string(),
        ));
    }
    reject_nested_destination(backup, destination)?;
    let manifest = verify_backup(backup)?;
    let partial = partial_path(destination)?;
    fs::create_dir(&partial).map_err(|error| io("create partial restore", &partial, error))?;

    let result = (|| {
        for record in &manifest.files {
            let relative = checked_relative(&record.path)?;
            let source = backup.join(&relative);
            let target = partial.join(&relative);
            let copied = copy_hashed(&source, &target)?;
            if copied.bytes != record.bytes || copied.blake3 != record.blake3 {
                return Err(BackupError::Integrity(format!(
                    "{} changed while restore was copying it",
                    record.path
                )));
            }
        }
        publish_partial(&partial, destination)?;
        Ok(manifest)
    })();

    if result.is_err() && partial.exists() {
        let _ = fs::remove_dir_all(&partial);
    }
    result
}
