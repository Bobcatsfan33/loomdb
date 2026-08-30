//! Consistent, content-verified backups for file-backed LoomDB stores.
//!
//! A backup is a directory containing the database files plus [`BACKUP_MANIFEST_FILE`]. The manifest
//! is an allow-list: every file has a byte length and BLAKE3 digest, extra files are refused, symlinks
//! are refused, and restore publishes through an atomic directory rename. [`Loom::backup_to`] holds
//! the database mutation lock while this module copies the files, so the refs and content-addressed
//! pages describe one committed prefix.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Current on-disk backup manifest version.
pub const BACKUP_FORMAT_VERSION: u32 = 1;
/// Manifest stored at the root of every completed backup.
pub const BACKUP_MANIFEST_FILE: &str = "loom-backup-manifest.json";
/// Detached signature stored beside a signed backup manifest.
pub const BACKUP_SIGNATURE_FILE: &str = "loom-backup-manifest.sig.json";
/// The detached-signature format this build *writes* by default.
///
/// Still 1. Per `docs/design/backup-signature-v2.md` §5, v2 verification lands everywhere before
/// anything emits v2 — a writer that emits a format some verifier does not yet accept is the same
/// distribute-then-trust mistake P8's `expand` step exists to prevent.
pub const BACKUP_SIGNATURE_VERSION: u32 = 1;
/// The digest-signing format, accepted by every verifier in this build and written on request.
pub const BACKUP_SIGNATURE_VERSION_V2: u32 = 2;

const PROCESS_LOCK_RELATIVE: &str = "loom/store.lock";
const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 16 * 1024;
const MAX_BACKUP_FILES: usize = 1_000_000;
const SIGNATURE_DOMAIN: &[u8] = b"loomdb-backup-manifest-signature-v1\0";
/// v2 signs a *digest* of the manifest rather than the manifest itself, so the payload is a fixed
/// ~95 bytes instead of growing with the store. See `docs/design/backup-signature-v2.md`.
const SIGNATURE_DOMAIN_V2: &[u8] = b"loomdb-backup-manifest-signature-v2\0";
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

/// Detached Ed25519 authenticity record for the exact manifest bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupSignature {
    /// Signature record format version.
    pub format_version: u32,
    /// Algorithm identifier. Version 1 supports only `ed25519`.
    pub algorithm: String,
    /// Operator-controlled trust-root identifier, bound into the signature.
    pub key_id: String,
    /// BLAKE3 of the exact manifest bytes, for audit receipts and fast diagnosis.
    pub manifest_blake3: String,
    /// Lowercase hex Ed25519 signature over the domain, key id, and manifest bytes.
    pub ed25519: String,
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
    /// A signing or verification key, signature record, or signature was invalid.
    #[error("backup authenticity check failed: {0}")]
    Authenticity(String),
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
            if (exclude_manifest
                && (relative == BACKUP_MANIFEST_FILE || relative == BACKUP_SIGNATURE_FILE))
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

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
        output.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap_or('0'));
    }
    output
}

fn decode_hex<const N: usize>(value: &str, what: &str) -> Result<[u8; N], BackupError> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(BackupError::Authenticity(format!(
            "{what} must be exactly {} hexadecimal characters",
            N * 2
        )));
    }
    let mut output = [0u8; N];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let pair = std::str::from_utf8(pair)
            .map_err(|error| BackupError::Authenticity(format!("{what}: {error}")))?;
        output[index] = u8::from_str_radix(pair, 16)
            .map_err(|error| BackupError::Authenticity(format!("{what}: {error}")))?;
    }
    Ok(output)
}

fn manifest_bytes(manifest: &BackupManifest) -> Result<Vec<u8>, BackupError> {
    let mut bytes = serde_json::to_vec_pretty(manifest)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn write_manifest(root: &Path, manifest: &BackupManifest) -> Result<Vec<u8>, BackupError> {
    let path = root.join(BACKUP_MANIFEST_FILE);
    let bytes = manifest_bytes(manifest)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .map_err(|error| io("create manifest", &path, error))?;
    file.write_all(&bytes)
        .map_err(|error| io("write manifest", &path, error))?;
    file.sync_all()
        .map_err(|error| io("sync manifest", &path, error))?;
    Ok(bytes)
}

/// **The v2 signed payload: a domain tag, the key identity, and a digest the caller computed.**
///
/// `manifest_digest` is deliberately a `[u8; 32]` and not a `&str`. The only way to obtain one is to
/// hash bytes, so a caller cannot reach for the digest a signature record *carries* — which is the
/// forgery in `docs/design/backup-signature-v2.md` §3, and the reason this signature means anything.
///
/// The key id is length-prefixed rather than NUL-separated. v1's separator was safe only because a
/// key id cannot contain a NUL; the prefix removes the reliance on that and matches the framing
/// `WriteEnvelope::signing_bytes` and the actor-registry attestation already use.
fn signature_payload_v2(key_id: &str, manifest_digest: &[u8; 32]) -> Vec<u8> {
    let key_id = key_id.as_bytes();
    let mut payload = Vec::with_capacity(SIGNATURE_DOMAIN_V2.len() + 8 + key_id.len() + 32);
    payload.extend_from_slice(SIGNATURE_DOMAIN_V2);
    payload.extend_from_slice(&(key_id.len() as u64).to_le_bytes());
    payload.extend_from_slice(key_id);
    payload.extend_from_slice(manifest_digest);
    payload
}

fn signature_payload(key_id: &str, manifest: &[u8]) -> Vec<u8> {
    let mut payload =
        Vec::with_capacity(SIGNATURE_DOMAIN.len() + key_id.len() + 1 + manifest.len());
    payload.extend_from_slice(SIGNATURE_DOMAIN);
    payload.extend_from_slice(key_id.as_bytes());
    payload.push(0);
    payload.extend_from_slice(manifest);
    payload
}

fn write_signature(
    root: &Path,
    key_id: &str,
    key: &SigningKey,
    manifest: &[u8],
    format_version: u32,
) -> Result<BackupSignature, BackupError> {
    if key_id.trim().is_empty() || key_id.len() > 256 || key_id.contains('\0') {
        return Err(BackupError::Authenticity(
            "backup signing key id must be 1..=256 characters and contain no NUL".into(),
        ));
    }
    let digest = blake3::hash(manifest);
    let payload = match format_version {
        BACKUP_SIGNATURE_VERSION => signature_payload(key_id, manifest),
        BACKUP_SIGNATURE_VERSION_V2 => signature_payload_v2(key_id, digest.as_bytes()),
        other => {
            return Err(BackupError::Authenticity(format!(
            "cannot write signature format {other}; this build writes {BACKUP_SIGNATURE_VERSION} \
                 or {BACKUP_SIGNATURE_VERSION_V2}"
        )))
        }
    };
    let signature = key.sign(&payload);
    let record = BackupSignature {
        format_version,
        algorithm: "ed25519".into(),
        key_id: key_id.into(),
        manifest_blake3: digest.to_hex().to_string(),
        ed25519: encode_hex(&signature.to_bytes()),
    };
    let path = root.join(BACKUP_SIGNATURE_FILE);
    let mut bytes = serde_json::to_vec_pretty(&record)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .map_err(|error| io("create signature", &path, error))?;
    file.write_all(&bytes)
        .map_err(|error| io("write signature", &path, error))?;
    file.sync_all()
        .map_err(|error| io("sync signature", &path, error))?;
    Ok(record)
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
    create_backup_inner(source, destination, tenant, None, BACKUP_SIGNATURE_VERSION)
}

pub(crate) fn create_signed_backup(
    source: &Path,
    destination: &Path,
    tenant: &str,
    key_id: &str,
    key: &SigningKey,
    format_version: u32,
) -> Result<BackupManifest, BackupError> {
    create_backup_inner(
        source,
        destination,
        tenant,
        Some((key_id, key)),
        format_version,
    )
}

fn create_backup_inner(
    source: &Path,
    destination: &Path,
    tenant: &str,
    signer: Option<(&str, &SigningKey)>,
    format_version: u32,
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
        let encoded = write_manifest(&partial, &manifest)?;
        if let Some((key_id, key)) = signer {
            write_signature(&partial, key_id, key, &encoded, format_version)?;
        }
        publish_partial(&partial, destination)?;
        Ok(manifest)
    })();

    if result.is_err() && partial.exists() {
        let _ = fs::remove_dir_all(&partial);
    }
    result
}

fn load_manifest_bytes(root: &Path) -> Result<Vec<u8>, BackupError> {
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
    fs::read(&path).map_err(|error| io("read manifest", &path, error))
}

fn decode_manifest(bytes: &[u8]) -> Result<BackupManifest, BackupError> {
    let manifest: BackupManifest = serde_json::from_slice(bytes)?;
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

fn load_manifest(root: &Path) -> Result<BackupManifest, BackupError> {
    decode_manifest(&load_manifest_bytes(root)?)
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
    verify_manifest_files(root, &manifest)?;
    Ok(manifest)
}

fn verify_manifest_files(root: &Path, manifest: &BackupManifest) -> Result<(), BackupError> {
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
    Ok(())
}

fn load_signature(root: &Path) -> Result<BackupSignature, BackupError> {
    let path = root.join(BACKUP_SIGNATURE_FILE);
    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            BackupError::Authenticity(format!(
                "required signature file {BACKUP_SIGNATURE_FILE} is missing"
            ))
        } else {
            io("stat signature", &path, error)
        }
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(BackupError::Authenticity(
            "backup signature must be a regular file".into(),
        ));
    }
    if metadata.len() > MAX_SIGNATURE_BYTES {
        return Err(BackupError::Authenticity(format!(
            "backup signature is {} bytes, over the {MAX_SIGNATURE_BYTES}-byte cap",
            metadata.len()
        )));
    }
    let bytes = fs::read(&path).map_err(|error| io("read signature", &path, error))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| BackupError::Authenticity(format!("signature record is invalid: {error}")))
}

/// **Rebuild the exact bytes a signature must cover, for whichever format the record declares.**
///
/// The v2 digest is RECOMPUTED here from `manifest`, and `record.manifest_blake3` is never used to
/// build it. That is the whole point of the format: verifying over a digest the record carries would
/// bind a claim the record makes about itself rather than the manifest, so an attacker could swap
/// the manifest, leave the record intact, and still verify. Integrity is not authenticity.
/// See `docs/design/backup-signature-v2.md` §3.
///
/// An unrecognized version is refused rather than guessed at.
fn verified_payload(record: &BackupSignature, manifest: &[u8]) -> Result<Vec<u8>, BackupError> {
    match record.format_version {
        BACKUP_SIGNATURE_VERSION => Ok(signature_payload(&record.key_id, manifest)),
        BACKUP_SIGNATURE_VERSION_V2 => Ok(signature_payload_v2(
            &record.key_id,
            blake3::hash(manifest).as_bytes(),
        )),
        other => Err(BackupError::Authenticity(format!(
            "signature format {other} is unsupported; this build accepts \
             {BACKUP_SIGNATURE_VERSION} and {BACKUP_SIGNATURE_VERSION_V2}"
        ))),
    }
}

/// The checks both verification paths share: a format this build understands, and a signature
/// record that actually commits to *these* manifest bytes.
fn check_signature_record(record: &BackupSignature, manifest: &[u8]) -> Result<(), BackupError> {
    if record.format_version != BACKUP_SIGNATURE_VERSION
        && record.format_version != BACKUP_SIGNATURE_VERSION_V2
    {
        return Err(BackupError::Authenticity(format!(
            "signature format {} is unsupported; this build accepts {} and {}",
            record.format_version, BACKUP_SIGNATURE_VERSION, BACKUP_SIGNATURE_VERSION_V2
        )));
    }
    let digest = blake3::hash(manifest).to_hex().to_string();
    if record.manifest_blake3 != digest {
        return Err(BackupError::Authenticity(format!(
            "signed manifest digest mismatch: expected {}, found {}",
            record.manifest_blake3, digest
        )));
    }
    Ok(())
}

fn verify_signature(
    root: &Path,
    manifest: &[u8],
    expected_key_id: &str,
    public_key: &VerifyingKey,
) -> Result<BackupSignature, BackupError> {
    let record = load_signature(root)?;
    check_signature_record(&record, manifest)?;
    if record.algorithm != "ed25519" {
        return Err(BackupError::Authenticity(format!(
            "signature algorithm {:?} is unsupported",
            record.algorithm
        )));
    }
    if record.key_id != expected_key_id {
        return Err(BackupError::Authenticity(format!(
            "backup was signed by key {:?}, not expected key {:?}",
            record.key_id, expected_key_id
        )));
    }
    let bytes = decode_hex::<64>(&record.ed25519, "Ed25519 signature")?;
    let signature = Signature::from_bytes(&bytes);
    public_key
        .verify(&verified_payload(&record, manifest)?, &signature)
        .map_err(|error| {
            BackupError::Authenticity(format!(
                "Ed25519 signature did not verify for key {:?}: {error}",
                record.key_id
            ))
        })?;
    Ok(record)
}

/// Verify both the Ed25519 authenticity record and every content digest in a backup.
///
/// `expected_key_id` is supplied by the deployment's trust-root policy. Binding it into the signed
/// payload prevents a valid signature from being relabelled as a different key during rotation.
pub fn verify_signed_backup(
    root: impl AsRef<Path>,
    expected_key_id: &str,
    public_key: &VerifyingKey,
) -> Result<BackupManifest, BackupError> {
    let root = root.as_ref();
    let bytes = load_manifest_bytes(root)?;
    verify_signature(root, &bytes, expected_key_id, public_key)?;
    let manifest = decode_manifest(&bytes)?;
    verify_manifest_files(root, &manifest)?;
    Ok(manifest)
}

/// **Verify a signed backup against a trust-root register rather than a bare key.**
///
/// The signature record already names the key id and the algorithm, so this reads them and asks
/// custody the question a bare `VerifyingKey` cannot answer: *is that key still trusted for the
/// backup role?* A revoked key's material verifies exactly as well as it did the day before it was
/// revoked, so refusing it has to be a decision somebody records — and this is where that decision
/// reaches the backup path.
///
/// Not one signed byte changes. The record, the domain separator, and the manifest bytes are the
/// P7 format; all that is added is which keys may still speak for the role.
pub fn verify_signed_backup_with(
    root: impl AsRef<Path>,
    directory: &loom_keys::KeyDirectory,
) -> Result<(BackupManifest, String), BackupError> {
    let root = root.as_ref();
    let bytes = load_manifest_bytes(root)?;
    let record = load_signature(root)?;
    check_signature_record(&record, &bytes)?;

    // Custody decides *whether this key may still authorize a backup*, and the algorithm the record
    // claims is checked against the algorithm the key is registered under — not against a hardcoded
    // string. A revoked key is refused as revoked, rather than quietly passing a check it would
    // mathematically pass.
    let signature = decode_hex::<64>(&record.ed25519, "Ed25519 signature")?;
    let trusted = directory
        .verify(
            &record.key_id,
            &record.algorithm,
            &verified_payload(&record, &bytes)?,
            &signature,
        )
        .map_err(|error| BackupError::Authenticity(error.to_string()))?;

    let manifest = decode_manifest(&bytes)?;
    verify_manifest_files(root, &manifest)?;
    Ok((manifest, trusted.key_id.clone()))
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
    let manifest = verify_backup(backup)?;
    restore_verified_backup(backup, destination, manifest)
}

/// Restore a backup only after its expected Ed25519 trust root and every file digest verify.
pub fn restore_signed_backup(
    backup: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    expected_key_id: &str,
    public_key: &VerifyingKey,
) -> Result<BackupManifest, BackupError> {
    let backup = backup.as_ref();
    let destination = destination.as_ref();
    let manifest = verify_signed_backup(backup, expected_key_id, public_key)?;
    restore_verified_backup(backup, destination, manifest)
}

fn restore_verified_backup(
    backup: &Path,
    destination: &Path,
    manifest: BackupManifest,
) -> Result<BackupManifest, BackupError> {
    if destination.exists() {
        return Err(BackupError::DestinationExists(
            destination.display().to_string(),
        ));
    }
    reject_nested_destination(backup, destination)?;
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

#[cfg(test)]
mod signature_format_tests {
    use super::*;

    fn record(format_version: u32, carried_digest: &str) -> BackupSignature {
        BackupSignature {
            format_version,
            algorithm: "ed25519".into(),
            key_id: "backup-root-2026-q3".into(),
            manifest_blake3: carried_digest.into(),
            ed25519: "00".repeat(64),
        }
    }

    /// **The discriminating test for design note §3.**
    ///
    /// `check_signature_record` also compares the carried digest to the computed one, and it runs
    /// first — so an end-to-end forgery test proves the *system* refuses without proving anything
    /// about which value the signature is checked against. This tests that directly: the payload
    /// v2 verification builds must be identical whether the record carries the right digest, a
    /// wrong one, or garbage, because it is derived from the manifest bytes alone.
    ///
    /// If this ever fails, the signature binds a claim the record makes about itself rather than
    /// the manifest, and the format is forgeable even with `check_signature_record` in place.
    #[test]
    fn v2_payload_ignores_the_digest_the_record_carries() {
        let manifest = br#"{"format_version":1,"tenant":"acme","files":[]}"#;
        let truthful = blake3::hash(manifest).to_hex().to_string();

        let from_truthful = verified_payload(&record(2, &truthful), manifest).expect("v2");
        let from_a_lie = verified_payload(&record(2, &"f".repeat(64)), manifest).expect("v2");
        let from_garbage = verified_payload(&record(2, "not-a-digest"), manifest).expect("v2");

        assert_eq!(from_truthful, from_a_lie);
        assert_eq!(from_truthful, from_garbage);

        // ...and it is the digest of THESE bytes, length-prefixed after the v2 domain and key id.
        let expected =
            signature_payload_v2("backup-root-2026-q3", blake3::hash(manifest).as_bytes());
        assert_eq!(from_truthful, expected);
        assert_eq!(expected.len(), 36 + 8 + "backup-root-2026-q3".len() + 32);
    }

    /// Changing one byte of the manifest changes the bytes a v2 signature must cover.
    #[test]
    fn v2_payload_tracks_the_manifest_bytes() {
        let a = br#"{"format_version":1,"tenant":"acme","files":[]}"#;
        let b = br#"{"format_version":1,"tenant":"beta","files":[]}"#;
        let truthful = blake3::hash(a).to_hex().to_string();
        assert_ne!(
            verified_payload(&record(2, &truthful), a).expect("v2"),
            verified_payload(&record(2, &truthful), b).expect("v2"),
            "the same record over different manifests must not produce the same signed bytes"
        );
    }

    /// v1 still signs the manifest itself, unchanged, so archived backups keep verifying.
    #[test]
    fn v1_payload_is_untouched() {
        let manifest = br#"{"format_version":1,"tenant":"acme","files":[]}"#;
        assert_eq!(
            verified_payload(&record(1, "ignored"), manifest).expect("v1"),
            signature_payload("backup-root-2026-q3", manifest)
        );
    }

    #[test]
    fn an_unknown_format_has_no_payload() {
        assert!(verified_payload(&record(3, "x"), b"{}").is_err());
    }
}
