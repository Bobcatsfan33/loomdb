//! `loomctl` — read-only-by-default operator diagnostics and verified backups.

mod metrics;
mod receipt;
mod retention;

use ed25519_dalek::{SigningKey, VerifyingKey};
use loom_branch::{
    restore_backup, restore_signed_backup, verify_backup, verify_signed_backup, BackupManifest,
    BackupSignature, Loom, BACKUP_SIGNATURE_FILE,
};
use loom_core::{BranchId, TenantId};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::metrics::Signals;
use crate::receipt::BackupReceipt;
use crate::retention::LegalHolds;

const USAGE: &str = r#"loomctl — LoomDB operator diagnostics

USAGE:
  loomctl inspect       --path <store> --tenant <tenant>
  loomctl verify        --path <store> --tenant <tenant>
  loomctl backup        --path <store> --tenant <tenant> --out <new-directory>
  loomctl backup-signed --path <store> --tenant <tenant> (--out <new-directory> | --root <shelf>) --signing-key-file <hex-key> --key-id <id>
  loomctl verify-backup --path <backup>
  loomctl verify-backup-signed (--path <backup> | --root <shelf>) --public-key-file <hex-key> --key-id <id>
  loomctl restore       --path <backup> --expected-tenant <tenant> --out <new-store>
  loomctl restore-signed (--path <backup> | --root <shelf>) --expected-tenant <tenant> (--out <new-store> | --out-root <dir>) --public-key-file <hex-key> --key-id <id>
  loomctl backup-prune  --root <backup-root> --keep-days <n> --minimum-copies <n> [--legal-hold-file <file>] [--apply]

`--root` names a shelf instead of one backup: writes mint a fresh `<tenant>-<unix>` destination under
it, and reads take the newest backup on it. That is what a scheduled job needs — verification and
rehearsal run later, as a different identity, and share no state with the writer beyond the shelf. An
empty shelf is an error, because "nothing to verify" must not look like "verification passed".

Any command may add --metrics-file <file> to publish operational signals for the host's collector.
The file is written atomically, carries no tenant identifier, and is written even when the command
fails, so a failed run is visible rather than silent.

Commands never mutate an existing database. `backup` creates a new destination and refuses to
overwrite it. `restore` verifies every digest, requires the expected tenant, creates a new destination,
and refuses to overwrite it. Open a restored store through a production constructor before serving it.
`backup-prune` is a dry run unless --apply is given, never deletes a backup under legal hold, never
deletes the newest --minimum-copies, and refuses to run inside a live store.
"#;

fn flag(args: &[String], name: &str) -> Result<String, String> {
    let index = args
        .iter()
        .position(|value| value == name)
        .ok_or_else(|| format!("missing required {name}\n\n{USAGE}"))?;
    args.get(index + 1)
        .filter(|value| !value.starts_with("--"))
        .cloned()
        .ok_or_else(|| format!("missing value for {name}\n\n{USAGE}"))
}

fn optional_flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|value| value == name)
        .and_then(|index| args.get(index + 1))
        .filter(|value| !value.starts_with("--"))
        .cloned()
}

fn switch(args: &[String], name: &str) -> bool {
    args.iter().any(|value| value == name)
}

fn number<T: std::str::FromStr>(args: &[String], name: &str) -> Result<T, String>
where
    T::Err: std::fmt::Display,
{
    flag(args, name)?
        .parse()
        .map_err(|error| format!("{name} must be a number: {error}"))
}

/// **Publish the signals for one run, whether it succeeded or failed.**
///
/// A collector that only ever hears from successful runs cannot tell "the backup is fine" from "the
/// job has not run since Tuesday". So the failure signal is written on the error path too, and the
/// original error is what the operator sees — a metrics problem never masks a backup problem.
fn publish(metrics_file: Option<&Path>, signals: &Signals, succeeded: bool) -> Result<(), String> {
    let Some(path) = metrics_file else {
        return Ok(());
    };
    match signals.write(path) {
        Ok(()) => Ok(()),
        Err(error) if !succeeded => {
            eprintln!(
                "loomctl: warning: could not write {}: {error}",
                path.display()
            );
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn existing_store(args: &[String]) -> Result<(PathBuf, TenantId), String> {
    let path = PathBuf::from(flag(args, "--path")?);
    if !path.is_dir() {
        return Err(format!(
            "store does not exist or is not a directory: {}",
            path.display()
        ));
    }
    Ok((path, TenantId::new(flag(args, "--tenant")?)))
}

fn open_store(path: &Path, tenant: TenantId) -> Result<Loom, String> {
    Loom::open(path, tenant).map_err(|error| error.to_string())
}

fn print_json(value: &impl serde::Serialize) -> Result<(), String> {
    let output = serde_json::to_string_pretty(value).map_err(|error| error.to_string())?;
    println!("{output}");
    Ok(())
}

fn decode_key_file<const N: usize>(path: &Path, what: &str) -> Result<[u8; N], String> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| format!("reading {what}: {error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{what} must be a regular, non-symlink file"));
    }
    let value = std::fs::read_to_string(path)
        .map_err(|error| format!("reading {what} {}: {error}", path.display()))?;
    let value = value.trim();
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "{what} must contain exactly {} hexadecimal characters",
            N * 2
        ));
    }
    let mut output = [0u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair =
            std::str::from_utf8(pair).map_err(|error| format!("decoding {what}: {error}"))?;
        output[index] =
            u8::from_str_radix(pair, 16).map_err(|error| format!("decoding {what}: {error}"))?;
    }
    Ok(output)
}

fn signing_key(args: &[String]) -> Result<SigningKey, String> {
    let path = PathBuf::from(flag(args, "--signing-key-file")?);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path)
            .map_err(|error| format!("reading signing key permissions: {error}"))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "signing key {} must not be group/world accessible (expected mode 0600 or stricter)",
                path.display()
            ));
        }
    }
    Ok(SigningKey::from_bytes(&decode_key_file(
        &path,
        "Ed25519 signing key",
    )?))
}

fn verifying_key(args: &[String]) -> Result<VerifyingKey, String> {
    let path = PathBuf::from(flag(args, "--public-key-file")?);
    VerifyingKey::from_bytes(&decode_key_file(&path, "Ed25519 public key")?)
        .map_err(|error| format!("decoding Ed25519 public key: {error}"))
}

fn run(args: &[String]) -> Result<(), String> {
    let command = args.get(1).map(String::as_str).unwrap_or("help");
    match command {
        "inspect" => {
            let (path, tenant) = existing_store(args)?;
            let db = open_store(&path, tenant)?;
            let branches = db
                .branch_names()
                .into_iter()
                .map(|name| {
                    let head = db
                        .head(&BranchId::new(&name))
                        .map_err(|error| error.to_string())?;
                    Ok((name, head.to_string()))
                })
                .collect::<Result<BTreeMap<_, _>, String>>()?;
            print_json(&json!({
                "healthy_to_open": true,
                "path": path,
                "tenant": db.tenant().as_str(),
                "branch_count": branches.len(),
                "branches": branches,
            }))
        }
        "verify" => {
            let metrics_file = optional_flag(args, "--metrics-file").map(PathBuf::from);
            let (path, tenant) = existing_store(args)?;
            let db = open_store(&path, tenant)?;
            let report = db.verify_integrity().map_err(|error| error.to_string())?;
            let damaged = report.corrupt.len() + report.missing.len() + report.bad_manifests.len();
            let mut signals = Signals::new();
            signals
                .set(metrics::SCRUB_DAMAGE, damaged as f64)
                .set(metrics::FAILURES, if damaged == 0 { 0.0 } else { 1.0 });
            publish(metrics_file.as_deref(), &signals, true)?;
            let value = json!({
                "healthy": report.is_healthy(),
                "healthy_pages": report.healthy,
                "unreferenced_pages": report.unreferenced,
                "corrupt_pages": report.corrupt.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "missing_pages": report.missing.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "bad_manifests": report.bad_manifests.iter().map(ToString::to_string).collect::<Vec<_>>(),
            });
            print_json(&value)?;
            if report.is_healthy() {
                Ok(())
            } else {
                Err("integrity verification found damaged objects".into())
            }
        }
        "backup" => {
            let (path, tenant) = existing_store(args)?;
            let destination = PathBuf::from(flag(args, "--out")?);
            let db = open_store(&path, tenant)?;
            let manifest = db
                .backup_to(destination)
                .map_err(|error| error.to_string())?;
            print_json(&manifest)
        }
        "backup-signed" => {
            let metrics_file = optional_flag(args, "--metrics-file").map(PathBuf::from);
            let started = std::time::Instant::now();
            let outcome = backup_signed(args);
            let duration = started.elapsed().as_secs_f64();

            let mut signals = Signals::new();
            signals.set(metrics::DURATION, duration);
            match &outcome {
                Ok((manifest, receipt)) => {
                    signals
                        .set(metrics::FAILURES, 0.0)
                        .set(metrics::LAST_SUCCESS, receipt.created_unix as f64)
                        .set(metrics::BYTES, receipt.bytes as f64)
                        .set(metrics::FILES, manifest.files.len() as f64);
                }
                Err(_) => {
                    signals.set(metrics::FAILURES, 1.0);
                }
            }
            publish(metrics_file.as_deref(), &signals, outcome.is_ok())?;
            let (manifest, receipt) = outcome?;
            print_json(&json!({ "manifest": manifest, "receipt": receipt }))
        }
        "verify-backup" => {
            let path = PathBuf::from(flag(args, "--path")?);
            let manifest = verify_backup(path).map_err(|error| error.to_string())?;
            print_json(&manifest)
        }
        // THE INDEPENDENT CHECK. This is the command the deployment runs from a *different* trust
        // domain than the one that wrote the backup: it holds the public trust root and no signing
        // key, so a compromise of the writer cannot also mint the verification that says it is fine.
        "verify-backup-signed" => {
            let metrics_file = optional_flag(args, "--metrics-file").map(PathBuf::from);
            let started = std::time::Instant::now();
            let outcome = target_backup(args).and_then(|path| verify_backup_signed(args, &path));
            let duration = started.elapsed().as_secs_f64();

            let mut signals = Signals::new();
            signals.set(metrics::DURATION, duration);
            match &outcome {
                Ok((manifest, recovery_point)) => {
                    let bytes: u64 = manifest.files.iter().map(|file| file.bytes).sum();
                    signals
                        .set(metrics::FAILURES, 0.0)
                        .set(metrics::SCRUB_DAMAGE, 0.0)
                        .set(metrics::LAST_VERIFIED, metrics::now_unix() as f64)
                        .set(metrics::BYTES, bytes as f64)
                        .set(metrics::FILES, manifest.files.len() as f64);
                    // An unknown recovery point is reported by *omitting* the signal, never by
                    // publishing a zero a dashboard would read as "1970" or a plausible-looking
                    // guess. The verification still happened and still says so.
                    if let Some(recovery_point) = recovery_point {
                        signals.set(metrics::RECOVERY_POINT, *recovery_point as f64);
                    }
                }
                Err(_) => {
                    // A backup that fails its signature or a digest is damage, not merely a failed
                    // job: the copy that was supposed to be the last line of defence is not one.
                    signals
                        .set(metrics::FAILURES, 1.0)
                        .set(metrics::SCRUB_DAMAGE, 1.0);
                }
            }
            publish(metrics_file.as_deref(), &signals, outcome.is_ok())?;
            let (manifest, recovery_point) = outcome?;
            print_json(&json!({
                "manifest": manifest,
                "recovery_point_unix": recovery_point,
                "recovery_point_source": match recovery_point {
                    Some(_) => "receipt",
                    None => "unknown — no receipt beside this backup",
                },
            }))
        }
        // Retention. A dry run unless --apply, and never able to remove the last copies or anything
        // a legal hold names.
        "backup-prune" => {
            let metrics_file = optional_flag(args, "--metrics-file").map(PathBuf::from);
            let root = PathBuf::from(flag(args, "--root")?);
            let keep_days: u32 = number(args, "--keep-days")?;
            let minimum_copies: usize = number(args, "--minimum-copies")?;
            let holds = match optional_flag(args, "--legal-hold-file") {
                Some(path) => LegalHolds::load(Path::new(&path))?,
                None => LegalHolds::none(),
            };
            let outcome = (|| -> Result<retention::Plan, String> {
                let mut plan = retention::plan(
                    &root,
                    keep_days,
                    minimum_copies,
                    &holds,
                    metrics::now_unix(),
                )?;
                if switch(args, "--apply") {
                    retention::apply(&mut plan)?;
                }
                Ok(plan)
            })();

            let mut signals = Signals::new();
            match &outcome {
                Ok(plan) => {
                    signals
                        .set(metrics::FAILURES, 0.0)
                        .set(metrics::RETAINED, plan.retained() as f64)
                        .set(metrics::LEGAL_HOLD, plan.legal_hold_retained() as f64)
                        .set(
                            metrics::PRUNED,
                            if plan.applied {
                                plan.to_prune().count() as f64
                            } else {
                                0.0
                            },
                        );
                }
                Err(_) => {
                    signals.set(metrics::FAILURES, 1.0);
                }
            }
            publish(metrics_file.as_deref(), &signals, outcome.is_ok())?;
            print_json(&outcome?)
        }
        "restore" => {
            let path = PathBuf::from(flag(args, "--path")?);
            let destination = PathBuf::from(flag(args, "--out")?);
            let expected_tenant = flag(args, "--expected-tenant")?;
            let manifest = verify_backup(&path).map_err(|error| error.to_string())?;
            if manifest.tenant != expected_tenant {
                return Err(format!(
                    "backup belongs to tenant {:?}, not expected tenant {:?}; refusing restore",
                    manifest.tenant, expected_tenant
                ));
            }
            let restored = restore_backup(path, destination).map_err(|error| error.to_string())?;
            print_json(&restored)
        }
        "restore-signed" => {
            let path = target_backup(args)?;
            let expected_tenant = flag(args, "--expected-tenant")?;
            let destination = destination(args, &expected_tenant, "--out-root")?;
            let key_id = flag(args, "--key-id")?;
            let key = verifying_key(args)?;
            let manifest =
                verify_signed_backup(&path, &key_id, &key).map_err(|error| error.to_string())?;
            if manifest.tenant != expected_tenant {
                return Err(format!(
                    "backup belongs to tenant {:?}, not expected tenant {:?}; refusing restore",
                    manifest.tenant, expected_tenant
                ));
            }
            let restored = restore_signed_backup(path, destination, &key_id, &key)
                .map_err(|error| error.to_string())?;
            print_json(&restored)
        }
        "help" | "--help" | "-h" => {
            println!("{USAGE}");
            Ok(())
        }
        other => Err(format!("unknown command {other:?}\n\n{USAGE}")),
    }
}

/// Resolve the backup a command should work on.
///
/// `--path` names one exactly. `--root` names the shelf and takes the newest backup on it, which is
/// what a *scheduled* verification or rehearsal needs: it runs later than the writer, as a different
/// identity, and shares no state with it beyond the shelf.
fn target_backup(args: &[String]) -> Result<PathBuf, String> {
    match (optional_flag(args, "--path"), optional_flag(args, "--root")) {
        (Some(path), None) => Ok(PathBuf::from(path)),
        (None, Some(root)) => retention::newest(Path::new(&root)),
        (Some(_), Some(_)) => {
            Err("--path and --root are mutually exclusive; name one backup or one shelf".into())
        }
        (None, None) => Err(format!("missing required --path or --root\n\n{USAGE}")),
    }
}

/// Mint a fresh destination under `--root`, or take the exact one `--out` names.
///
/// A scheduled job cannot invent a unique name from its environment without depending on something
/// the two deployment flavours express differently, so the tool mints its own: `<tenant>-<unix>`.
/// The publish still refuses to overwrite, so a repeated name is a failed job, never a lost backup.
fn destination(args: &[String], tenant: &str, root_flag: &str) -> Result<PathBuf, String> {
    match (optional_flag(args, "--out"), optional_flag(args, root_flag)) {
        (Some(out), None) => Ok(PathBuf::from(out)),
        (None, Some(root)) => {
            let root = PathBuf::from(root);
            std::fs::create_dir_all(&root)
                .map_err(|error| format!("cannot create {}: {error}", root.display()))?;
            Ok(root.join(format!("{tenant}-{}", metrics::now_unix())))
        }
        (Some(_), Some(_)) => Err(format!(
            "--out and {root_flag} are mutually exclusive; name one destination or one shelf"
        )),
        (None, None) => Err(format!("missing required --out or {root_flag}\n\n{USAGE}")),
    }
}

/// Take a signed backup and record the operational receipt beside it.
///
/// The receipt is written **after** the backup is published, so a receipt never describes a backup
/// that does not exist. The reverse — a published backup whose receipt failed to write — is a backup
/// with an unknown recovery point, which the verifier reports honestly rather than guessing.
fn backup_signed(args: &[String]) -> Result<(BackupManifest, BackupReceipt), String> {
    let (path, tenant) = existing_store(args)?;
    let destination = destination(args, tenant.as_str(), "--root")?;
    let key_id = flag(args, "--key-id")?;
    let key = signing_key(args)?;
    let started = std::time::Instant::now();
    let db = open_store(&path, tenant)?;
    let manifest = db
        .backup_to_signed(&destination, &key_id, &key)
        .map_err(|error| error.to_string())?;
    let duration_seconds = started.elapsed().as_secs_f64();

    let signature = read_signature(&destination)?;
    let receipt = BackupReceipt {
        schema_version: BackupReceipt::SCHEMA_VERSION,
        tenant: manifest.tenant.clone(),
        key_id,
        manifest_blake3: signature.manifest_blake3,
        created_unix: metrics::now_unix(),
        duration_seconds,
        bytes: manifest.files.iter().map(|file| file.bytes).sum(),
        files: manifest.files.len() as u64,
    };
    receipt.write_beside(&destination)?;
    Ok((manifest, receipt))
}

/// Verify a signed backup and report the recovery point it represents, if one is knowable.
fn verify_backup_signed(
    args: &[String],
    path: &Path,
) -> Result<(BackupManifest, Option<u64>), String> {
    let key_id = flag(args, "--key-id")?;
    let key = verifying_key(args)?;
    let manifest = verify_signed_backup(path, &key_id, &key).map_err(|error| error.to_string())?;
    // The receipt is unsigned and is read only *after* the trust-root signature has already passed.
    // It can move a number on a dashboard; it can never make a tampered backup verify.
    let recovery_point = BackupReceipt::read_beside(path)?.and_then(|receipt| {
        (receipt.manifest_blake3 == read_signature(path).ok()?.manifest_blake3)
            .then_some(receipt.created_unix)
    });
    Ok((manifest, recovery_point))
}

fn read_signature(backup: &Path) -> Result<BackupSignature, String> {
    let path = backup.join(BACKUP_SIGNATURE_FILE);
    let bytes =
        std::fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|error| {
        format!(
            "{} is not a valid signature record: {error}",
            path.display()
        )
    })
}

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    if let Err(error) = run(&args) {
        eprintln!("loomctl: {error}");
        std::process::exit(1);
    }
}
