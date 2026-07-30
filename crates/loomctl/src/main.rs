//! `loomctl` — read-only-by-default operator diagnostics and verified backups.

use ed25519_dalek::{SigningKey, VerifyingKey};
use loom_branch::{
    restore_backup, restore_signed_backup, verify_backup, verify_signed_backup, Loom,
};
use loom_core::{BranchId, TenantId};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const USAGE: &str = r#"loomctl — LoomDB operator diagnostics

USAGE:
  loomctl inspect       --path <store> --tenant <tenant>
  loomctl verify        --path <store> --tenant <tenant>
  loomctl backup        --path <store> --tenant <tenant> --out <new-directory>
  loomctl backup-signed --path <store> --tenant <tenant> --out <new-directory> --signing-key-file <hex-key> --key-id <id>
  loomctl verify-backup --path <backup>
  loomctl verify-backup-signed --path <backup> --public-key-file <hex-key> --key-id <id>
  loomctl restore       --path <backup> --expected-tenant <tenant> --out <new-store>
  loomctl restore-signed --path <backup> --expected-tenant <tenant> --out <new-store> --public-key-file <hex-key> --key-id <id>

Commands never mutate an existing database. `backup` creates a new destination and refuses to
overwrite it. `restore` verifies every digest, requires the expected tenant, creates a new destination,
and refuses to overwrite it. Open a restored store through a production constructor before serving it.
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
            let (path, tenant) = existing_store(args)?;
            let db = open_store(&path, tenant)?;
            let report = db.verify_integrity().map_err(|error| error.to_string())?;
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
            let (path, tenant) = existing_store(args)?;
            let destination = PathBuf::from(flag(args, "--out")?);
            let key_id = flag(args, "--key-id")?;
            let key = signing_key(args)?;
            let db = open_store(&path, tenant)?;
            let manifest = db
                .backup_to_signed(destination, &key_id, &key)
                .map_err(|error| error.to_string())?;
            print_json(&manifest)
        }
        "verify-backup" => {
            let path = PathBuf::from(flag(args, "--path")?);
            let manifest = verify_backup(path).map_err(|error| error.to_string())?;
            print_json(&manifest)
        }
        "verify-backup-signed" => {
            let path = PathBuf::from(flag(args, "--path")?);
            let key_id = flag(args, "--key-id")?;
            let key = verifying_key(args)?;
            let manifest =
                verify_signed_backup(path, &key_id, &key).map_err(|error| error.to_string())?;
            print_json(&manifest)
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
            let path = PathBuf::from(flag(args, "--path")?);
            let destination = PathBuf::from(flag(args, "--out")?);
            let expected_tenant = flag(args, "--expected-tenant")?;
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

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    if let Err(error) = run(&args) {
        eprintln!("loomctl: {error}");
        std::process::exit(1);
    }
}
