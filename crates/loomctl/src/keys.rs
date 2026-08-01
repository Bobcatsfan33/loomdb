//! `loomctl keys` — the operator surface for trust-root custody.
//!
//! Every command here works on a register **file**. Nothing reaches a network or a KMS, because the
//! people running these commands are often the ones with neither: an operator inside an enclave
//! inspecting what their deployment trusts, or an incident responder revoking a key at 3am.
//!
//! # The sequence, as commands
//!
//! ```text
//!   loomctl keys expand   --role release --key-id release-2026-q4 --public-key-file new.pub …
//!   loomctl keys activate --role release --key-id release-2026-q4
//!   loomctl keys drill    --role release --signing-key-file new.key      # prove both halves
//!   loomctl keys revoke   --role release --key-id release-2026-q3 --reason "superseded"
//! ```
//!
//! `expand` and `activate` are separate on purpose: a key has to reach every verifier before it
//! starts authorizing anything, or the rotation has a window in which half the fleet is wrong.
//! `revoke` is last and separately approved because it is the only step that invalidates anything.

use std::path::{Path, PathBuf};

use loom_keys::{
    Algorithm, Approval, Backend, Ceremony, KeyDirectory, KeyRole, KeyStatus, SignedReceipt,
    Signer, SoftwareSigner, TrustRoot, TrustRootRegister,
};
use serde_json::json;

use crate::{flag, metrics, optional_flag, print_json, switch};

/// The bytes a drill signs. Fixed, so a drill signature can never be mistaken for an artifact
/// signature: it commits to nothing but the drill itself.
const DRILL_DOMAIN: &[u8] = b"loomdb-key-custody-drill-v1\0";

fn role(args: &[String]) -> Result<KeyRole, String> {
    match flag(args, "--role")?.as_str() {
        "actor-governance" => Ok(KeyRole::ActorGovernance),
        "release" => Ok(KeyRole::Release),
        "backup-root" => Ok(KeyRole::BackupRoot),
        other => Err(format!(
            "unknown --role {other:?}; expected actor-governance, release, or backup-root"
        )),
    }
}

fn register_path(args: &[String]) -> Result<PathBuf, String> {
    Ok(PathBuf::from(flag(args, "--trust-roots")?))
}

fn load(args: &[String]) -> Result<(PathBuf, TrustRootRegister), String> {
    let path = register_path(args)?;
    let register = TrustRootRegister::load(&path).map_err(|error| error.to_string())?;
    Ok((path, register))
}

/// `--approver` may be repeated; dual control counts the distinct ones.
fn approvals(args: &[String]) -> Vec<Approval> {
    let now = metrics::now_unix();
    args.iter()
        .enumerate()
        .filter(|(_, value)| *value == "--approver")
        .filter_map(|(index, _)| args.get(index + 1))
        .filter(|value| !value.starts_with("--"))
        .map(|approver| Approval {
            approver: approver.clone(),
            at_unix: now,
        })
        .collect()
}

/// Run one `loomctl keys …` subcommand.
pub fn run(args: &[String]) -> Result<(), String> {
    match args.get(2).map(String::as_str).unwrap_or("inspect") {
        "inspect" => inspect(args),
        "expand" => expand(args),
        "activate" => activate(args),
        "retire" => retire(args),
        "revoke" => revoke(args),
        "drill" => drill(args),
        other => Err(format!(
            "unknown keys subcommand {other:?}; expected inspect, expand, activate, retire, \
             revoke, or drill"
        )),
    }
}

/// What does this deployment trust, right now, and on whose approval?
fn inspect(args: &[String]) -> Result<(), String> {
    let (path, register) = load(args)?;
    let roots: Vec<_> = register
        .roots
        .iter()
        .map(|root| {
            json!({
                "key_id": root.key_id,
                "role": root.role.as_str(),
                "algorithm": root.algorithm.as_str(),
                "backend": root.backend.as_str(),
                "status": root.status.as_str(),
                "generation": root.generation,
                "verifies": root.status.verifies(),
                "signs": root.status.signs(),
                "ceremony": root.ceremony.reference,
                "approvers": root.ceremony.approvers().into_iter().collect::<Vec<_>>(),
                "revocation_reason": root.revocation_reason,
            })
        })
        .collect();
    print_json(&json!({ "trust_roots": path, "count": roots.len(), "roots": roots }))
}

/// Stage a new trust root. It authorizes nothing until `activate`.
fn expand(args: &[String]) -> Result<(), String> {
    let (path, register) = load(args)?;
    let role = role(args)?;
    let key_id = flag(args, "--key-id")?;
    let public_key = read_public_key(Path::new(&flag(args, "--public-key-file")?))?;
    let generation: u64 = flag(args, "--generation")?
        .parse()
        .map_err(|error| format!("--generation must be a u64: {error}"))?;
    let backend = match optional_flag(args, "--backend").as_deref() {
        None | Some("software") => Backend::Software,
        Some("aws-kms") => Backend::AwsKms,
        Some(other) => return Err(format!("unknown --backend {other:?}")),
    };

    let next = loom_keys::expand(
        &register,
        TrustRoot {
            key_id: key_id.clone(),
            role,
            algorithm: Algorithm::Ed25519,
            public_key,
            backend,
            status: KeyStatus::Pending,
            generation,
            ceremony: Ceremony {
                reference: flag(args, "--ceremony")?,
                approvals: approvals(args),
            },
            revocation_reason: None,
        },
    )
    .map_err(|error| error.to_string())?;
    write(&next, &path)?;
    print_json(&json!({
        "expanded": key_id,
        "role": role.as_str(),
        "status": KeyStatus::Pending.as_str(),
        "note": "staged; it authorizes nothing until `keys activate`, so distribute the register \
                 to every verifier first",
    }))
}

/// Promote a staged key to signing; the key it supersedes retires and keeps verifying.
fn activate(args: &[String]) -> Result<(), String> {
    let (path, register) = load(args)?;
    let role = role(args)?;
    let key_id = flag(args, "--key-id")?;
    let next = loom_keys::activate(&register, role, &key_id).map_err(|error| error.to_string())?;
    write(&next, &path)?;
    let retired: Vec<&str> = next
        .in_role(role)
        .filter(|root| root.status == KeyStatus::Retired)
        .map(|root| root.key_id.as_str())
        .collect();
    print_json(&json!({
        "activated": key_id,
        "role": role.as_str(),
        "retired": retired,
        "note": "the retired key still VERIFIES what it signed before this point; it is revoked \
                 separately, once nothing depends on it",
    }))
}

/// Stop a key signing while leaving it able to verify.
fn retire(args: &[String]) -> Result<(), String> {
    let (path, register) = load(args)?;
    let role = role(args)?;
    let key_id = flag(args, "--key-id")?;
    let next = loom_keys::retire(&register, role, &key_id).map_err(|error| error.to_string())?;
    write(&next, &path)?;
    print_json(&json!({ "retired": key_id, "role": role.as_str() }))
}

/// Revoke a key. The only step that invalidates anything.
fn revoke(args: &[String]) -> Result<(), String> {
    let (path, register) = load(args)?;
    let role = role(args)?;
    let key_id = flag(args, "--key-id")?;
    let reason = flag(args, "--reason")?;
    let next = loom_keys::revoke(
        &register,
        role,
        &key_id,
        &reason,
        switch(args, "--seal-role"),
    )
    .map_err(|error| error.to_string())?;
    write(&next, &path)?;
    print_json(&json!({
        "revoked": key_id,
        "role": role.as_str(),
        "reason": reason,
        "note": "artifacts signed by this key no longer verify. Its material is unchanged; this is \
                 a recorded decision, not a cryptographic event",
    }))
}

/// **The rotation drill.**
///
/// Signs a fixed drill payload with the role's active key and verifies it back through the
/// directory, then reports what every registered key in the role would do with it. This is the
/// evidence a rotation actually worked, and its receipt is labelled with the backend that produced
/// it — so a software drill can never be read as a hardware ceremony.
fn drill(args: &[String]) -> Result<(), String> {
    let (_, register) = load(args)?;
    let role = role(args)?;
    let directory = KeyDirectory::new(register, role).map_err(|error| error.to_string())?;
    let signing_root = directory
        .signing_root()
        .map_err(|error| error.to_string())?;
    let signer =
        SoftwareSigner::from_file(signing_root, Path::new(&flag(args, "--signing-key-file")?))
            .map_err(|error| error.to_string())?;

    let receipt: SignedReceipt = signer
        .sign_receipt(DRILL_DOMAIN)
        .map_err(|error| error.to_string())?;
    let signature = loom_keys::decode_receipt_signature(&receipt).map_err(|e| e.to_string())?;

    // The drill signature must verify through the directory, not merely against the key we just
    // used — otherwise it proves the key works and says nothing about whether custody accepts it.
    let verified = directory
        .verify(
            signer.key_id(),
            signer.algorithm().as_str(),
            DRILL_DOMAIN,
            &signature,
        )
        .map_err(|error| error.to_string())?;

    let outcomes: Vec<_> = directory
        .register()
        .in_role(role)
        .map(|root| {
            let would = directory.verify(
                root.key_id.as_str(),
                root.algorithm.as_str(),
                DRILL_DOMAIN,
                &signature,
            );
            json!({
                "key_id": root.key_id,
                "status": root.status.as_str(),
                "accepts_the_drill_signature": would.is_ok(),
                "refusal": would.err().map(|error| error.to_string()),
            })
        })
        .collect();

    print_json(&json!({
        "role": role.as_str(),
        "signed_by": verified.key_id,
        "backend": receipt.backend.as_str(),
        "custody_claim": match receipt.backend {
            Backend::Software => "SOFTWARE-BACKED DRILL. This proves the rotation sequence, not \
                                  hardware custody. EXT-HSM remains open.",
            Backend::AwsKms => "hardware-backed",
        },
        "receipt": receipt,
        "per_key": outcomes,
    }))
}

fn write(register: &TrustRootRegister, path: &Path) -> Result<(), String> {
    register.write(path).map_err(|error| error.to_string())
}

fn read_public_key(path: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let text = text.trim();
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "{} must contain 64 hexadecimal characters (a 32-byte Ed25519 verifying key)",
            path.display()
        ));
    }
    Ok(text.to_string())
}
