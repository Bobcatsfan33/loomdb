//! The `loomd` binary: a JSON-RPC-over-stdio loop.
//!
//! One line in, one line out — newline-delimited JSON, the simplest transport MCP allows. The engine
//! is in-process; this is a single-tenant daemon. Real deployments put a transport and a tenant router
//! in front of it, but the protocol surface an agent sees is exactly what this serves.
//!
//! The process serves exactly one tenant (`LOOM_TENANT`) out of exactly one store
//! (`LOOM_DATA_DIR`). That 1:1:1 shape is what makes cross-tenant reach structurally impossible
//! rather than a runtime filter, and it is the contract the reference host profile in
//! `deploy/reference` renders. See `docs/host-profile.md`.

use std::collections::BTreeMap;
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ed25519_dalek::VerifyingKey;
use loom_action::ActionGateway;
use loom_branch::{ActorRegistryAttestation, Loom};
use loom_core::{ActorId, TenantId};
use loom_keys::{KeyDirectory, KeyRole};
#[cfg(feature = "observability")]
use loom_mcp::OtlpTelemetry;
use loom_mcp::{
    decode_hex, read_bounded_line, AdmissionConfig, AdmissionController, BoundedLine, LoomServer,
    Request, Response,
};
use loom_policy::{Effect, Engine, Match, PolicyRule, PolicySet};

fn main() -> std::io::Result<()> {
    let admission_config = AdmissionConfig::from_env().unwrap_or_else(|error| {
        eprintln!("loomd: invalid admission configuration: {error}");
        std::process::exit(2);
    });
    let mut admission = AdmissionController::new(admission_config);

    let policy_set = load_policy().unwrap_or_else(|error| {
        eprintln!("loomd: invalid policy configuration: {error}");
        std::process::exit(2);
    });
    let tenant = std::env::var("LOOM_TENANT").unwrap_or_else(|_| "default".into());
    // Loaded before the store is touched, and fatal if it is declared but unusable. A daemon that
    // fell back to an unauthenticated open here would keep serving while silently dropping the
    // guarantee its deployment was written to make.
    let registry = load_actor_registry().unwrap_or_else(|error| {
        eprintln!("loomd: invalid actor registry configuration: {error}");
        std::process::exit(2);
    });
    let db = match open_engine(&tenant, registry) {
        Ok(db) => Arc::new(db),
        Err(e) => {
            eprintln!("loomd: could not open engine: {e}");
            std::process::exit(1);
        }
    };
    let gateway = ActionGateway::new(tenant.clone(), Engine::new(&policy_set));
    let server = LoomServer::new(
        db,
        Engine::new(&policy_set),
        gateway,
        tenant,
        1_700_000_000_000,
    );
    #[cfg(feature = "observability")]
    let telemetry = match std::env::var("LOOM_OTEL_ENABLED") {
        Ok(value) if value == "true" => {
            Some(Arc::new(OtlpTelemetry::new().unwrap_or_else(|error| {
                eprintln!("loomd: telemetry was enabled but initialization failed: {error}");
                std::process::exit(2);
            })))
        }
        Ok(value) if value == "false" => None,
        Err(std::env::VarError::NotPresent) => None,
        Ok(value) => {
            eprintln!("loomd: LOOM_OTEL_ENABLED must be exactly 'true' or 'false', got '{value}'");
            std::process::exit(2);
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            eprintln!("loomd: LOOM_OTEL_ENABLED must be valid UTF-8");
            std::process::exit(2);
        }
    };
    #[cfg(feature = "observability")]
    let server = match &telemetry {
        Some(telemetry) => server.with_observer(telemetry.clone()),
        None => server,
    };

    let stdin = std::io::stdin();
    let mut stdin = BufReader::new(stdin.lock());
    let mut stdout = std::io::stdout();
    loop {
        let frame = read_bounded_line(&mut stdin, admission_config.max_request_bytes)?;
        let response = match frame {
            BoundedLine::Eof => break,
            BoundedLine::TooLarge => Response::err(
                None,
                loom_mcp::codes::RESOURCE_EXHAUSTED,
                format!(
                    "request exceeds LOOM_MAX_REQUEST_BYTES ({})",
                    admission_config.max_request_bytes
                ),
            ),
            BoundedLine::Line(line) if line.iter().all(u8::is_ascii_whitespace) => continue,
            BoundedLine::Line(_) if !admission.admit() => Response::err(
                None,
                loom_mcp::codes::RESOURCE_EXHAUSTED,
                "tenant request-rate budget exhausted; retry with backoff",
            ),
            BoundedLine::Line(line) => match serde_json::from_slice::<Request>(&line) {
                Ok(req) => server.handle(&req),
                Err(e) => Response::err(
                    None,
                    loom_mcp::codes::INVALID_REQUEST,
                    format!("bad JSON-RPC: {e}"),
                ),
            },
        };
        let out = serde_json::to_string(&response).unwrap_or_else(|_| "{}".into());
        writeln!(stdout, "{out}")?;
        stdout.flush()?;
    }
    #[cfg(feature = "observability")]
    if let Some(telemetry) = telemetry {
        telemetry.shutdown().map_err(|error| {
            std::io::Error::other(format!("telemetry shutdown failed: {error}"))
        })?;
    }
    Ok(())
}

/// Open this process's single tenant store.
///
/// Without `LOOM_DATA_DIR` the daemon stays in-memory: nothing survives the process, which is right
/// for the demo and for tests but is not a deployment. With `LOOM_DATA_DIR` the daemon opens a
/// durable store at that path, so a restarted host reopens the same committed state.
///
/// The directory is validated fail-closed: it must be a real directory — not a symlink an attacker
/// could repoint at another tenant's store between restarts — and it must not be world-writable. A
/// misconfigured data directory stops startup rather than silently serving the wrong store.
///
/// Unlike `LOOM_POLICY_FILE`, the *group* write bit is permitted here. A reviewed policy file has one
/// owner and no reason to be group-writable, but a data directory does: Kubernetes applies `fsGroup`
/// to a mounted volume by granting the group write access, so requiring `g-w` would stop every
/// non-root pod with a persistent volume — including the one the reference profile renders. Exclusion
/// of a second writer is enforced where it actually can be: the exclusive advisory lock on
/// `<store>/loom/store.lock`, which fails closed for a second process whatever the directory mode.
///
/// **With a registry, the store is opened attested.** `Loom::open_production_attested` verifies the
/// governance signature, the tenant binding, the rollback floor, and the registry fingerprint before
/// a single store file is opened, and every write is then checked against the key of the actor the
/// envelope claims to be. There is no branch here that answers a registry failure by opening
/// unauthenticated: a declared registry that cannot be honoured stops startup.
fn open_engine(tenant: &str, registry: Option<ActorRegistry>) -> Result<Loom, String> {
    let tenant = TenantId::new(tenant);
    let Some(data_dir) = std::env::var_os("LOOM_DATA_DIR") else {
        // An attested registry describes a *durable* store's writers. Starting ephemeral with one
        // declared would discard both the registry and the tenant's history without saying so.
        if registry.is_some() {
            return Err(
                "LOOM_ACTOR_REGISTRY_FILE is set but LOOM_DATA_DIR is not; an attested actor \
                 registry requires the durable store it authorizes writes to"
                    .into(),
            );
        }
        return Loom::in_memory(tenant).map_err(|error| error.to_string());
    };
    let path = PathBuf::from(data_dir);
    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|error| format!("cannot inspect LOOM_DATA_DIR {}: {error}", path.display()))?;
    if !metadata.file_type().is_dir() {
        return Err(format!(
            "LOOM_DATA_DIR {} must be an existing directory, not a symlink, file, or device",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o002 != 0 {
            return Err(format!(
                "LOOM_DATA_DIR {} must not be world-writable",
                path.display()
            ));
        }
    }
    let Some(registry) = registry else {
        return Loom::open(&path, tenant)
            .map_err(|error| format!("cannot open store at {}: {error}", path.display()));
    };
    // THE ATTESTED OPEN. The governance signature, the tenant binding, the rollback floor, and the
    // registry fingerprint are all checked *before* any store file is opened, and the resulting
    // database refuses a write from an actor it does not know rather than trusting the name.
    // ── CUSTODY DECIDES *WHICH* GOVERNANCE KEY, BEFORE THE STORE IS TOUCHED ────────────────────
    //
    // The attestation carries no key id — adding one would change a signed format, and an
    // attestation issued before custody existed must keep verifying. So each trusted governance
    // root is tried against the exact bytes governance signed, newest generation first, and the one
    // that verified is named in the startup log.
    //
    // Revoked and staged roots are never tried. That is the entire mechanism by which a revoked
    // governance key stops authorizing writers: its material still verifies, and this loop simply
    // never offers it.
    let trusted = registry
        .governance
        .verify_any(
            &registry.attestation.signed_bytes(),
            registry.attestation.signature(),
        )
        .map_err(|error| {
            format!("the actor registry attestation was not signed by a trusted governance key: {error}")
        })?;
    let governance_key = trusted.verifying_key().map_err(|error| error.to_string())?;
    eprintln!(
        "loomd: actor registry attested by governance key {:?} (generation {}, {} backend)",
        trusted.key_id, trusted.generation, trusted.backend
    );

    Loom::open_production_attested(
        &path,
        tenant,
        registry.keys,
        &registry.attestation,
        &governance_key,
        registry.minimum_generation,
    )
    .map_err(|error| format!("cannot open attested store at {}: {error}", path.display()))
}

/// Everything `Loom::open_production_attested` needs, assembled from three separate sources.
///
/// The separation is the point, and it is why this is not one file:
///
/// - the **registry and its attestation** come from the externally managed actor-registry mount,
///   which rotates whenever an actor's key does;
/// - the **governance verifying key** is a trust root and arrives on the trust-root mount, through
///   the same independent channel as the release public key — a registry that carried its own
///   trust root would authenticate itself;
/// - the **rollback floor** is deployment configuration, rendered into the manifest a reviewer
///   reads, so raising it after a revocation is a change to the deployment rather than a value the
///   compromised material could carry.
struct ActorRegistry {
    keys: BTreeMap<ActorId, VerifyingKey>,
    attestation: ActorRegistryAttestation,
    /// The governance trust roots, with their statuses. **P8**: this replaced a bare public key.
    ///
    /// A bare key answers "did this verify"; it cannot answer "is the party that signed this still
    /// the governance authority". A retired key verifies exactly as well as the current one, and a
    /// revoked key verifies exactly as well as it did the day before it was revoked — so refusing
    /// one has to be a decision somebody recorded, and the register is where that decision lives.
    governance: KeyDirectory,
    minimum_generation: u64,
}

/// The actor registry document as it is delivered on the read-only mount.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ActorRegistryDocument {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    /// Actor id → Ed25519 verifying key, hex-encoded.
    actors: BTreeMap<String, String>,
    /// The governance signature over this registry's fingerprint, tenant, and generation.
    attestation: ActorRegistryAttestation,
}

/// The largest actor registry `loomd` will read. A registry is a governance artifact listing the
/// writers of one tenant, not a directory.
const MAX_ACTOR_REGISTRY_BYTES: u64 = 1024 * 1024;
const MAX_ACTORS: usize = 4096;

/// **Load the externally managed actor registry, or refuse to start.**
///
/// Returns `Ok(None)` only when the deployment declares no registry at all — the embedded and
/// development posture, where writes stay attributable but unauthenticated exactly as they were.
/// Every other outcome is either a complete, verified registry or an error: there is no path
/// through this function that turns a broken registry into an unauthenticated daemon.
///
/// The three variables are all-or-nothing on purpose. A deployment that mounted a registry but lost
/// its trust root — a mis-projected secret, a renamed key file — would otherwise start with
/// authentication silently off, which is the failure this whole increment exists to remove.
fn load_actor_registry() -> Result<Option<ActorRegistry>, String> {
    let registry_path = std::env::var_os("LOOM_ACTOR_REGISTRY_FILE");
    let governance_path = std::env::var_os("LOOM_ACTOR_GOVERNANCE_KEY_FILE");
    let generation = std::env::var_os("LOOM_ACTOR_MIN_GENERATION");

    let declared: Vec<&str> = [
        registry_path.as_ref().map(|_| "LOOM_ACTOR_REGISTRY_FILE"),
        governance_path
            .as_ref()
            .map(|_| "LOOM_ACTOR_GOVERNANCE_KEY_FILE"),
        generation.as_ref().map(|_| "LOOM_ACTOR_MIN_GENERATION"),
    ]
    .into_iter()
    .flatten()
    .collect();
    if declared.is_empty() {
        return Ok(None);
    }
    let (Some(registry_path), Some(governance_path), Some(generation)) =
        (registry_path, governance_path, generation)
    else {
        return Err(format!(
            "actor registry enforcement needs LOOM_ACTOR_REGISTRY_FILE, \
             LOOM_ACTOR_GOVERNANCE_KEY_FILE, and LOOM_ACTOR_MIN_GENERATION together; only {} \
             {} set. Refusing to start with write authentication partially configured",
            declared.join(", "),
            if declared.len() == 1 { "is" } else { "are" },
        ));
    };

    let minimum_generation: u64 = generation
        .to_str()
        .ok_or("LOOM_ACTOR_MIN_GENERATION must be valid UTF-8")?
        .trim()
        .parse()
        .map_err(|error| format!("LOOM_ACTOR_MIN_GENERATION must be a u64: {error}"))?;
    if minimum_generation == 0 {
        return Err(
            "LOOM_ACTOR_MIN_GENERATION must be at least 1; a floor of 0 accepts every attested \
             generation and would make a revoked registry replayable"
                .into(),
        );
    }

    let governance = KeyDirectory::load(Path::new(&governance_path), KeyRole::ActorGovernance)
        .map_err(|error| {
            format!(
                "cannot load the actor-governance trust roots from {}: {error}",
                Path::new(&governance_path).display()
            )
        })?;

    let registry_path = PathBuf::from(registry_path);
    let bytes = read_protected_file(
        &registry_path,
        "LOOM_ACTOR_REGISTRY_FILE",
        MAX_ACTOR_REGISTRY_BYTES,
    )?;
    let document: ActorRegistryDocument = serde_json::from_slice(&bytes).map_err(|error| {
        format!("LOOM_ACTOR_REGISTRY_FILE is not a valid actor registry document: {error}")
    })?;
    if document.schema_version != 1 {
        return Err(format!(
            "LOOM_ACTOR_REGISTRY_FILE schemaVersion must equal 1, got {}",
            document.schema_version
        ));
    }
    if document.actors.is_empty() {
        return Err(
            "LOOM_ACTOR_REGISTRY_FILE registers no actors; an empty registry seals the store \
             against every write rather than authenticating one"
                .into(),
        );
    }
    if document.actors.len() > MAX_ACTORS {
        return Err(format!(
            "LOOM_ACTOR_REGISTRY_FILE registers more than {MAX_ACTORS} actors"
        ));
    }

    let mut keys = BTreeMap::new();
    for (actor, key) in document.actors {
        if actor.is_empty() || actor.len() > 256 {
            return Err(format!(
                "LOOM_ACTOR_REGISTRY_FILE actor id must contain 1..=256 bytes, got {} for {actor:?}",
                actor.len()
            ));
        }
        let bytes = decode_hex::<32>(&key).ok_or_else(|| {
            format!(
                "LOOM_ACTOR_REGISTRY_FILE key for actor {actor:?} must be 64 hexadecimal \
                 characters (a 32-byte Ed25519 verifying key)"
            )
        })?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|error| {
            format!("LOOM_ACTOR_REGISTRY_FILE key for actor {actor:?} is not on the curve: {error}")
        })?;
        keys.insert(ActorId::new(actor), key);
    }

    Ok(Some(ActorRegistry {
        keys,
        attestation: document.attestation,
        governance,
        minimum_generation,
    }))
}

/// Read a file that must be a real, size-bounded, non-writable-by-others regular file.
///
/// Same fail-closed shape as `LOOM_POLICY_FILE`: a symlink is refused because it can be repointed
/// between restarts, and group- or world-writable trust material is refused because anything that
/// can rewrite it can appoint its own writers. The registry and trust-root mounts are rendered
/// `0440`, so this is the mode the reference profile already produces.
fn read_protected_file(path: &Path, what: &str, limit: u64) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {what} at {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "{what} at {} must be a regular file, not a symlink, directory, or device",
            path.display()
        ));
    }
    if metadata.len() > limit {
        return Err(format!(
            "{what} at {} exceeds the {limit} byte limit",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(format!(
                "{what} at {} must not be group- or world-writable",
                path.display()
            ));
        }
    }
    std::fs::read(path)
        .map_err(|error| format!("cannot read {what} at {}: {error}", path.display()))
}

fn load_policy() -> Result<PolicySet, String> {
    let policy_path = std::env::var_os("LOOM_POLICY_FILE");
    let permissive = match std::env::var("LOOM_ALLOW_PERMISSIVE_POLICY") {
        Ok(value) if value == "true" => true,
        Ok(value) if value == "false" => false,
        Err(std::env::VarError::NotPresent) => false,
        Ok(value) => {
            return Err(format!(
                "LOOM_ALLOW_PERMISSIVE_POLICY must be exactly 'true' or 'false', got '{value}'"
            ))
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err("LOOM_ALLOW_PERMISSIVE_POLICY must be valid UTF-8".into())
        }
    };

    if policy_path.is_some() && permissive {
        return Err(
            "LOOM_POLICY_FILE and LOOM_ALLOW_PERMISSIVE_POLICY=true are mutually exclusive".into(),
        );
    }
    if permissive {
        eprintln!("loomd: WARNING: permissive development policy explicitly enabled");
        return Ok(PolicySet::new(
            "loomd-development",
            vec![PolicyRule {
                actor: Match::Any,
                label: Match::Any,
                purpose: Match::Any,
                action: Match::Any,
                effect: Effect::Allow,
            }],
        ));
    }
    let Some(policy_path) = policy_path else {
        return Ok(PolicySet::empty("loomd-deny-by-default"));
    };

    let metadata = std::fs::symlink_metadata(&policy_path)
        .map_err(|error| format!("cannot inspect LOOM_POLICY_FILE: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err("LOOM_POLICY_FILE must be a regular file, not a symlink or device".into());
    }
    if metadata.len() > 1024 * 1024 {
        return Err("LOOM_POLICY_FILE exceeds the 1 MiB limit".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err("LOOM_POLICY_FILE must not be group- or world-writable".into());
        }
    }
    let bytes = std::fs::read(&policy_path)
        .map_err(|error| format!("cannot read LOOM_POLICY_FILE: {error}"))?;
    let policy: PolicySet = serde_json::from_slice(&bytes).map_err(|error| {
        format!("LOOM_POLICY_FILE is not a valid PolicySet JSON document: {error}")
    })?;
    validate_policy(&policy)?;
    Ok(policy)
}

fn validate_policy(policy: &PolicySet) -> Result<(), String> {
    if policy.version.is_empty() || policy.version.len() > 128 {
        return Err("policy version must contain 1..=128 bytes".into());
    }
    if policy.rules.len() > 10_000 {
        return Err("policy contains more than 10,000 rules".into());
    }
    for (index, rule) in policy.rules.iter().enumerate() {
        for (name, pattern) in [
            ("actor", &rule.actor),
            ("purpose", &rule.purpose),
            ("action", &rule.action),
        ] {
            if let Match::Is(value) = pattern {
                if value.is_empty() || value.len() > 256 {
                    return Err(format!(
                        "policy rule {index} {name} match must contain 1..=256 bytes"
                    ));
                }
            }
        }
    }
    Ok(())
}
