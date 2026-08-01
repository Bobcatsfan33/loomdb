//! Process-boundary tests for **write authenticity through `loomd`**.
//!
//! `docs/host-profile.md` used to say, in §6, that the reference profile *mounts* an actor registry
//! but does not make the daemon enforce it — writes over MCP were attributable but not
//! signature-authenticated. This file is the evidence that the sentence is no longer true.
//!
//! Everything here starts the real binary, because that is where the claim lives. A registry the
//! library would have accepted proves nothing about a daemon that never reads it, and the failure
//! mode this increment exists to remove — *starting anyway, unauthenticated* — is only observable at
//! the process boundary.
//!
//! The shape under test:
//!
//! | Source | Carries | Why it is separate |
//! |---|---|---|
//! | `LOOM_ACTOR_REGISTRY_FILE` | the actor→key map and its governance attestation | rotates with any actor's key |
//! | `LOOM_ACTOR_GOVERNANCE_KEY_FILE` | the governance verifying key | a registry that carried its own trust root would authenticate itself |
//! | `LOOM_ACTOR_MIN_GENERATION` | the rollback floor | raising it after a revocation must be a deployment change, not a value the compromised material supplies |

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use ed25519_dalek::SigningKey;
use loom_branch::{ActorRegistryAttestation, Loom};
use loom_core::{ActorId, BranchId, SessionId, TenantId, WriteEnvelope};
use serde_json::{json, Value};

const TENANT: &str = "alpha-corp";
const AGENT: &str = "alpha-agent";

// ── fixture ──────────────────────────────────────────────────────────────────────────────────────

/// A deterministic key. Tests must not depend on an RNG to be reproducible under `--nocapture`.
fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The material a deployment mounts: a store, a registry, and a trust root.
struct Deployment {
    _root: tempfile::TempDir,
    data_dir: PathBuf,
    registry_file: PathBuf,
    governance_file: PathBuf,
    minimum_generation: String,
    /// The signing key of the one registered actor.
    agent: SigningKey,
}

impl Deployment {
    /// Provision the honest case: one registered actor, generation 7, floor 7.
    fn new() -> Self {
        Self::with(7, 7, |_| {})
    }

    /// Provision a deployment, letting the caller corrupt the rendered registry document first.
    ///
    /// `attested_generation` is what governance signed; `floor` is what the deployment will accept.
    fn with(attested_generation: u64, floor: u64, tamper: impl FnOnce(&mut Value)) -> Self {
        let root = tempfile::tempdir().expect("temp root");
        let data_dir = root.path().join("store");
        std::fs::create_dir(&data_dir).expect("store directory");

        let agent = key(1);
        let governance = key(2);
        let actors = [(ActorId::new(AGENT), agent.verifying_key())];
        let attestation = ActorRegistryAttestation::issue(
            TenantId::new(TENANT),
            attested_generation,
            actors,
            &governance,
        );

        let mut document = json!({
            "schemaVersion": 1,
            "actors": { AGENT: hex(agent.verifying_key().as_bytes()) },
            "attestation": serde_json::to_value(&attestation).expect("attestation serializes"),
        });
        tamper(&mut document);

        let registry_file = root.path().join("actors.json");
        std::fs::write(
            &registry_file,
            serde_json::to_vec_pretty(&document).expect("registry serializes"),
        )
        .expect("registry writes");
        let governance_file = root.path().join("governance.pub");
        std::fs::write(&governance_file, hex(governance.verifying_key().as_bytes()))
            .expect("trust root writes");

        Deployment {
            _root: root,
            data_dir,
            registry_file,
            governance_file,
            minimum_generation: floor.to_string(),
            agent,
        }
    }

    /// The environment the reference profile renders for this tenant.
    fn environment(&self) -> Vec<(&'static str, String)> {
        vec![
            ("LOOM_TENANT", TENANT.to_string()),
            ("LOOM_DATA_DIR", path(&self.data_dir)),
            ("LOOM_ACTOR_REGISTRY_FILE", path(&self.registry_file)),
            (
                "LOOM_ACTOR_GOVERNANCE_KEY_FILE",
                path(&self.governance_file),
            ),
            ("LOOM_ACTOR_MIN_GENERATION", self.minimum_generation.clone()),
        ]
    }
}

fn path(path: &Path) -> String {
    path.to_str().expect("UTF-8 path").to_string()
}

/// Start `loomd` with a clean environment plus `environment`.
fn spawn(environment: &[(&'static str, String)]) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_loomd"));
    for name in [
        "LOOM_MAX_REQUEST_BYTES",
        "LOOM_REQUESTS_PER_SECOND",
        "LOOM_REQUEST_BURST",
        "LOOM_ALLOW_PERMISSIVE_POLICY",
        "LOOM_POLICY_FILE",
        "LOOM_OTEL_ENABLED",
        "LOOM_DATA_DIR",
        "LOOM_TENANT",
        "LOOM_ACTOR_REGISTRY_FILE",
        "LOOM_ACTOR_GOVERNANCE_KEY_FILE",
        "LOOM_ACTOR_MIN_GENERATION",
    ] {
        command.env_remove(name);
    }
    for (name, value) in environment {
        command.env(name, value);
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("loomd starts")
}

/// Start `loomd`, let it exit immediately, and return what it did.
fn start_and_exit(environment: &[(&'static str, String)]) -> std::process::Output {
    let child = spawn(environment);
    child.wait_with_output().expect("loomd exits")
}

/// A live daemon driven over its stdio stream.
///
/// `stdin` is an `Option` so that closing it — the only way to ask a stdio daemon to exit — does not
/// require moving out of a type that also has a `Drop` guard against leaking the child process.
struct Session {
    child: Child,
    stdin: Option<std::process::ChildStdin>,
    stdout: BufReader<std::process::ChildStdout>,
    token: Value,
    branch: String,
}

impl Session {
    /// Start a daemon and open one session on it.
    fn open(environment: &[(&'static str, String)]) -> Self {
        let mut child = spawn(environment);
        let mut stdin = child.stdin.take().expect("piped stdin");
        let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));

        let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":"session.open","arguments":{}}});
        writeln!(stdin, "{request}").expect("session.open writes");
        stdin.flush().expect("stdin flushes");
        let mut line = String::new();
        stdout.read_line(&mut line).expect("session.open answers");
        let opened: Value = serde_json::from_str(&line).expect("JSON-RPC response");
        assert!(
            !opened["result"]["token"].is_null(),
            "session.open must mint a token on an attested daemon: {opened}"
        );

        let token = opened["result"]["token"].clone();
        let branch = opened["result"]["branch"]
            .as_str()
            .expect("session branch")
            .to_string();
        Session {
            child,
            stdin: Some(stdin),
            stdout,
            token,
            branch,
        }
    }

    /// Ingest an observation as `actor`, signing the envelope with `signer` when one is supplied.
    ///
    /// The signature is computed exactly the way a client must compute it: over
    /// `WriteEnvelope::signing_bytes()` for the envelope the server will rebuild from these
    /// arguments. If the wire contract and the signed bytes ever drift apart, this stops passing.
    fn observe(&mut self, actor: &str, signer: Option<&SigningKey>, key_name: &str) -> Value {
        let session = "s-1";
        let mut arguments = json!({
            "token": self.token,
            "branch": self.branch,
            "session": session,
            "actor": actor,
            "key": key_name,
            "system": "erp",
            "source": "invoice-88",
            "trust": "VerifiedSystem",
            "text": "a confirmed fraud case",
        });
        if let Some(signer) = signer {
            let envelope = WriteEnvelope::new(
                ActorId::new(actor),
                SessionId::new(session),
                BranchId::new(&self.branch),
                "observe",
            )
            .signed_by(signer);
            arguments["signature"] = json!(hex(&envelope.signature));
        }

        let request = json!({"jsonrpc":"2.0","id":2,"method":"tools/call",
            "params":{"name":"observe","arguments":arguments}});
        let stdin = self.stdin.as_mut().expect("stdin is open");
        writeln!(stdin, "{request}").expect("observe writes");
        stdin.flush().expect("stdin flushes");
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("observe answers");
        serde_json::from_str(&line).expect("JSON-RPC response")
    }

    /// Close stdin and require a clean exit.
    fn finish(mut self) {
        self.stdin.take();
        let status = self.child.wait().expect("loomd exits");
        if !status.success() {
            let mut stderr = String::new();
            if let Some(mut pipe) = self.child.stderr.take() {
                use std::io::Read;
                let _ = pipe.read_to_string(&mut stderr);
            }
            panic!("loomd exited with {status}: {stderr}");
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.stdin.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ── the positive claim ───────────────────────────────────────────────────────────────────────────

/// **The claim this increment makes.** A write that carries a valid signature from a registered
/// actor commits; the daemon is opened with `Loom::open_production_attested`, so this is
/// authentication, not attribution.
#[test]
fn an_attested_daemon_commits_a_signed_write_from_a_registered_actor() {
    let deployment = Deployment::new();
    let mut session = Session::open(&deployment.environment());
    let agent = &deployment.agent;

    let response = session.observe(AGENT, Some(agent), "obs/erp");
    assert!(
        response["result"]["committed"].is_string(),
        "a signed write from a registered actor must commit: {response}"
    );
    session.finish();
}

/// **The gap, closed.** The same write with no signature is refused — this is exactly what a daemon
/// opened with `Loom::open` would have accepted and recorded as gospel.
#[test]
fn an_unsigned_write_is_refused_by_an_attested_daemon() {
    let deployment = Deployment::new();
    let mut session = Session::open(&deployment.environment());

    let response = session.observe(AGENT, None, "obs/erp");
    let message = response["error"]["message"]
        .as_str()
        .unwrap_or_else(|| panic!("an unsigned write must be refused: {response}"));
    assert!(
        message.contains("is not signed"),
        "the refusal must name the missing signature: {message}"
    );
    session.finish();
}

/// **An unregistered actor is refused, not trusted.** The attacker's move is to pick a name nobody
/// registered and write as a ghost; a real key of the wrong identity does not help.
#[test]
fn an_unregistered_actor_cannot_write_through_an_attested_daemon() {
    let deployment = Deployment::new();
    let mut session = Session::open(&deployment.environment());
    let ghost = key(9);

    let response = session.observe("ghost-agent", Some(&ghost), "obs/erp");
    let message = response["error"]["message"]
        .as_str()
        .unwrap_or_else(|| panic!("an unregistered actor must be refused: {response}"));
    assert!(
        message.contains("no verifying key is registered for actor ghost-agent"),
        "the refusal must name the unregistered actor: {message}"
    );
    session.finish();
}

/// Impersonation: sign with a key you do hold, claim to be the actor you are not. The lookup is by
/// the *claimed* actor, so this fails against the registered key.
#[test]
fn a_signature_from_the_wrong_key_cannot_impersonate_a_registered_actor() {
    let deployment = Deployment::new();
    let mut session = Session::open(&deployment.environment());
    let impostor = key(9);

    let response = session.observe(AGENT, Some(&impostor), "obs/erp");
    let message = response["error"]["message"]
        .as_str()
        .unwrap_or_else(|| panic!("an impersonated write must be refused: {response}"));
    assert!(
        message.contains("does not verify against that actor's registered key"),
        "the refusal must name the failed verification: {message}"
    );
    session.finish();
}

// ── fail-closed startup ──────────────────────────────────────────────────────────────────────────

/// **The core fail-closed property.** A declared registry that cannot be loaded stops startup. It
/// must never become an unauthenticated daemon that serves anyway.
#[test]
fn a_declared_registry_that_cannot_be_loaded_stops_startup() {
    let deployment = Deployment::new();
    std::fs::remove_file(&deployment.registry_file).expect("registry removed");

    let output = start_and_exit(&deployment.environment());
    assert_eq!(
        output.status.code(),
        Some(2),
        "an unloadable registry must stop startup: {output:?}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid actor registry configuration")
            && stderr.contains("cannot inspect LOOM_ACTOR_REGISTRY_FILE"),
        "the refusal must name the registry: {stderr}"
    );
}

/// A registry without its trust root is authentication half-configured. Starting would mean
/// verifying nothing, so the daemon refuses rather than choosing the weaker half.
#[test]
fn a_registry_without_its_governance_trust_root_stops_startup() {
    let deployment = Deployment::new();
    let environment: Vec<_> = deployment
        .environment()
        .into_iter()
        .filter(|(name, _)| *name != "LOOM_ACTOR_GOVERNANCE_KEY_FILE")
        .collect();

    let output = start_and_exit(&environment);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("LOOM_ACTOR_GOVERNANCE_KEY_FILE")
            && stderr.contains("partially configured"),
        "the refusal must name what is missing: {stderr}"
    );
}

/// A registry declared with no durable store would authorize writes to a database that evaporates.
#[test]
fn a_registry_declared_without_a_data_directory_stops_startup() {
    let deployment = Deployment::new();
    let environment: Vec<_> = deployment
        .environment()
        .into_iter()
        .filter(|(name, _)| *name != "LOOM_DATA_DIR")
        .collect();

    let output = start_and_exit(&environment);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("requires the durable store"),
        "{output:?}"
    );
}

/// **Rollback.** An older registry generation is still correctly signed — that is precisely why a
/// floor exists. Revoking an actor and then replaying yesterday's registry must not restore it.
#[test]
fn a_stale_actor_generation_stops_startup() {
    let deployment = Deployment::with(3, 9, |_| {});

    let output = start_and_exit(&deployment.environment());
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("actor registry rollback refused")
            && stderr.contains("minimum generation 9")
            && stderr.contains("attested generation 3"),
        "the refusal must name the rollback and both generations: {stderr}"
    );
}

/// **Substitution.** Adding an actor to a signed registry changes its fingerprint, and the
/// attestation covers the fingerprint.
#[test]
fn a_tampered_registry_stops_startup() {
    let deployment = Deployment::with(7, 7, |document| {
        let intruder = key(9);
        document["actors"]["intruder"] = json!(hex(intruder.verifying_key().as_bytes()));
    });

    let output = start_and_exit(&deployment.environment());
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("actor key registry fingerprint mismatch"),
        "the refusal must name the fingerprint mismatch: {output:?}"
    );
}

/// A forged governance signature is refused before any store file is opened.
#[test]
fn a_forged_governance_signature_stops_startup() {
    let deployment = Deployment::with(7, 7, |document| {
        let signature = document["attestation"]["signature"]
            .as_array_mut()
            .expect("the attestation carries a signature");
        let first = signature[0].as_u64().expect("signature byte");
        signature[0] = json!((first ^ 1) as u8);
    });

    let output = start_and_exit(&deployment.environment());
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("actor registry governance signature is invalid"),
        "the refusal must name the invalid signature: {output:?}"
    );
}

/// The registry belongs to one tenant. Pointing another tenant's daemon at it is refused by the
/// binding governance signed, not by a comparison the daemon could be told to skip.
#[test]
fn a_registry_issued_for_another_tenant_stops_startup() {
    let deployment = Deployment::new();
    let environment: Vec<_> = deployment
        .environment()
        .into_iter()
        .map(|(name, value)| {
            if name == "LOOM_TENANT" {
                (name, "beta-industries".to_string())
            } else {
                (name, value)
            }
        })
        .collect();

    let output = start_and_exit(&environment);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("actor registry attestation tenant mismatch"),
        "the refusal must name the tenant mismatch: {output:?}"
    );
}

/// A floor of zero accepts every generation ever signed, which is the same as having no floor.
#[test]
fn a_rollback_floor_of_zero_stops_startup() {
    let deployment = Deployment::with(7, 0, |_| {});

    let output = start_and_exit(&deployment.environment());
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("must be at least 1"),
        "{output:?}"
    );
}

/// An empty registry is a configuration mistake that would seal the store, not a way to turn
/// authentication off.
#[test]
fn an_empty_registry_stops_startup() {
    let deployment = Deployment::with(7, 7, |document| {
        document["actors"] = json!({});
    });

    let output = start_and_exit(&deployment.environment());
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("registers no actors"),
        "{output:?}"
    );
}

/// Anything that can rewrite the registry can appoint its own writers, so a group-writable registry
/// is refused the same way a group-writable policy file is.
#[cfg(unix)]
#[test]
fn a_group_writable_registry_stops_startup() {
    use std::os::unix::fs::PermissionsExt;

    let deployment = Deployment::new();
    let mut permissions = std::fs::metadata(&deployment.registry_file)
        .expect("registry metadata")
        .permissions();
    permissions.set_mode(0o660);
    std::fs::set_permissions(&deployment.registry_file, permissions).expect("mode set");

    let output = start_and_exit(&deployment.environment());
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("must not be group- or world-writable"),
        "{output:?}"
    );
}

/// A registry reachable through a symlink can be repointed between restarts.
#[cfg(unix)]
#[test]
fn a_symlinked_registry_stops_startup() {
    let deployment = Deployment::new();
    let link = deployment.registry_file.with_extension("link.json");
    std::os::unix::fs::symlink(&deployment.registry_file, &link).expect("symlink");
    let environment: Vec<_> = deployment
        .environment()
        .into_iter()
        .map(|(name, value)| {
            if name == "LOOM_ACTOR_REGISTRY_FILE" {
                (name, path(&link))
            } else {
                (name, value)
            }
        })
        .collect();

    let output = start_and_exit(&environment);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("must be a regular file"),
        "{output:?}"
    );
}

// ── the host-profile criteria, re-proven through the attested path ───────────────────────────────

/// **The restart criterion, attested.** `host_profile.rs` proves a restarted daemon reopens the same
/// committed state with its integrity intact. That must remain true when the store is opened through
/// `Loom::open_production_attested` — a constructor that verifies before it opens is a constructor
/// that could plausibly leave a store half-initialized.
#[test]
fn a_restarted_attested_process_reopens_the_same_store_with_integrity_intact() {
    let deployment = Deployment::new();
    let agent = &deployment.agent;

    let mut first = Session::open(&deployment.environment());
    let branch = first.branch.clone();
    assert!(
        first.observe(AGENT, Some(agent), "obs/erp")["result"]["committed"].is_string(),
        "the first signed write must commit"
    );
    first.finish();

    let reopened =
        Loom::open(&deployment.data_dir, TenantId::new(TENANT)).expect("the store reopens");
    let report = reopened
        .verify_integrity()
        .expect("integrity verification runs");
    assert!(
        report.is_healthy(),
        "an attested store must verify clean after a restart: corrupt={:?} missing={:?} \
         bad_manifests={:?}",
        report.corrupt,
        report.missing,
        report.bad_manifests
    );
    assert!(
        reopened.branch_names().contains(&branch),
        "the branch written before the restart must survive it: {:?}",
        reopened.branch_names()
    );
    drop(reopened);

    // Restart through the attested path and write again: reopening must find the earlier branch,
    // which is what distinguishes "reopened the same store" from "started a fresh one".
    let mut second = Session::open(&deployment.environment());
    let second_branch = second.branch.clone();
    assert_ne!(second_branch, branch, "each session opens its own branch");
    assert!(
        second.observe(AGENT, Some(agent), "obs/crm")["result"]["committed"].is_string(),
        "the second signed write must commit"
    );
    second.finish();

    let after =
        Loom::open(&deployment.data_dir, TenantId::new(TENANT)).expect("the store reopens again");
    assert!(
        after
            .verify_integrity()
            .expect("verification runs")
            .is_healthy(),
        "the store must still verify clean after a second attested restart"
    );
    let names = after.branch_names();
    for expected in [&branch, &second_branch] {
        assert!(
            names.contains(expected),
            "an attested restart must preserve earlier branches, got {names:?}"
        );
    }
}

/// **The ownership criterion, attested.** A second process must not take a store that is already
/// owned, and the attested constructor must not weaken that: attestation happens before the store is
/// opened, so the challenger still loses on the `store.lock` advisory lock.
#[test]
fn a_second_attested_process_cannot_take_a_store_that_is_already_owned() {
    let deployment = Deployment::new();
    let owner = Session::open(&deployment.environment());

    let challenger = start_and_exit(&deployment.environment());
    assert_eq!(
        challenger.status.code(),
        Some(1),
        "the second attested process must fail closed: {challenger:?}"
    );
    let stderr = String::from_utf8_lossy(&challenger.stderr);
    assert!(
        stderr.contains("already open by another process"),
        "the refusal must name the ownership conflict: {stderr}"
    );

    // Releasing the owner releases the lock: ownership is held, not permanently claimed.
    owner.finish();
    let successor = start_and_exit(&deployment.environment());
    assert!(
        successor.status.success(),
        "an attested restart after a clean exit must acquire the store: {successor:?}"
    );
}
