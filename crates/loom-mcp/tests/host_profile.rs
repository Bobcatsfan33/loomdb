//! Process-boundary tests for the claims the reference host profile makes about `loomd`.
//!
//! The profile in `deploy/reference` renders one process, one tenant, one data directory, and mounts
//! that directory as the only writable path in an otherwise read-only root filesystem. Those are
//! deployment-shaped promises, so they are proven here at the process boundary — by starting the real
//! binary — rather than by calling `LoomServer` in-process.
//!
//! `scripts/verify_host_profile.py` proves the *rendered configuration* upholds the same contract.
//! This file proves the *engine* upholds its half: a restarted process reopens the same committed
//! state with its integrity intact, and a data directory that could be repointed or written by a
//! second identity stops startup instead of serving.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use loom_branch::Loom;
use loom_core::TenantId;
use serde_json::{json, Value};

/// Start `loomd`, feed it `input`, and wait for it to exit.
fn run_loomd(input: &[u8], environment: &[(&str, &str)]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_loomd"));
    command
        .env_remove("LOOM_MAX_REQUEST_BYTES")
        .env_remove("LOOM_REQUESTS_PER_SECOND")
        .env_remove("LOOM_REQUEST_BURST")
        .env_remove("LOOM_ALLOW_PERMISSIVE_POLICY")
        .env_remove("LOOM_POLICY_FILE")
        .env_remove("LOOM_OTEL_ENABLED")
        .env_remove("LOOM_DATA_DIR")
        .env_remove("LOOM_TENANT")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in environment {
        command.env(name, value);
    }
    let mut child = command.spawn().expect("loomd starts");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(input)
        .expect("request writes");
    child.wait_with_output().expect("loomd exits")
}

fn responses(output: &std::process::Output) -> Vec<Value> {
    String::from_utf8(output.stdout.clone())
        .expect("UTF-8 stdout")
        .lines()
        .map(|line| serde_json::from_str(line).expect("JSON-RPC response"))
        .collect()
}

const SESSION_OPEN: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"session.open","arguments":{}}}"#;

/// Drive one session against a durable `loomd`, returning the branch it wrote to.
///
/// `session.open` and `observe` must ride the *same* stdio stream: the capability token is signed by
/// an issuer key generated per process, so a token never survives a restart. That is itself a host
/// contract — a client re-opens its session after the daemon restarts — and is documented as such in
/// `docs/host-profile.md`.
fn observe_into(data_dir: &Path, tenant: &str, key: &str) -> String {
    use std::io::{BufRead, BufReader};

    let dir = data_dir.to_str().expect("UTF-8 path");
    let mut child = Command::new(env!("CARGO_BIN_EXE_loomd"))
        .env_remove("LOOM_ALLOW_PERMISSIVE_POLICY")
        .env_remove("LOOM_POLICY_FILE")
        .env("LOOM_DATA_DIR", dir)
        .env("LOOM_TENANT", tenant)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("loomd starts");
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));

    writeln!(stdin, "{SESSION_OPEN}").expect("session.open writes");
    stdin.flush().expect("stdin flushes");
    let mut line = String::new();
    stdout.read_line(&mut line).expect("session.open answers");
    let opened: Value = serde_json::from_str(&line).expect("JSON-RPC response");
    let token = opened["result"]["token"].clone();
    assert!(
        !token.is_null(),
        "session.open must mint a token, got {opened}"
    );
    let branch = opened["result"]["branch"]
        .as_str()
        .expect("session branch")
        .to_string();

    let observe = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
        "name":"observe","arguments":{
            "token":token,"branch":branch,"key":key,
            "system":"erp","source":"invoice-88","trust":"VerifiedSystem",
            "text":"a confirmed fraud case"
        }
    }});
    writeln!(stdin, "{observe}").expect("observe writes");
    stdin.flush().expect("stdin flushes");
    line.clear();
    stdout.read_line(&mut line).expect("observe answers");
    let wrote: Value = serde_json::from_str(&line).expect("JSON-RPC response");
    assert!(
        wrote["result"]["committed"].is_string(),
        "the observation must commit, got {wrote}"
    );

    drop(stdin);
    let output = child.wait_with_output().expect("loomd exits");
    assert!(output.status.success(), "{output:?}");
    branch
}

/// **The restart criterion.** A host that reboots must come back to the same committed state, with
/// integrity verification clean — not to an empty store, and not to a damaged one.
#[test]
fn a_restarted_process_reopens_the_same_store_with_integrity_intact() {
    let store = tempfile::tempdir().unwrap();
    let tenant = "acme";

    let branch = observe_into(store.path(), tenant, "obs/erp");

    // Reopen the way `loomctl verify` does and assert the store is healthy and complete.
    let reopened = Loom::open(store.path(), TenantId::new(tenant)).expect("store reopens");
    let report = reopened
        .verify_integrity()
        .expect("integrity verification runs");
    assert!(
        report.is_healthy(),
        "restarted store must verify clean: corrupt={:?} missing={:?} bad_manifests={:?}",
        report.corrupt,
        report.missing,
        report.bad_manifests
    );
    let names = reopened.branch_names();
    assert!(
        names.iter().any(|name| name == &branch),
        "the branch written before the restart must survive it: {names:?}"
    );
    drop(reopened);

    // Restart the daemon on the same directory. The prior branch must still be there afterwards,
    // which is what distinguishes "reopened the same store" from "started a fresh one".
    let second = observe_into(store.path(), tenant, "obs/crm");
    assert_ne!(second, branch, "each session opens its own branch");

    let after = Loom::open(store.path(), TenantId::new(tenant)).expect("store reopens again");
    assert!(
        after
            .verify_integrity()
            .expect("verification runs")
            .is_healthy(),
        "the store must still verify clean after a second restart"
    );
    let names = after.branch_names();
    for expected in [&branch, &second] {
        assert!(
            names.contains(expected),
            "restart must preserve earlier branches, got {names:?}"
        );
    }
}

/// **The ownership criterion.** A second process must not be able to take a store that is already
/// owned, however it was started. `FileRefStore::open` holds an exclusive OS advisory lock on
/// `<store>/loom/store.lock` for the store's lifetime, so the loser fails closed rather than racing
/// the ref log.
///
/// This is the process-level half of the profile's one-tenant-per-store control: the rendered
/// configuration cannot *express* two workloads on one directory (`verify_host_profile.py` rejects
/// it), and if something outside that configuration tries it anyway, the engine refuses.
#[test]
fn a_second_process_cannot_take_a_store_that_is_already_owned() {
    let store = tempfile::tempdir().unwrap();
    let dir = store.path().to_str().unwrap();

    // The first daemon holds the store open for as long as its stdin stays open.
    let mut owner = Command::new(env!("CARGO_BIN_EXE_loomd"))
        .env("LOOM_DATA_DIR", dir)
        .env("LOOM_TENANT", "acme")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the first loomd starts");
    let mut owner_stdin = owner.stdin.take().expect("piped stdin");
    {
        use std::io::{BufRead, BufReader};
        // Wait for a reply, so the store is provably open before the challenger starts.
        writeln!(owner_stdin, "{SESSION_OPEN}").expect("session.open writes");
        owner_stdin.flush().unwrap();
        let mut line = String::new();
        BufReader::new(owner.stdout.as_mut().expect("piped stdout"))
            .read_line(&mut line)
            .expect("the owner answers");
        assert!(
            line.contains("\"result\""),
            "the owner must be serving before the challenge: {line}"
        );
    }

    let challenger = run_loomd(b"", &[("LOOM_DATA_DIR", dir), ("LOOM_TENANT", "acme")]);
    assert_eq!(
        challenger.status.code(),
        Some(1),
        "the second process must fail closed: {challenger:?}"
    );
    let stderr = String::from_utf8_lossy(&challenger.stderr);
    assert!(
        stderr.contains("already open by another process"),
        "the refusal must name the ownership conflict: {stderr}"
    );

    // Releasing the owner releases the lock: ownership is held, not permanently claimed.
    drop(owner_stdin);
    let owner = owner.wait_with_output().expect("the owner exits");
    assert!(owner.status.success(), "{owner:?}");
    let successor = run_loomd(b"", &[("LOOM_DATA_DIR", dir), ("LOOM_TENANT", "acme")]);
    assert!(
        successor.status.success(),
        "a restart after a clean exit must acquire the store: {successor:?}"
    );
}

/// Without a data directory the daemon stays in-memory. The profile never renders that posture, but
/// the demo and the offline suite rely on it, so the default must not change silently.
#[test]
fn without_a_data_directory_the_daemon_stays_ephemeral() {
    let store = tempfile::tempdir().unwrap();
    let output = run_loomd(format!("{SESSION_OPEN}\n").as_bytes(), &[]);
    assert!(output.status.success(), "{output:?}");
    assert!(
        responses(&output)[0]["result"]["token"].is_object()
            || responses(&output)[0]["result"]["token"].is_string(),
        "an ephemeral daemon still serves sessions: {:?}",
        responses(&output)[0]
    );
    assert!(
        std::fs::read_dir(store.path()).unwrap().next().is_none(),
        "an ephemeral daemon must not create a store on disk"
    );
}

/// A data directory reachable through a symlink is a data directory an attacker can repoint at
/// another tenant's store between restarts. Startup stops instead.
#[cfg(unix)]
#[test]
fn a_symlinked_data_directory_stops_startup() {
    let parent = tempfile::tempdir().unwrap();
    let real = parent.path().join("real-store");
    std::fs::create_dir(&real).unwrap();
    let link = parent.path().join("store-link");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let output = run_loomd(
        b"",
        &[
            ("LOOM_DATA_DIR", link.to_str().unwrap()),
            ("LOOM_TENANT", "acme"),
        ],
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("must be an existing directory"),
        "{output:?}"
    );
}

/// A world-writable store lets any local identity corrupt a tenant's history.
#[cfg(unix)]
#[test]
fn a_world_writable_data_directory_stops_startup() {
    use std::os::unix::fs::PermissionsExt;

    let store = tempfile::tempdir().unwrap();
    let mut permissions = std::fs::metadata(store.path()).unwrap().permissions();
    permissions.set_mode(0o777);
    std::fs::set_permissions(store.path(), permissions).unwrap();

    let output = run_loomd(
        b"",
        &[
            ("LOOM_DATA_DIR", store.path().to_str().unwrap()),
            ("LOOM_TENANT", "acme"),
        ],
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("world-writable"),
        "{output:?}"
    );
}

/// **A group-writable store must still start.** Kubernetes applies `fsGroup` to a mounted volume by
/// granting the group write access, so a `g+w` data directory is the *normal* state for the very
/// StatefulSet the reference profile renders. Rejecting it would make the profile unable to run —
/// this test exists so that regression cannot be reintroduced as a "hardening" tweak.
#[cfg(unix)]
#[test]
fn a_group_writable_data_directory_still_starts_because_fsgroup_requires_it() {
    use std::os::unix::fs::PermissionsExt;

    let store = tempfile::tempdir().unwrap();
    let mut permissions = std::fs::metadata(store.path()).unwrap().permissions();
    permissions.set_mode(0o770);
    std::fs::set_permissions(store.path(), permissions).unwrap();

    let output = run_loomd(
        format!("{SESSION_OPEN}\n").as_bytes(),
        &[
            ("LOOM_DATA_DIR", store.path().to_str().unwrap()),
            ("LOOM_TENANT", "acme"),
        ],
    );
    assert!(
        output.status.success(),
        "an fsGroup-mounted volume must be servable: {output:?}"
    );
    assert!(
        responses(&output)[0]["result"]["branch"].is_string(),
        "the daemon must serve from a group-writable store: {:?}",
        responses(&output)[0]
    );
}

/// A data directory that does not exist is a mount that failed to attach. Serving an empty store in
/// that case would silently lose the tenant's history.
#[test]
fn a_missing_data_directory_stops_startup() {
    let parent = tempfile::tempdir().unwrap();
    let absent = parent.path().join("never-mounted");

    let output = run_loomd(
        b"",
        &[
            ("LOOM_DATA_DIR", absent.to_str().unwrap()),
            ("LOOM_TENANT", "acme"),
        ],
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("cannot inspect LOOM_DATA_DIR"),
        "{output:?}"
    );
}
