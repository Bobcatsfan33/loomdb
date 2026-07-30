//! Process-boundary tests for the limits that cannot be proven by calling `LoomServer` directly.

use std::io::Write;
use std::process::{Command, Stdio};

use loom_mcp::codes;
use serde_json::{json, Value};

fn run_loomd(input: &[u8], environment: &[(&str, &str)]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_loomd"));
    command
        .env_remove("LOOM_MAX_REQUEST_BYTES")
        .env_remove("LOOM_REQUESTS_PER_SECOND")
        .env_remove("LOOM_REQUEST_BURST")
        .env_remove("LOOM_ALLOW_PERMISSIVE_POLICY")
        .env_remove("LOOM_POLICY_FILE")
        .env_remove("LOOM_OTEL_ENABLED")
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

#[test]
fn oversized_request_is_bounded_drained_and_following_request_survives() {
    let mut input = vec![b'x'; 257];
    input.push(b'\n');
    input.extend_from_slice(
        format!(
            "{}\n",
            json!({"jsonrpc":"2.0","id":7,"method":"initialize","params":{}})
        )
        .as_bytes(),
    );

    let output = run_loomd(
        &input,
        &[
            ("LOOM_MAX_REQUEST_BYTES", "256"),
            ("LOOM_REQUEST_BURST", "10"),
        ],
    );
    assert!(output.status.success(), "{:?}", output);
    let responses = responses(&output);
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["error"]["code"], codes::RESOURCE_EXHAUSTED);
    assert_eq!(responses[1]["id"], 7);
    assert!(responses[1]["result"].is_object());
}

#[test]
fn request_burst_is_rejected_before_engine_entry() {
    let request = format!(
        "{}\n",
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}})
    );
    let output = run_loomd(
        format!("{request}{request}").as_bytes(),
        &[
            ("LOOM_REQUESTS_PER_SECOND", "1"),
            ("LOOM_REQUEST_BURST", "1"),
        ],
    );
    assert!(output.status.success(), "{:?}", output);
    let responses = responses(&output);
    assert!(responses[0]["result"].is_object());
    assert_eq!(responses[1]["error"]["code"], codes::RESOURCE_EXHAUSTED);
}

#[test]
fn invalid_limit_fails_startup_instead_of_falling_back() {
    let output = run_loomd(b"", &[("LOOM_MAX_REQUEST_BYTES", "unbounded")]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("invalid admission configuration"),
        "{:?}",
        output
    );
}

#[test]
fn production_default_denies_and_development_override_is_explicit() {
    let request = format!(
        "{}\n",
        json!({
            "jsonrpc":"2.0",
            "id":1,
            "method":"tools/call",
            "params":{"name":"action.propose","arguments":{
                "action":"identity.suspend_account",
                "target":"u1",
                "evidence_label":"VerifiedSystem"
            }}
        })
    );
    let denied = run_loomd(request.as_bytes(), &[]);
    assert_eq!(responses(&denied)[0]["result"]["would_be_permitted"], false);

    let allowed = run_loomd(
        request.as_bytes(),
        &[("LOOM_ALLOW_PERMISSIVE_POLICY", "true")],
    );
    assert_eq!(responses(&allowed)[0]["result"]["would_be_permitted"], true);
    assert!(String::from_utf8_lossy(&allowed.stderr).contains("WARNING"));
}

#[test]
fn reviewed_policy_file_drives_the_runtime_and_conflicting_bypass_is_refused() {
    let mut policy = tempfile::NamedTempFile::new().unwrap();
    write!(
        policy,
        "{}",
        json!({
            "version":"approved-2026-07",
            "rules":[{
                "actor":"Any",
                "label":"Any",
                "purpose":"Any",
                "action":"Any",
                "effect":"Allow"
            }]
        })
    )
    .unwrap();
    policy.flush().unwrap();
    let path = policy.path().to_str().unwrap();
    let request = format!(
        "{}\n",
        json!({
            "jsonrpc":"2.0",
            "id":1,
            "method":"tools/call",
            "params":{"name":"action.propose","arguments":{
                "action":"identity.suspend_account",
                "target":"u1",
                "evidence_label":"VerifiedSystem"
            }}
        })
    );

    let allowed = run_loomd(request.as_bytes(), &[("LOOM_POLICY_FILE", path)]);
    assert!(allowed.status.success(), "{:?}", allowed);
    assert_eq!(responses(&allowed)[0]["result"]["would_be_permitted"], true);

    let conflict = run_loomd(
        b"",
        &[
            ("LOOM_POLICY_FILE", path),
            ("LOOM_ALLOW_PERMISSIVE_POLICY", "true"),
        ],
    );
    assert_eq!(conflict.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&conflict.stderr).contains("mutually exclusive"));
}

#[cfg(unix)]
#[test]
fn policy_loader_refuses_symlinks_and_group_writable_files() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let directory = tempfile::tempdir().unwrap();
    let policy_path = directory.path().join("policy.json");
    std::fs::write(&policy_path, br#"{"version":"v1","rules":[]}"#).unwrap();
    let link_path = directory.path().join("policy-link.json");
    symlink(&policy_path, &link_path).unwrap();

    let symlinked = run_loomd(b"", &[("LOOM_POLICY_FILE", link_path.to_str().unwrap())]);
    assert_eq!(symlinked.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&symlinked.stderr).contains("regular file"));

    let mut permissions = std::fs::metadata(&policy_path).unwrap().permissions();
    permissions.set_mode(0o660);
    std::fs::set_permissions(&policy_path, permissions).unwrap();
    let writable = run_loomd(b"", &[("LOOM_POLICY_FILE", policy_path.to_str().unwrap())]);
    assert_eq!(writable.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&writable.stderr).contains("group- or world-writable"));
}
