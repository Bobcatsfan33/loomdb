//! The `loomd` binary: a JSON-RPC-over-stdio loop.
//!
//! One line in, one line out — newline-delimited JSON, the simplest transport MCP allows. The engine
//! is in-process; this is a single-tenant daemon. Real deployments put a transport and a tenant router
//! in front of it, but the protocol surface an agent sees is exactly what this serves.

use std::io::{BufReader, Write};
use std::sync::Arc;

use loom_action::ActionGateway;
use loom_branch::Loom;
use loom_core::TenantId;
#[cfg(feature = "observability")]
use loom_mcp::OtlpTelemetry;
use loom_mcp::{
    read_bounded_line, AdmissionConfig, AdmissionController, BoundedLine, LoomServer, Request,
    Response,
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
    let db = match Loom::in_memory(TenantId::new(tenant.as_str())) {
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
