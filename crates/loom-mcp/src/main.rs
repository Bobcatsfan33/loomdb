//! The `loomd` binary: a JSON-RPC-over-stdio loop.
//!
//! One line in, one line out — newline-delimited JSON, the simplest transport MCP allows. The engine
//! is in-process; this is a single-tenant daemon. Real deployments put a transport and a tenant router
//! in front of it, but the protocol surface an agent sees is exactly what this serves.

use std::io::{BufRead, Write};
use std::sync::Arc;

use loom_action::ActionGateway;
use loom_branch::Loom;
use loom_core::TenantId;
use loom_mcp::{LoomServer, Request, Response};
use loom_policy::{Effect, Engine, Match, PolicyRule, PolicySet};

fn main() -> std::io::Result<()> {
    // A permissive default policy for the bare daemon; a real deployment loads a real policy set.
    let policy = Engine::new(&PolicySet::new(
        "loomd-default",
        vec![PolicyRule {
            actor: Match::Any,
            label: Match::Any,
            purpose: Match::Any,
            action: Match::Any,
            effect: Effect::Allow,
        }],
    ));
    let tenant = std::env::var("LOOM_TENANT").unwrap_or_else(|_| "default".into());
    let db = match Loom::in_memory(TenantId::new(tenant.as_str())) {
        Ok(db) => Arc::new(db),
        Err(e) => {
            eprintln!("loomd: could not open engine: {e}");
            std::process::exit(1);
        }
    };
    let gateway = ActionGateway::new(tenant.clone(), Engine::new(&PolicySet::empty("gw")));
    let server = LoomServer::new(db, policy, gateway, tenant, 1_700_000_000_000);

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(req) => server.handle(&req),
            Err(e) => Response::err(
                None,
                loom_mcp::codes::INVALID_REQUEST,
                format!("bad JSON-RPC: {e}"),
            ),
        };
        let out = serde_json::to_string(&response).unwrap_or_else(|_| "{}".into());
        writeln!(stdout, "{out}")?;
        stdout.flush()?;
    }
    Ok(())
}
