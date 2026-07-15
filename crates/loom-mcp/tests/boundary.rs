//! **AT-019 and AT-027, re-proven at the MCP front door.**
//!
//! Both were written to hold "through every API surface including MCP". The MCP server is a new front
//! door and exactly the place a guarantee proven at the store could leak. These tests drive the server
//! the way an agent client does — real JSON-RPC `tools/call` messages, serialized and parsed — and
//! check that the locks hold through the door, not just behind it.

use std::sync::Arc;

use loom_action::ActionGateway;
use loom_branch::Loom;
use loom_core::TenantId;
use loom_mcp::{codes, LoomServer, Request};
use loom_policy::{Effect, Engine, Match, PolicyRule, PolicySet};
use serde_json::{json, Value};

fn allow_all() -> Engine {
    Engine::new(&PolicySet::new(
        "v1",
        vec![PolicyRule {
            actor: Match::Any,
            label: Match::Any,
            purpose: Match::Any,
            action: Match::Any,
            effect: Effect::Allow,
        }],
    ))
}

fn server() -> LoomServer {
    let db = Arc::new(
        Loom::in_memory(TenantId::new("acme"))
            .unwrap()
            .with_clock(|| 1_700_000_000_000),
    );
    let gw = ActionGateway::new("acme", Engine::new(&PolicySet::empty("gw")));
    LoomServer::new(db, allow_all(), gw, "acme", 1_700_000_000_000)
}

/// Send a JSON-RPC request the way a client does: serialize, cross the boundary, parse the response.
fn rpc(server: &LoomServer, method: &str, params: Value) -> Value {
    let wire = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
    let req: Request = serde_json::from_str(&wire).expect("valid JSON-RPC");
    let resp = server.handle(&req);
    serde_json::to_value(&resp).unwrap()
}

fn call(server: &LoomServer, tool: &str, args: Value) -> Value {
    rpc(
        server,
        "tools/call",
        json!({"name": tool, "arguments": args}),
    )
}

/// **AT-027 through MCP: there is no execute tool in the agent's menu.**
#[test]
fn at_027_no_execute_tool_is_exposed_over_mcp() {
    let s = server();
    let listed = rpc(&s, "tools/list", json!({}));
    let tools = listed["result"]["tools"].as_array().expect("a tool list");
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();

    // The agent can propose.
    assert!(
        names.contains(&"action.propose"),
        "an agent must be able to propose"
    );

    // The agent CANNOT execute — no tool with 'execute' or 'act' in its name exists.
    for n in &names {
        assert!(
            !n.contains("execute") && *n != "action.execute" && *n != "act",
            "AT-027: the MCP surface exposed an execution tool ('{n}'). An agent must not be able to act."
        );
    }

    // And asking for it by name is refused like any unknown tool — no hidden door.
    let denied = call(
        &s,
        "action.execute",
        json!({"action": "identity.suspend_account", "target": "u1"}),
    );
    assert!(
        denied["error"].is_object(),
        "action.execute must not resolve to anything"
    );
    assert_eq!(denied["error"]["code"], codes::METHOD_NOT_FOUND);
}

/// **AT-019 through MCP: a token cannot reach a branch outside its scope.**
#[test]
fn at_019_a_token_out_of_scope_is_refused_over_mcp() {
    let s = server();

    // Open a session → get a token scoped to that session's branch.
    let opened = call(&s, "session.open", json!({}));
    let token = opened["result"]["token"].clone();
    let branch = opened["result"]["branch"].as_str().unwrap().to_string();

    // Writing on the session's own branch: allowed.
    let ok = call(
        &s,
        "observe",
        json!({"token": token, "branch": branch, "key": "obs/1", "system": "web",
               "source": "s", "trust": "Untrusted", "text": "hi", "session": "s"}),
    );
    assert!(
        ok["result"].is_object(),
        "a write on the token's own branch must succeed: {ok}"
    );

    // Writing on a DIFFERENT branch the token does not cover: refused, through the door.
    let denied = call(
        &s,
        "observe",
        json!({"token": token, "branch": "some-other-branch", "key": "obs/2", "system": "web",
               "source": "s", "trust": "Untrusted", "text": "hi", "session": "s"}),
    );
    assert!(
        denied["error"].is_object(),
        "AT-019: a token must not reach a branch outside its scope, even through MCP: {denied}"
    );
    assert_eq!(
        denied["error"]["code"],
        codes::DENIED,
        "and it is a DENIED decision, not a protocol error"
    );
}

/// **Every data tool requires a token. A tokenless call is refused, not silently run.**
#[test]
fn a_data_tool_without_a_token_is_refused() {
    let s = server();
    let no_token = call(
        &s,
        "observe",
        json!({"branch": "main", "key": "k", "system": "w", "source": "s", "trust": "Untrusted"}),
    );
    assert!(
        no_token["error"].is_object(),
        "a data tool with no token must be refused"
    );
    assert_eq!(no_token["error"]["code"], codes::INVALID_PARAMS);
}
