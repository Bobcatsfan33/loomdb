//! The LoomDB MCP server: the engine, behind the front door.
//!
//! # The two structural guarantees, re-asserted at this surface
//!
//! - **AT-019 — token scope is inescapable, *through MCP too*.** Every data tool takes a `token` and
//!   passes it to the same engine method that authorises a direct call. There is no tool that reaches
//!   a page without a token, and a token out of scope is refused here exactly as it is at the store.
//! - **AT-027 — an agent cannot act, *through MCP too*.** `tools/list` — the agent's whole menu — has
//!   **no execute tool**. An agent can `action.propose`; it cannot execute. Execution is
//!   [`LoomServer::approve_and_execute`], an operator path that is *not a tool* and does not appear in
//!   the agent's tool list, so an agent driving `tools/call` cannot find or reach it.

use std::sync::Arc;

use loom_action::{ActionGateway, ActionRecord, AgentStore};
use loom_branch::{CapabilityToken, Loom, MergePolicy};
use loom_core::{
    ActorId, BranchId, Claim, ClaimId, Confidence, IndexHint, Interval, Method, Observation,
    ObservationId, Record, SessionId, SourceRef, Timestamp, TrustClass, Value, WriteEnvelope,
};
use loom_memory::{RetrievalQuery, Retriever};
use loom_policy::{may_pack, Engine};
use loom_provenance::Provenance;
use serde_json::{json, Value as Json};

use crate::protocol::{codes, Request, Response};

/// The server. One tenant, one engine, one policy, one gateway.
pub struct LoomServer {
    db: Arc<Loom>,
    policy: Engine,
    gateway: ActionGateway,
    tenant: String,
    now: u64,
}

impl LoomServer {
    /// Build a server over an engine.
    pub fn new(
        db: Arc<Loom>,
        policy: Engine,
        gateway: ActionGateway,
        tenant: impl Into<String>,
        now: u64,
    ) -> Self {
        LoomServer {
            db,
            policy,
            gateway,
            tenant: tenant.into(),
            now,
        }
    }

    /// The engine, for the operator paths that are not agent tools.
    pub fn db(&self) -> &Arc<Loom> {
        &self.db
    }

    /// The gateway, for the operator execution path.
    pub fn gateway(&self) -> &ActionGateway {
        &self.gateway
    }

    /// The tenant this server serves. One server, one tenant — the outermost isolation boundary, and
    /// the reason a cross-tenant identifier request (AT-039) cannot even be *named* here: another
    /// tenant's data is in another pool, reachable only through another server.
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// **Handle one JSON-RPC request.** This is the whole MCP surface an agent can reach.
    pub fn handle(&self, req: &Request) -> Response {
        let id = req.id.clone();
        match req.method.as_str() {
            "initialize" => Response::ok(
                id,
                json!({
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": "loomd", "version": env!("CARGO_PKG_VERSION")},
                    "capabilities": {"tools": {}}
                }),
            ),
            "tools/list" => Response::ok(id, json!({ "tools": Self::tool_list() })),
            "tools/call" => self.call_tool(req),
            other => Response::err(
                id,
                codes::METHOD_NOT_FOUND,
                format!("no such method '{other}'"),
            ),
        }
    }

    /// **The agent's entire menu.** Note what is *not* here: no `action.execute`, no `admin.*`, nothing
    /// that performs an external effect. This list IS the AT-027 boundary at the MCP surface.
    fn tool_list() -> Vec<Json> {
        let tool = |name: &str, desc: &str| json!({"name": name, "description": desc});
        vec![
            tool(
                "session.open",
                "Open a session (forks the tenant base). Returns a session and a capability token.",
            ),
            tool(
                "observe",
                "Ingest an observation from a source with a trust class.",
            ),
            tool(
                "branch.create",
                "Fork the current branch into a named hypothesis.",
            ),
            tool(
                "claim.assert",
                "Assert a claim, derived from what the session has read.",
            ),
            tool("read", "Read a record by key on a branch."),
            tool(
                "retrieve",
                "Retrieve memory for a purpose, influence-filtered, packed to a budget.",
            ),
            tool(
                "branch.merge",
                "Merge a branch into another, at record granularity.",
            ),
            tool(
                "branch.rewind",
                "Rewind a branch to a prior commit. Auditable, not destroyed.",
            ),
            tool(
                "action.propose",
                "PROPOSE an action. Returns a decision. Does not execute — only the gateway acts.",
            ),
            tool(
                "audit.taint",
                "Taint a source: a dry-run recall plan, irreversible actions first.",
            ),
        ]
    }

    fn call_tool(&self, req: &Request) -> Response {
        let id = req.id.clone();
        let name = match req.params.get("name").and_then(Json::as_str) {
            Some(n) => n,
            None => return Response::err(id, codes::INVALID_PARAMS, "tools/call needs a 'name'"),
        };
        let args = req.params.get("arguments").cloned().unwrap_or(json!({}));

        let result = match name {
            "session.open" => self.t_session_open(&args),
            "observe" => self.t_observe(&args),
            "branch.create" => self.t_branch_create(&args),
            "claim.assert" => self.t_claim_assert(&args),
            "read" => self.t_read(&args),
            "retrieve" => self.t_retrieve(&args),
            "branch.merge" => self.t_merge(&args),
            "branch.rewind" => self.t_rewind(&args),
            "action.propose" => self.t_action_propose(&args),
            "audit.taint" => self.t_taint(&args),
            // The one that MUST NOT exist for an agent. If a client asks for it by name, it is told the
            // same thing as any other unknown tool — there is no hidden execute.
            other => {
                return Response::err(
                    id,
                    codes::METHOD_NOT_FOUND,
                    format!("no such tool '{other}'"),
                )
            }
        };

        match result {
            Ok(v) => Response::ok(id, v),
            Err(ToolError::Denied(m)) => Response::err(id, codes::DENIED, m),
            Err(ToolError::BadArgs(m)) => Response::err(id, codes::INVALID_PARAMS, m),
        }
    }

    // ── tools ─────────────────────────────────────────────────────────────────────────────────────

    fn t_session_open(&self, _args: &Json) -> ToolResult {
        let (handle, token) = self.db.open_session().map_err(denied)?;
        Ok(json!({
            "session": handle.id.as_str(),
            "branch": handle.branch.as_str(),
            "token": token,
        }))
    }

    fn t_observe(&self, args: &Json) -> ToolResult {
        let token = parse_token(args)?;
        let branch = BranchId::new(arg_str(args, "branch")?);
        let key = arg_str(args, "key")?.as_bytes().to_vec();
        let source = SourceRef::new(arg_str(args, "system")?, arg_str(args, "source")?);
        let trust = parse_trust(arg_str(args, "trust")?)?;
        let text = arg_str(args, "text").unwrap_or_default();

        let record = Record::Observation(Box::new(Observation {
            id: ObservationId::of(key.as_slice()),
            source,
            trust,
            observed_at: None,
            ingested_at: Timestamp::from_ms(self.now),
            payload: text.as_bytes().to_vec(),
        }));
        let env = self.envelope(args, &branch, "observe")?;
        let commit = self
            .db
            .write_indexed(&token, &branch, key, record, IndexHint::text(text), &env)
            .map_err(denied)?;
        Ok(json!({ "committed": commit.to_hex() }))
    }

    fn t_branch_create(&self, args: &Json) -> ToolResult {
        let token = parse_token(args)?;
        let from = BranchId::new(arg_str(args, "from")?);
        let name = arg_str(args, "name")?;
        let (branch, new_token) = self.db.branch(&token, &from, name).map_err(denied)?;
        Ok(json!({ "branch": branch.as_str(), "token": new_token }))
    }

    fn t_claim_assert(&self, args: &Json) -> ToolResult {
        let token = parse_token(args)?;
        let branch = BranchId::new(arg_str(args, "branch")?);
        let key = arg_str(args, "key")?.as_bytes().to_vec();
        let subject = arg_str(args, "subject")?;
        let predicate = arg_str(args, "predicate")?;
        let text = arg_str(args, "text").unwrap_or_default();
        let evidence: Vec<SourceRef> = args
            .get("evidence")
            .and_then(Json::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|e| {
                        Some(SourceRef::new(
                            e.get("system")?.as_str()?,
                            e.get("source")?.as_str()?,
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();

        let claim = Claim {
            id: ClaimId::of(key.as_slice()),
            predicate: predicate.to_string(),
            subject: subject.to_string(),
            object: Value::Text(text.to_string()),
            valid: Interval::from(Timestamp::from_ms(self.now)),
            known: Interval::from(Timestamp::from_ms(self.now)),
            confidence: Confidence::new(0.9, Method::Rule, "v1"),
            evidence,
            status: loom_core::ClaimStatus::Asserted,
            policy: None,
            actor: ActorId::new(arg_str(args, "actor").unwrap_or("agent")),
        };
        let env = self.envelope(args, &branch, "claim")?;
        let commit = self
            .db
            .write_indexed(
                &token,
                &branch,
                key,
                Record::Claim(Box::new(claim)),
                IndexHint::text(text),
                &env,
            )
            .map_err(denied)?;
        Ok(json!({ "committed": commit.to_hex() }))
    }

    fn t_read(&self, args: &Json) -> ToolResult {
        let token = parse_token(args)?;
        let branch = BranchId::new(arg_str(args, "branch")?);
        let key = arg_str(args, "key")?.as_bytes().to_vec();
        let found = self.db.read(&token, &branch, &key).map_err(denied)?;
        Ok(json!({ "found": found.is_some(), "kind": found.as_ref().map(record_kind) }))
    }

    fn t_retrieve(&self, args: &Json) -> ToolResult {
        let token = parse_token(args)?;
        let branch = BranchId::new(arg_str(args, "branch")?);
        let query_text = arg_str(args, "query")?;
        let purpose = arg_str(args, "purpose").unwrap_or("internal");
        let budget = args.get("budget").and_then(Json::as_u64).unwrap_or(1000) as u32;
        let actor = arg_str(args, "actor").unwrap_or("agent").to_string();

        let retr = Retriever::new(&self.db);
        let query = RetrievalQuery::text(query_text, budget);
        // Influence filter, BEFORE packing (AT-036): restricted candidates never enter the window.
        let packed = retr
            .retrieve_filtered(&token, &branch, &query, &|entry| {
                may_pack(&self.policy, &actor, purpose, entry)
            })
            .map_err(denied)?;

        Ok(json!({
            "items": packed.items.iter().map(|i| json!({
                "key": String::from_utf8_lossy(&i.key),
                "text": i.text,
                "stale": i.stale,
                "citations": i.citations.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "used_tokens": packed.used_tokens,
            "dropped_for_budget": packed.dropped_for_budget,
        }))
    }

    fn t_merge(&self, args: &Json) -> ToolResult {
        let token = parse_token(args)?;
        let source = BranchId::new(arg_str(args, "source")?);
        let target = BranchId::new(arg_str(args, "target")?);
        let env = self.envelope(args, &target, "merge")?;
        let result = self
            .db
            .merge(&token, &source, &target, &MergePolicy::Conflict, &env)
            .map_err(denied)?;
        Ok(json!({ "outcome": format!("{result:?}") }))
    }

    fn t_rewind(&self, args: &Json) -> ToolResult {
        let token = parse_token(args)?;
        let branch = BranchId::new(arg_str(args, "branch")?);
        let to = arg_str(args, "to")?;
        let commit = loom_core::CommitId::from_hex(to)
            .map_err(|_| ToolError::BadArgs("'to' is not a valid commit id".into()))?;
        self.db.rewind(&token, &branch, &commit).map_err(denied)?;
        Ok(json!({ "rewound_to": to }))
    }

    /// **Propose an action. Does not execute.** This is the AT-027 boundary in a single method: the
    /// most an agent can do to the outside world through MCP is ask. The response is the gateway's
    /// *decision* — and for an injection (Untrusted evidence → suspend), that decision is a refusal.
    fn t_action_propose(&self, args: &Json) -> ToolResult {
        let action_type = arg_str(args, "action")?;
        let target = arg_str(args, "target")?;
        let label = parse_trust(arg_str(args, "evidence_label").unwrap_or("Untrusted"))?;
        let actor = arg_str(args, "actor").unwrap_or("agent");

        // The influence check (AT-034), surfaced without executing: would policy permit this?
        let decision = loom_policy::may_authorize_action(&self.policy, actor, action_type, label);
        Ok(json!({
            "proposed": true,
            "action": action_type,
            "target": target,
            "would_be_permitted": decision.decision.is_allowed(),
            "rationale": decision.rationale,
            "note": "proposed only. An agent cannot execute; the gateway acts after approval.",
        }))
    }

    fn t_taint(&self, args: &Json) -> ToolResult {
        let system = arg_str(args, "system")?;
        let source_id = arg_str(args, "source")?;
        let source = SourceRef::new(system, source_id);
        let executed: Vec<_> = self
            .gateway
            .records()
            .iter()
            .filter_map(|r| r.to_executed())
            .collect();
        let prov = Provenance::new(&self.db);
        let (plan, _) = prov
            .taint_with_actions(&source, &executed)
            .map_err(denied)?;
        Ok(json!({
            "irreversible": plan.irreversible.iter().map(|i| json!({
                "action": i.action_type,
                "target": i.target,
                "receipt": i.receipt,
                "compensating_action": i.compensating_action,
                "escalation": i.escalation,
            })).collect::<Vec<_>>(),
            "reversible_count": plan.reversible.len(),
            "report": plan.to_string(),
        }))
    }

    /// **The operator execution path. NOT a tool.** It never appears in `tools/list`, so an agent
    /// driving `tools/call` cannot reach it. Executing an approved proposal is the gateway's job, and
    /// this is how loomd's operator surface — a human, an approval workflow — reaches it. Keeping it off
    /// the tool list is AT-027: the door exists, but not in the room the agent is in.
    pub fn approve_and_execute(&self, proposal: &loom_action::Proposal) -> ActionRecord {
        self.gateway.execute(proposal)
    }

    /// Build an agent handle for the operator path.
    pub fn agent_on(&self, branch: &str, simulation: bool) -> AgentStore {
        AgentStore::new(ActorId::new("agent"), branch, simulation)
    }

    fn envelope(
        &self,
        args: &Json,
        branch: &BranchId,
        intent: &str,
    ) -> Result<WriteEnvelope, ToolError> {
        let session = SessionId::new(arg_str(args, "session").unwrap_or("s"));
        let actor = ActorId::new(arg_str(args, "actor").unwrap_or("agent"));
        Ok(WriteEnvelope::new(actor, session, branch.clone(), intent))
    }
}

// ── small helpers ─────────────────────────────────────────────────────────────────────────────────

enum ToolError {
    Denied(String),
    BadArgs(String),
}
type ToolResult = Result<Json, ToolError>;

fn denied(e: loom_core::LoomError) -> ToolError {
    ToolError::Denied(e.to_string())
}

fn arg_str<'a>(args: &'a Json, key: &str) -> Result<&'a str, ToolError> {
    args.get(key)
        .and_then(Json::as_str)
        .ok_or_else(|| ToolError::BadArgs(format!("missing string argument '{key}'")))
}

fn parse_token(args: &Json) -> Result<CapabilityToken, ToolError> {
    let t = args
        .get("token")
        .ok_or_else(|| ToolError::BadArgs("every data tool needs a 'token'".into()))?;
    serde_json::from_value(t.clone())
        .map_err(|e| ToolError::BadArgs(format!("malformed token: {e}")))
}

fn parse_trust(s: &str) -> Result<TrustClass, ToolError> {
    match s {
        "VerifiedSystem" => Ok(TrustClass::VerifiedSystem),
        "Human" => Ok(TrustClass::Human),
        "ThirdParty" => Ok(TrustClass::ThirdParty),
        "Untrusted" => Ok(TrustClass::Untrusted),
        other => Err(ToolError::BadArgs(format!("unknown trust class '{other}'"))),
    }
}

fn record_kind(r: &Record) -> &'static str {
    match r {
        Record::Observation(_) => "observation",
        Record::Claim(_) => "claim",
        Record::Value(_) => "value",
    }
}
