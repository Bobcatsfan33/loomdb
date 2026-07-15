//! The gateway, the agent surface, and the kill switch.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use loom_core::{ActorId, Claim, TrustClass};
use loom_policy::{may_authorize_action, Engine};

use crate::connector::{Connector, ConnectorOutcome};
use crate::record::{ActionId, ActionRecord, ActionStatus};

/// A proposed action. **Inert data.** Producing one does nothing; only [`ActionGateway::execute`] acts.
///
/// An agent builds these through [`AgentStore::propose`]. Note what a proposal carries: the evidence
/// it is justified by, and that evidence's effective label. The gateway re-checks both — a proposal is
/// a request, not a permission.
#[derive(Clone, Debug)]
pub struct Proposal {
    /// What kind of action, e.g. `"identity.suspend_account"`.
    pub action_type: String,
    /// What it acts on.
    pub target: String,
    /// Stable across retries of the same logical action — the basis of idempotency (AT-028).
    pub idempotency_key: String,
    /// Who is proposing.
    pub actor: ActorId,
    /// The branch it was proposed on.
    pub branch: String,
    /// **Whether that branch is a simulation.** A simulation-branch proposal may not reach a production
    /// connector (AT-031). The branch context has to travel with the proposal all the way here, or
    /// containment leaks.
    pub simulation: bool,
    /// The claims justifying it. Each must be action-eligible (cites evidence, not stale) or the whole
    /// proposal is refused (AT-007, AT-030).
    pub evidence: Vec<Claim>,
    /// The effective trust label of that evidence — the most restrictive over the cited claims. The
    /// policy check reads this (AT-034): `Untrusted` evidence cannot authorize a destructive action.
    pub evidence_label: TrustClass,
}

/// **The agent's surface. It can propose. It cannot act.** (AT-027)
///
/// Read the impl: there is one method, `propose`, and it returns inert data. There is no `execute`,
/// no `run`, no `commit` — nothing that reaches a connector. An agent that has been told by a poisoned
/// document to "call execute_action" is asking for a method that does not exist on the only handle it
/// holds. That is a stronger guarantee than a runtime check, because there is nothing to check.
///
/// The absence is enforced by the compiler, and this doctest is how it stays enforced: it **must fail
/// to compile**, and CI runs it. If someone adds `AgentStore::execute`, this starts compiling, the
/// doctest fails, and the build goes red — the structural guarantee cannot be quietly removed.
///
/// ```compile_fail
/// use loom_action::AgentStore;
/// use loom_core::{ActorId, TrustClass};
/// let agent = AgentStore::new(ActorId::new("a"), "main", false);
/// // There is no such method. An agent cannot act.
/// agent.execute("identity.suspend_account", "user-1");
/// ```
#[derive(Clone, Debug)]
pub struct AgentStore {
    actor: ActorId,
    branch: String,
    simulation: bool,
}

impl AgentStore {
    /// An agent handle for an actor on a branch.
    pub fn new(actor: ActorId, branch: impl Into<String>, simulation: bool) -> Self {
        AgentStore {
            actor,
            branch: branch.into(),
            simulation,
        }
    }

    /// **Propose an action.** Returns inert data. Nothing happens until a gateway — which the agent
    /// does not hold — executes it.
    pub fn propose(
        &self,
        action_type: impl Into<String>,
        target: impl Into<String>,
        idempotency_key: impl Into<String>,
        evidence: Vec<Claim>,
        evidence_label: TrustClass,
    ) -> Proposal {
        Proposal {
            action_type: action_type.into(),
            target: target.into(),
            idempotency_key: idempotency_key.into(),
            actor: self.actor.clone(),
            branch: self.branch.clone(),
            simulation: self.simulation,
            evidence,
            evidence_label,
        }
    }
}

/// The action-disable control. Global, and per-tenant.
///
/// **Disabling actions must never disable investigation** (AT-033). This gates only the gateway;
/// reads, writes, and audit do not pass through here, so flipping the switch stops new external
/// effects while leaving fully intact the ability to find out why you flipped it.
#[derive(Debug, Default)]
pub struct KillSwitch {
    global: bool,
    disabled_tenants: BTreeSet<String>,
}

impl KillSwitch {
    /// A switch with everything enabled (actions allowed).
    pub fn new() -> Self {
        KillSwitch::default()
    }

    /// Disable **all** external actions, every tenant.
    pub fn disable_all(&mut self) {
        self.global = true;
    }

    /// Re-enable all (subject to per-tenant switches).
    pub fn enable_all(&mut self) {
        self.global = false;
    }

    /// Disable actions for one tenant.
    pub fn disable_tenant(&mut self, tenant: impl Into<String>) {
        self.disabled_tenants.insert(tenant.into());
    }

    /// Are actions disabled for this tenant?
    pub fn is_disabled(&self, tenant: &str) -> bool {
        self.global || self.disabled_tenants.contains(tenant)
    }
}

/// **The only thing that can perform an external effect.**
pub struct ActionGateway {
    tenant: String,
    connectors: BTreeMap<String, Box<dyn Connector>>,
    policy: Engine,
    kill: Mutex<KillSwitch>,
    /// The whole of the mutable state, behind one lock. Actions are **serialized** through it.
    ///
    /// This is deliberately boring: holding one lock across the check-and-execute makes at-most-once
    /// idempotency (AT-028) obviously correct, at the cost of throughput. A real deployment shards this
    /// by idempotency key; the correctness argument is the same and the lock is per-shard. Serializing
    /// is stated here rather than discovered under load.
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// id → the record of an action already decided. A retry finds its answer here and does not act
    /// again — at most one side effect per idempotency key (AT-028).
    done: BTreeMap<ActionId, ActionRecord>,
}

impl ActionGateway {
    /// Build a gateway for a tenant.
    pub fn new(tenant: impl Into<String>, policy: Engine) -> Self {
        ActionGateway {
            tenant: tenant.into(),
            connectors: BTreeMap::new(),
            policy,
            kill: Mutex::new(KillSwitch::new()),
            state: Mutex::new(State::default()),
        }
    }

    /// Register a connector for its action type.
    pub fn with_connector(mut self, connector: Box<dyn Connector>) -> Self {
        self.connectors
            .insert(connector.action_type().to_string(), connector);
        self
    }

    /// Access the kill switch to flip it.
    pub fn kill_switch(&self) -> &Mutex<KillSwitch> {
        &self.kill
    }

    /// Every action this gateway has decided, for the audit trail and for taint's irreversible section.
    pub fn records(&self) -> Vec<ActionRecord> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .done
            .values()
            .cloned()
            .collect()
    }

    /// **Execute a proposal — after every check, idempotently.**
    ///
    /// Returns the `ActionRecord`. A retry with the same idempotency key returns the *same* record and
    /// does not act again.
    pub fn execute(&self, proposal: &Proposal) -> ActionRecord {
        let id = ActionId::of(&proposal.idempotency_key);

        // One lock for the whole decide-and-act, so idempotency is not racy. See `state`.
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        // AT-028: already decided? Return the same answer. No second effect.
        if let Some(existing) = state.done.get(&id) {
            return existing.clone();
        }

        let record = self.decide_and_run(&id, proposal);
        state.done.insert(id, record.clone());
        record
    }

    fn decide_and_run(&self, id: &ActionId, proposal: &Proposal) -> ActionRecord {
        let refuse = |reason: String| ActionRecord {
            id: id.clone(),
            action_type: proposal.action_type.clone(),
            target: proposal.target.clone(),
            actor: proposal.actor.clone(),
            branch: proposal.branch.clone(),
            policy_version: String::new(),
            status: ActionStatus::Refused { reason },
        };

        // 1. Kill switch (AT-033).
        if self
            .kill
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_disabled(&self.tenant)
        {
            return refuse(
                "external actions are disabled by the kill switch. Reads, writes, and audit remain \
                 available; re-enable actions to proceed."
                    .to_string(),
            );
        }

        // 2. Evidence: every cited claim must be action-eligible (AT-007, AT-030).
        for claim in &proposal.evidence {
            if !claim.is_action_eligible() {
                let why = claim
                    .ineligibility_reason()
                    .unwrap_or_else(|| "a cited claim is not action-eligible".to_string());
                return refuse(why);
            }
        }
        if proposal.evidence.is_empty() {
            return refuse(
                "this action cites no evidence and cannot be authorized. Attach at least one \
                 action-eligible claim."
                    .to_string(),
            );
        }

        // 3. Policy (AT-034, AT-037). Deny-overrides, fail-closed.
        let decision = may_authorize_action(
            &self.policy,
            proposal.actor.as_str(),
            &proposal.action_type,
            proposal.evidence_label,
        );
        let policy_version = decision.policy_version.clone();
        if !decision.decision.is_allowed() {
            return ActionRecord {
                id: id.clone(),
                action_type: proposal.action_type.clone(),
                target: proposal.target.clone(),
                actor: proposal.actor.clone(),
                branch: proposal.branch.clone(),
                policy_version,
                status: ActionStatus::Refused {
                    reason: format!(
                        "policy refused this action: {}. This is the injection boundary — {:?}-labeled \
                         evidence may not authorize {}.",
                        decision.rationale, proposal.evidence_label, proposal.action_type
                    ),
                },
            };
        }

        // 4. Simulation containment (AT-031). A simulation-branch proposal may only reach a simulated
        //    connector. There is no production effect from a what-if.
        let connector = match self.connectors.get(&proposal.action_type) {
            Some(c) => c,
            None => return refuse(format!(
                "no connector is registered for action '{}'. Register one, or this action cannot \
                     be performed.",
                proposal.action_type
            )),
        };
        if proposal.simulation && !connector.is_simulated() {
            return refuse(format!(
                "this proposal is on a SIMULATION branch and '{}' has only a production connector. A \
                 simulation may not cause a real effect; register a simulated connector or run it on a \
                 real branch.",
                proposal.action_type
            ));
        }

        // 5. Execute, and translate the outcome honestly.
        let status = match connector.execute(&proposal.target, &proposal.idempotency_key) {
            ConnectorOutcome::Succeeded { receipt } => ActionStatus::Succeeded { receipt },
            // AT-032: success without a receipt is not terminal success. We do not know it happened in
            // a way we could prove, so we do not claim it did.
            ConnectorOutcome::SucceededWithoutReceipt => ActionStatus::Indeterminate {
                detail:
                    "the connector reported success but returned no receipt, so the action is not \
                         confirmed. Treat as unknown until a receipt is obtained."
                        .to_string(),
            },
            ConnectorOutcome::Failed { reason } => ActionStatus::Failed { reason },
            // AT-029: unknown is unknown. Not a failure, not a success.
            ConnectorOutcome::Indeterminate { detail } => ActionStatus::Indeterminate { detail },
        };

        ActionRecord {
            id: id.clone(),
            action_type: proposal.action_type.clone(),
            target: proposal.target.clone(),
            actor: proposal.actor.clone(),
            branch: proposal.branch.clone(),
            policy_version,
            status,
        }
    }
}
