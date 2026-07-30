#![cfg(feature = "observability")]

use std::sync::{Arc, Mutex};

use loom_action::ActionGateway;
use loom_branch::Loom;
use loom_core::TenantId;
use loom_mcp::{LoomServer, Request, RequestObservation, RequestObserver};
use loom_policy::{Engine, PolicySet};
use serde_json::json;

#[derive(Default)]
struct RecordingObserver {
    completed: Mutex<Vec<(String, String, bool)>>,
}

impl RequestObserver for RecordingObserver {
    fn record(&self, observation: RequestObservation<'_>) {
        self.completed.lock().unwrap().push((
            observation.method.to_owned(),
            observation.tool.to_owned(),
            observation.response.error.is_none(),
        ));
    }
}

#[test]
fn server_emits_one_completion_for_success_and_denial_without_arguments() {
    let db = Arc::new(Loom::in_memory(TenantId::new("secret-tenant")).unwrap());
    let gateway = ActionGateway::new("secret-tenant", Engine::new(&PolicySet::empty("gateway")));
    let observer = Arc::new(RecordingObserver::default());
    let server = LoomServer::new(
        db,
        Engine::new(&PolicySet::empty("deny")),
        gateway,
        "secret-tenant",
        1_700_000_000_000,
    )
    .with_observer(observer.clone());

    let initialize: Request = serde_json::from_value(
        json!({"jsonrpc":"2.0","id":"sensitive-request","method":"initialize","params":{}}),
    )
    .unwrap();
    assert!(server.handle(&initialize).error.is_none());

    let denied: Request = serde_json::from_value(json!({
        "jsonrpc":"2.0",
        "id":"another-sensitive-request",
        "method":"tools/call",
        "params":{"name":"read","arguments":{"token":"super-secret"}}
    }))
    .unwrap();
    assert!(server.handle(&denied).error.is_some());

    assert_eq!(
        *observer.completed.lock().unwrap(),
        vec![
            ("initialize".into(), "none".into(), true),
            ("tools/call".into(), "read".into(), false),
        ]
    );
}
