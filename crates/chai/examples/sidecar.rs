//! Runnable PDP sidecar (feature = `server`).
//!
//! Serves the decision point over HTTP so a proxy (FastMCP, agentgateway) can
//! call us as the PEP→PDP boundary:
//!   POST /authorize_tool_call   : agent → tool gate
//!   POST /filter_tool_result    : tool → agent/user emission control
//!
//! Usage:
//!   cargo run --features server --example sidecar -- [POLICY_FILE] [ADDR]
//! Defaults: a demo policy on 127.0.0.1:8731.

use std::sync::Arc;

use chai_dsl::afc::Afc;
use chai_dsl::entity::EntityStore;
use chai_dsl::parse_chai;
use chai_dsl::server::{serve_blocking, AppState};

// A demo policy spanning both planes: trust-tier authorization (the `subject`
// facts are present on /authorize_tool_call and /extauthz) and emission-time DLP
// (the `dlp_facts` are present on /filter_tool_result, injected by AFC). The DLP
// rules are marked `lenient` so that on the authorization endpoints, where
// `dlp_facts` is absent by design, a strict effect-tagged error (§1.1) does not
// deny every call. In the emission plane AFC always injects `dlp_facts`, so
// `lenient` never relaxes the DLP guards there (a real detector reading still
// denies/redacts). A production deployment would carry distinct authz and emission
// policies rather than one policy across both planes.
const DEMO_POLICY: &str = "\
@id(\"untrusted\") forbid when subject.trust_tier < 3
@id(\"ok\")        permit when subject.trust_tier >= 3
@id(\"secret\")    deny lenient   when dlp_facts.secrets_found == true
@id(\"pii\")       redact lenient when dlp_facts.pii_confidence > 0.4
@id(\"clean\")     permit when dlp_facts.pii_confidence <= 0.4
";

fn main() {
    // Policy: arg, else CHAI_POLICY_FILE env, else the demo policy.
    let args: Vec<String> = std::env::args().collect();
    let policy_path = args.get(1).cloned().or_else(|| std::env::var("CHAI_POLICY_FILE").ok());
    let policy_src = match policy_path {
        Some(path) => std::fs::read_to_string(&path).expect("read policy file"),
        None => DEMO_POLICY.to_string(),
    };
    // Addr: arg, else CHAI_ADDR env, else 0.0.0.0:8731 (a server meant to be called).
    let addr = args
        .get(2)
        .cloned()
        .or_else(|| std::env::var("CHAI_ADDR").ok())
        .unwrap_or_else(|| "0.0.0.0:8731".to_string());

    let program = parse_chai(&policy_src).expect("parse policy");
    // Optional bearer-token auth: set CHAI_SIDECAR_TOKEN to require it.
    let token = std::env::var("CHAI_SIDECAR_TOKEN").ok();
    if token.is_some() {
        eprintln!("bearer-token auth: ENABLED");
    }
    let state = Arc::new(AppState {
        program,
        store: EntityStore::new(),
        afc: Afc::with_default_detectors(),
        token,
    });
    serve_blocking(&addr, state);
}
