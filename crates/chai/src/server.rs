//! HTTP sidecar (feature = `server`). Exposes the MCP interceptors over HTTP so
//! agent/MCP code in any language (Python/TS/...) can call the safety layer
//! without linking Rust. Build/run with `--features server`. Optional so
//! embedders that link the library directly don't pull in axum/tokio.
//!
//!   POST /authorize_tool_call   agent to tool gate
//!   POST /filter_tool_result    tool to agent/user emission control

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::{extract::{DefaultBodyLimit, State}, routing::post, Json, Router};
use serde::{Deserialize, Serialize};

use crate::afc::Afc;
use chai_core::ast::{ChaiProgram, Decision, Value};
use chai_core::emission::EmitAction;
use chai_core::entity::{json_to_value, EntityStore};
use crate::mcp::{authorize_tool_call, filter_tool_result, AgentSubject};

/// Shared state. Holds the loaded policy, entity store, AFC, and an optional
/// bearer token. `token = None` disables auth (e.g. when you front this with your
/// own mTLS or network policy). `Some(t)` requires `Authorization: Bearer <t>` on
/// every request.
pub struct AppState {
    pub program: ChaiProgram,
    pub store: EntityStore,
    pub afc: Afc,
    pub token: Option<String>,
}

/// Fail-closed bearer-token gate. With a token configured, a missing or wrong
/// `Authorization` header gets a `401` and the request never reaches a handler.
async fn require_auth(
    State(st): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(expected) = &st.token {
        let want = format!("Bearer {expected}");
        let ok = req
            .headers()
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .map(|h| ct_eq(h.as_bytes(), want.as_bytes()))
            .unwrap_or(false);
        if !ok {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }
    Ok(next.run(req).await)
}

/// Length-then-content constant-time byte comparison, so the bearer-token check
/// does not leak the secret through timing. (Length is not secret.)
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn obj_to_attrs(v: &serde_json::Value) -> HashMap<String, Value> {
    match json_to_value(v) {
        Value::Dict(m) => m,
        _ => HashMap::new(),
    }
}

#[derive(Deserialize)]
struct ToolCallReq {
    subject_uid: String,
    #[serde(default)]
    subject_attrs: serde_json::Value,
    tool: String,
    #[serde(default)]
    args: serde_json::Value,
    resource: Option<String>,
}

#[derive(Serialize)]
struct DecisionResp {
    effect: String,
    reason: String,
    rule_trace: Vec<String>,
    errors: Vec<String>,
}

impl From<Decision> for DecisionResp {
    fn from(d: Decision) -> Self {
        DecisionResp {
            effect: format!("{:?}", d.effect),
            reason: d.reason,
            rule_trace: d.rule_trace,
            errors: d.errors,
        }
    }
}

async fn authorize(
    State(st): State<Arc<AppState>>,
    Json(req): Json<ToolCallReq>,
) -> Json<DecisionResp> {
    let subject = AgentSubject { uid: req.subject_uid, attrs: obj_to_attrs(&req.subject_attrs) };
    let args = obj_to_attrs(&req.args);
    let resp = match authorize_tool_call(
        &st.program, &st.store, &subject, &req.tool, &args, req.resource.as_deref(),
    ) {
        Ok(d) => DecisionResp::from(d),
        // Fail-closed. An internal error becomes a deny.
        Err(e) => DecisionResp {
            effect: "Deny".into(),
            reason: format!("error: {e}"),
            rule_trace: vec![],
            errors: vec![e.to_string()],
        },
    };
    Json(resp)
}

#[derive(Deserialize)]
struct ResultReq {
    subject_uid: String,
    #[serde(default)]
    subject_attrs: serde_json::Value,
    tool: String,
    result: String,
}

#[derive(Serialize)]
struct ResultResp {
    action: String,
    released: Option<String>,
    effect: String,
    reason: String,
}

async fn filter(State(st): State<Arc<AppState>>, Json(req): Json<ResultReq>) -> Json<ResultResp> {
    let subject = AgentSubject { uid: req.subject_uid, attrs: obj_to_attrs(&req.subject_attrs) };
    let rd = filter_tool_result(&st.program, &st.store, &st.afc, &subject, &req.tool, &req.result);
    let (action, released) = match rd.action {
        EmitAction::Emit(s) => ("emit", Some(s)),
        EmitAction::Redact(s) => ("redact", Some(s)),
        EmitAction::Drop => ("drop", None),
        EmitAction::Buffer => ("buffer", None),
        EmitAction::RequireHuman => ("require_human", None),
    };
    Json(ResultResp {
        action: action.into(),
        released,
        effect: format!("{:?}", rd.decision.effect),
        reason: rd.decision.reason,
    })
}

/// Streamable-HTTP / SSE result governance. The proxy forwards the upstream
/// tool-result SSE stream as the request body; we drive the proven streaming
/// state machine over its chunks and return a governed SSE stream: released
/// prefixes as `data:` events, withheld chunks as verdict-only comments, an
/// unapproved buffer dropped at end-of-stream (fail-closed). Identity comes from
/// `x-chai-subject-uid` / `x-chai-subject-attrs`; the tool name from `x-chai-tool`.
async fn filter_sse(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> impl axum::response::IntoResponse {
    let subject = subject_from_headers(&headers);
    let tool = headers.get("x-chai-tool").and_then(|h| h.to_str().ok()).unwrap_or("stream");
    let mut gov = crate::mcp_contract::StreamingResultGovernor::new(
        &st.program, &st.store, &st.afc, &subject, tool,
    );
    let governed = crate::mcp_contract::govern_sse(&mut gov, &body);
    ([(axum::http::header::CONTENT_TYPE, "text/event-stream")], governed)
}

/// agentgateway-style HTTP external authorization endpoint.
///
/// agentgateway's `extAuthz` (with `includeRequestBody`) forwards the intercepted
/// MCP request, JSON-RPC body included, to this endpoint and applies the
/// 2xx-allow / non-2xx-deny convention. We parse the body as a `tools/call`,
/// decide, and return `200` (allow) or `403` (deny). Identity comes from the
/// `x-chai-subject-uid` / `x-chai-subject-attrs` headers. Set them via the
/// extAuthz `includeRequestHeaders` or a JWT-to-header mapping. Fail-closed. A
/// body we can't parse, or one that doesn't decide as allow, is denied.
async fn extauthz(State(st): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> StatusCode {
    // Gate tool calls only, via the shared fail-closed gate. MCP plumbing
    // (initialize, tools/list, notifications, ping) and non-JSON-RPC bodies pass
    // through, since extAuthz fires on every request and gating the handshake
    // would kill the session. Batches are authorized element by element.
    let subject = subject_from_headers(&headers);
    match crate::mcp_contract::gate_intercepted_body(&st.program, &st.store, &subject, &body) {
        crate::mcp_contract::GateVerdict::Deny => StatusCode::FORBIDDEN,
        _ => StatusCode::OK,
    }
}

fn subject_from_headers(headers: &HeaderMap) -> AgentSubject {
    let uid = headers
        .get("x-chai-subject-uid")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Agent::anonymous");
    let mut subject = AgentSubject::new(uid);
    if let Some(attrs) = headers.get("x-chai-subject-attrs").and_then(|h| h.to_str().ok()) {
        if let Ok(serde_json::Value::Object(m)) = serde_json::from_str::<serde_json::Value>(attrs) {
            for (k, v) in m {
                subject.attrs.insert(k, json_to_value(&v));
            }
        }
    }
    subject
}

/// Max request body accepted, in bytes. An oversized request is rejected with
/// `413 Payload Too Large` before any handler runs, bounding per-request memory
/// against a giant-payload DoS. Fail-closed: the SDK treats a 413 as a deny/drop,
/// so a rejected result is withheld, never emitted. Override with
/// `CHAI_MAX_BODY_BYTES`; defaults to 1 MiB.
fn max_body_bytes() -> usize {
    std::env::var("CHAI_MAX_BODY_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1 << 20)
}

/// Build the router. Mount it in your server. `state` carries policy, store, AFC.
///
/// Deployment hardening: requests are authenticated with a bearer token
/// (`AppState.token`, constant-time checked) and bounded by `max_body_bytes`.
/// Terminate TLS at a reverse proxy or mesh sidecar (mTLS), and keep the PDP on a
/// private network; it is a decision point, not a public edge.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/authorize_tool_call", post(authorize))
        .route("/filter_tool_result", post(filter))
        .route("/filter_tool_result_sse", post(filter_sse))
        .route("/extauthz", post(extauthz))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .layer(DefaultBodyLimit::max(max_body_bytes()))
        .with_state(state)
}

/// Bind `addr` and serve, blocking the current thread on its own tokio runtime.
/// Lets a plain binary or example run the PDP sidecar without itself depending on
/// axum/tokio.
pub fn serve_blocking(addr: &str, state: Arc<AppState>) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let listener = tokio::net::TcpListener::bind(addr).await.expect("bind sidecar addr");
        eprintln!("PDP sidecar listening on http://{addr}");
        axum::serve(listener, router(state)).await.expect("serve");
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use chai_core::parser::parse_chai;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn state() -> Arc<AppState> {
        // A demo policy spanning both planes: trust-tier authorization (evaluated
        // with `subject` present) and emission-time DLP (evaluated with
        // `dlp_facts` present). The DLP rules are marked `lenient` because in the
        // *authorization* plane their fact namespace is absent by design, not by
        // detector failure, under strict effect-tagged errors (§1.1) an
        // unresolved `dlp_facts.*` would otherwise deny every tool call. In the
        // emission plane AFC always injects `dlp_facts`, so `lenient` never relaxes
        // the DLP guards there (a real detector reading still denies/redacts). A
        // production deployment would carry distinct authz and emission policies.
        let program = parse_chai(
            "@id(\"untrusted\") forbid when subject.trust_tier < 3\n\
             @id(\"ok\") permit when subject.trust_tier >= 3\n\
             @id(\"secret\") deny lenient when dlp_facts.secrets_found == true\n\
             @id(\"pii\") redact lenient when dlp_facts.pii_confidence > 0.4\n\
             @id(\"clean\") permit when dlp_facts.pii_confidence <= 0.4\n",
        )
        .unwrap();
        Arc::new(AppState {
            program,
            store: EntityStore::new(),
            afc: Afc::with_default_detectors(),
            token: None,
        })
    }

    fn state_with_token(tok: &str) -> Arc<AppState> {
        let program = parse_chai("permit when true\n").unwrap();
        Arc::new(AppState {
            program,
            store: EntityStore::new(),
            afc: Afc::with_default_detectors(),
            token: Some(tok.to_string()),
        })
    }

    async fn post_with_auth(state: Arc<AppState>, auth: Option<&str>) -> StatusCode {
        let mut req = Request::builder()
            .method("POST")
            .uri("/authorize_tool_call")
            .header("content-type", "application/json");
        if let Some(a) = auth {
            req = req.header("authorization", a);
        }
        let resp = router(state)
            .oneshot(req.body(Body::from(
                serde_json::json!({"subject_uid": "Agent::a1", "tool": "t"}).to_string(),
            )).unwrap())
            .await
            .unwrap();
        resp.status()
    }

    async fn post_extauthz(body: &str, attrs: &str) -> StatusCode {
        let resp = router(state())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/extauthz")
                    .header("content-type", "application/json")
                    .header("x-chai-subject-uid", "Agent::a1")
                    .header("x-chai-subject-attrs", attrs)
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        resp.status()
    }

    #[tokio::test]
    async fn extauthz_maps_decision_to_2xx_or_403() {
        let call = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "db.write", "arguments": {}}
        })
        .to_string();
        // trusted -> allow -> 200, untrusted -> deny -> 403 (matches the engine)
        assert_eq!(post_extauthz(&call, "{\"trust_tier\": 4}").await, StatusCode::OK);
        assert_eq!(post_extauthz(&call, "{\"trust_tier\": 1}").await, StatusCode::FORBIDDEN);
        // MCP plumbing passes through (gating the handshake would kill the session)
        let init = serde_json::json!({"jsonrpc": "2.0", "id": 0, "method": "initialize"}).to_string();
        assert_eq!(post_extauthz(&init, "{\"trust_tier\": 1}").await, StatusCode::OK);
        let non_json = "not json at all";
        assert_eq!(post_extauthz(non_json, "{}").await, StatusCode::OK);
        // A recognized but broken tools/call is fail-closed denied.
        let broken = serde_json::json!({"jsonrpc": "2.0", "method": "tools/call"}).to_string();
        assert_eq!(post_extauthz(&broken, "{\"trust_tier\": 4}").await, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn bearer_token_is_enforced() {
        // No token configured -> open (back-compatible).
        assert_eq!(post_with_auth(state(), None).await, StatusCode::OK);
        // Token configured -> missing or wrong header is 401, correct is 200.
        assert_eq!(post_with_auth(state_with_token("s3cr3t"), None).await, StatusCode::UNAUTHORIZED);
        assert_eq!(post_with_auth(state_with_token("s3cr3t"), Some("Bearer wrong")).await, StatusCode::UNAUTHORIZED);
        assert_eq!(post_with_auth(state_with_token("s3cr3t"), Some("Bearer s3cr3t")).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn filter_sse_endpoint_governs_stream() {
        // An SSE tool-result stream: two clean rows then a secret chunk.
        let sse = "data: row 1 \n\ndata: row 2 \n\ndata: password: hunter2\n\n";
        let resp = router(state())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/filter_tool_result_sse")
                    .header("x-chai-subject-uid", "Agent::a1")
                    .header("x-chai-subject-attrs", "{\"trust_tier\": 5}")
                    .header("x-chai-tool", "db.read")
                    .header("content-type", "text/event-stream")
                    .body(Body::from(sse))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").and_then(|h| h.to_str().ok()),
            Some("text/event-stream")
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let out = String::from_utf8(bytes.to_vec()).unwrap();
        // clean rows forwarded, secret withheld (never in output)
        assert!(out.contains("data: row 1 "), "{out}");
        assert!(!out.contains("hunter2"), "secret leaked: {out}");
        assert!(out.contains(": withheld (drop)"), "{out}");
    }

    async fn post_json(uri: &str, body: serde_json::Value) -> serde_json::Value {
        let resp = router(state())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn authorize_endpoint_over_http() {
        let allow = post_json("/authorize_tool_call", serde_json::json!({
            "subject_uid": "Agent::a1", "subject_attrs": {"trust_tier": 4}, "tool": "db.write"
        })).await;
        assert_eq!(allow["effect"], "Allow");

        let deny = post_json("/authorize_tool_call", serde_json::json!({
            "subject_uid": "Agent::a1", "subject_attrs": {"trust_tier": 1}, "tool": "db.write"
        })).await;
        assert_eq!(deny["effect"], "Deny");
        assert_eq!(deny["rule_trace"][0], "untrusted");
    }

    #[tokio::test]
    async fn filter_endpoint_over_http() {
        let drop = post_json("/filter_tool_result", serde_json::json!({
            "subject_uid": "Agent::a1", "subject_attrs": {"trust_tier": 5},
            "tool": "vault.read", "result": "password: hunter2"
        })).await;
        assert_eq!(drop["action"], "drop");

        let clean = post_json("/filter_tool_result", serde_json::json!({
            "subject_uid": "Agent::a1", "subject_attrs": {"trust_tier": 5},
            "tool": "db.read", "result": "row count is 12"
        })).await;
        assert_eq!(clean["action"], "emit");
    }

    #[tokio::test]
    async fn oversized_body_is_rejected_413() {
        // A body over the 1 MiB default limit is refused before any handler runs,
        // bounding per-request memory.
        let big = "x".repeat((1 << 20) + 1024);
        let body = serde_json::json!({
            "subject_uid": "Agent::a1", "subject_attrs": {"trust_tier": 5},
            "tool": "db.read", "result": big
        });
        let resp = router(state())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/filter_tool_result")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
