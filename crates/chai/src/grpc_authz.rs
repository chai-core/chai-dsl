//! Envoy-compatible ext-authz gRPC service (feature = `grpc`).
//!
//! Implements the Envoy External Authorization v3 `Authorization/Check` API, so
//! Chai drops in as the authz service for Envoy / Istio / agentgateway (all
//! Envoy-ext-authz-compatible) over gRPC. This sits alongside the HTTP sidecar
//! and ICAP transports.
//!
//! The proxy forwards the request, body included for MCP `tools/call`. We decide
//! and return OK (allow) or PermissionDenied (block). Fail-closed.

use chai_core::ast::ChaiProgram;
use chai_core::entity::EntityStore;
use crate::mcp::AgentSubject;
use crate::mcp_contract::{gate_intercepted_body, GateVerdict};
use envoy_types::ext_authz::v3::CheckResponseExt;
use envoy_types::pb::envoy::service::auth::v3::authorization_server::{Authorization, AuthorizationServer};
use envoy_types::pb::envoy::service::auth::v3::{CheckRequest, CheckResponse};
use tonic::{Request, Response, Status};

pub struct ChaiAuth {
    pub program: ChaiProgram,
    pub store: EntityStore,
}

#[tonic::async_trait]
impl Authorization for ChaiAuth {
    async fn check(&self, request: Request<CheckRequest>) -> Result<Response<CheckResponse>, Status> {
        let body = request
            .into_inner()
            .attributes
            .and_then(|a| a.request)
            .and_then(|r| r.http)
            .map(|h| h.body)
            .unwrap_or_default();

        // Gate only tool calls (including batched ones); other MCP plumbing
        // passes through. Fail-closed via the shared gate.
        let subject = AgentSubject::new("Agent::anonymous");
        let allow = !matches!(
            gate_intercepted_body(&self.program, &self.store, &subject, body.as_bytes()),
            GateVerdict::Deny
        );

        let resp = if allow {
            CheckResponse::with_status(Status::ok("allowed"))
        } else {
            CheckResponse::with_status(Status::permission_denied("blocked by Chai policy"))
        };
        Ok(Response::new(resp))
    }
}

/// Build the gRPC service. Mount it on a `tonic::transport::Server`.
pub fn service(program: ChaiProgram, store: EntityStore) -> AuthorizationServer<ChaiAuth> {
    AuthorizationServer::new(ChaiAuth { program, store })
}

#[cfg(test)]
mod tests {
    use super::*;
    use envoy_types::pb::envoy::service::auth::v3::attribute_context::{HttpRequest, Request as AttrRequest};
    use envoy_types::pb::envoy::service::auth::v3::AttributeContext;

    fn check_req(body: &str) -> Request<CheckRequest> {
        Request::new(CheckRequest {
            attributes: Some(AttributeContext {
                request: Some(AttrRequest {
                    http: Some(HttpRequest { body: body.to_string(), ..Default::default() }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        })
    }

    fn call(tool: &str) -> String {
        format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{{\"name\":\"{tool}\",\"arguments\":{{}}}}}}")
    }

    #[tokio::test]
    async fn extauthz_check_matches_engine() {
        let auth = ChaiAuth {
            program: crate::parse_chai("@id(\"no-write\") forbid when action == \"write\"\n@id(\"ok\") permit when true\n").unwrap(),
            store: EntityStore::new(),
        };
        // Envoy status codes. 0 is OK (allow), 7 is PermissionDenied (block).
        let read = auth.check(check_req(&call("read"))).await.unwrap().into_inner();
        assert_eq!(read.status.as_ref().unwrap().code, 0, "read -> allow");
        let write = auth.check(check_req(&call("write"))).await.unwrap().into_inner();
        assert_eq!(write.status.as_ref().unwrap().code, 7, "write -> deny");
        // non-tool-call plumbing passes through
        let init = auth.check(check_req("{\"method\":\"initialize\"}")).await.unwrap().into_inner();
        assert_eq!(init.status.as_ref().unwrap().code, 0);
    }
}
