//! gdrive authorization in Chai, now backed by an entity store.
//!
//! Mirrors the Cedar paper's gdrive model (Appendix A.1): view access that is
//! inherited through the folder hierarchy, ownership, and public documents.
//! This exercises exactly what was impossible before the entity store:
//! transitive `in` and entity attribute resolution.

use chai_dsl::ast::Value;
use chai_dsl::{eval_with_store, parse_chai, Entity, EntityStore};
use std::collections::HashMap;

/// gdrive policy, written in Chai single-line form.
const POLICY: &str = "\
permit action \"read\" when resource in principal.viewable
permit action \"read\" when resource in principal.owned_documents or resource in principal.owned_folders
permit action \"write\" when resource in principal.owned_documents
permit action \"change_owner\" when principal.owned_documents contains resource
permit action \"read\" when resource.is_public
";

/// Build the entity store: a folder hierarchy + users with view/ownership sets.
///
///   folder:root
///     └── folder:shared           (alice has view access here)
///           └── doc:readme         -> readable by alice transitively
///   doc:budget                     (owned by alice)
///   doc:announce  is_public=true   (readable by anyone)
///   doc:secret    is_public=false  (no access)
fn build_store() -> EntityStore {
    let mut s = EntityStore::new();

    s.insert(Entity::new("folder:root"));
    s.insert(Entity::new("folder:shared").parent("folder:root"));
    s.insert(
        Entity::new("doc:readme")
            .parent("folder:shared")
            .attr("is_public", Value::Bool(false)),
    );
    s.insert(Entity::new("doc:budget").attr("is_public", Value::Bool(false)));
    s.insert(Entity::new("doc:announce").attr("is_public", Value::Bool(true)));
    s.insert(Entity::new("doc:secret").attr("is_public", Value::Bool(false)));

    // alice: view access to the shared folder, owns the budget doc.
    s.insert(
        Entity::new("user:alice")
            .attr(
                "viewable",
                Value::List(vec![Value::EntityUid("folder:shared".into())]),
            )
            .attr(
                "owned_documents",
                Value::List(vec![Value::EntityUid("doc:budget".into())]),
            )
            .attr("owned_folders", Value::List(vec![])),
    );
    // bob: nothing.
    s.insert(
        Entity::new("user:bob")
            .attr("viewable", Value::List(vec![]))
            .attr("owned_documents", Value::List(vec![]))
            .attr("owned_folders", Value::List(vec![])),
    );

    s
}

fn request(principal: &str, action: &str, resource: &str) -> HashMap<String, Value> {
    let mut ctx = HashMap::new();
    ctx.insert("principal".to_string(), Value::EntityUid(principal.into()));
    ctx.insert("action".to_string(), Value::String(action.into()));
    ctx.insert("resource".to_string(), Value::EntityUid(resource.into()));
    ctx
}

fn main() {
    let program = parse_chai(POLICY).expect("policy should parse");
    let store = build_store();

    // (label, principal, action, resource, expected)
    let cases = [
        ("alice reads readme (inherited via folder)", "user:alice", "read", "doc:readme", "Allow"),
        ("alice reads her budget doc (owned)", "user:alice", "read", "doc:budget", "Allow"),
        ("alice reads secret (no access)", "user:alice", "read", "doc:secret", "Deny"),
        ("alice changes owner of budget (owned)", "user:alice", "change_owner", "doc:budget", "Allow"),
        ("alice changes owner of readme (not owned)", "user:alice", "change_owner", "doc:readme", "Deny"),
        ("bob reads announce (public)", "user:bob", "read", "doc:announce", "Allow"),
        ("bob reads readme (not shared with bob)", "user:bob", "read", "doc:readme", "Deny"),
    ];

    println!("=== gdrive on Chai + entity store ===\n");
    let mut correct = 0;
    for (label, p, a, r, expected) in cases {
        let decision = eval_with_store(&program, request(p, a, r), &store).unwrap();
        let got = format!("{:?}", decision.effect);
        let ok = got == expected;
        correct += ok as usize;
        println!(
            "[{}] {label}\n      => {got} (expected {expected})",
            if ok { "PASS" } else { "FAIL" }
        );
    }
    println!("\n{correct}/{} cases correct", cases.len());
}
