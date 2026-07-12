//! Live Postgres `EntityResolver` integration test (feature = `postgres`).
//!
//! Requires a running Postgres seeded with the schema in `src/pg_store.rs`:
//!   entity_attr(uid,name,value JSONB), entity_parent(child,parent)
//! Conn string from `CHAI_PG_TEST_URL`, else a local default. If no DB is
//! reachable the test skips (so it never breaks a DB-less environment).
//!
//! Seed used here (see the test setup SQL):
//!   Photo::p0 [isPublic=true] -> Album::a0 -> Album::a1
//!   User::alice [trust_tier=4] -> Group::eng
#![cfg(feature = "postgres")]

use chai_dsl::ast::{Effect, Value};
use chai_dsl::entity::EntityResolver;
use chai_dsl::pg_store::PgStore;
use chai_dsl::{eval_with_store, parse_chai};
use std::collections::HashMap;

fn store() -> Option<PgStore> {
    let conn = std::env::var("CHAI_PG_TEST_URL")
        .unwrap_or_else(|_| "host=localhost user=madhavagaikwad dbname=chai_pgtest".into());
    match PgStore::connect(&conn) {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("no Postgres ({e}); skipping live test");
            None
        }
    }
}

#[test]
fn pg_resolver_attr_has_and_transitive_in() {
    let Some(s) = store() else { return };

    // attr: JSONB decoded via the same json_to_value as Cedar entity JSON
    assert_eq!(s.attr("Photo::p0", "isPublic").unwrap(), Some(Value::Bool(true)));
    assert_eq!(s.attr("User::alice", "trust_tier").unwrap(), Some(Value::Int(4)));
    assert!(s.attr("Photo::p0", "missing").unwrap().is_none());

    // has_attr
    assert!(s.has_attr("Photo::p0", "isPublic").unwrap());
    assert!(!s.has_attr("Photo::p0", "nope").unwrap());

    // is_in: reflexive, direct, transitive (recursive CTE), negative
    assert!(s.is_in("Photo::p0", "Photo::p0").unwrap()); // reflexive
    assert!(s.is_in("Photo::p0", "Album::a0").unwrap()); // direct
    assert!(s.is_in("Photo::p0", "Album::a1").unwrap()); // transitive: p0 -> a0 -> a1
    assert!(s.is_in("User::alice", "Group::eng").unwrap()); // direct
    assert!(!s.is_in("Photo::p0", "Album::nope").unwrap()); // negative
}

#[test]
fn pg_store_drives_rebac_policy() {
    let Some(s) = store() else { return };

    // A ReBAC decision resolved entirely through Postgres (transitive `in`).
    let program = parse_chai("@id(\"nested\") permit when resource in Album::\"a1\"\n").unwrap();
    let mut ctx = HashMap::new();
    ctx.insert("resource".to_string(), Value::EntityUid("Photo::p0".to_string()));
    let d = eval_with_store(&program, ctx, &s).unwrap();
    assert!(matches!(d.effect, Effect::Allow), "expected allow via p0->a0->a1");
}
