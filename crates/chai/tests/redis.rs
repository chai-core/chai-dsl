//! Live Redis `EntityResolver` integration test (feature = `redis`).
//!
//! Self-seeding: it writes a small entity graph, then asserts attr / has_attr /
//! transitive `in` and a full ReBAC decision resolved through Redis. Connection
//! from `CHAI_REDIS_TEST_URL`, else `redis://127.0.0.1/`. If no Redis is reachable
//! the test skips, so it never breaks a Redis-less environment.
//!
//! Seed:
//!   Photo::p0 [isPublic=true] -> Album::a0 -> Album::a1
//!   User::alice [trust_tier=4] -> Group::eng
#![cfg(feature = "redis")]

use chai_dsl::ast::{Effect, Value};
use chai_dsl::entity::EntityResolver;
use chai_dsl::redis_store::RedisStore;
use chai_dsl::{eval_with_store, parse_chai};
use std::collections::HashMap;

fn url() -> String {
    std::env::var("CHAI_REDIS_TEST_URL").unwrap_or_else(|_| "redis://127.0.0.1/".into())
}

/// Connect and seed a small graph. Returns None (skip) if no Redis is reachable.
fn seed() -> Option<RedisStore> {
    let client = redis::Client::open(url()).ok()?;
    let mut c = match client.get_connection() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("no Redis ({e}); skipping live test");
            return None;
        }
    };
    let seeded: redis::RedisResult<()> = redis::pipe()
        .cmd("HSET").arg("chai:attr:Photo::p0").arg("isPublic").arg("true")
        .cmd("HSET").arg("chai:attr:User::alice").arg("trust_tier").arg("4")
        .cmd("SADD").arg("chai:parents:Photo::p0").arg("Album::a0")
        .cmd("SADD").arg("chai:parents:Album::a0").arg("Album::a1")
        .cmd("SADD").arg("chai:parents:User::alice").arg("Group::eng")
        .query(&mut c);
    if let Err(e) = seeded {
        eprintln!("Redis seed failed ({e}); skipping");
        return None;
    }
    Some(RedisStore::from_connection(c))
}

#[test]
fn redis_resolver_attr_has_and_transitive_in() {
    let Some(s) = seed() else { return };

    // attr: JSON values decoded via the same json_to_value as Cedar entity JSON.
    assert_eq!(s.attr("Photo::p0", "isPublic").unwrap(), Some(Value::Bool(true)));
    assert_eq!(s.attr("User::alice", "trust_tier").unwrap(), Some(Value::Int(4)));
    assert!(s.attr("Photo::p0", "missing").unwrap().is_none());

    // has_attr
    assert!(s.has_attr("Photo::p0", "isPublic").unwrap());
    assert!(!s.has_attr("Photo::p0", "nope").unwrap());

    // is_in: reflexive, direct, transitive (client-side BFS), negative
    assert!(s.is_in("Photo::p0", "Photo::p0").unwrap()); // reflexive
    assert!(s.is_in("Photo::p0", "Album::a0").unwrap()); // direct
    assert!(s.is_in("Photo::p0", "Album::a1").unwrap()); // transitive: p0 -> a0 -> a1
    assert!(s.is_in("User::alice", "Group::eng").unwrap()); // direct
    assert!(!s.is_in("Photo::p0", "Album::nope").unwrap()); // negative
}

#[test]
fn redis_store_drives_rebac_policy() {
    let Some(s) = seed() else { return };

    // A ReBAC decision resolved entirely through Redis (transitive `in`).
    let program = parse_chai("@id(\"nested\") permit when resource in Album::\"a1\"\n").unwrap();
    let mut ctx = HashMap::new();
    ctx.insert("resource".to_string(), Value::EntityUid("Photo::p0".to_string()));
    let d = eval_with_store(&program, ctx, &s).unwrap();
    assert!(matches!(d.effect, Effect::Allow), "expected allow via p0 -> a0 -> a1");
}
