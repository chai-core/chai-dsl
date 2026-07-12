//! Redis-backed `EntityResolver` (feature = `redis`).
//!
//! A second reference backend alongside `PgStore`, plugged in through the same
//! `EntityResolver` trait, so the evaluator, the sidecar, and every deployment
//! surface use it unchanged.
//!
//! Data model:
//! ```text
//!   HSET chai:attr:<uid>    <name> <json-value>   entity attributes
//!   SADD chai:parents:<uid> <parent-uid>          direct parent edges
//! ```
//!
//! Transitive `in` walks the parent edges client-side (breadth-first with a
//! visited set), since Redis has no recursive query. Attribute values are JSON,
//! decoded via the same `json_to_value` used for Cedar entity JSON. Fail-closed:
//! a Redis outage (lock, connection, or command error) is surfaced as a resolver
//! error, which becomes the `Err` outcome for the rule under evaluation, never a
//! spurious "not a member" that could let a `forbid ... in ...` rule silently
//! not fire.
//!
//! Compiled and type-checked here; a live integration test needs a running Redis.

use chai_core::ast::Value;
use chai_core::entity::{json_to_value, EntityResolver};
use chai_core::error::ChaiError;
use redis::Commands;
use std::collections::HashSet;
use std::sync::Mutex;

pub struct RedisStore {
    conn: Mutex<redis::Connection>,
}

impl RedisStore {
    /// Connect using a Redis URL, e.g. `redis://127.0.0.1/`.
    pub fn connect(url: &str) -> redis::RedisResult<Self> {
        let client = redis::Client::open(url)?;
        Ok(RedisStore { conn: Mutex::new(client.get_connection()?) })
    }

    /// Wrap an existing connection.
    pub fn from_connection(conn: redis::Connection) -> Self {
        RedisStore { conn: Mutex::new(conn) }
    }

    fn attr_key(uid: &str) -> String {
        format!("chai:attr:{uid}")
    }

    fn parents_key(uid: &str) -> String {
        format!("chai:parents:{uid}")
    }
}

impl EntityResolver for RedisStore {
    fn attr(&self, uid: &str, name: &str) -> Result<Option<Value>, ChaiError> {
        let mut c = self
            .conn
            .lock()
            .map_err(|e| ChaiError::ResolverUnavailable(format!("redis lock poisoned: {e}")))?;
        let raw: Option<String> = c
            .hget(Self::attr_key(uid), name)
            .map_err(|e| ChaiError::ResolverUnavailable(format!("redis hget failed: {e}")))?;
        let Some(raw) = raw else { return Ok(None) };
        let json: serde_json::Value = serde_json::from_str(&raw)
            .map_err(|e| ChaiError::ResolverUnavailable(format!("redis malformed attr json: {e}")))?;
        Ok(Some(json_to_value(&json)))
    }

    fn has_attr(&self, uid: &str, name: &str) -> Result<bool, ChaiError> {
        let mut c = self
            .conn
            .lock()
            .map_err(|e| ChaiError::ResolverUnavailable(format!("redis lock poisoned: {e}")))?;
        c.hexists(Self::attr_key(uid), name)
            .map_err(|e| ChaiError::ResolverUnavailable(format!("redis hexists failed: {e}")))
    }

    fn is_in(&self, descendant: &str, ancestor: &str) -> Result<bool, ChaiError> {
        if descendant == ancestor {
            return Ok(true); // reflexive
        }
        let mut c = self
            .conn
            .lock()
            .map_err(|e| ChaiError::ResolverUnavailable(format!("redis lock poisoned: {e}")))?;
        // Walk up the parent edges. A Redis error propagates (fail-closed) instead
        // of collapsing to "not a member". The start node is pre-marked so a cycle
        // back to it never re-fetches its parents.
        let mut seen: HashSet<String> = HashSet::from([descendant.to_string()]);
        let mut frontier: Vec<String> = vec![descendant.to_string()];
        while let Some(node) = frontier.pop() {
            let parents: Vec<String> = c
                .smembers(Self::parents_key(&node))
                .map_err(|e| ChaiError::ResolverUnavailable(format!("redis smembers failed: {e}")))?;
            for p in parents {
                if p == ancestor {
                    return Ok(true);
                }
                if seen.insert(p.clone()) {
                    frontier.push(p);
                }
            }
        }
        Ok(false)
    }
}
