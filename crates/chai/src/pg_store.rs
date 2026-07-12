//! Postgres-backed `EntityResolver` (feature = `postgres`).
//!
//! Most authorization is moderate-scale, where Postgres is plenty. Once you
//! outgrow it, swap in a SpiceDB/OpenFGA adapter behind the same trait. Uses the
//! synchronous `postgres` crate so it slots into the sync `EntityResolver` API.
//!
//! Expected schema:
//! ```sql
//! CREATE TABLE entity_attr   (uid TEXT, name TEXT, value JSONB);
//! CREATE TABLE entity_parent (child TEXT, parent TEXT);
//! ```
//!
//! NOTE: compiled and type-checked here, not integration-tested in this
//! environment (no live database). Transitive `in` is a single recursive CTE
//! round-trip. Attribute values are stored as JSONB and decoded via the same
//! `json_to_value` used for Cedar entity JSON.

use chai_core::ast::Value;
use chai_core::entity::{json_to_value, EntityResolver};
use chai_core::error::ChaiError;
use postgres::{Client, NoTls};
use std::sync::Mutex;

pub struct PgStore {
    client: Mutex<Client>,
}

impl PgStore {
    /// Connect using a libpq connection string, e.g. "host=… user=… dbname=…".
    pub fn connect(conn: &str) -> Result<Self, postgres::Error> {
        Ok(PgStore { client: Mutex::new(Client::connect(conn, NoTls)?) })
    }

    pub fn from_client(client: Client) -> Self {
        PgStore { client: Mutex::new(client) }
    }
}

impl EntityResolver for PgStore {
    fn attr(&self, uid: &str, name: &str) -> Result<Option<Value>, ChaiError> {
        // A lock, query, or decode failure is a resolver outage, NOT "no such
        // attribute". Surface it as an error so the rule fails closed.
        let mut c = self
            .client
            .lock()
            .map_err(|e| ChaiError::ResolverUnavailable(format!("pg lock poisoned: {e}")))?;
        let rows = c
            .query(
                "SELECT value::text FROM entity_attr WHERE uid = $1 AND name = $2 LIMIT 1",
                &[&uid, &name],
            )
            .map_err(|e| ChaiError::ResolverUnavailable(format!("pg query failed: {e}")))?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let text: String = row.get(0);
        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| ChaiError::ResolverUnavailable(format!("pg malformed attr json: {e}")))?;
        Ok(Some(json_to_value(&json)))
    }

    fn has_attr(&self, uid: &str, name: &str) -> Result<bool, ChaiError> {
        let mut c = self
            .client
            .lock()
            .map_err(|e| ChaiError::ResolverUnavailable(format!("pg lock poisoned: {e}")))?;
        let rows = c
            .query(
                "SELECT 1 FROM entity_attr WHERE uid = $1 AND name = $2 LIMIT 1",
                &[&uid, &name],
            )
            .map_err(|e| ChaiError::ResolverUnavailable(format!("pg query failed: {e}")))?;
        Ok(!rows.is_empty())
    }

    fn is_in(&self, descendant: &str, ancestor: &str) -> Result<bool, ChaiError> {
        if descendant == ancestor {
            return Ok(true); // reflexive
        }
        let mut c = self
            .client
            .lock()
            .map_err(|e| ChaiError::ResolverUnavailable(format!("pg lock poisoned: {e}")))?;
        // Transitive ancestor check via a recursive CTE over entity_parent.
        let sql = "WITH RECURSIVE anc(node) AS ( \
                       SELECT parent FROM entity_parent WHERE child = $1 \
                       UNION \
                       SELECT ep.parent FROM entity_parent ep JOIN anc ON ep.child = anc.node \
                   ) SELECT 1 FROM anc WHERE node = $2 LIMIT 1";
        let rows = c
            .query(sql, &[&descendant, &ancestor])
            .map_err(|e| ChaiError::ResolverUnavailable(format!("pg query failed: {e}")))?;
        Ok(!rows.is_empty())
    }
}
