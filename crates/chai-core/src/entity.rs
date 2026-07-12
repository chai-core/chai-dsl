//! Entity store for Cedar-style relationship-based access control.
//!
//! Cedar's `in` operator is hierarchical. `a in b` holds when `b` is an
//! ancestor-or-self of `a` in the entity parent graph (a document inside a
//! folder inside a folder, a user inside a group). This module provides the
//! entity records and the transitive ancestor resolution that `in`/`has`
//! evaluation needs.

use crate::ast::Value;
use crate::error::ChaiError;
use std::collections::{HashMap, HashSet};

/// Canonical UID string for a Cedar entity, rendered quote-free as `User::alice`.
///
/// Cedar writes `User::"alice"`. Our string-literal grammar cannot contain a
/// `"` (a known capability gap), so a policy could not name such a UID. We
/// normalize UIDs to quote-free form on both the store side and the request
/// side so the two line up.
pub fn cedar_uid(entity_type: &str, id: &str) -> String {
    format!("{}::{}", entity_type, id)
}

/// Normalize a Cedar request UID string (e.g. `User::"alice"`) to our quote-free
/// canonical form (`User::alice`).
pub fn normalize_uid(s: &str) -> String {
    s.replace('"', "")
}

/// A single entity. Stable UID, attribute map, and direct parents (UIDs).
#[derive(Debug, Clone)]
pub struct Entity {
    pub uid: String,
    pub attrs: HashMap<String, Value>,
    pub parents: Vec<String>,
}

impl Entity {
    pub fn new(uid: impl Into<String>) -> Self {
        Entity {
            uid: uid.into(),
            attrs: HashMap::new(),
            parents: Vec::new(),
        }
    }

    /// Attach an attribute.
    pub fn attr(mut self, key: impl Into<String>, value: Value) -> Self {
        self.attrs.insert(key.into(), value);
        self
    }

    /// Add a direct parent (an `in` hierarchy edge).
    pub fn parent(mut self, parent_uid: impl Into<String>) -> Self {
        self.parents.push(parent_uid.into());
        self
    }
}

/// A collection of entities supporting attribute and hierarchy queries.
#[derive(Debug, Clone, Default)]
pub struct EntityStore {
    entities: HashMap<String, Entity>,
}

impl EntityStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, entity: Entity) {
        self.entities.insert(entity.uid.clone(), entity);
    }

    pub fn get(&self, uid: &str) -> Option<&Entity> {
        self.entities.get(uid)
    }

    pub fn len(&self) -> usize {
        self.entities.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entities.is_empty()
    }

    /// Load entities from Cedar's entity-JSON format.
    /// `[{ "uid": {"type","id"}, "attrs": {...}, "parents": [{"type","id"} | {"__entity": {...}}] }]`.
    /// Lets us run our evaluator against Cedar's own functional test corpus.
    pub fn from_cedar_entities_json(json: &serde_json::Value) -> Result<Self, String> {
        let arr = json.as_array().ok_or("entities JSON must be an array")?;
        let mut store = EntityStore::new();
        for e in arr {
            let uid = e.get("uid").ok_or("entity missing uid")?;
            let uid_str = cedar_uid_from_json(uid)?;
            let mut entity = Entity::new(uid_str);

            if let Some(attrs) = e.get("attrs").and_then(|a| a.as_object()) {
                for (k, v) in attrs {
                    entity.attrs.insert(k.clone(), json_to_value(v));
                }
            }
            if let Some(parents) = e.get("parents").and_then(|p| p.as_array()) {
                for p in parents {
                    entity.parents.push(cedar_uid_from_json(p)?);
                }
            }
            store.insert(entity);
        }
        Ok(store)
    }

}

/// The storage seam. Everything the evaluator needs from an entity store is
/// attribute lookup and transitive `in`. The in-memory `EntityStore` is one
/// implementation. A Postgres-backed store, or a SpiceDB / OpenFGA adapter at
/// Zanzibar scale, implements the same trait and drops in without touching the
/// evaluator. Object-safe so the evaluator can hold `&dyn EntityResolver`.
pub trait EntityResolver {
    /// Look up an attribute on an entity. `Ok(None)` = the entity has no such
    /// attribute; `Err` = the backend could not answer (fail-closed).
    fn attr(&self, uid: &str, name: &str) -> Result<Option<Value>, ChaiError>;
    /// Whether an entity has a given attribute. `Err` = backend unreachable.
    fn has_attr(&self, uid: &str, name: &str) -> Result<bool, ChaiError>;
    /// Cedar `in`. Is `ancestor` reachable by walking up `descendant`'s parent
    /// chain? Reflexive, so `a in a`. `Err` = the backend could not answer, in
    /// which case the caller must not treat the relation as false: a resolver
    /// outage is an error outcome, not a silent non-membership.
    fn is_in(&self, descendant: &str, ancestor: &str) -> Result<bool, ChaiError>;
}

impl EntityResolver for EntityStore {
    fn attr(&self, uid: &str, name: &str) -> Result<Option<Value>, ChaiError> {
        Ok(self.entities.get(uid).and_then(|e| e.attrs.get(name).cloned()))
    }

    fn has_attr(&self, uid: &str, name: &str) -> Result<bool, ChaiError> {
        Ok(self
            .entities
            .get(uid)
            .map_or(false, |e| e.attrs.contains_key(name)))
    }

    /// Walks the parent graph transitively with a cycle guard, so malformed
    /// stores with parent cycles terminate and never loop. The in-memory store
    /// is total (never fails), so this is always `Ok`.
    fn is_in(&self, descendant: &str, ancestor: &str) -> Result<bool, ChaiError> {
        if descendant == ancestor {
            return Ok(true);
        }
        let mut stack = vec![descendant.to_string()];
        let mut seen: HashSet<String> = HashSet::new();
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur.clone()) {
                continue;
            }
            if let Some(e) = self.entities.get(&cur) {
                for p in &e.parents {
                    if p == ancestor {
                        return Ok(true);
                    }
                    stack.push(p.clone());
                }
            }
        }
        Ok(false)
    }
}

/// Extract a canonical UID string from Cedar's JSON entity-ref encodings.
/// Either `{"type","id"}` or `{"__entity": {"type","id"}}`.
fn cedar_uid_from_json(v: &serde_json::Value) -> Result<String, String> {
    let inner = v.get("__entity").unwrap_or(v);
    let ty = inner
        .get("type")
        .and_then(|t| t.as_str())
        .ok_or("entity ref missing type")?;
    let id = inner
        .get("id")
        .and_then(|i| i.as_str())
        .ok_or("entity ref missing id")?;
    Ok(cedar_uid(ty, id))
}

/// Convert a Cedar attribute JSON value into our `Value`.
pub fn json_to_value(v: &serde_json::Value) -> Value {
    use serde_json::Value as J;
    match v {
        J::Bool(b) => Value::Bool(*b),
        J::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i)
            } else {
                Value::Float(n.as_f64().unwrap_or(0.0))
            }
        }
        J::String(s) => Value::String(s.clone()),
        J::Array(a) => Value::List(a.iter().map(json_to_value).collect()),
        J::Object(_) => {
            // Cedar extension value, e.g. {"__extn":{"fn":"ip","arg":"10.0.0.1"}}.
            if let Some(ext) = v.get("__extn") {
                let func = ext.get("fn").and_then(|x| x.as_str());
                let arg = ext.get("arg").and_then(|x| x.as_str());
                if let (Some(f), Some(a)) = (func, arg) {
                    match f {
                        "ip" => return Value::Ip(a.to_string()),
                        "decimal" => {
                            if let Some(d) = crate::evaluator::parse_decimal(a) {
                                return Value::Decimal(d);
                            }
                        }
                        _ => {}
                    }
                }
            }
            // An entity reference, or a nested record.
            if v.get("__entity").is_some() {
                match cedar_uid_from_json(v) {
                    Ok(uid) => Value::EntityUid(uid),
                    Err(_) => Value::String(String::new()),
                }
            } else {
                let map = v
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(k, val)| (k.clone(), json_to_value(val)))
                    .collect();
                Value::Dict(map)
            }
        }
        J::Null => Value::String(String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transitive_membership() {
        let mut s = EntityStore::new();
        // doc:readme  in  folder:shared  in  folder:root
        s.insert(Entity::new("folder:root"));
        s.insert(Entity::new("folder:shared").parent("folder:root"));
        s.insert(Entity::new("doc:readme").parent("folder:shared"));

        assert!(s.is_in("doc:readme", "doc:readme").unwrap()); // reflexive
        assert!(s.is_in("doc:readme", "folder:shared").unwrap()); // direct
        assert!(s.is_in("doc:readme", "folder:root").unwrap()); // transitive
        assert!(!s.is_in("folder:root", "doc:readme").unwrap()); // not downward
        assert!(!s.is_in("doc:readme", "folder:other").unwrap()); // unrelated
    }

    #[test]
    fn cycle_guard_terminates() {
        let mut s = EntityStore::new();
        s.insert(Entity::new("a").parent("b"));
        s.insert(Entity::new("b").parent("a"));
        // Must not infinite-loop; "c" is unreachable.
        assert!(!s.is_in("a", "c").unwrap());
        assert!(s.is_in("a", "b").unwrap());
    }
}
