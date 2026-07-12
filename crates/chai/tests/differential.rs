//! Generative differential testing against the REAL Cedar crate.
//!
//! For each randomly generated scenario (entity hierarchy + attributes + request
//! + policy set), we render it to BOTH Cedar's syntax and ours, run BOTH engines,
//! and assert they reach the same Allow/Deny. This is the strongest test we have:
//! it compares against Cedar on inputs neither of us hand-picked.
//!
//! Run with: `cargo test --features cedar-diff`
#![cfg(feature = "cedar-diff")]

use std::str::FromStr;

use cedar_policy::{Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request};
use chai_dsl::ast::{Effect, Value};
use chai_dsl::entity::{normalize_uid, EntityStore};
use chai_dsl::{eval_with_store, parse_chai};
use proptest::prelude::*;
use std::collections::HashMap;

fn user_uid(i: u8) -> String {
    format!("User::\"u{}\"", i % 2)
}
fn action_uid(i: u8) -> String {
    format!("Action::\"{}\"", if i % 2 == 0 { "view" } else { "edit" })
}
fn resource_uid(i: u8) -> String {
    match i % 4 {
        0 => "Photo::\"p0\"".into(),
        1 => "Photo::\"p1\"".into(),
        2 => "Album::\"a0\"".into(),
        _ => "Album::\"a1\"".into(),
    }
}

fn ent(ty: &str, id: &str) -> String {
    format!("{{\"__entity\":{{\"type\":\"{ty}\",\"id\":\"{id}\"}}}}")
}

/// Decimal + record attributes per resource id, so `resource.cost`/`resource.meta`
/// always resolve (every resource carries them, avoids missing-attribute
/// divergence between engines). cost > 100 for p0/a0; meta.level >= 2 for p0/a0.
fn res_attrs(id: &str) -> String {
    let (cost, level) = match id {
        "p0" => ("150.00", 3),
        "p1" => ("50.00", 1),
        "a0" => ("200.00", 2),
        _ => ("20.00", 0), // a1
    };
    format!("\"cost\":{{\"__extn\":{{\"fn\":\"decimal\",\"arg\":\"{cost}\"}}}},\"meta\":{{\"level\":{level}}}")
}

/// Cedar-format entity JSON shared by both engines. Includes principal groups
/// (User -> Group), a deeper resource chain (Photo -> Album -> Album), and now
/// `decimal()` + record attributes on every resource.
fn entities_json(
    public: [bool; 2],
    photo_parents: [u8; 2],
    user_groups: [u8; 2],
    user_addr: [u8; 2],
    a0_parent_a1: bool,
) -> String {
    let photo = |id: &str, pub_: bool, par: u8| {
        let parents = if par < 2 { format!("[{}]", ent("Album", &format!("a{par}"))) } else { "[]".into() };
        format!(
            "{{\"uid\":{{\"type\":\"Photo\",\"id\":\"{id}\"}},\"attrs\":{{\"isPublic\":{pub_},{attrs}}},\"parents\":{parents}}}",
            attrs = res_attrs(id)
        )
    };
    let user = |id: &str, grp: u8, addr_idx: u8| {
        let parents = if grp < 2 { format!("[{}]", ent("Group", &format!("g{grp}"))) } else { "[]".into() };
        let addr = if addr_idx == 0 { "10.0.0.5" } else { "192.168.1.5" }; // in / out of 10.0.0.0/24
        format!(
            "{{\"uid\":{{\"type\":\"User\",\"id\":\"{id}\"}},\"attrs\":{{\"addr\":{{\"__extn\":{{\"fn\":\"ip\",\"arg\":\"{addr}\"}}}}}},\"parents\":{parents}}}"
        )
    };
    let a0_parents = if a0_parent_a1 { format!("[{}]", ent("Album", "a1")) } else { "[]".into() };
    format!(
        "[{u0},{u1},\
         {{\"uid\":{{\"type\":\"Group\",\"id\":\"g0\"}},\"attrs\":{{}},\"parents\":[]}},\
         {{\"uid\":{{\"type\":\"Group\",\"id\":\"g1\"}},\"attrs\":{{}},\"parents\":[]}},\
         {{\"uid\":{{\"type\":\"Action\",\"id\":\"view\"}},\"attrs\":{{}},\"parents\":[]}},\
         {{\"uid\":{{\"type\":\"Action\",\"id\":\"edit\"}},\"attrs\":{{}},\"parents\":[]}},\
         {{\"uid\":{{\"type\":\"Album\",\"id\":\"a0\"}},\"attrs\":{{{a0_attrs}}},\"parents\":{a0_parents}}},\
         {{\"uid\":{{\"type\":\"Album\",\"id\":\"a1\"}},\"attrs\":{{{a1_attrs}}},\"parents\":[]}},\
         {p0},{p1}]",
        u0 = user("u0", user_groups[0], user_addr[0]),
        u1 = user("u1", user_groups[1], user_addr[1]),
        p0 = photo("p0", public[0], photo_parents[0]),
        p1 = photo("p1", public[1], photo_parents[1]),
        a0_attrs = res_attrs("a0"),
        a1_attrs = res_attrs("a1"),
    )
}

/// A rule: effect + principal/action/resource scope codes + when-{public,ip,decimal,record}.
type Rule = (bool, u8, u8, u8, bool, bool, bool, bool);

fn p_scope(c: u8) -> Option<String> {
    match c % 5 {
        0 => None,
        1 => Some(format!("principal == {}", user_uid(0))),
        2 => Some(format!("principal == {}", user_uid(1))),
        3 => Some("principal in Group::\"g0\"".into()),
        _ => Some("principal in Group::\"g1\"".into()),
    }
}
fn a_scope(c: u8) -> Option<String> {
    match c % 4 {
        0 => None,
        1 => Some("action == Action::\"view\"".into()),
        2 => Some("action == Action::\"edit\"".into()),
        _ => Some("action in [Action::\"view\", Action::\"edit\"]".into()),
    }
}
fn r_scope(c: u8) -> Option<String> {
    match c % 7 {
        0 => None,
        n @ 1..=4 => Some(format!("resource == {}", resource_uid(n - 1))),
        5 => Some("resource in Album::\"a0\"".into()),
        _ => Some("resource in Album::\"a1\"".into()),
    }
}

const IP_TERM: &str = "principal.addr.isInRange(ip(\"10.0.0.0/24\"))";
const DECIMAL_TERM: &str = "resource.cost.greaterThan(decimal(\"100.00\"))";
const RECORD_TERM: &str = "resource.meta.level >= 2";

fn when_terms(when_public: bool, when_ip: bool, when_decimal: bool, when_record: bool) -> Vec<String> {
    let mut t = Vec::new();
    if when_public {
        t.push("resource.isPublic".to_string());
    }
    if when_ip {
        t.push(IP_TERM.to_string());
    }
    if when_decimal {
        t.push(DECIMAL_TERM.to_string());
    }
    if when_record {
        t.push(RECORD_TERM.to_string());
    }
    t
}

fn cedar_policy_text(rules: &[Rule]) -> String {
    rules
        .iter()
        .map(|&(forbid, p, a, r, when_public, when_ip, when_decimal, when_record)| {
            let eff = if forbid { "forbid" } else { "permit" };
            let ps = p_scope(p).unwrap_or_else(|| "principal".into());
            let as_ = a_scope(a).unwrap_or_else(|| "action".into());
            let rs = r_scope(r).unwrap_or_else(|| "resource".into());
            let terms = when_terms(when_public, when_ip, when_decimal, when_record);
            let cond = if terms.is_empty() { String::new() } else { format!(" when {{ {} }}", terms.join(" && ")) };
            format!("{eff} (\n  {ps},\n  {as_},\n  {rs}\n){cond};\n")
        })
        .collect()
}

fn our_policy_text(rules: &[Rule]) -> String {
    rules
        .iter()
        .map(|&(forbid, p, a, r, when_public, when_ip, when_decimal, when_record)| {
            let eff = if forbid { "forbid" } else { "permit" };
            let mut conds: Vec<String> = [p_scope(p), a_scope(a), r_scope(r)].into_iter().flatten().collect();
            conds.extend(when_terms(when_public, when_ip, when_decimal, when_record));
            let body = if conds.is_empty() { "true".into() } else { conds.join(" and ") };
            format!("{eff} when {body}\n")
        })
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]
    #[test]
    fn agrees_with_cedar(
        public in any::<[bool; 2]>(),
        photo_parents in [0u8..3, 0u8..3],
        user_groups in [0u8..3, 0u8..3],
        user_addr in [0u8..2, 0u8..2],
        a0_parent_a1 in any::<bool>(),
        req in (0u8..2, 0u8..2, 0u8..4),
        rules in proptest::collection::vec((any::<bool>(), 0u8..5, 0u8..4, 0u8..7, any::<bool>(), any::<bool>(), any::<bool>(), any::<bool>()), 1..4),
    ) {
        let ent_json = entities_json(public, photo_parents, user_groups, user_addr, a0_parent_a1);

        // --- Cedar ---
        let pset = PolicySet::from_str(&cedar_policy_text(&rules)).expect("cedar policy parses");
        let entities = Entities::from_json_str(&ent_json, None).expect("cedar entities parse");
        let request = Request::new(
            EntityUid::from_str(&user_uid(req.0)).unwrap(),
            EntityUid::from_str(&action_uid(req.1)).unwrap(),
            EntityUid::from_str(&resource_uid(req.2)).unwrap(),
            Context::empty(),
            None,
        ).unwrap();
        let cedar_allow = matches!(
            Authorizer::new().is_authorized(&request, &pset, &entities).decision(),
            Decision::Allow
        );

        // --- Ours ---
        let prog = parse_chai(&our_policy_text(&rules)).expect("our policy parses");
        let store = EntityStore::from_cedar_entities_json(&serde_json::from_str(&ent_json).unwrap()).unwrap();
        let mut ctx = HashMap::new();
        ctx.insert("principal".into(), Value::EntityUid(normalize_uid(&user_uid(req.0))));
        ctx.insert("action".into(), Value::EntityUid(normalize_uid(&action_uid(req.1))));
        ctx.insert("resource".into(), Value::EntityUid(normalize_uid(&resource_uid(req.2))));
        let ours = eval_with_store(&prog, ctx, &store).unwrap();

        // Effect-tagged errors (§1.1) make Chai deliberately MORE conservative than
        // Cedar when a rule's guard errors, e.g. a `forbid` touching an attribute
        // the entity lacks. Cedar treats that rule as Indeterminate and skips it
        // (and may allow); Chai denies (XACML `Indeterminate{D}`). Agreement with
        // Cedar is the claim on the *error-free* fragment, so the oracle compares
        // only runs with no recorded evaluation error.
        prop_assume!(ours.errors.is_empty());
        let ours_allow = matches!(ours.effect, Effect::Allow);

        prop_assert_eq!(
            cedar_allow, ours_allow,
            "DIVERGENCE\n--cedar policy--\n{}\n--our policy--\n{}\nrequest: {:?}\nentities: {}",
            cedar_policy_text(&rules), our_policy_text(&rules), req, ent_json
        );
    }
}
