use crate::ast::*;
use crate::entity::{EntityStore, EntityResolver};
use crate::error::ChaiError;
use std::collections::HashMap;

pub struct Evaluator<'a> {
    variables: HashMap<String, Value>,
    store: &'a dyn EntityResolver,
    /// Evidence tier per fact root (e.g. `approval` -> Attested). Populated from a
    /// reserved `__tiers` context entry so no evaluation signatures change. A root
    /// not listed defaults to `Measured` (the conservative floor).
    tiers: HashMap<String, Tier>,
}

impl<'a> Evaluator<'a> {
    pub fn new(store: &'a dyn EntityResolver) -> Self {
        Evaluator {
            variables: HashMap::new(),
            store,
            tiers: HashMap::new(),
        }
    }

    pub fn with_context(mut self, variables: HashMap<String, Value>) -> Self {
        // A reserved `__tiers` entry carries fact provenance: a dict of
        // root-name -> tier-name ("measured"/"derived"/"attested").
        if let Some(Value::Dict(map)) = variables.get("__tiers") {
            for (root, v) in map {
                if let Value::String(t) = v {
                    let tier = match t.as_str() {
                        "attested" => Tier::Attested,
                        "derived" => Tier::Derived,
                        _ => Tier::Measured,
                    };
                    self.tiers.insert(root.clone(), tier);
                }
            }
        }
        self.variables = variables;
        self
    }

    /// The evidence tier of a fact root (defaults to `Measured`).
    fn tier_of(&self, root: &str) -> Tier {
        self.tiers.get(root).copied().unwrap_or(Tier::Measured)
    }

    /// The effective evidence tier of a guard: the minimum tier over the fact roots
    /// it reads (the weakest evidence it rests on), or `Measured` if it reads none.
    fn guard_tier(&self, expr: &Expr) -> Tier {
        let mut roots = std::collections::HashSet::new();
        collect_roots(expr, &mut roots);
        roots.iter().map(|r| self.tier_of(r)).min().unwrap_or(Tier::Measured)
    }

    /// Resolve a request variable (principal/action/resource) to its UID string.
    /// Accepts a plain String or an EntityUid binding.
    fn resolve_uid(&self, name: &str) -> Option<String> {
        match self.variables.get(name) {
            Some(Value::EntityUid(u)) => Some(u.clone()),
            Some(Value::String(s)) => Some(s.clone()),
            _ => None,
        }
    }

    pub fn eval_expr(&self, expr: &Expr) -> Result<Value, ChaiError> {
        match expr {
            Expr::Literal(val) => Ok(val.clone()),
            Expr::Variable(name) => {
                // boolean keyword literals
                if name == "true" {
                    return Ok(Value::Bool(true));
                }
                if name == "false" {
                    return Ok(Value::Bool(false));
                }
                self.variables
                    .get(name)
                    .cloned()
                    .ok_or_else(|| ChaiError::UnknownEntity(name.clone()))
            }
            Expr::BinaryOp { left, op, right } => {
                let left_val = self.eval_expr(left)?;
                let right_val = self.eval_expr(right)?;
                self.eval_binary_op(&left_val, *op, &right_val)
            }
            Expr::UnaryOp { op, operand } => {
                let val = self.eval_expr(operand)?;
                self.eval_unary_op(*op, &val)
            }
            Expr::FieldAccess { object, field } => {
                let obj = self.eval_expr(object)?;
                self.get_field(&obj, field)
            }
            Expr::FunctionCall { name, args } => {
                let arg_vals: Result<Vec<_>, _> = args.iter().map(|a| self.eval_expr(a)).collect();
                self.eval_function(name, arg_vals?)
            }
            Expr::List(items) => {
                let vals: Result<Vec<_>, _> = items.iter().map(|e| self.eval_expr(e)).collect();
                Ok(Value::List(vals?))
            }
            Expr::Dict(entries) => {
                let mut map = HashMap::new();
                for (k, v) in entries {
                    map.insert(k.clone(), self.eval_expr(v)?);
                }
                Ok(Value::Dict(map))
            }
            Expr::MethodCall { object, method, args } => {
                let recv = self.eval_expr(object)?;
                let arg_vals = args
                    .iter()
                    .map(|a| self.eval_expr(a))
                    .collect::<Result<Vec<_>, _>>()?;
                eval_method(&recv, method, &arg_vals)
            }
            // an unlinked template slot must never silently succeed. fail-closed.
            Expr::Slot(name) => Err(ChaiError::EvalError(format!("unlinked template slot ?{}", name))),
        }
    }

    fn eval_binary_op(&self, left: &Value, op: BinaryOp, right: &Value) -> Result<Value, ChaiError> {
        match (left, right, op) {
            // Arithmetic. Overflow is a visible eval error, not a panic (Cedar
            // does the same), keeping the fail-closed + visible-error invariant.
            (Value::Int(a), Value::Int(b), BinaryOp::Add) => a
                .checked_add(*b)
                .map(Value::Int)
                .ok_or_else(|| ChaiError::EvalError("integer overflow in +".to_string())),
            (Value::Int(a), Value::Int(b), BinaryOp::Sub) => a
                .checked_sub(*b)
                .map(Value::Int)
                .ok_or_else(|| ChaiError::EvalError("integer overflow in -".to_string())),
            (Value::Int(a), Value::Int(b), BinaryOp::Mul) => a
                .checked_mul(*b)
                .map(Value::Int)
                .ok_or_else(|| ChaiError::EvalError("integer overflow in *".to_string())),
            (Value::Int(a), Value::Int(b), BinaryOp::Div) => {
                if *b == 0 {
                    Err(ChaiError::EvalError("Division by zero".to_string()))
                } else {
                    Ok(Value::Int(a / b))
                }
            }
            (Value::Int(a), Value::Int(b), BinaryOp::Mod) => {
                if *b == 0 {
                    Err(ChaiError::EvalError("Modulo by zero".to_string()))
                } else {
                    Ok(Value::Int(a % b))
                }
            }

            // Floating point arithmetic
            (Value::Float(a), Value::Float(b), BinaryOp::Add) => Ok(Value::Float(a + b)),
            (Value::Float(a), Value::Float(b), BinaryOp::Sub) => Ok(Value::Float(a - b)),
            (Value::Float(a), Value::Float(b), BinaryOp::Mul) => Ok(Value::Float(a * b)),
            (Value::Float(a), Value::Float(b), BinaryOp::Div) => {
                if *b == 0.0 {
                    Err(ChaiError::EvalError("Division by zero".to_string()))
                } else {
                    Ok(Value::Float(a / b))
                }
            }

            // Comparisons
            (Value::Int(a), Value::Int(b), BinaryOp::Eq) => Ok(Value::Bool(a == b)),
            (Value::Int(a), Value::Int(b), BinaryOp::Ne) => Ok(Value::Bool(a != b)),
            (Value::Int(a), Value::Int(b), BinaryOp::Lt) => Ok(Value::Bool(a < b)),
            (Value::Int(a), Value::Int(b), BinaryOp::Le) => Ok(Value::Bool(a <= b)),
            (Value::Int(a), Value::Int(b), BinaryOp::Gt) => Ok(Value::Bool(a > b)),
            (Value::Int(a), Value::Int(b), BinaryOp::Ge) => Ok(Value::Bool(a >= b)),

            // Float comparisons
            (Value::Float(a), Value::Float(b), BinaryOp::Eq) => Ok(Value::Bool((a - b).abs() < f64::EPSILON)),
            (Value::Float(a), Value::Float(b), BinaryOp::Ne) => Ok(Value::Bool((a - b).abs() >= f64::EPSILON)),
            (Value::Float(a), Value::Float(b), BinaryOp::Lt) => Ok(Value::Bool(a < b)),
            (Value::Float(a), Value::Float(b), BinaryOp::Le) => Ok(Value::Bool(a <= b)),
            (Value::Float(a), Value::Float(b), BinaryOp::Gt) => Ok(Value::Bool(a > b)),
            (Value::Float(a), Value::Float(b), BinaryOp::Ge) => Ok(Value::Bool(a >= b)),

            // String comparisons
            (Value::String(a), Value::String(b), BinaryOp::Eq) => Ok(Value::Bool(a == b)),
            (Value::String(a), Value::String(b), BinaryOp::Ne) => Ok(Value::Bool(a != b)),
            (Value::String(a), Value::String(b), BinaryOp::Like) => {
                Ok(Value::Bool(pattern_match(a, b)))
            }

            // Boolean logic
            (Value::Bool(a), Value::Bool(b), BinaryOp::And) => Ok(Value::Bool(*a && *b)),
            (Value::Bool(a), Value::Bool(b), BinaryOp::Or) => Ok(Value::Bool(*a || *b)),
            (Value::Bool(a), Value::Bool(b), BinaryOp::Eq) => Ok(Value::Bool(a == b)),
            (Value::Bool(a), Value::Bool(b), BinaryOp::Ne) => Ok(Value::Bool(a != b)),

            // IP equality compares the parsed address. "::1" equals
            // "0:0:0:0:0:0:0:1" since they are the same IPv6 address.
            (Value::Ip(a), Value::Ip(b), BinaryOp::Eq) => Ok(Value::Bool(ip_eq(a, b))),
            (Value::Ip(a), Value::Ip(b), BinaryOp::Ne) => Ok(Value::Bool(!ip_eq(a, b))),

            // structural equality for records, lists, and decimals
            (Value::Dict(_), Value::Dict(_), BinaryOp::Eq)
            | (Value::List(_), Value::List(_), BinaryOp::Eq)
            | (Value::Decimal(_), Value::Decimal(_), BinaryOp::Eq) => Ok(Value::Bool(left == right)),
            (Value::Dict(_), Value::Dict(_), BinaryOp::Ne)
            | (Value::List(_), Value::List(_), BinaryOp::Ne)
            | (Value::Decimal(_), Value::Decimal(_), BinaryOp::Ne) => Ok(Value::Bool(left != right)),

            // entity identity equality. also compares against a UID string
            // literal written in a policy (there is no entity-literal syntax yet).
            (Value::EntityUid(a), Value::EntityUid(b), BinaryOp::Eq) => Ok(Value::Bool(a == b)),
            (Value::EntityUid(a), Value::EntityUid(b), BinaryOp::Ne) => Ok(Value::Bool(a != b)),
            (Value::EntityUid(a), Value::String(b), BinaryOp::Eq)
            | (Value::String(b), Value::EntityUid(a), BinaryOp::Eq) => Ok(Value::Bool(a == b)),
            (Value::EntityUid(a), Value::String(b), BinaryOp::Ne)
            | (Value::String(b), Value::EntityUid(a), BinaryOp::Ne) => Ok(Value::Bool(a != b)),

            // entity hierarchy. `a in b` is transitive ancestor-or-self.
            (Value::EntityUid(a), Value::EntityUid(b), BinaryOp::In) => {
                Ok(Value::Bool(self.store.is_in(a, b)?))
            }
            // `entity in "Type::\"id\""`. RHS string literal is treated as a UID.
            (Value::EntityUid(a), Value::String(b), BinaryOp::In) => {
                Ok(Value::Bool(self.store.is_in(a, b)?))
            }
            // `entity is Type`. the type is the UID prefix before the last `::`.
            (Value::EntityUid(uid), Value::String(ty), BinaryOp::Is) => {
                let actual = uid.rsplit_once("::").map(|(t, _)| t).unwrap_or(uid);
                Ok(Value::Bool(actual == ty))
            }
            // `a in [set]` is true if `a` is a descendant-or-self of any entity
            // in the set (Cedar semantics). non-entity elements fall back to equality.
            // A resolver failure on any element propagates (fail-closed), rather
            // than being swallowed into a `false`.
            (Value::EntityUid(a), Value::List(items), BinaryOp::In) => {
                for it in items {
                    let member = match it {
                        Value::EntityUid(b) => self.store.is_in(a, b)?,
                        other => other == left,
                    };
                    if member {
                        return Ok(Value::Bool(true));
                    }
                }
                Ok(Value::Bool(false))
            }
            // `entity has "attr"`. attribute presence on an entity.
            (Value::EntityUid(uid), Value::String(attr), BinaryOp::Has) => {
                Ok(Value::Bool(self.store.has_attr(uid, attr)?))
            }

            // collection operators
            // `x in [..]` membership. element on the left, collection on the right.
            (_, Value::List(items), BinaryOp::In) => {
                Ok(Value::Bool(items.iter().any(|v| v == left)))
            }
            // `[..] contains x` flips `in`. collection on the left.
            (Value::List(items), _, BinaryOp::Contains) => {
                Ok(Value::Bool(items.iter().any(|v| v == right)))
            }
            // `"abc" contains "b"` substring containment.
            (Value::String(s), Value::String(sub), BinaryOp::Contains) => {
                Ok(Value::Bool(s.contains(sub.as_str())))
            }
            // `record has "attr"`. attribute presence on a dict/entity.
            (Value::Dict(map), Value::String(key), BinaryOp::Has) => {
                Ok(Value::Bool(map.contains_key(key)))
            }

            _ => Err(ChaiError::InvalidOperation(
                format!("Cannot apply {:?} to {:?} and {:?}", op, left, right),
            )),
        }
    }

    fn eval_unary_op(&self, op: UnaryOp, operand: &Value) -> Result<Value, ChaiError> {
        match (op, operand) {
            (UnaryOp::Not, Value::Bool(b)) => Ok(Value::Bool(!b)),
            (UnaryOp::Neg, Value::Int(n)) => Ok(Value::Int(-n)),
            (UnaryOp::Neg, Value::Float(f)) => Ok(Value::Float(-f)),
            _ => Err(ChaiError::InvalidOperation(
                format!("Cannot apply {:?} to {:?}", op, operand),
            )),
        }
    }

    fn get_field(&self, obj: &Value, field: &str) -> Result<Value, ChaiError> {
        match obj {
            Value::Dict(map) => {
                map.get(field)
                    .cloned()
                    .ok_or_else(|| ChaiError::UnknownEntity(field.to_string()))
            }
            // resolve the attribute against the entity store
            Value::EntityUid(uid) => self.store.attr(uid, field)?.ok_or_else(|| {
                ChaiError::EvalError(format!("entity {} has no attribute {}", uid, field))
            }),
            _ => Err(ChaiError::TypeError(
                format!("Cannot access field {} on {:?}", field, obj),
            )),
        }
    }

    fn eval_function(&self, name: &str, args: Vec<Value>) -> Result<Value, ChaiError> {
        match name {
            "size" | "len" => {
                if args.len() != 1 {
                    return Err(ChaiError::InvalidOperation(
                        format!("{} expects 1 argument", name),
                    ));
                }
                match &args[0] {
                    Value::List(l) => Ok(Value::Int(l.len() as i64)),
                    Value::String(s) => Ok(Value::Int(s.len() as i64)),
                    Value::Dict(d) => Ok(Value::Int(d.len() as i64)),
                    _ => Err(ChaiError::TypeError("size() requires a collection".to_string())),
                }
            }
            // containsAll(s, t) holds when every element of t is in s.
            // containsAny(s, t) holds when some element of t is in s.
            "containsAll" | "containsAny" => {
                if let [Value::List(s), Value::List(t)] = args.as_slice() {
                    let pred = |x: &Value| s.contains(x);
                    let result = if name == "containsAll" {
                        t.iter().all(pred)
                    } else {
                        t.iter().any(pred)
                    };
                    Ok(Value::Bool(result))
                } else {
                    Err(ChaiError::TypeError(format!("{} expects two lists", name)))
                }
            }
            // extension type constructors
            "ip" => match args.as_slice() {
                [Value::String(s)] => Ok(Value::Ip(s.clone())),
                _ => Err(ChaiError::TypeError("ip() expects one string".to_string())),
            },
            "decimal" => match args.as_slice() {
                [Value::String(s)] => parse_decimal(s)
                    .map(Value::Decimal)
                    .ok_or_else(|| ChaiError::TypeError(format!("invalid decimal: {s}"))),
                _ => Err(ChaiError::TypeError("decimal() expects one string".to_string())),
            },
            _ => Err(ChaiError::UnknownEntity(format!("Unknown function: {}", name))),
        }
    }
}

/// Dispatch an extension-type method call like `ip(...).isInRange(...)`.
fn eval_method(recv: &Value, method: &str, args: &[Value]) -> Result<Value, ChaiError> {
    match (recv, method) {
        // ip methods
        (Value::Ip(s), "isLoopback") => Ok(Value::Bool(parse_ip(s).map_or(false, |a| a.is_loopback()))),
        (Value::Ip(s), "isMulticast") => Ok(Value::Bool(parse_ip(s).map_or(false, |a| a.is_multicast()))),
        (Value::Ip(s), "isIpv4") => Ok(Value::Bool(matches!(parse_ip(s), Some(std::net::IpAddr::V4(_))))),
        (Value::Ip(s), "isIpv6") => Ok(Value::Bool(matches!(parse_ip(s), Some(std::net::IpAddr::V6(_))))),
        (Value::Ip(s), "isInRange") => match args.first() {
            Some(Value::Ip(range)) => Ok(Value::Bool(ip_in_range(s, range))),
            _ => Err(ChaiError::TypeError("isInRange expects an ip".to_string())),
        },
        // decimal comparison methods
        (Value::Decimal(a), "lessThan") => decimal_cmp(*a, args, |x, y| x < y),
        (Value::Decimal(a), "lessThanOrEqual") => decimal_cmp(*a, args, |x, y| x <= y),
        (Value::Decimal(a), "greaterThan") => decimal_cmp(*a, args, |x, y| x > y),
        (Value::Decimal(a), "greaterThanOrEqual") => decimal_cmp(*a, args, |x, y| x >= y),
        _ => Err(ChaiError::InvalidOperation(format!(
            "no method `{}` on {:?}",
            method, recv
        ))),
    }
}

fn decimal_cmp(a: i64, args: &[Value], op: fn(i64, i64) -> bool) -> Result<Value, ChaiError> {
    match args.first() {
        Some(Value::Decimal(b)) => Ok(Value::Bool(op(a, *b))),
        _ => Err(ChaiError::TypeError("decimal comparison expects a decimal".to_string())),
    }
}

/// Parse "12.3456" into fixed-point with 4 fractional digits (scaled by 10_000).
pub(crate) fn parse_decimal(s: &str) -> Option<i64> {
    let (neg, s) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };
    if frac_part.len() > 4 || int_part.is_empty() && frac_part.is_empty() {
        return None;
    }
    // reject non-digit parts, e.g. "1.2.3" splits to frac "2.3"
    if !int_part.chars().all(|c| c.is_ascii_digit()) || !frac_part.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let int: i64 = if int_part.is_empty() { 0 } else { int_part.parse().ok()? };
    let mut frac_padded = String::from(frac_part);
    while frac_padded.len() < 4 {
        frac_padded.push('0');
    }
    let frac: i64 = frac_padded.parse().ok()?;
    // checked arithmetic. a too-large value returns None and never panics.
    let val = int.checked_mul(10_000)?.checked_add(frac)?;
    Some(if neg { val.checked_neg()? } else { val })
}

fn parse_ip(s: &str) -> Option<std::net::IpAddr> {
    s.split('/').next().unwrap_or(s).parse().ok()
}

/// IP equality by address value. Plain addresses compare by parsed `IpAddr`,
/// so different textual forms of the same address are equal. CIDR ranges and
/// unparseable values fall back to string equality.
fn ip_eq(a: &str, b: &str) -> bool {
    if a.contains('/') || b.contains('/') {
        return a == b;
    }
    match (parse_ip(a), parse_ip(b)) {
        (Some(x), Some(y)) => x == y,
        _ => a == b,
    }
}

/// Whether `addr` falls within `range`, a single ip or CIDR like "10.0.0.0/24".
fn ip_in_range(addr: &str, range: &str) -> bool {
    use std::net::IpAddr;
    let (base_str, prefix) = match range.split_once('/') {
        Some((a, p)) => (a, p.parse::<u32>().ok()),
        None => (range, None),
    };
    match (parse_ip(addr), base_str.parse::<IpAddr>().ok()) {
        (Some(IpAddr::V4(a)), Some(IpAddr::V4(b))) => {
            let p = prefix.unwrap_or(32).min(32);
            let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
            (u32::from(a) & mask) == (u32::from(b) & mask)
        }
        (Some(IpAddr::V6(a)), Some(IpAddr::V6(b))) => {
            let p = prefix.unwrap_or(128).min(128);
            let mask = if p == 0 { 0 } else { u128::MAX << (128 - p) };
            (u128::from(a) & mask) == (u128::from(b) & mask)
        }
        _ => false,
    }
}

pub fn eval(program: &ChaiProgram, context: HashMap<String, Value>) -> Result<Decision, ChaiError> {
    let store = EntityStore::new();
    eval_with_store(program, context, &store)
}

/// Evaluate a program against an explicit entity store. Required for Cedar-style
/// relationship-based access control like `resource in principal.viewable`.
pub fn eval_with_store(
    program: &ChaiProgram,
    context: HashMap<String, Value>,
    store: &dyn EntityResolver,
) -> Result<Decision, ChaiError> {
    match program {
        ChaiProgram::SingleLineRules(rules) => eval_rules(rules, context, store),
        ChaiProgram::StructuredRules(policy) => eval_rules(&policy.rules, context, store),
        ChaiProgram::HierarchicalConfig(config) => eval_rules(&config.rules, context, store),
    }
}

pub fn eval_rules(
    rules: &[Rule],
    context: HashMap<String, Value>,
    store: &dyn EntityResolver,
) -> Result<Decision, ChaiError> {
    let evaluator = Evaluator::new(store).with_context(context);

    // bucket every satisfied rule by effect
    let mut denies = Vec::new();
    let mut require_humans = Vec::new();
    let mut defers = Vec::new();
    let mut redacts = Vec::new();
    let mut downgrades = Vec::new();
    let mut allows = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    for rule in rules {
        let contributes = match eval_rule(&evaluator, rule) {
            Ok(true) => true,
            Ok(false) => false,
            // Effect-tagged errors (XACML `Indeterminate`, specialized to the
            // erroring rule's effect). The error is always recorded so a broken
            // policy is never mistaken for a clean decision. A *strict,
            // restrictive* rule additionally contributes its effect: we could
            // not check the condition that would have restricted, so we restrict.
            // A permit or a `lenient` rule stays inert (it can never grant).
            Err(e) => {
                errors.push(format!("rule {}: {}", rule.id.as_deref().unwrap_or("?"), e));
                rule.error_contributes()
            }
        };
        if contributes {
            match rule.effect {
                Effect::Deny | Effect::Forbid => denies.push(rule),
                Effect::RequireHuman => require_humans.push(rule),
                Effect::Defer => defers.push(rule),
                Effect::Redact => redacts.push(rule),
                Effect::Downgrade => downgrades.push(rule),
                Effect::Allow => allows.push(rule),
            }
        }
    }

    // most-restrictive-wins lattice. deny-overrides generalized to the full
    // emission algebra. DENY > REQUIRE_HUMAN > DEFER > REDACT > DOWNGRADE > ALLOW.
    // for permit/forbid-only policies this reduces exactly to Cedar's
    // deny-overrides. every determining rule is reported (Cedar-style diagnostics).
    let resolved: Option<(Effect, &Vec<&Rule>, &str)> = if !denies.is_empty() {
        Some((Effect::Deny, &denies, "forbid_overrides"))
    } else if !require_humans.is_empty() {
        Some((Effect::RequireHuman, &require_humans, "require_human"))
    } else if !defers.is_empty() {
        Some((Effect::Defer, &defers, "defer"))
    } else if !redacts.is_empty() {
        Some((Effect::Redact, &redacts, "redact"))
    } else if !downgrades.is_empty() {
        Some((Effect::Downgrade, &downgrades, "downgrade"))
    } else if !allows.is_empty() {
        Some((Effect::Allow, &allows, "permit_allowed"))
    } else {
        None
    };

    // Seal-on-presence: a matched (or strictly-errored) require_human rule seals
    // the stream even when a more-restrictive effect (deny) wins the verdict.
    let require_human_present = !require_humans.is_empty();

    if let Some((effect, winners, code)) = resolved {
        // Accumulate release transforms: when the verdict releases, every matched
        // releasing rule at-or-below the verdict contributes its transform, in
        // ascending-rank order (Downgrade before Redact), the verdict's own
        // transform included. `Allow` is identity and is never listed. This is
        // what makes redact(SSN)+downgrade(labels) apply *both* to the release.
        let mut transforms = Vec::new();
        if effect.is_releasing() {
            if !downgrades.is_empty() && Effect::Downgrade.rank() <= effect.rank() {
                transforms.push(Effect::Downgrade);
            }
            if !redacts.is_empty() && Effect::Redact.rank() <= effect.rank() {
                transforms.push(Effect::Redact);
            }
        }
        return Ok(Decision {
            effect,
            reason: format!("{:?} by rule(s): {}", effect, ids_of(winners).join(", ")),
            reason_codes: vec![code.to_string()],
            obligations: obligations_of(winners),
            rule_trace: ids_of(winners),
            errors,
            require_human_present,
            transforms,
            metadata: HashMap::new(),
        });
    }

    // no rule matched. fail-closed default deny.
    let reason = if errors.is_empty() {
        "No rules matched, defaulting to deny".to_string()
    } else {
        format!("Default deny; {} rule(s) errored during evaluation", errors.len())
    };
    Ok(Decision {
        effect: Effect::Deny,
        reason,
        reason_codes: vec!["default_deny".to_string()],
        obligations: Vec::new(),
        rule_trace: Vec::new(),
        errors,
        require_human_present: false,
        transforms: Vec::new(),
        metadata: HashMap::new(),
    })
}

/// How a policy set resolves multiple matching rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalStrategy {
    /// Cedar-style. Evaluate all rules. Forbid overrides permit. Order-independent.
    /// Safe default. A rule can never be shadowed by ordering.
    DenyOverride,
    /// ipfw/firewall-style. The first matching rule decides and order is priority.
    /// Order becomes security-critical here since a rule can shadow a later deny.
    /// Explicit opt-in only.
    FirstMatch,
}

/// Evaluate a program under an explicit strategy. `eval` and `eval_with_store`
/// default to `DenyOverride`.
pub fn eval_with_strategy(
    program: &ChaiProgram,
    context: HashMap<String, Value>,
    store: &dyn EntityResolver,
    strategy: EvalStrategy,
) -> Result<Decision, ChaiError> {
    let rules = match program {
        ChaiProgram::SingleLineRules(rules) => rules.as_slice(),
        ChaiProgram::StructuredRules(policy) => policy.rules.as_slice(),
        ChaiProgram::HierarchicalConfig(config) => config.rules.as_slice(),
    };
    match strategy {
        EvalStrategy::DenyOverride => eval_rules(rules, context, store),
        EvalStrategy::FirstMatch => Ok(eval_rules_first_match(rules, context, store)),
    }
}

/// ipfw/firewall semantics. Rules in order, first match wins.
fn eval_rules_first_match(
    rules: &[Rule],
    context: HashMap<String, Value>,
    store: &dyn EntityResolver,
) -> Decision {
    let evaluator = Evaluator::new(store).with_context(context);
    let mut errors = Vec::new();

    for rule in rules {
        let contributes = match eval_rule(&evaluator, rule) {
            Ok(true) => true,
            Ok(false) => false,
            // Effect-tagged errors under first-match: a strict restrictive rule's
            // error is a match on that rule's effect (fail-closed), so it decides
            // here; a permit or lenient rule is skipped. The error is recorded
            // either way.
            Err(e) => {
                errors.push(format!("rule {}: {}", rule.id.as_deref().unwrap_or("?"), e));
                rule.error_contributes()
            }
        };
        if contributes {
            let effect = match rule.effect {
                Effect::Forbid => Effect::Deny,
                e => e,
            };
            let id = rule.id.clone().unwrap_or_else(|| "<anonymous>".to_string());
            // First-match has a single deciding rule, so the transform set is just
            // that rule's own releasing transform (Allow is identity, unlisted).
            let transforms = if effect.is_releasing() && effect != Effect::Allow {
                vec![effect]
            } else {
                Vec::new()
            };
            return Decision {
                effect,
                reason: format!("First-match: rule {} decided", id),
                reason_codes: vec!["first_match".to_string()],
                obligations: rule.obligations.clone(),
                rule_trace: vec![id],
                errors,
                // First-match seals on the winning verdict; require_human as the
                // verdict is handled by the emission effect match.
                require_human_present: matches!(effect, Effect::RequireHuman),
                transforms,
                metadata: HashMap::new(),
            };
        }
    }

    Decision {
        effect: Effect::Deny,
        reason: "No rule matched (first-match); default deny".to_string(),
        reason_codes: vec!["default_deny".to_string()],
        obligations: Vec::new(),
        rule_trace: Vec::new(),
        errors,
        require_human_present: false,
        transforms: Vec::new(),
        metadata: HashMap::new(),
    }
}

fn ids_of(rules: &[&Rule]) -> Vec<String> {
    rules
        .iter()
        .map(|r| r.id.clone().unwrap_or_else(|| "<anonymous>".to_string()))
        .collect()
}

fn obligations_of(rules: &[&Rule]) -> Vec<String> {
    rules.iter().flat_map(|r| r.obligations.clone()).collect()
}

fn eval_rule(evaluator: &Evaluator<'_>, rule: &Rule) -> Result<bool, ChaiError> {
    // Evidence-tier gate: a rule annotated `requires <tier>` fires only if the
    // facts its guard reads all meet that tier. Fail-closed: a gated rule resting
    // on weaker evidence (e.g. a permit requiring attested but reading measured
    // detector output) simply does not fire.
    if let Some(min_tier) = rule.min_tier {
        let gtier = rule
            .condition
            .as_ref()
            .map_or(Tier::Measured, |c| evaluator.guard_tier(c));
        if gtier < min_tier {
            return Ok(false);
        }
    }

    // principal
    if let Some(principal) = &rule.principal {
        if !eval_principal_pattern(evaluator, principal)? {
            return Ok(false);
        }
    }

    // action
    if let Some(action) = &rule.action {
        if !eval_action_pattern(evaluator, action)? {
            return Ok(false);
        }
    }

    // resource
    if let Some(resource) = &rule.resource {
        if !eval_resource_pattern(evaluator, resource)? {
            return Ok(false);
        }
    }

    // condition. errors propagate up for the caller to collect. they must never
    // be silently treated as a non-match.
    if let Some(condition) = &rule.condition {
        match evaluator.eval_expr(condition)? {
            Value::Bool(b) => Ok(b),
            other => Err(ChaiError::TypeError(format!(
                "condition did not evaluate to a boolean: {:?}",
                other
            ))),
        }
    } else {
        Ok(true)
    }
}

fn eval_principal_pattern(evaluator: &Evaluator<'_>, pattern: &PrincipalPattern) -> Result<bool, ChaiError> {
    match pattern {
        PrincipalPattern::Any => Ok(true),
        PrincipalPattern::Eq(expected) => {
            Ok(evaluator.resolve_uid("principal").as_deref() == Some(expected.as_str()))
        }
        PrincipalPattern::Like(pattern) => match evaluator.resolve_uid("principal") {
            Some(principal) => Ok(pattern_match(&principal, pattern)),
            None => Ok(false),
        },
        PrincipalPattern::Condition(expr) => match evaluator.eval_expr(expr)? {
            Value::Bool(b) => Ok(b),
            other => Err(ChaiError::TypeError(format!(
                "principal condition not boolean: {:?}",
                other
            ))),
        },
        // `principal in Group::"..."`. transitive membership in the entity store.
        PrincipalPattern::In(group) => match evaluator.resolve_uid("principal") {
            Some(principal) => evaluator.store.is_in(&principal, group),
            None => Ok(false),
        },
    }
}

fn eval_action_pattern(evaluator: &Evaluator<'_>, pattern: &ActionPattern) -> Result<bool, ChaiError> {
    match pattern {
        ActionPattern::Any => Ok(true),
        ActionPattern::Eq(expected) => {
            Ok(evaluator.resolve_uid("action").as_deref() == Some(expected.as_str()))
        }
        ActionPattern::In(actions) => match evaluator.resolve_uid("action") {
            Some(action) => Ok(actions.contains(&action)),
            None => Ok(false),
        },
    }
}

fn eval_resource_pattern(evaluator: &Evaluator<'_>, pattern: &ResourcePattern) -> Result<bool, ChaiError> {
    match pattern {
        ResourcePattern::Any => Ok(true),
        ResourcePattern::Eq(expected) => {
            Ok(evaluator.resolve_uid("resource").as_deref() == Some(expected.as_str()))
        }
        ResourcePattern::Like(pattern) => match evaluator.resolve_uid("resource") {
            Some(resource) => Ok(pattern_match(&resource, pattern)),
            None => Ok(false),
        },
        ResourcePattern::Condition(expr) => match evaluator.eval_expr(expr)? {
            Value::Bool(b) => Ok(b),
            other => Err(ChaiError::TypeError(format!(
                "resource condition not boolean: {:?}",
                other
            ))),
        },
        // `resource in Album::"..."`. transitive membership in the entity store.
        ResourcePattern::In(group) => match evaluator.resolve_uid("resource") {
            Some(resource) => evaluator.store.is_in(&resource, group),
            None => Ok(false),
        },
    }
}

/// Collect the fact roots a guard reads (the base name of each variable/field
/// access), so the tier gate can check the evidence the guard rests on. Boolean
/// keyword literals are not facts and are excluded.
fn collect_roots(expr: &Expr, roots: &mut std::collections::HashSet<String>) {
    match expr {
        Expr::Variable(name) => {
            if name != "true" && name != "false" {
                roots.insert(name.clone());
            }
        }
        Expr::FieldAccess { object, .. } => collect_roots(object, roots),
        Expr::BinaryOp { left, right, .. } => {
            collect_roots(left, roots);
            collect_roots(right, roots);
        }
        Expr::UnaryOp { operand, .. } => collect_roots(operand, roots),
        Expr::MethodCall { object, args, .. } => {
            collect_roots(object, roots);
            for a in args {
                collect_roots(a, roots);
            }
        }
        Expr::FunctionCall { args, .. } => {
            for a in args {
                collect_roots(a, roots);
            }
        }
        Expr::List(items) => {
            for i in items {
                collect_roots(i, roots);
            }
        }
        Expr::Dict(entries) => {
            for (_, v) in entries {
                collect_roots(v, roots);
            }
        }
        Expr::Literal(_) | Expr::Slot(_) => {}
    }
}

fn pattern_match(text: &str, pattern: &str) -> bool {
    // glob matching. * matches any sequence
    if pattern == "*" {
        return true;
    }

    let mut text_chars = text.chars();
    let mut pattern_chars = pattern.chars().peekable();

    while let Some(pc) = pattern_chars.next() {
        match pc {
            '*' => {
                if pattern_chars.peek().is_none() {
                    return true;
                }
                let remaining_pattern: String = pattern_chars.collect();
                // Try each char-boundary suffix (plus the empty one). Byte-slicing
                // at a non-boundary index panics on multibyte UTF-8, and the
                // evaluator's left operand is often arbitrary agent output.
                let offsets = text.char_indices().map(|(i, _)| i).chain(std::iter::once(text.len()));
                for i in offsets {
                    if pattern_match(&text[i..], &remaining_pattern) {
                        return true;
                    }
                }
                return false;
            }
            '?' => {
                if text_chars.next().is_none() {
                    return false;
                }
            }
            c => {
                if text_chars.next() != Some(c) {
                    return false;
                }
            }
        }
    }

    text_chars.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arithmetic() {
        let mut context = HashMap::new();
        context.insert("a".to_string(), Value::Int(5));
        context.insert("b".to_string(), Value::Int(3));

        let store = EntityStore::new();
        let eval = Evaluator::new(&store).with_context(context);
        let expr = Expr::BinaryOp {
            left: Box::new(Expr::Variable("a".to_string())),
            op: BinaryOp::Add,
            right: Box::new(Expr::Variable("b".to_string())),
        };

        let result = eval.eval_expr(&expr).unwrap();
        assert_eq!(result, Value::Int(8));
    }

    #[test]
    fn arithmetic_parses_and_evaluates_end_to_end() {
        use crate::ast::Effect;
        use crate::parser::parse_chai;
        fn ctx(pairs: &[(&str, i64)]) -> HashMap<String, Value> {
            pairs.iter().map(|(k, v)| (k.to_string(), Value::Int(*v))).collect()
        }
        fn decide(src: &str, c: HashMap<String, Value>) -> Effect {
            let prog = parse_chai(src).unwrap();
            eval_with_store(&prog, c, &EntityStore::new()).map(|d| d.effect).unwrap_or(Effect::Deny)
        }
        // Regression: the parser used to drop `+ b`, so `a + b == 8` evaluated as
        // `a == 8` and denied (a=5,b=3). It must now allow.
        assert_eq!(decide("permit when a + b == 8\n", ctx(&[("a", 5), ("b", 3)])), Effect::Allow);
        assert_eq!(decide("permit when a + b == 5\n", ctx(&[("a", 5), ("b", 3)])), Effect::Deny);
        // Precedence: `*` binds tighter than `+`, so 5 + 3*2 == 11.
        assert_eq!(decide("permit when a + b * c == 11\n", ctx(&[("a", 5), ("b", 3), ("c", 2)])), Effect::Allow);
        // Subtraction, division, modulo all reach the evaluator.
        assert_eq!(decide("permit when a - b == 2\n", ctx(&[("a", 5), ("b", 3)])), Effect::Allow);
        assert_eq!(decide("permit when a / b == 2\n", ctx(&[("a", 6), ("b", 3)])), Effect::Allow);
        assert_eq!(decide("permit when a % b == 1\n", ctx(&[("a", 7), ("b", 3)])), Effect::Allow);
        // Overflow is a visible eval error, so the rule cannot grant: fail-closed deny, no panic.
        assert_eq!(decide("permit when a + b == 0\n", ctx(&[("a", i64::MAX), ("b", 1)])), Effect::Deny);
    }

    #[test]
    fn like_glob_handles_multibyte_utf8_without_panic() {
        use crate::ast::Effect;
        use crate::parser::parse_chai;
        fn decide(pattern: &str, subject: &str) -> Effect {
            let src = format!("permit when resource like \"{pattern}\"\n");
            let prog = parse_chai(&src).unwrap();
            let mut ctx = HashMap::new();
            ctx.insert("resource".to_string(), Value::String(subject.to_string()));
            eval_with_store(&prog, ctx, &EntityStore::new()).map(|d| d.effect).unwrap_or(Effect::Deny)
        }
        // Regression: the `*` branch byte-sliced `&text[i..]`, panicking when the
        // subject held a multibyte char. These must decide, not crash.
        assert_eq!(decide("*x", "café"), Effect::Deny); // no match, exercises the `*` suffix loop
        assert_eq!(decide("caf*", "café"), Effect::Allow);
        assert_eq!(decide("*f?", "café"), Effect::Allow); // `?` consumes the multibyte `é`
    }

    #[test]
    fn test_comparison() {
        let mut context = HashMap::new();
        context.insert("x".to_string(), Value::Int(10));

        let store = EntityStore::new();
        let eval = Evaluator::new(&store).with_context(context);
        let expr = Expr::BinaryOp {
            left: Box::new(Expr::Variable("x".to_string())),
            op: BinaryOp::Gt,
            right: Box::new(Expr::Literal(Value::Int(5))),
        };

        let result = eval.eval_expr(&expr).unwrap();
        assert_eq!(result, Value::Bool(true));
    }

    #[test]
    fn starlark_features() {
        use crate::parser::parse_chai;

        // `is` type test
        let p = parse_chai("permit when resource is Photo\n").unwrap();
        let mut ctx = HashMap::new();
        ctx.insert("resource".to_string(), Value::EntityUid("Photo::x".to_string()));
        assert!(matches!(eval(&p, ctx).unwrap().effect, Effect::Allow));

        // wrong type denies
        let mut ctx = HashMap::new();
        ctx.insert("resource".to_string(), Value::EntityUid("Album::x".to_string()));
        assert!(matches!(eval(&p, ctx).unwrap().effect, Effect::Deny));

        // record literal equality
        let p = parse_chai("permit when { city: \"DC\" } == { city: \"DC\" }\n").unwrap();
        assert!(matches!(eval(&p, HashMap::new()).unwrap().effect, Effect::Allow));

        // containsAll
        let p = parse_chai("permit when containsAll([1, 2, 3], [1, 2])\n").unwrap();
        assert!(matches!(eval(&p, HashMap::new()).unwrap().effect, Effect::Allow));
    }

    #[test]
    fn strategies_diverge_and_ids_thread_through() {
        use crate::parser::parse_chai;
        let prog = parse_chai(
            "@id(\"p\") permit when principal == User::\"bob\"\n@id(\"d\") deny when true\n",
        )
        .unwrap();
        let store = EntityStore::new();
        let mut ctx = HashMap::new();
        ctx.insert("principal".to_string(), Value::EntityUid("User::bob".to_string()));

        // deny-override. the broad deny wins, reported by id.
        let deny = eval_with_strategy(&prog, ctx.clone(), &store, EvalStrategy::DenyOverride).unwrap();
        assert!(matches!(deny.effect, Effect::Deny));
        assert_eq!(deny.rule_trace, vec!["d".to_string()]);

        // first-match. the earlier permit wins.
        let allow = eval_with_strategy(&prog, ctx, &store, EvalStrategy::FirstMatch).unwrap();
        assert!(matches!(allow.effect, Effect::Allow));
        assert_eq!(allow.rule_trace, vec!["p".to_string()]);
    }

    #[test]
    fn mode_directive_selects_strategy() {
        use crate::parser::parse_chai_with_mode;
        let src = "mode first_match\n@id(\"p\") permit when principal == User::\"bob\"\n@id(\"d\") deny when true\n";
        let (strategy, prog) = parse_chai_with_mode(src).unwrap();
        assert_eq!(strategy, EvalStrategy::FirstMatch);

        let store = EntityStore::new();
        let mut ctx = HashMap::new();
        ctx.insert("principal".to_string(), Value::EntityUid("User::bob".to_string()));
        let d = eval_with_strategy(&prog, ctx, &store, strategy).unwrap();
        assert!(matches!(d.effect, Effect::Allow)); // first-match, permit wins

        // no directive falls back to deny-override
        let (strategy, _) = parse_chai_with_mode("permit when true\n").unwrap();
        assert_eq!(strategy, EvalStrategy::DenyOverride);
    }

    #[test]
    fn extension_types_and_action_groups() {
        use crate::entity::Entity;
        use crate::parser::parse_chai;
        let store = EntityStore::new();

        // ip equality, decimal comparison, ip CIDR range
        let p = parse_chai(
            "permit when ip(\"127.0.0.1\") == ip(\"127.0.0.1\") and decimal(\"0.8\").greaterThanOrEqual(decimal(\"0.75\")) and ip(\"192.168.0.5\").isInRange(ip(\"192.168.0.1/24\"))\n",
        )
        .unwrap();
        assert!(matches!(eval_with_store(&p, HashMap::new(), &store).unwrap().effect, Effect::Allow));

        // decimal that fails the comparison denies
        let p = parse_chai("permit when decimal(\"0.5\").greaterThanOrEqual(decimal(\"0.75\"))\n").unwrap();
        assert!(matches!(eval_with_store(&p, HashMap::new(), &store).unwrap().effect, Effect::Deny));

        // action groups. Action::"view" is a member of ActionGroup::"readOps"
        // via the entity hierarchy, so `action in ActionGroup::"readOps"` matches.
        let mut s = EntityStore::new();
        s.insert(Entity::new("ActionGroup::readOps"));
        s.insert(Entity::new("Action::view").parent("ActionGroup::readOps"));
        let p = parse_chai("permit when action in ActionGroup::\"readOps\"\n").unwrap();

        let mut ctx = HashMap::new();
        ctx.insert("action".to_string(), Value::EntityUid("Action::view".to_string()));
        assert!(matches!(eval_with_store(&p, ctx, &s).unwrap().effect, Effect::Allow));

        let mut ctx2 = HashMap::new();
        ctx2.insert("action".to_string(), Value::EntityUid("Action::delete".to_string()));
        assert!(matches!(eval_with_store(&p, ctx2, &s).unwrap().effect, Effect::Deny));
    }

    #[test]
    fn errored_rule_is_visible_not_silent_deny() {
        // `"abc" < 5` is a type error. the rule must not silently vanish into a
        // clean deny. the error has to surface in the decision.
        let prog = crate::parser::parse_chai("permit when \"abc\" < 5\n").unwrap();
        let decision = eval(&prog, HashMap::new()).unwrap();
        assert!(matches!(decision.effect, Effect::Deny));
        assert_eq!(decision.errors.len(), 1, "the evaluation error must be recorded");
    }
}
