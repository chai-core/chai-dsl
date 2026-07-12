use pest::Parser;
use pest_derive::Parser;
use crate::ast::{self, *};
use crate::error::ChaiError;
use crate::evaluator::EvalStrategy;

#[derive(Parser)]
#[grammar_inline = r##"
WHITESPACE = _{ " " | "\t" }
COMMENT = _{ "#" ~ (!"\n" ~ ANY)* }

program = { SOI ~ blank* ~ (mode_decl ~ stmt_end ~ blank*)? ~ (statement ~ stmt_end ~ blank*)* ~ EOI }
blank = _{ nl }
stmt_end = _{ ";" | nl | &EOI }

// Optional leading directive declaring how multiple matching rules resolve.
mode_decl = { "mode" ~ mode_name }
mode_name = @{ "first_match" | "deny_override" }

statement = {
    annotation* ~ (structured_rule | rule_stmt)
}

// Policy annotation, e.g. @id("pii-guard"). Cedar-style.
annotation = { "@" ~ ident ~ "(" ~ string ~ ")" }

structured_rule = {
    effect ~ err_mode? ~ tier_req? ~ "(" ~ param_list ~ ")" ~ "when" ~ ":" ~ nl ~ conditions ~ obligation_list?
}

param_list = {
    param ~ ("," ~ param)*
}

param = {
    ident ~ ":" ~ type_name
}

type_name = @{ "Agent" | "Resource" | "Channel" | "string" | "int" | "float" | "bool" }

conditions = {
    cond_expr ~ (nl ~ cond_expr)*
}

obligation_list = {
    nl ~ "obligations" ~ ":" ~ "[" ~ obligation ~ ("," ~ obligation)* ~ "]"
}

obligation = {
    string
}

rule_stmt = {
    effect ~ err_mode? ~ tier_req? ~ ("from" ~ principal_expr)? ~ ("to" ~ resource_expr)? ~ ("action" ~ action_expr)? ~ ("when" ~ when_expr)?
}

effect = @{ "permit" | "deny" | "forbid" | "redact" | "defer" | "require_human" | "downgrade" }

// Optional per-rule error annotation: how a condition error feeds the decision.
err_mode = @{ "strict" | "lenient" }

// Optional minimum evidence tier the guard's facts must meet, e.g. `requires attested`.
tier_req = { "requires" ~ tier_name }
tier_name = @{ "measured" | "derived" | "attested" }

principal_expr = { "any" | cond_expr }
resource_expr = { "any" | cond_expr }
action_expr = { string | ident }
when_expr = { cond_expr }

cond_expr = { or_cond }

or_cond = {
    and_cond ~ (("||" | "or") ~ and_cond)*
}

and_cond = {
    cmp_cond ~ (("&&" | "and") ~ cmp_cond)*
}

cmp_cond = {
    add_expr ~ ((cmp_op ~ add_expr) | (col_op ~ add_expr) | (is_kw ~ type_path))?
}

is_kw = @{ "is" ~ !('a'..'z' | 'A'..'Z' | '0'..'9' | "_") }
type_path = @{ ident ~ ("::" ~ ident)* }

add_expr = {
    mul_expr ~ (add_op ~ mul_expr)*
}

mul_expr = {
    unary_expr ~ (mul_op ~ unary_expr)*
}

// Captured (not silent literals) so the parser can see the operator. Without
// this, Pest emits no pair for a bare `"+"`, and parse_add_expr/parse_mul_expr
// silently drop the operator and the right operand.
add_op = @{ "+" | "-" }
mul_op = @{ "*" | "/" | "%" }

unary_expr = {
    (unary_op ~ unary_expr) | atom_expr
}

// Captured (not a silent literal) so the parser can actually see the operator.
unary_op = @{ "!" | "-" | ("not" ~ !('a'..'z' | 'A'..'Z' | '0'..'9' | "_")) }

// An atom is a base value followed by zero or more `.method(args)` postfixes.
atom_expr = { base_expr ~ method_call* }

base_expr = {
    entity_lit | slot | record_lit | list_lit | func_call | field_chain | prim_lit | "(" ~ cond_expr ~ ")"
}

// Postfix method call, e.g. `.isInRange(ip("10.0.0.0/8"))`.
method_call = { "." ~ ident ~ "(" ~ (cond_expr ~ ("," ~ cond_expr)*)? ~ ")" }

// Template slot, e.g. ?principal / ?resource.
slot = @{ "?" ~ ident }

// Entity UID literal, e.g. User::"alice" or PhotoFlash::Data::User::"alice".
entity_lit = @{ ident ~ ("::" ~ ident)* ~ "::" ~ string }

// List literal, e.g. [Action::"view", Action::"edit"].
list_lit = { "[" ~ (cond_expr ~ ("," ~ cond_expr)*)? ~ "]" }

// Record literal, e.g. { city: "DC", street: "main" } (keys bare or quoted).
record_lit = { "{" ~ (record_entry ~ ("," ~ record_entry)*)? ~ "}" }
record_entry = { (string | ident) ~ ":" ~ cond_expr }

// A field chain stops before a name that is immediately a method call, so
// `principal.addr.isInRange(...)` splits into base `principal.addr` + a method.
field_chain = {
    (ident | "agent" | "channel" | "dlp_facts" | "safety_facts" | "thresholds") ~ ("." ~ ident ~ !"(")*
}

func_call = {
    ident ~ "(" ~ (cond_expr ~ ("," ~ cond_expr)*)? ~ ")"
}

prim_lit = {
    bool_val | number | string | ident
}

bool_val = @{ "true" | "false" }
number = @{ "-"? ~ ('0'..'9')+ ~ ("." ~ ('0'..'9')+)? }
string = @{ "\"" ~ (!"\"" ~ ANY)* ~ "\"" }
ident = @{ ('a'..'z' | 'A'..'Z' | "_") ~ ('a'..'z' | 'A'..'Z' | '0'..'9' | "_")* }

cmp_op = @{ "==" | "!=" | "<=" | ">=" | "<" | ">" }
col_op = @{ "in" | "has" | "contains" | "like" }

nl = _{ "\r\n" | "\n" }
"##]
pub struct ChaiParser;

pub fn parse_chai(input: &str) -> Result<ChaiProgram, ChaiError> {
    let pairs = ChaiParser::parse(Rule::program, input)
        .map_err(|e| ChaiError::ParseError(e.to_string()))?;

    let mut rules = Vec::new();

    // pairs iterates the top-level matches. We expect a single program rule.
    // A statement that fails to build is a hard error, never silently dropped.
    // Dropping one would turn a malformed policy into a misleading default-deny.
    for program_pair in pairs {
        for pair in program_pair.into_inner() {
            if pair.as_rule() == Rule::statement {
                rules.push(parse_statement(pair)?);
            }
        }
    }

    Ok(ChaiProgram::SingleLineRules(rules))
}

/// Parse a policy and read its optional leading `mode` directive
/// (`mode first_match` or `mode deny_override`). Defaults to `DenyOverride`.
pub fn parse_chai_with_mode(input: &str) -> Result<(EvalStrategy, ChaiProgram), ChaiError> {
    let pairs = ChaiParser::parse(Rule::program, input)
        .map_err(|e| ChaiError::ParseError(e.to_string()))?;

    let mut rules = Vec::new();
    let mut strategy = EvalStrategy::DenyOverride;

    for program_pair in pairs {
        for pair in program_pair.into_inner() {
            match pair.as_rule() {
                Rule::mode_decl => {
                    let name = pair.into_inner().next().map(|n| n.as_str()).unwrap_or("");
                    strategy = match name {
                        "first_match" => EvalStrategy::FirstMatch,
                        _ => EvalStrategy::DenyOverride,
                    };
                }
                Rule::statement => rules.push(parse_statement(pair)?),
                _ => {}
            }
        }
    }

    Ok((strategy, ChaiProgram::SingleLineRules(rules)))
}

fn parse_statement(pair: pest::iterators::Pair<Rule>) -> Result<ast::Rule, ChaiError> {
    let mut id: Option<String> = None;
    let mut rule: Option<ast::Rule> = None;

    for p in pair.into_inner() {
        match p.as_rule() {
            Rule::annotation => {
                let mut a = p.into_inner();
                let name = a.next().map(|n| n.as_str().to_string()).unwrap_or_default();
                let val = a.next().map(|v| v.as_str().to_string()).unwrap_or_default();
                if name == "id" && val.len() >= 2 {
                    id = Some(val[1..val.len() - 1].to_string());
                }
            }
            Rule::structured_rule => rule = Some(parse_structured_rule(p)?),
            Rule::rule_stmt => rule = Some(parse_rule_stmt(p)?),
            _ => {}
        }
    }

    let mut rule = rule.ok_or_else(|| ChaiError::ParseError("Missing rule in statement".to_string()))?;
    if id.is_some() {
        rule.id = id;
    }
    Ok(rule)
}

fn parse_rule_stmt(pair: pest::iterators::Pair<Rule>) -> Result<ast::Rule, ChaiError> {
    let mut rule = ast::Rule {
        id: None,
        effect: Effect::Deny,
        principal: None,
        action: None,
        resource: None,
        condition: None,
        obligations: Vec::new(),
        error_mode: None,
        min_tier: None,
    };

    let mut stmt_inner = pair.into_inner();

    // First element is the effect.
    if let Some(effect_pair) = stmt_inner.next() {
        rule.effect = parse_effect_str(effect_pair.as_str())?;
    } else {
        return Err(ChaiError::ParseError("Missing effect".to_string()));
    }

    // The rest are optional clauses.
    while let Some(p) = stmt_inner.next() {
        match p.as_rule() {
            Rule::principal_expr => {
                rule.principal = Some(parse_principal_expr(p)?);
            }
            Rule::resource_expr => {
                rule.resource = Some(parse_resource_expr(p)?);
            }
            Rule::action_expr => {
                rule.action = Some(parse_action_expr(p)?);
            }
            Rule::when_expr => {
                rule.condition = Some(parse_when_expr(p)?);
            }
            Rule::err_mode => {
                rule.error_mode = Some(parse_err_mode(p.as_str())?);
            }
            Rule::tier_req => {
                rule.min_tier = Some(parse_tier_req(p)?);
            }
            _ => {}
        }
    }

    Ok(rule)
}

fn parse_structured_rule(pair: pest::iterators::Pair<Rule>) -> Result<ast::Rule, ChaiError> {
    let mut rule = ast::Rule {
        id: None,
        effect: Effect::Deny,
        principal: None,
        action: None,
        resource: None,
        condition: None,
        obligations: Vec::new(),
        error_mode: None,
        min_tier: None,
    };

    let mut inner = pair.into_inner();

    if let Some(effect_pair) = inner.next() {
        rule.effect = parse_effect_str(effect_pair.as_str())?;
    } else {
        return Err(ChaiError::ParseError("Missing effect in structured rule".to_string()));
    }

    // Optional error annotation and tier requirement sit between effect and params.
    let mut next = inner.next();
    if let Some(p) = &next {
        if p.as_rule() == Rule::err_mode {
            rule.error_mode = Some(parse_err_mode(p.as_str())?);
            next = inner.next();
        }
    }
    if let Some(p) = next.clone() {
        if p.as_rule() == Rule::tier_req {
            rule.min_tier = Some(parse_tier_req(p)?);
            next = inner.next();
        }
    }

    // Skip param_list and use the wildcard approach. Params look like
    // `principal: Agent, action: string, resource: Channel`.
    if let Some(param_pair) = &next {
        if param_pair.as_rule() == Rule::param_list {
            // TODO: extract parameter type information
        }
    }

    if let Some(cond_pair) = inner.next() {
        if cond_pair.as_rule() == Rule::conditions {
            if let Some(first_cond) = cond_pair.into_inner().next() {
                rule.condition = Some(parse_cond_expr(first_cond)?);
            }
        }
    }

    while let Some(p) = inner.next() {
        if p.as_rule() == Rule::obligation_list {
            for obl in p.into_inner() {
                if obl.as_rule() == Rule::obligation {
                    if let Some(s) = obl.into_inner().next() {
                        let text = s.as_str();
                        rule.obligations.push(text[1..text.len()-1].to_string());
                    }
                }
            }
        }
    }

    Ok(rule)
}

fn parse_effect_str(s: &str) -> Result<Effect, ChaiError> {
    match s {
        "permit" => Ok(Effect::Allow),
        "deny" => Ok(Effect::Deny),
        "forbid" => Ok(Effect::Forbid),
        "redact" => Ok(Effect::Redact),
        "defer" => Ok(Effect::Defer),
        "require_human" => Ok(Effect::RequireHuman),
        "downgrade" => Ok(Effect::Downgrade),
        _ => Err(ChaiError::ParseError(format!("Unknown effect: {}", s))),
    }
}

fn parse_err_mode(s: &str) -> Result<ast::ErrorMode, ChaiError> {
    match s {
        "strict" => Ok(ast::ErrorMode::Strict),
        "lenient" => Ok(ast::ErrorMode::Lenient),
        _ => Err(ChaiError::ParseError(format!("Unknown error mode: {}", s))),
    }
}

fn parse_tier_req(pair: pest::iterators::Pair<Rule>) -> Result<ast::Tier, ChaiError> {
    // `requires <tier_name>` -> the tier_name token.
    let name = pair
        .into_inner()
        .find(|p| p.as_rule() == Rule::tier_name)
        .map(|p| p.as_str().to_string())
        .ok_or_else(|| ChaiError::ParseError("Missing tier name".to_string()))?;
    match name.as_str() {
        "measured" => Ok(ast::Tier::Measured),
        "derived" => Ok(ast::Tier::Derived),
        "attested" => Ok(ast::Tier::Attested),
        other => Err(ChaiError::ParseError(format!("Unknown tier: {}", other))),
    }
}

fn parse_principal_expr(pair: pest::iterators::Pair<Rule>) -> Result<ast::PrincipalPattern, ChaiError> {
    let inner = pair.into_inner().next();
    if let Some(p) = inner {
        match p.as_rule() {
            Rule::cond_expr => {
                let expr = parse_cond_expr(p)?;
                Ok(ast::PrincipalPattern::Condition(expr))
            }
            _ => Ok(ast::PrincipalPattern::Any),
        }
    } else {
        Ok(ast::PrincipalPattern::Any)
    }
}

fn parse_resource_expr(pair: pest::iterators::Pair<Rule>) -> Result<ast::ResourcePattern, ChaiError> {
    let inner = pair.into_inner().next();
    if let Some(p) = inner {
        match p.as_rule() {
            Rule::cond_expr => {
                let expr = parse_cond_expr(p)?;
                Ok(ast::ResourcePattern::Condition(expr))
            }
            _ => Ok(ast::ResourcePattern::Any),
        }
    } else {
        Ok(ast::ResourcePattern::Any)
    }
}

fn parse_action_expr(pair: pest::iterators::Pair<Rule>) -> Result<ast::ActionPattern, ChaiError> {
    let inner = pair.into_inner().next().ok_or_else(|| ChaiError::ParseError("Missing action".to_string()))?;
    match inner.as_rule() {
        Rule::string => {
            let s = inner.as_str();
            Ok(ast::ActionPattern::Eq(s[1..s.len() - 1].to_string()))
        }
        Rule::ident => Ok(ast::ActionPattern::Eq(inner.as_str().to_string())),
        _ => Err(ChaiError::ParseError("Invalid action".to_string())),
    }
}

fn parse_when_expr(pair: pest::iterators::Pair<Rule>) -> Result<Expr, ChaiError> {
    let inner = pair.into_inner().next().ok_or_else(|| ChaiError::ParseError("Missing condition".to_string()))?;
    parse_cond_expr(inner)
}

fn parse_cond_expr(pair: pest::iterators::Pair<Rule>) -> Result<Expr, ChaiError> {
    let inner = pair.into_inner().next().ok_or_else(|| ChaiError::ParseError("Missing or condition".to_string()))?;
    parse_or_cond(inner)
}

fn parse_or_cond(pair: pest::iterators::Pair<Rule>) -> Result<Expr, ChaiError> {
    let mut inner = pair.into_inner();
    let mut left = parse_and_cond(inner.next().ok_or_else(|| ChaiError::ParseError("Missing and condition".to_string()))?)?;

    while let Some(p) = inner.next() {
        if p.as_rule() == Rule::and_cond {
            let right = parse_and_cond(p)?;
            left = Expr::BinaryOp {
                left: Box::new(left),
                op: BinaryOp::Or,
                right: Box::new(right),
            };
        }
    }

    Ok(left)
}

fn parse_and_cond(pair: pest::iterators::Pair<Rule>) -> Result<Expr, ChaiError> {
    let mut inner = pair.into_inner();
    let mut left = parse_cmp_cond(inner.next().ok_or_else(|| ChaiError::ParseError("Missing comparison".to_string()))?)?;

    while let Some(p) = inner.next() {
        if p.as_rule() == Rule::cmp_cond {
            let right = parse_cmp_cond(p)?;
            left = Expr::BinaryOp {
                left: Box::new(left),
                op: BinaryOp::And,
                right: Box::new(right),
            };
        }
    }

    Ok(left)
}

fn parse_cmp_cond(pair: pest::iterators::Pair<Rule>) -> Result<Expr, ChaiError> {
    let mut inner = pair.into_inner();
    let mut left = parse_add_expr(inner.next().ok_or_else(|| ChaiError::ParseError("Missing additive expression".to_string()))?)?;

    while let Some(p) = inner.next() {
        match p.as_rule() {
            Rule::cmp_op => {
                let op = parse_cmp_op(p.as_str())?;
                let right = parse_add_expr(inner.next().ok_or_else(|| ChaiError::ParseError("Missing right side".to_string()))?)?;
                left = Expr::BinaryOp {
                    left: Box::new(left),
                    op,
                    right: Box::new(right),
                };
            }
            Rule::col_op => {
                let op = parse_col_op(p.as_str())?;
                let right = parse_add_expr(inner.next().ok_or_else(|| ChaiError::ParseError("Missing right side".to_string()))?)?;
                left = Expr::BinaryOp {
                    left: Box::new(left),
                    op,
                    right: Box::new(right),
                };
            }
            // `entity is Type`. RHS is the type-name path as a string literal.
            Rule::is_kw => {
                let ty = inner.next().ok_or_else(|| ChaiError::ParseError("Missing type after `is`".to_string()))?;
                left = Expr::BinaryOp {
                    left: Box::new(left),
                    op: BinaryOp::Is,
                    right: Box::new(Expr::Literal(Value::String(ty.as_str().to_string()))),
                };
            }
            _ => {}
        }
    }

    Ok(left)
}

fn parse_add_expr(pair: pest::iterators::Pair<Rule>) -> Result<Expr, ChaiError> {
    let mut inner = pair.into_inner();
    let mut left = parse_mul_expr(inner.next().ok_or_else(|| ChaiError::ParseError("Missing multiplicative expression".to_string()))?)?;

    while let Some(p) = inner.next() {
        let op_str = p.as_str();
        let op = match op_str {
            "+" => BinaryOp::Add,
            "-" => BinaryOp::Sub,
            _ => continue,
        };
        let right = parse_mul_expr(inner.next().ok_or_else(|| ChaiError::ParseError("Missing right side".to_string()))?)?;
        left = Expr::BinaryOp {
            left: Box::new(left),
            op,
            right: Box::new(right),
        };
    }

    Ok(left)
}

fn parse_mul_expr(pair: pest::iterators::Pair<Rule>) -> Result<Expr, ChaiError> {
    let mut inner = pair.into_inner();
    let mut left = parse_unary_expr(inner.next().ok_or_else(|| ChaiError::ParseError("Missing unary expression".to_string()))?)?;

    while let Some(p) = inner.next() {
        let op_str = p.as_str();
        let op = match op_str {
            "*" => BinaryOp::Mul,
            "/" => BinaryOp::Div,
            "%" => BinaryOp::Mod,
            _ => continue,
        };
        let right = parse_unary_expr(inner.next().ok_or_else(|| ChaiError::ParseError("Missing right side".to_string()))?)?;
        left = Expr::BinaryOp {
            left: Box::new(left),
            op,
            right: Box::new(right),
        };
    }

    Ok(left)
}

fn parse_unary_expr(pair: pest::iterators::Pair<Rule>) -> Result<Expr, ChaiError> {
    let mut inner = pair.into_inner();
    let first = inner.next().ok_or_else(|| ChaiError::ParseError("Missing expression".to_string()))?;

    match first.as_rule() {
        Rule::unary_op => {
            let op = match first.as_str().trim() {
                "-" => UnaryOp::Neg,
                _ => UnaryOp::Not, // "!" or "not"
            };
            let operand = parse_unary_expr(
                inner.next().ok_or_else(|| ChaiError::ParseError("Missing operand".to_string()))?,
            )?;
            Ok(Expr::UnaryOp { op, operand: Box::new(operand) })
        }
        _ => parse_atom_expr(first),
    }
}

fn parse_atom_expr(pair: pest::iterators::Pair<Rule>) -> Result<Expr, ChaiError> {
    match pair.as_rule() {
        Rule::atom_expr => {
            // base_expr followed by zero or more `.method(args)` postfixes.
            let mut inner = pair.into_inner();
            let base = inner.next().ok_or_else(|| ChaiError::ParseError("Empty atom_expr".to_string()))?;
            let mut expr = parse_atom_expr(base)?;
            for mc in inner {
                if mc.as_rule() != Rule::method_call {
                    continue;
                }
                let mut mi = mc.into_inner();
                let method = mi.next().ok_or_else(|| ChaiError::ParseError("Missing method name".to_string()))?.as_str().to_string();
                let mut args = Vec::new();
                for a in mi {
                    args.push(parse_cond_expr(a)?);
                }
                expr = Expr::MethodCall { object: Box::new(expr), method, args };
            }
            Ok(expr)
        }
        Rule::base_expr => {
            let inner = pair.into_inner().next().ok_or_else(|| ChaiError::ParseError("Empty base_expr".to_string()))?;
            parse_atom_expr(inner)
        }
        // Template slot `?principal`.
        Rule::slot => Ok(Expr::Slot(pair.as_str().trim_start_matches('?').to_string())),
        Rule::func_call => {
            let mut inner = pair.into_inner();
            let name = inner.next().ok_or_else(|| ChaiError::ParseError("Missing function name".to_string()))?;
            let mut args = Vec::new();
            for arg in inner {
                args.push(parse_cond_expr(arg)?);
            }
            Ok(Expr::FunctionCall {
                name: name.as_str().to_string(),
                args,
            })
        }
        Rule::field_chain => {
            let mut inner = pair.into_inner();
            let first = inner.next().ok_or_else(|| ChaiError::ParseError("Missing field".to_string()))?;
            let mut expr = Expr::Variable(first.as_str().to_string());
            for p in inner {
                expr = Expr::FieldAccess {
                    object: Box::new(expr),
                    field: p.as_str().to_string(),
                };
            }
            Ok(expr)
        }
        Rule::prim_lit => parse_prim_lit(pair),
        // Entity UID literal `Type::"id"`. Quotes stripped so it matches store keys.
        Rule::entity_lit => Ok(Expr::Literal(Value::EntityUid(pair.as_str().replace('"', "")))),
        // List literal `[a, b, c]`.
        Rule::list_lit => {
            let mut items = Vec::new();
            for el in pair.into_inner() {
                items.push(parse_cond_expr(el)?);
            }
            Ok(Expr::List(items))
        }
        // Record literal `{ key: val, ... }`.
        Rule::record_lit => {
            let mut entries = Vec::new();
            for entry in pair.into_inner() {
                let mut it = entry.into_inner();
                let key_pair = it.next().ok_or_else(|| ChaiError::ParseError("Missing record key".to_string()))?;
                let key = match key_pair.as_rule() {
                    Rule::string => {
                        let s = key_pair.as_str();
                        s[1..s.len() - 1].to_string()
                    }
                    _ => key_pair.as_str().to_string(),
                };
                let val = parse_cond_expr(it.next().ok_or_else(|| ChaiError::ParseError("Missing record value".to_string()))?)?;
                entries.push((key, val));
            }
            Ok(Expr::Dict(entries))
        }
        // Parenthesized sub-expression `( cond_expr )`.
        Rule::cond_expr => parse_cond_expr(pair),
        _ => Err(ChaiError::ParseError(format!("Unknown atom expression: {:?}", pair.as_rule()))),
    }
}

fn parse_prim_lit(pair: pest::iterators::Pair<Rule>) -> Result<Expr, ChaiError> {
    let inner = pair.into_inner().next().ok_or_else(|| ChaiError::ParseError("Missing literal".to_string()))?;
    match inner.as_rule() {
        Rule::bool_val => {
            Ok(Expr::Literal(Value::Bool(inner.as_str() == "true")))
        }
        Rule::number => {
            let s = inner.as_str();
            if let Ok(n) = s.parse::<i64>() {
                Ok(Expr::Literal(Value::Int(n)))
            } else if let Ok(f) = s.parse::<f64>() {
                Ok(Expr::Literal(Value::Float(f)))
            } else {
                Err(ChaiError::ParseError("Invalid number".to_string()))
            }
        }
        Rule::string => {
            let s = inner.as_str();
            Ok(Expr::Literal(Value::String(s[1..s.len() - 1].to_string())))
        }
        Rule::ident => {
            Ok(Expr::Variable(inner.as_str().to_string()))
        }
        _ => Err(ChaiError::ParseError("Unknown literal".to_string())),
    }
}

fn parse_cmp_op(s: &str) -> Result<BinaryOp, ChaiError> {
    match s {
        "==" => Ok(BinaryOp::Eq),
        "!=" => Ok(BinaryOp::Ne),
        "<" => Ok(BinaryOp::Lt),
        "<=" => Ok(BinaryOp::Le),
        ">" => Ok(BinaryOp::Gt),
        ">=" => Ok(BinaryOp::Ge),
        _ => Err(ChaiError::ParseError(format!("Unknown comparison operator: {}", s))),
    }
}

fn parse_col_op(s: &str) -> Result<BinaryOp, ChaiError> {
    match s {
        "in" => Ok(BinaryOp::In),
        "has" => Ok(BinaryOp::Has),
        "contains" => Ok(BinaryOp::Contains),
        "like" => Ok(BinaryOp::Like),
        _ => Err(ChaiError::ParseError(format!("Unknown collection operator: {}", s))),
    }
}
