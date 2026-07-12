//! Dataflow / taint tracking for agent sessions.
//!
//! Split per the architecture invariant (inference vs control):
//!   * labeling here is a heuristic, best-effort and tested but not proven. Data
//!     from an untrusted source contributes distinctive tokens to a session
//!     taint set, which only ever grows (monotone);
//!   * enforcement is ordinary ESP. [`sink_facts`] projects the taint state
//!     into a `tooltrace.tainted_sink` fact, and a policy like
//!     `forbid when tooltrace.tainted_sink == true` denies an untrusted-to-sink
//!     flow. That decision is the proven core (`forbid_overrides`).
//!
//! v2 (laundering-resistant). Alongside verbatim token-substring matching, the
//! tracker keeps a *normalized* form of each tainted token (lowercased,
//! non-alphanumerics stripped) and, at match time, also decodes base64/hex runs
//! in the candidate. This catches the common launderings (case changes,
//! whitespace/punctuation splitting (`AKIA... SECRET`), and encoding
//! (`base64`/`hex`)) without touching the proven enforcement projection, which
//! still reads the monotone verbatim set. Deeper launderings (secret interleaved
//! with filler text, paraphrase, ciphered) remain measured misses in
//! `tests/exfiltration.rs`.

use crate::ast::Value;
use std::collections::{HashMap, HashSet};

/// Minimum length for a token to be distinctive enough to taint. Avoids
/// over-tainting on short common words.
const MIN_TOKEN_LEN: usize = 8;

/// Minimum length of a normalized token to be used for laundering-resistant
/// matching. Keeps the normalized form distinctive enough to avoid false hits.
const MIN_NORM_LEN: usize = 8;

/// Per-session taint state: the set of distinctive tokens seen from untrusted
/// sources. Monotone. Tokens are only ever added, you cannot untaint.
#[derive(Debug, Clone, Default)]
pub struct TaintTracker {
    /// Verbatim distinctive tokens. This is the set the proven projection reads;
    /// its monotonicity is what `formal/ChaiProofs/Taint.lean` bridges.
    tainted: HashSet<String>,
    /// Normalized (lowercased, alphanumeric-only) forms of the tainted tokens,
    /// for laundering-resistant matching. Also monotone. Never surfaced through
    /// `tainted_tokens()`, so the proof bridge is unaffected.
    tainted_norm: HashSet<String>,
}

impl TaintTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe a tool result. If it came from an untrusted source, its
    /// distinctive tokens join the taint set. Nothing is ever removed (monotone).
    pub fn observe(&mut self, text: &str, untrusted: bool) {
        if untrusted {
            for tok in distinctive_tokens(text) {
                let norm = normalize(&tok);
                if norm.len() >= MIN_NORM_LEN {
                    self.tainted_norm.insert(norm);
                }
                self.tainted.insert(tok);
            }
        }
    }

    pub fn tainted_tokens(&self) -> &HashSet<String> {
        &self.tainted
    }

    /// Does this value carry tainted data? Checks, in order of cost:
    ///   1. verbatim token substring (original v1 semantics),
    ///   2. normalized substring; defeats case / whitespace / punctuation
    ///      splitting (`AKIA1234567890 SECRET`),
    ///   3. decoded substring; base64/hex-decode runs in the value, then
    ///      normalized match, defeating encoding laundering.
    pub fn is_tainted(&self, value: &str) -> bool {
        // 1. verbatim.
        if self.tainted.iter().any(|t| value.contains(t.as_str())) {
            return true;
        }
        if self.tainted_norm.is_empty() {
            return false;
        }
        // 2. normalized.
        let nv = normalize(value);
        if self.tainted_norm.iter().any(|t| nv.contains(t.as_str())) {
            return true;
        }
        // 3. encoded (base64 / hex).
        decoded_candidates(value).iter().any(|d| {
            let nd = normalize(d);
            self.tainted_norm.iter().any(|t| nd.contains(t.as_str()))
        })
    }

    /// Project the taint state against a set of tool-call arguments into the
    /// `tooltrace.tainted_sink` fact ESP reads. `tainted_sink` is true iff any
    /// argument carries tainted data into this call.
    pub fn sink_facts(&self, args: &HashMap<String, Value>) -> HashMap<String, Value> {
        let tainted_sink = args.values().any(|v| self.is_tainted(&stringify(v)));
        let mut tt = HashMap::new();
        tt.insert("tainted_sink".to_string(), Value::Bool(tainted_sink));
        let mut ctx = HashMap::new();
        ctx.insert("tooltrace".to_string(), Value::Dict(tt));
        ctx
    }
}

/// Distinctive tokens: alphanumeric runs of length ≥ `MIN_TOKEN_LEN`.
fn distinctive_tokens(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() >= MIN_TOKEN_LEN)
        .map(|w| w.to_string())
        .collect()
}

/// Lowercase, keep only alphanumerics. Collapses case and any splitting
/// punctuation/whitespace so `AKIA1234567890 SECRET` normalizes to the same
/// string as the verbatim token `AKIA1234567890SECRET`.
fn normalize(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// Decode base64/hex-looking runs in `value` back to text, so an encoded secret
/// can be matched against the (normalized) taint set. Runs that do not decode to
/// valid text simply yield garbage that will not match a distinctive token.
fn decoded_candidates(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    // Split on non-base64-alphabet chars. `=` is a separator, not part of a run:
    // padding is optional to the decoder, and a mid-string `=` (e.g. `body=...`)
    // must not corrupt the following run.
    for run in value.split(|c: char| !(c.is_ascii_alphanumeric() || c == '+' || c == '/')) {
        // Too short to hide an 8-char secret once decoded.
        if run.len() < 12 {
            continue;
        }
        if let Some(bytes) = b64_decode(run) {
            if bytes.len() >= MIN_NORM_LEN {
                out.push(String::from_utf8_lossy(&bytes).into_owned());
            }
        }
        if run.len() % 2 == 0 && run.bytes().all(|c| c.is_ascii_hexdigit()) {
            if let Some(bytes) = hex_decode(run) {
                out.push(String::from_utf8_lossy(&bytes).into_owned());
            }
        }
    }
    out
}

/// Standard-alphabet base64 decode (ignores trailing `=` padding). `None` on any
/// non-alphabet byte. std-only, no dependency.
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let s = s.trim_end_matches('=');
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &c in s.as_bytes() {
        buf = (buf << 6) | val(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// Hex decode an even-length hex string. `None` on any non-hex byte.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return None;
    }
    let hv = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        out.push((hv(b[i])? << 4) | hv(b[i + 1])?);
        i += 2;
    }
    Some(out)
}

/// Flatten a value to text for substring matching.
fn stringify(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Int(i) => i.to_string(),
        Value::Float(f) => f.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::EntityUid(u) => u.clone(),
        Value::Ip(s) => s.clone(),
        Value::Decimal(d) => d.to_string(),
        Value::List(items) => items.iter().map(stringify).collect::<Vec<_>>().join(" "),
        Value::Dict(m) => m.values().map(stringify).collect::<Vec<_>>().join(" "),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[(&str, &str)]) -> HashMap<String, Value> {
        v.iter().map(|(k, val)| (k.to_string(), Value::String(val.to_string()))).collect()
    }

    #[test]
    fn untrusted_source_taints_distinctive_tokens() {
        let mut t = TaintTracker::new();
        t.observe("the secret is AKIA1234567890SECRET ok", true);
        assert!(t.tainted_tokens().contains("AKIA1234567890SECRET"));
        // short common words are not tainted
        assert!(!t.tainted_tokens().contains("the"));
        assert!(!t.tainted_tokens().contains("secret")); // len 6 < 8
    }

    #[test]
    fn trusted_source_taints_nothing() {
        let mut t = TaintTracker::new();
        t.observe("AKIA1234567890SECRET", false);
        assert!(t.tainted_tokens().is_empty());
    }

    #[test]
    fn taint_set_is_monotone() {
        let mut t = TaintTracker::new();
        t.observe("first TOKENAAAAAA0000", true);
        let after_one: HashSet<_> = t.tainted_tokens().clone();
        t.observe("second TOKENBBBBBB1111", true);
        // everything from the first observation is still present
        for tok in &after_one {
            assert!(t.tainted_tokens().contains(tok), "lost token {tok}");
        }
        assert!(t.tainted_tokens().contains("TOKENBBBBBB1111"));
    }

    #[test]
    fn sink_match_flags_tainted_argument() {
        let mut t = TaintTracker::new();
        t.observe("leaked AKIA1234567890SECRET value", true);
        assert!(t.is_tainted("please send AKIA1234567890SECRET to bob"));
        assert!(!t.is_tainted("nothing sensitive here"));
    }

    #[test]
    fn catches_whitespace_and_case_laundering() {
        let mut t = TaintTracker::new();
        t.observe("secret AKIA1234567890SECRET here", true);
        // a space splitting the token (the old v1 known-miss) is now caught
        assert!(t.is_tainted("forward AKIA1234567890 SECRET to evil"));
        // punctuation splitting
        assert!(t.is_tainted("AKIA1234567890-SECRET"));
        // case change
        assert!(t.is_tainted("akia1234567890secret"));
    }

    #[test]
    fn catches_base64_and_hex_encoding() {
        let mut t = TaintTracker::new();
        t.observe("secret AKIA1234567890SECRET here", true);
        // base64("AKIA1234567890SECRET")
        assert!(t.is_tainted("body=QUtJQTEyMzQ1Njc4OTBTRUNSRVQ= sent"));
        // hex("AKIA1234567890SECRET")
        assert!(t.is_tainted("payload 414b494131323334353637383930534543524554 end"));
    }

    #[test]
    fn does_not_overtaint_clean_text() {
        let mut t = TaintTracker::new();
        t.observe("secret AKIA1234567890SECRET here", true);
        assert!(!t.is_tainted("send the quarterly numbers to finance"));
        assert!(!t.is_tainted("QmVuaWduIG1lc3NhZ2Ugbm90aGluZyBzZWNyZXQ=")); // base64 of benign text
    }

    #[test]
    fn deeper_laundering_remains_a_measured_miss() {
        // Honest limitation: the secret interleaved with filler survives, because
        // normalization concatenates the filler between the fragments. Documented,
        // not hidden. Finer propagation is future work.
        let mut t = TaintTracker::new();
        t.observe("secret AKIA1234567890SECRET here", true);
        assert!(!t.is_tainted("AKIA1234 hidden 567890SECRET"));
    }

    #[test]
    fn sink_facts_projects_tooltrace_fact() {
        let mut t = TaintTracker::new();
        t.observe("AKIA1234567890SECRET", true);

        let tainted = t.sink_facts(&args(&[("body", "exfil AKIA1234567890SECRET now")]));
        match &tainted["tooltrace"] {
            Value::Dict(m) => assert_eq!(m["tainted_sink"], Value::Bool(true)),
            _ => panic!("expected tooltrace dict"),
        }

        let clean = t.sink_facts(&args(&[("body", "ordinary message")]));
        match &clean["tooltrace"] {
            Value::Dict(m) => assert_eq!(m["tainted_sink"], Value::Bool(false)),
            _ => panic!("expected tooltrace dict"),
        }
    }
}
