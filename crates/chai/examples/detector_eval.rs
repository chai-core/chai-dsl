//! Live DLP detector benchmark: scores our real `PresidioDetector` adapter on
//! the REAL Microsoft Presidio output captured in `eval/presidio_cases.jsonl`
//! (produced by `eval/presidio_eval.py`; see `DETECTOR_EVAL.md`).
//!
//! Nothing here is mocked: each case's `presidio_raw` is the analyzer's native
//! JSON, fed through the exact production code path (`PresidioDetector::detect`
//! → `parse_presidio`) via a `RemoteCall` that replays the captured body. We then
//! compare the surfaced DLP facts against the seeded ground-truth labels.
//!
//! Run:  cargo run --example detector_eval
//! (regenerate the corpus first with the Python step if it is missing.)

use std::collections::BTreeMap;
use std::fs;

use chai_dsl::afc::{DetectCtx, PresidioDetector};
use chai_dsl::ast::Value;
use chai_dsl::Detector;

const THRESHOLD: f64 = 0.5; // pii_confidence ≥ THRESHOLD ⇒ "PII present"
const TARGETS: &[&str] = &[
    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "US_SSN",
    "IP_ADDRESS", "LOCATION", "URL", "IBAN_CODE",
];

struct Case {
    text: String,
    gt: Vec<String>,
    raw: String,
}

fn load(path: &str) -> Vec<Case> {
    let body = fs::read_to_string(path).unwrap_or_else(|_| {
        panic!("missing {path}; generate it first:\n  \
                eval/.venv/bin/python eval/presidio_eval.py > eval/presidio_cases.jsonl")
    });
    body.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).expect("valid jsonl");
            Case {
                text: v["text"].as_str().unwrap().to_string(),
                gt: v["gt_types"].as_array().unwrap().iter()
                    .map(|t| t.as_str().unwrap().to_string()).collect(),
                raw: v["presidio_raw"].as_str().unwrap().to_string(),
            }
        })
        .collect()
}

/// Run the real adapter on one captured Presidio body.
fn run_adapter(raw: &str, text: &str) -> (f64, Vec<String>) {
    let raw_owned = raw.to_string();
    let det = PresidioDetector::new(Box::new(move |_q: &str| Ok(raw_owned.clone())));
    let ctx = DetectCtx { prefix: text, timestamp: 0, tools: &[] };
    let facts = det.detect(&ctx);
    let mut conf = 0.0;
    let mut ents = Vec::new();
    for (k, ev) in &facts {
        match (k.as_str(), &ev.value) {
            ("pii_confidence", Value::Float(f)) => conf = *f,
            ("pii_entities", Value::List(items)) => {
                for it in items {
                    if let Value::String(s) = it { ents.push(s.clone()); }
                }
            }
            _ => {}
        }
    }
    (conf, ents)
}

fn pct(n: usize, d: usize) -> f64 { if d == 0 { 0.0 } else { 100.0 * n as f64 / d as f64 } }
fn f1(p: f64, r: f64) -> f64 { if p + r == 0.0 { 0.0 } else { 2.0 * p * r / (p + r) } }

fn main() {
    let cases = load("eval/presidio_cases.jsonl");
    let n_pos = cases.iter().filter(|c| !c.gt.is_empty()).count();
    let n_neg = cases.len() - n_pos;

    // Detection (any-PII) confusion at THRESHOLD, on the raw adapter stream.
    let (mut tp, mut fp, mut fn_, mut tn) = (0usize, 0, 0, 0);
    // Per-type recall over the planted entity.
    let mut injected: BTreeMap<&str, usize> = BTreeMap::new();
    let mut recalled: BTreeMap<&str, usize> = BTreeMap::new();
    // Micro type-level confusion, restricted to TARGETS.
    let (mut t_tp, mut t_fp, mut t_fn) = (0usize, 0, 0);
    let mut fn_examples: Vec<String> = Vec::new();
    let mut fp_examples: Vec<String> = Vec::new();

    for c in &cases {
        let (conf, ents) = run_adapter(&c.raw, &c.text);
        let gt_pos = !c.gt.is_empty();
        let pred_pos = conf >= THRESHOLD;
        match (gt_pos, pred_pos) {
            (true, true) => tp += 1,
            (false, true) => { fp += 1; if fp_examples.len() < 4 { fp_examples.push(format!("\"{}\" → conf {:.2}, {:?}", c.text, conf, ents)); } }
            (true, false) => { fn_ += 1; if fn_examples.len() < 4 { fn_examples.push(format!("\"{}\" (planted {:?}) → conf {:.2}", c.text, c.gt, conf)); } }
            (false, false) => tn += 1,
        }
        for t in &c.gt {
            *injected.entry(TARGETS.iter().find(|x| **x == *t).copied().unwrap_or("?")).or_default() += 1;
            if ents.iter().any(|e| e == t) { *recalled.entry(t.as_str()).or_default() += 1; }
        }
        // Type-level (TARGETS only): predicted target types vs gt.
        for t in TARGETS {
            let in_gt = c.gt.iter().any(|g| g == t);
            let in_pred = ents.iter().any(|e| e == t);
            match (in_gt, in_pred) {
                (true, true) => t_tp += 1,
                (false, true) => t_fp += 1,
                (true, false) => t_fn += 1,
                (false, false) => {}
            }
        }
    }

    let det_p = pct(tp, tp + fp);
    let det_r = pct(tp, tp + fn_);
    let tp_p = pct(t_tp, t_tp + t_fp);
    let tp_r = pct(t_tp, t_tp + t_fn);

    println!("\n=== Live DLP detector eval: real Presidio (en_core_web_lg) via PresidioDetector adapter ===");
    println!("corpus: {} cases  ({} with planted PII, {} clean)   threshold = {:.2}\n", cases.len(), n_pos, n_neg, THRESHOLD);

    println!("Detection (any-PII present?), on the raw adapter confidence stream:");
    println!("  precision {:.1}%   recall {:.1}%   F1 {:.1}%   (TP {} FP {} FN {} TN {})",
             det_p, det_r, f1(det_p, det_r), tp, fp, fn_, tn);

    println!("\nEntity-type (micro, over the {} target types):", TARGETS.len());
    println!("  precision {:.1}%   recall {:.1}%   F1 {:.1}%   (TP {} FP {} FN {})",
             tp_p, tp_r, f1(tp_p, tp_r), t_tp, t_fp, t_fn);

    println!("\nPer-type recall on planted entities:");
    for t in TARGETS {
        let inj = *injected.get(*t).unwrap_or(&0);
        let rec = *recalled.get(*t).unwrap_or(&0);
        if inj > 0 {
            println!("  {:<14} {:>3}/{:<3}  {:>5.1}%", t, rec, inj, pct(rec, inj));
        }
    }

    println!("\nExample false negatives (planted PII, adapter said clean):");
    for e in &fn_examples { println!("  - {e}"); }
    println!("\nExample false positives (clean text, adapter flagged):");
    for e in &fp_examples { println!("  - {e}"); }
    println!();
}
