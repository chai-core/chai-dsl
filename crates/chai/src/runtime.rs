//! Control-plane runtime pieces. Obligation execution and audit.
//!
//! A `Decision` carries obligations (e.g. `log_emit`, `alert_security`,
//! `increment_quota`) and is itself the audit record. This module turns those
//! from advisory data into executed side effects and a durable trail.
//!   * `ObligationExecutor` runs a registered handler per obligation, and
//!     surfaces obligations that have no handler. Fail-loud, never silent.
//!   * `AuditSink` streams every decision out. In-memory for tests, JSONL for
//!     real deployments.

use chai_core::ast::Decision;
use std::collections::HashMap;
use std::io::Write;
use std::sync::Mutex;

/// A side effect to run when a decision carries a named obligation.
pub type ObligationFn = Box<dyn Fn(&Decision) + Send + Sync>;

/// Which obligations ran, and which had no registered handler.
#[derive(Debug, Default, Clone)]
pub struct ObligationReport {
    pub executed: Vec<String>,
    pub unhandled: Vec<String>,
}

impl ObligationReport {
    pub fn all_handled(&self) -> bool {
        self.unhandled.is_empty()
    }
}

/// Dispatches a decision's obligations to registered handlers.
#[derive(Default)]
pub struct ObligationExecutor {
    handlers: HashMap<String, ObligationFn>,
}

impl ObligationExecutor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a handler for an obligation name (builder style).
    pub fn on(mut self, name: impl Into<String>, handler: ObligationFn) -> Self {
        self.handlers.insert(name.into(), handler);
        self
    }

    /// Run every obligation on the decision. Report what ran and what didn't.
    /// An obligation with no handler is reported as `unhandled`, never silently
    /// dropped. A policy that demands `alert_security` with no handler is a
    /// misconfiguration you want to see.
    pub fn run(&self, decision: &Decision) -> ObligationReport {
        let mut report = ObligationReport::default();
        for ob in &decision.obligations {
            match self.handlers.get(ob) {
                Some(h) => {
                    h(decision);
                    report.executed.push(ob.clone());
                }
                None => report.unhandled.push(ob.clone()),
            }
        }
        report
    }
}

/// A destination for decision audit records.
pub trait AuditSink: Send + Sync {
    fn record(&self, decision: &Decision);
}

/// Collects decisions in memory, for tests and inspection.
#[derive(Default)]
pub struct MemoryAuditSink {
    entries: Mutex<Vec<Decision>>,
}

impl MemoryAuditSink {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn entries(&self) -> Vec<Decision> {
        self.entries.lock().unwrap().clone()
    }
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl AuditSink for MemoryAuditSink {
    fn record(&self, decision: &Decision) {
        self.entries.lock().unwrap().push(decision.clone());
    }
}

/// Writes one JSON object per decision (JSONL) to any writer (stdout, file, ...).
pub struct JsonlAuditSink<W: Write + Send> {
    writer: Mutex<W>,
}

impl<W: Write + Send> JsonlAuditSink<W> {
    pub fn new(writer: W) -> Self {
        Self { writer: Mutex::new(writer) }
    }
}

impl<W: Write + Send> AuditSink for JsonlAuditSink<W> {
    fn record(&self, decision: &Decision) {
        if let Ok(line) = serde_json::to_string(decision) {
            let mut w = self.writer.lock().unwrap();
            // The audit trail is security-relevant; a dropped record must not be
            // silent. Signal on stderr rather than swallowing the error.
            if writeln!(w, "{}", line).is_err() {
                eprintln!("chai: audit-log write failed, decision record dropped");
            }
        }
    }
}

/// Record a decision to the sink, then execute its obligations. Returns the
/// obligation report so callers can react to unhandled obligations.
pub fn settle(
    decision: &Decision,
    sink: &dyn AuditSink,
    executor: &ObligationExecutor,
) -> ObligationReport {
    sink.record(decision);
    executor.run(decision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chai_core::ast::{Effect, Value};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn decision_with(obligations: Vec<&str>) -> Decision {
        Decision {
            effect: Effect::Deny,
            reason: "test".into(),
            reason_codes: vec![],
            obligations: obligations.into_iter().map(String::from).collect(),
            rule_trace: vec!["r1".into()],
            errors: vec![],
            require_human_present: false,
            transforms: Vec::new(),
            metadata: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn obligations_run_and_unhandled_are_surfaced() {
        let alerts = Arc::new(AtomicUsize::new(0));
        let a = alerts.clone();
        let exec = ObligationExecutor::new()
            .on("alert_security", Box::new(move |_d| {
                a.fetch_add(1, Ordering::SeqCst);
            }));

        let report = exec.run(&decision_with(vec!["alert_security", "increment_quota"]));
        assert_eq!(alerts.load(Ordering::SeqCst), 1);
        assert_eq!(report.executed, vec!["alert_security".to_string()]);
        assert_eq!(report.unhandled, vec!["increment_quota".to_string()]);
        assert!(!report.all_handled());
    }

    #[test]
    fn memory_sink_and_settle() {
        let sink = MemoryAuditSink::new();
        let logged = Arc::new(AtomicUsize::new(0));
        let l = logged.clone();
        let exec = ObligationExecutor::new()
            .on("log_emit", Box::new(move |_d| {
                l.fetch_add(1, Ordering::SeqCst);
            }));

        let d = decision_with(vec!["log_emit"]);
        let report = settle(&d, &sink, &exec);

        assert_eq!(sink.len(), 1);
        assert_eq!(sink.entries()[0].rule_trace, vec!["r1".to_string()]);
        assert!(report.all_handled());
        assert_eq!(logged.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn jsonl_sink_serializes() {
        let buf: Vec<u8> = Vec::new();
        let sink = JsonlAuditSink::new(buf);
        sink.record(&decision_with(vec![]));
        let inner = sink.writer.into_inner().unwrap();
        let s = String::from_utf8(inner).unwrap();
        assert!(s.contains("\"effect\""));
        assert!(s.trim_end().ends_with('}'));
        let _ = Value::Bool(true);
    }
}
