//! Runnable ICAP server. cargo run --features icap --example icap -- [addr]
use chai_dsl::icap::{serve, IcapState};
use chai_dsl::{parse_chai, Afc, EntityStore};
use std::sync::Arc;

const POLICY: &str = "\
@id(\"no-write\") forbid when action == \"write\"
@id(\"secret\")   deny   when dlp_facts.secrets_found == true
@id(\"pii\")      redact when dlp_facts.pii_confidence > 0.4
@id(\"ok\")       permit when true
";

fn main() {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:1344".into());
    let state = Arc::new(IcapState {
        program: parse_chai(POLICY).unwrap(),
        store: EntityStore::new(),
        afc: Afc::with_default_detectors(),
    });
    serve(&addr, state).unwrap();
}
