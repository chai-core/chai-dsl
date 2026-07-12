//! Production Policy Suite: real-world policies from various domains.
//!
//! A shared corpus data model. Descriptive fields (`domain`, `description`,
//! `test_cases`) document the corpus; a given consumer (e.g. the `evaluation`
//! bench, which reads only `name`/`policy`) need not read them all, so dead-code
//! for the unread descriptors is expected here.
#![allow(dead_code)]

pub struct ProductionPolicy {
    pub name: &'static str,
    pub domain: &'static str,
    pub description: &'static str,
    pub policy: &'static str,
    pub test_cases: &'static [TestCase],
}

pub struct TestCase {
    pub name: &'static str,
    pub output: &'static str,
    pub expected_effect: &'static str,
}

// ============================================================================
// DOMAIN 1: LLM Output Security (Guardrails)
// ============================================================================

pub const LLM_GUARDRAIL_POLICY: &str = r#"
forbid when dlp_facts.pii_confidence > 0.85
forbid when dlp_facts.secrets_found == true
forbid when safety_facts.harm > 0.75
forbid when safety_facts.toxicity > 0.7
forbid when safety_facts.jailbreak_attempt == true

redact when dlp_facts.pii_confidence > 0.6 and dlp_facts.pii_confidence <= 0.85
redact when dlp_facts.entropy > 7.5

defer when safety_facts.harm > 0.5 and safety_facts.harm <= 0.75
defer when dlp_facts.credential_matches != []

permit when grounding_facts.has_citations == true
permit when dlp_facts.pii_confidence < 0.3 and safety_facts.harm < 0.3
"#;

pub const LLM_GUARDRAIL_TESTS: &[TestCase] = &[
    TestCase {
        name: "benign_greeting",
        output: "Hello! How can I help you today?",
        expected_effect: "ALLOW",
    },
    TestCase {
        name: "ssn_leak",
        output: "I found your social security number: 123-45-6789",
        expected_effect: "DENY",
    },
    TestCase {
        name: "api_key_leak",
        output: "Here's your API key: sk_live_abc123def456",
        expected_effect: "DENY",
    },
    TestCase {
        name: "violent_content",
        output: "You should violently attack your neighbors because they're different",
        expected_effect: "DENY",
    },
    TestCase {
        name: "mild_bias",
        output: "All people from that region are always lazy",
        expected_effect: "REDACT",
    },
    TestCase {
        name: "pii_redaction",
        output: "The patient's email is john.doe@example.com",
        expected_effect: "REDACT",
    },
    TestCase {
        name: "with_citation",
        output: "According to [Nature 2023], climate change is accelerating.",
        expected_effect: "ALLOW",
    },
];

// ============================================================================
// DOMAIN 2: API Gateway Security (Kong/Envoy style)
// ============================================================================

pub const API_GATEWAY_POLICY: &str = r#"
forbid when subject.trust_tier < 1
forbid when dlp_facts.secrets_found == true
forbid when object.action == "delete" and subject.trust_tier < 3

permit when subject.trust_tier >= 3 and object.action == "read"
permit when subject.trust_tier >= 4 and object.action == "write"
permit when subject.trust_tier >= 4 and object.action == "admin"

defer when safety_facts.harm > 0.5
redact when dlp_facts.entropy > 6.0
"#;

pub const API_GATEWAY_TESTS: &[TestCase] = &[
    TestCase {
        name: "low_trust_blocked",
        output: "Request from trust_tier=0",
        expected_effect: "DENY",
    },
    TestCase {
        name: "read_allowed",
        output: "Request from trust_tier=3 for read action",
        expected_effect: "ALLOW",
    },
    TestCase {
        name: "write_allowed",
        output: "Request from trust_tier=4 for write action",
        expected_effect: "ALLOW",
    },
    TestCase {
        name: "delete_denied",
        output: "Request from trust_tier=2 for delete action",
        expected_effect: "DENY",
    },
    TestCase {
        name: "admin_high_trust",
        output: "Request from trust_tier=4 for admin action",
        expected_effect: "ALLOW",
    },
];

// ============================================================================
// DOMAIN 3: Data Loss Prevention (Enterprise DLP)
// ============================================================================

pub const DLP_ENTERPRISE_POLICY: &str = r#"
forbid when dlp_facts.pii_confidence > 0.8
forbid when dlp_facts.secrets_found == true
forbid when dlp_facts.credential_matches.size > 0

redact when dlp_facts.pii_confidence > 0.5
redact when dlp_facts.entropy > 7.0

defer when object.persistence == true and dlp_facts.pii_confidence > 0.3
defer when object.destination == "cloud" and dlp_facts.entropy > 6.0

permit when object.channel == "internal_only"
permit when object.audience == "system"
"#;

pub const DLP_ENTERPRISE_TESTS: &[TestCase] = &[
    TestCase {
        name: "internal_safe",
        output: "Internal system message",
        expected_effect: "ALLOW",
    },
    TestCase {
        name: "credit_card",
        output: "Card: 4532-1234-5678-9010",
        expected_effect: "DENY",
    },
    TestCase {
        name: "password_in_output",
        output: "password: MySecretPassword123!",
        expected_effect: "DENY",
    },
    TestCase {
        name: "pii_redact",
        output: "Patient: John Doe, DOB: 01/15/1985",
        expected_effect: "REDACT",
    },
    TestCase {
        name: "high_entropy",
        output: "aBcDeF1234567890xYzWvUtSrQpOnMlKjI",
        expected_effect: "REDACT",
    },
    TestCase {
        name: "persistent_cloud",
        output: "Saving customer email to cloud",
        expected_effect: "DEFER",
    },
];

// ============================================================================
// DOMAIN 4: Kubernetes RBAC (Container Orchestration)
// ============================================================================

pub const KUBERNETES_RBAC_POLICY: &str = r#"
forbid when subject.role != ["admin", "operator", "viewer"]

permit when subject.role == "admin"
permit when subject.role == "operator" and object.action == "read"
permit when subject.role == "operator" and object.action == "write"
permit when subject.role == "viewer" and object.action == "read"

forbid when object.channel == "kube-system" and subject.trust_tier < 4
forbid when object.action == "delete" and subject.trust_tier < 4
"#;

pub const KUBERNETES_RBAC_TESTS: &[TestCase] = &[
    TestCase {
        name: "admin_full_access",
        output: "Admin user with trust_tier=4",
        expected_effect: "ALLOW",
    },
    TestCase {
        name: "operator_read",
        output: "Operator reading pod info",
        expected_effect: "ALLOW",
    },
    TestCase {
        name: "operator_write",
        output: "Operator updating deployment",
        expected_effect: "ALLOW",
    },
    TestCase {
        name: "viewer_only_read",
        output: "Viewer attempting write",
        expected_effect: "DENY",
    },
    TestCase {
        name: "kube_system_denied",
        output: "Low trust user accessing kube-system",
        expected_effect: "DENY",
    },
    TestCase {
        name: "delete_denied",
        output: "Operator attempting delete",
        expected_effect: "DENY",
    },
];

// ============================================================================
// DOMAIN 5: Healthcare HIPAA Compliance
// ============================================================================

pub const HIPAA_COMPLIANCE_POLICY: &str = r#"
forbid when dlp_facts.pii_confidence > 0.9
forbid when object.audience != "healthcare_provider"
forbid when dlp_facts.secrets_found == true

redact when dlp_facts.pii_confidence > 0.7
redact when dlp_facts.entropy > 6.5

defer when object.persistence == true and dlp_facts.pii_confidence > 0.5

permit when subject.role == "doctor" and object.action == "read"
permit when subject.role == "doctor" and dlp_facts.pii_confidence < 0.5
permit when grounding_facts.has_citations == true and subject.trust_tier >= 2
"#;

pub const HIPAA_COMPLIANCE_TESTS: &[TestCase] = &[
    TestCase {
        name: "patient_record",
        output: "Patient: Jane Smith, MRN: 123456, diagnosed with diabetes",
        expected_effect: "DENY",
    },
    TestCase {
        name: "treatment_notes",
        output: "Patient responded well to treatment protocol",
        expected_effect: "ALLOW",
    },
    TestCase {
        name: "wrong_audience",
        output: "Patient info shared to public audience",
        expected_effect: "DENY",
    },
    TestCase {
        name: "doctor_access",
        output: "Doctor accessing patient records for care",
        expected_effect: "ALLOW",
    },
];

// ============================================================================
// DOMAIN 6: Financial Services (PCI-DSS Compliance)
// ============================================================================

pub const FINTECH_PCI_POLICY: &str = r#"
forbid when dlp_facts.pii_confidence > 0.85
forbid when object.channel != "secure_channel"
forbid when dlp_facts.credential_matches.size > 0

redact when dlp_facts.pii_confidence > 0.6
redact when object.persistence == true and dlp_facts.pii_confidence > 0.4

defer when object.destination == "external_api" and dlp_facts.pii_confidence > 0.3

permit when subject.trust_tier >= 3 and subject.role == "trader"
permit when subject.role == "compliance_officer"
"#;

pub const FINTECH_PCI_TESTS: &[TestCase] = &[
    TestCase {
        name: "credit_card_forbidden",
        output: "Card number: 4532123456789010",
        expected_effect: "DENY",
    },
    TestCase {
        name: "ssn_forbidden",
        output: "SSN: 123-45-6789",
        expected_effect: "DENY",
    },
    TestCase {
        name: "safe_transaction",
        output: "Transaction processed for account ****9010",
        expected_effect: "ALLOW",
    },
    TestCase {
        name: "trader_access",
        output: "Trader viewing market data",
        expected_effect: "ALLOW",
    },
];

// ============================================================================
// Policy Registry
// ============================================================================

pub const PRODUCTION_POLICIES: &[ProductionPolicy] = &[
    ProductionPolicy {
        name: "llm_guardrail",
        domain: "LLM Safety",
        description: "Guardrails for LLM output safety and security",
        policy: LLM_GUARDRAIL_POLICY,
        test_cases: LLM_GUARDRAIL_TESTS,
    },
    ProductionPolicy {
        name: "api_gateway",
        domain: "API Security",
        description: "API gateway access control (Kong/Envoy style)",
        policy: API_GATEWAY_POLICY,
        test_cases: API_GATEWAY_TESTS,
    },
    ProductionPolicy {
        name: "dlp_enterprise",
        domain: "Data Protection",
        description: "Enterprise data loss prevention",
        policy: DLP_ENTERPRISE_POLICY,
        test_cases: DLP_ENTERPRISE_TESTS,
    },
    ProductionPolicy {
        name: "kubernetes_rbac",
        domain: "Container Security",
        description: "Kubernetes RBAC policy",
        policy: KUBERNETES_RBAC_POLICY,
        test_cases: KUBERNETES_RBAC_TESTS,
    },
    ProductionPolicy {
        name: "hipaa_compliance",
        domain: "Healthcare",
        description: "HIPAA-compliant healthcare data access",
        policy: HIPAA_COMPLIANCE_POLICY,
        test_cases: HIPAA_COMPLIANCE_TESTS,
    },
    ProductionPolicy {
        name: "fintech_pci",
        domain: "Finance",
        description: "PCI-DSS financial data protection",
        policy: FINTECH_PCI_POLICY,
        test_cases: FINTECH_PCI_TESTS,
    },
];

pub fn get_policy(domain: &str) -> Option<&'static ProductionPolicy> {
    PRODUCTION_POLICIES.iter().find(|p| p.domain == domain)
}
