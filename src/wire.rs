//! Wire names for the damavand-proto `policy` capability.
//!
//! Defined here until this crate depends on damavand-proto. Error codes are
//! in the policy block 1000-1999 of the damavand-proto code registry.

use serde_json::{Value, json};

use crate::types::{Approver, Decision, EscalateReason};

/// Capability name. Its parameters are `{"bundle": "<sha>"}`.
pub const CAPABILITY: &str = "policy";
/// Decide one request. All three outcomes are successful results.
pub const METHOD_DECIDE: &str = "policy/decide";
/// The autonomy caps from git, for the UI.
pub const METHOD_AUTONOMY_CAPS: &str = "policy/autonomyCaps";
/// Bundle sha and schema version.
pub const METHOD_BUNDLE_INFO: &str = "policy/bundleInfo";

/// Wire error codes (block 1000-1999). An enforcer treats any error or
/// timeout as Deny.
pub mod codes {
    /// The bundle does not load.
    pub const BUNDLE_INVALID: i64 = 1000;
    /// The request does not match the bundle schema.
    pub const REQUEST_SCHEMA_MISMATCH: i64 = 1001;
    /// The action is not in the bundle schema.
    pub const UNKNOWN_ACTION: i64 = 1002;
    /// An entity in the request is not in the bundle schema.
    pub const UNKNOWN_ENTITY: i64 = 1003;
    /// The caller pinned a different bundle.
    pub const BUNDLE_PIN_MISMATCH: i64 = 1004;
    /// The grant is malformed.
    pub const GRANT_INVALID: i64 = 1005;
}

/// The `policy/decide` result for a decision:
/// `{outcome, notify?, rule?, reason?, param?, to?, decisionId}`.
pub fn decision_result(d: &Decision) -> Value {
    let to = |a: &Approver| match a {
        Approver::Child => "child",
        Approver::Main => "main",
        Approver::User => "user",
    };
    let id = &d.record().decision_id;
    match d {
        Decision::Allow { notify, .. } => {
            json!({"outcome": "allow", "notify": notify, "decisionId": id})
        }
        Decision::Deny { rule, .. } => json!({"outcome": "deny", "rule": rule, "decisionId": id}),
        Decision::Escalate {
            reason, to: who, ..
        } => {
            let mut v = json!({"outcome": "escalate", "to": to(who), "decisionId": id});
            let (name, extra) = match reason {
                EscalateReason::NoMatch => ("noMatch", None),
                EscalateReason::PolicyAsk(rule) => ("policyAsk", Some(("rule", rule.as_str()))),
                EscalateReason::AutonomyRequiresApproval => ("autonomyRequiresApproval", None),
                EscalateReason::TaintedParam(p) => ("taintedParam", Some(("param", p.as_str()))),
            };
            v["reason"] = Value::from(name);
            if let Some((k, val)) = extra {
                v[k] = Value::from(val);
            }
            v
        }
    }
}

/// The `policy/autonomyCaps` result: `{"projects": {id: {class: level}},
/// "loops": {...}}`.
pub fn autonomy_caps(engine: &crate::Engine) -> Value {
    let caps = engine.autonomy_caps();
    let table = |rows: &std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<crate::ActionClass, crate::Autonomy>,
    >| {
        rows.iter()
            .map(|(id, row)| {
                let row: serde_json::Map<String, Value> = row
                    .iter()
                    .map(|(c, l)| (c.name().to_string(), Value::from(l.level())))
                    .collect();
                (id.clone(), Value::Object(row))
            })
            .collect::<serde_json::Map<String, Value>>()
    };
    json!({"projects": table(caps.projects()), "loops": table(caps.loops())})
}

/// The `policy/bundleInfo` result: `{"bundle": sha, "schemaVersion": 1}`.
pub fn bundle_info(engine: &crate::Engine) -> Value {
    json!({"bundle": engine.bundle_id().0, "schemaVersion": SCHEMA_VERSION})
}

/// Version of the Damavand Cedar schema this crate speaks.
pub const SCHEMA_VERSION: u32 = 1;
