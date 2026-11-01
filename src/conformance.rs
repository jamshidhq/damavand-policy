//! Conformance cases: a request and the expected `policy/decide` result.
//!
//! Cases are data (serde), so they can live in YAML or JSON files and run
//! against [`crate::Engine`] in process or against any server over the wire:
//! [`Expect::check`] compares a `policy/decide` result object.

use serde::Deserialize;
use serde_json::Value;

use crate::types::{Approver, DecisionRequest, Grant};

/// A file of cases.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct Suite {
    /// The cases, run in order.
    pub cases: Vec<Case>,
}

/// One case.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct Case {
    /// Case name, unique in its suite.
    pub name: String,
    /// The request.
    pub request: DecisionRequest,
    /// Attach a grant from this approver for the request's own digest.
    #[serde(default)]
    pub grant_from: Option<Approver>,
    /// Attach a grant from this approver for the digest of a different
    /// request (a grant that must not match).
    #[serde(default)]
    pub foreign_grant: Option<ForeignGrant>,
    /// The expected result.
    pub expect: Expect,
}

/// A grant bound to another request.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct ForeignGrant {
    /// Who approved.
    pub approver: Approver,
    /// The request the grant was made for.
    pub request: DecisionRequest,
}

impl Case {
    /// The request to send, with any grant attached.
    pub fn request(&self) -> DecisionRequest {
        let mut req = self.request.clone();
        if let Some(approver) = self.grant_from {
            req.approval = Some(Grant::new(req.digest(), approver));
        }
        if let Some(f) = &self.foreign_grant {
            req.approval = Some(Grant::new(f.request.digest(), f.approver));
        }
        req
    }
}

/// Expected fields of a `policy/decide` result. Absent fields are not
/// checked.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Expect {
    /// `allow`, `deny` or `escalate`.
    pub outcome: String,
    /// Allow only.
    #[serde(default)]
    pub notify: Option<bool>,
    /// The deny rule, or the ask rule of a PolicyAsk escalation.
    #[serde(default)]
    pub rule: Option<String>,
    /// Escalate only: `noMatch`, `policyAsk`, `autonomyRequiresApproval`,
    /// `taintedParam`.
    #[serde(default)]
    pub reason: Option<String>,
    /// TaintedParam only: the parameter name.
    #[serde(default)]
    pub param: Option<String>,
    /// Escalate only: `child`, `main` or `user`.
    #[serde(default)]
    pub to: Option<String>,
}

impl Expect {
    /// Compare a `policy/decide` result object with this expectation.
    pub fn check(&self, result: &Value) -> Result<(), String> {
        let mut want: Vec<(&str, Value)> = vec![("outcome", Value::from(self.outcome.clone()))];
        if let Some(v) = self.notify {
            want.push(("notify", Value::from(v)));
        }
        for (k, v) in [
            ("rule", &self.rule),
            ("reason", &self.reason),
            ("param", &self.param),
            ("to", &self.to),
        ] {
            if let Some(v) = v {
                want.push((k, Value::from(v.clone())));
            }
        }
        let mismatches: Vec<String> = want
            .into_iter()
            .filter(|(k, v)| result.get(*k) != Some(v))
            .map(|(k, v)| {
                format!(
                    "{k}: want {v}, got {}",
                    result.get(k).unwrap_or(&Value::Null)
                )
            })
            .collect();
        if mismatches.is_empty() {
            Ok(())
        } else {
            Err(mismatches.join("; "))
        }
    }
}

/// Run every case against an engine. Returns the failing case names with
/// their mismatches.
pub fn run(engine: &crate::Engine, suite: &Suite) -> Vec<String> {
    suite
        .cases
        .iter()
        .filter_map(|case| {
            let result = crate::wire::decision_result(&engine.decide(&case.request()));
            case.expect
                .check(&result)
                .err()
                .map(|e| format!("{}: {e}", case.name))
        })
        .collect()
}
