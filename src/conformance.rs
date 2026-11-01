//! Conformance cases: a request and the expected `policy/decide` result.
//!
//! Cases are data (serde), so they can live in YAML or JSON files and run
//! against [`crate::Engine`] in process or against any server over the wire:
//! [`Expect::check`] compares a `policy/decide` result object.

//!
//! Grants in cases are signed with a test broker key from a seed the
//! runner is given; the bundle must trust its public key.

use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::grant::grant_signing_bytes;
use crate::types::{
    Approver, BrokerKey, Decision, DecisionRequest, EscalateReason, Grant, GrantNonce,
    GrantSignature,
};

/// Lifetime of a case grant, in seconds after the request's `now`.
pub const GRANT_TTL: u64 = 300;

/// The public key for a broker seed, to put in a test bundle.
pub fn broker_key(seed: &[u8; 32]) -> BrokerKey {
    BrokerKey(SigningKey::from_bytes(seed).verifying_key().to_bytes())
}

/// Sign a grant as the broker with this seed would: over the engine's bundle
/// id, the request, and the reasons of the engine's own decision on it
/// (none when it does not escalate).
pub fn sign_grant(
    engine: &crate::Engine,
    req: &DecisionRequest,
    approver: Approver,
    expires_at: u64,
    nonce: GrantNonce,
    seed: &[u8; 32],
) -> Option<Grant> {
    let mut bare = req.clone();
    bare.approval = None;
    let reasons: Vec<EscalateReason> = match engine.decide(&bare) {
        Decision::Escalate { reasons, .. } => reasons,
        _ => Vec::new(),
    };
    let msg = grant_signing_bytes(
        engine.bundle_id(),
        req,
        &reasons,
        approver,
        expires_at,
        &nonce,
    )?;
    let sig = SigningKey::from_bytes(seed).sign(&msg);
    Some(Grant::new(
        approver,
        expires_at,
        nonce,
        GrantSignature(sig.to_bytes()),
    ))
}

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
    /// Attach a grant from this approver, signed for this request.
    #[serde(default)]
    pub grant_from: Option<Approver>,
    /// Attach a grant from this approver, signed for this request but
    /// expiring at the request's `now`.
    #[serde(default)]
    pub expired_grant_from: Option<Approver>,
    /// Attach a grant from this approver signed for a different request (a
    /// grant that must not match).
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
    /// The request to send, with any grant attached, signed with the broker
    /// seed.
    pub fn request(&self, engine: &crate::Engine, seed: &[u8; 32]) -> DecisionRequest {
        let nonce = {
            let h: [u8; 32] = Sha256::digest(self.name.as_bytes()).into();
            let mut n = [0u8; 16];
            n.copy_from_slice(&h[..16]);
            GrantNonce(n)
        };
        let mut req = self.request.clone();
        let now = req.now;
        let sign = |r: &DecisionRequest, a, exp| sign_grant(engine, r, a, exp, nonce, seed);
        if let Some(a) = self.grant_from {
            req.approval = sign(&req, a, now.saturating_add(GRANT_TTL));
        }
        if let Some(a) = self.expired_grant_from {
            req.approval = sign(&req, a, now);
        }
        if let Some(f) = &self.foreign_grant {
            req.approval = sign(&f.request, f.approver, now.saturating_add(GRANT_TTL));
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

/// Run every case against an engine, signing grants with the broker seed.
/// Returns the failing case names with their mismatches.
pub fn run(engine: &crate::Engine, suite: &Suite, seed: &[u8; 32]) -> Vec<String> {
    suite
        .cases
        .iter()
        .filter_map(|case| {
            let result = crate::wire::decision_result(&engine.decide(&case.request(engine, seed)));
            case.expect
                .check(&result)
                .err()
                .map(|e| format!("{}: {e}", case.name))
        })
        .collect()
}
