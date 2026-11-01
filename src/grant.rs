//! Signed grants: the bytes an approval broker signs, and verification.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::gates::entities_digest;
use crate::types::{
    Approver, BrokerKey, BundleId, DecisionRequest, EscalateReason, Grant, GrantNonce,
};

const DOMAIN: &[u8] = b"damavand-policy/grant/v1";

fn put(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u64).to_be_bytes());
    out.extend_from_slice(b);
}

/// The exact bytes an approval broker signs for a grant, and the engine
/// verifies. One encoder for both sides.
///
/// Canonical and length-prefixed, no maps or floats: domain tag, bundle id,
/// run id, request digest ([`DecisionRequest::digest`]), entities digest
/// (order-independent), every escalation reason in the order the
/// [`crate::Decision::Escalate`] lists them (with rule id or parameter name),
/// approver, `expires_at` and nonce.
///
/// `None` when an entity attribute holds a float: such a request has no
/// canonical form, so no grant can be made for it.
pub fn grant_signing_bytes(
    bundle: &BundleId,
    req: &DecisionRequest,
    reasons: &[EscalateReason],
    approver: Approver,
    expires_at: u64,
    nonce: &GrantNonce,
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    put(&mut out, DOMAIN);
    put(&mut out, &bundle.0);
    put(&mut out, req.run_id.as_bytes());
    put(&mut out, &req.digest().0);
    put(&mut out, &entities_digest(&req.entities)?);
    out.extend_from_slice(&(reasons.len() as u64).to_be_bytes());
    for r in reasons {
        let (tag, text): (u8, &str) = match r {
            EscalateReason::NoMatch => (0, ""),
            EscalateReason::PolicyAsk(rule) => (1, rule.as_str()),
            EscalateReason::AutonomyRequiresApproval => (2, ""),
            EscalateReason::TaintedParam(p) => (3, p.as_str()),
        };
        out.push(tag);
        put(&mut out, text.as_bytes());
    }
    out.push(match approver {
        Approver::Child => 0,
        Approver::Main => 1,
        Approver::User => 2,
    });
    out.extend_from_slice(&expires_at.to_be_bytes());
    put(&mut out, &nonce.0);
    Some(out)
}

/// A broker key that is a valid, non-weak Ed25519 point.
pub(crate) fn verifying_key(key: &BrokerKey) -> Option<VerifyingKey> {
    let k = VerifyingKey::from_bytes(&key.0).ok()?;
    (!k.is_weak()).then_some(k)
}

/// True when the grant lifts this escalation: the approver ranks at least
/// `to`, `now` is before `expires_at`, `expires_at` is at most `max_ttl`
/// seconds past `now`, and one broker key verifies the signature (strictly)
/// over the bytes recomputed from this bundle, request and reason list.
pub(crate) fn grant_lifts(
    keys: &[VerifyingKey],
    max_ttl: u64,
    bundle: &BundleId,
    req: &DecisionRequest,
    grant: &Grant,
    reasons: &[EscalateReason],
    to: Approver,
) -> bool {
    if grant.approver < to
        || req.now >= grant.expires_at
        || grant.expires_at.saturating_sub(req.now) > max_ttl
    {
        return false;
    }
    let Some(msg) = grant_signing_bytes(
        bundle,
        req,
        reasons,
        grant.approver,
        grant.expires_at,
        &grant.nonce,
    ) else {
        return false;
    };
    let sig = Signature::from_bytes(&grant.signature.0);
    keys.iter().any(|k| k.verify_strict(&msg, &sig).is_ok())
}
