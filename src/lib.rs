//! Deterministic policy gateway for damavand agent-safety crates.
//!
//! Models propose actions; this crate decides them. [`Engine::load`] reads a
//! [`Bundle`] (Cedar schema, policies, autonomy caps) and
//! [`Engine::decide`] turns a [`DecisionRequest`] into a [`Decision`]:
//! Allow, Deny or Escalate. `decide` is infallible and fails closed.
//!
//! The outcome is the meet of three parts, weakest wins
//! (Deny < Escalate < Allow with notify < Allow):
//!
//! 1. Cedar: forbid beats permit; no permit is Escalate (NoMatch); a forbid
//!    marked `@outcome("ask")` is Escalate (PolicyAsk); any evaluation error
//!    is Deny.
//! 2. Autonomy: effective level = min(git cap, caller override).
//! 3. Taint: an untrusted parameter that no bundle constraint clears is
//!    Escalate to the user.
//!
//! Never actions are denied before Cedar runs. An approval ([`Grant`]),
//! signed by the core's approval broker over the bundle, run, request,
//! entities and escalation reasons, lifts Escalate to Allow; it never lifts
//! Deny. The engine is stateless: the core consumes the grant nonce that the
//! Allow carries.
//!
//! No Cedar type is in the public API.
#![forbid(unsafe_code)]

mod bundle;
mod engine;
mod gates;
mod grant;
mod types;
pub mod wire;

#[cfg(feature = "conformance")]
pub mod conformance;

pub use bundle::{Bundle, DEFAULT_MAX_GRANT_TTL, LoadError};
pub use engine::{AutonomyCaps, Engine, NEVER_ACTIONS};
pub use grant::grant_signing_bytes;
pub use types::{
    ActionClass, Approver, Autonomy, BrokerKey, Budget, BundleId, Decision, DecisionRecord,
    DecisionRequest, Entity, EntityRef, EscalateReason, Grant, GrantNonce, GrantSignature, Outcome,
    Param, RequestDigest, RuleId, Taint,
};
