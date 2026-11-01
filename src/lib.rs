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
//! 3. Taint: an untrusted parameter that no manifest constraint clears is
//!    Escalate to the user.
//!
//! Never actions are denied before Cedar runs. An approval ([`Grant`]) bound
//! to the request digest lifts Escalate to Allow; it never lifts Deny.
//!
//! No Cedar type is in the public API.
#![forbid(unsafe_code)]

mod bundle;
mod engine;
mod gates;
mod types;
pub mod wire;

#[cfg(feature = "conformance")]
pub mod conformance;

pub use bundle::{Bundle, LoadError};
pub use engine::{AutonomyCaps, Engine, NEVER_ACTIONS};
pub use types::{
    ActionClass, Approver, Autonomy, Budget, BundleId, Decision, DecisionRecord, DecisionRequest,
    Entity, EntityRef, EscalateReason, Grant, Outcome, Param, ParamConstraint, RequestDigest,
    RuleId, Taint,
};
