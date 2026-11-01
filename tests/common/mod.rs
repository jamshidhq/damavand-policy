#![allow(dead_code)]

use std::path::PathBuf;

use damavand_policy::{
    Approver, BrokerKey, Bundle, Decision, DecisionRequest, Engine, Entity, EntityRef,
    EscalateReason, Grant, GrantNonce, GrantSignature, grant_signing_bytes,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

pub const SCHEMA: &str = include_str!("../bundles/jamshid-default/schema.cedarschema");

pub fn bundles_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/bundles")
}

/// The bundle label used in tests (a commit sha in real use).
pub fn id() -> &'static str {
    "0000000000000000000000000000000000000000"
}

/// The core's clock in every test request.
pub const NOW: u64 = 1_800_000_000;

/// Seed of the test approval broker. Built in code so no key literal sits
/// in the tree.
pub fn broker_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    for (i, b) in s.iter_mut().enumerate() {
        *b = i as u8 ^ 0x5a;
    }
    s
}

/// Seed of a broker no bundle trusts.
pub fn rogue_seed() -> [u8; 32] {
    [0x42; 32]
}

pub fn broker_key() -> BrokerKey {
    BrokerKey(
        SigningKey::from_bytes(&broker_seed())
            .verifying_key()
            .to_bytes(),
    )
}

/// A bundle with the shared schema, one global file, full L3 caps for
/// project jamshid, and the test broker key.
pub fn bundle(global: &str) -> Bundle {
    Bundle::new(id(), SCHEMA)
        .with_global("global/test.cedar", global)
        .with_autonomy(FULL_CAPS)
        .with_broker_key(broker_key())
}

/// The reasons of the engine's decision on the request without approval.
pub fn reasons(e: &Engine, req: &DecisionRequest) -> Vec<EscalateReason> {
    let mut bare = req.clone();
    bare.approval = None;
    match e.decide(&bare) {
        Decision::Escalate { reasons, .. } => reasons,
        _ => Vec::new(),
    }
}

/// A grant signed with `seed` over explicit fields.
#[allow(clippy::too_many_arguments)]
pub fn sign_raw(
    seed: &[u8; 32],
    bundle: &damavand_policy::BundleId,
    req: &DecisionRequest,
    reasons: &[EscalateReason],
    approver: Approver,
    expires_at: u64,
    nonce: [u8; 16],
) -> Grant {
    let nonce = GrantNonce(nonce);
    let msg = grant_signing_bytes(bundle, req, reasons, approver, expires_at, &nonce)
        .expect("canonical request");
    let sig = SigningKey::from_bytes(seed).sign(&msg).to_bytes();
    Grant::new(approver, expires_at, nonce, GrantSignature(sig))
}

/// A valid grant: the test broker signs this request's own reasons on `e`.
pub fn grant(e: &Engine, req: &DecisionRequest, approver: Approver) -> Grant {
    sign_raw(
        &broker_seed(),
        e.bundle_id(),
        req,
        &reasons(e, req),
        approver,
        NOW + 60,
        [7; 16],
    )
}

pub const FULL_CAPS: &str = r#"
[project.jamshid]
read = 3
draft = 3
"write.worktree" = 3
"write.remote" = 3
egress = 3
"k8s.mutate" = 3
"secret.use" = 3
"#;

pub fn load(global: &str) -> Engine {
    Engine::load(&bundle(global)).expect("test bundle loads")
}

pub fn r(kind: &str, id: &str) -> EntityRef {
    EntityRef::new(kind, id)
}

/// Entity graph: w1 -> child -> main -> Project jamshid; lib.rs -> Repo
/// jamshid -> Project jamshid.
pub fn entities() -> Vec<Entity> {
    vec![
        Entity::new(r("Project", "jamshid")),
        Entity::new(r("Orchestrator", "main"))
            .parent(r("Project", "jamshid"))
            .attr("depth", json!("main")),
        Entity::new(r("Orchestrator", "child"))
            .parent(r("Orchestrator", "main"))
            .attr("depth", json!("child")),
        Entity::new(r("Worker", "w1")).parent(r("Orchestrator", "child")),
        Entity::new(r("Repo", "jamshid")).parent(r("Project", "jamshid")),
        Entity::new(r("Path", "jamshid/src/lib.rs")).parent(r("Repo", "jamshid")),
    ]
}

pub fn request(
    principal: EntityRef,
    action: &str,
    resource: EntityRef,
) -> damavand_policy::DecisionRequest {
    let mut req = damavand_policy::DecisionRequest::new(principal, action, resource, NOW);
    for e in entities() {
        req = req.entity(e);
    }
    req
}

pub fn w1() -> EntityRef {
    r("Worker", "w1")
}

pub fn lib() -> EntityRef {
    r("Path", "jamshid/src/lib.rs")
}

pub fn repo() -> EntityRef {
    r("Repo", "jamshid")
}

pub const NEVER_ACTION: &str = "terraform_apply";
