#![allow(dead_code)]

use std::path::PathBuf;

use damavand_policy::{Bundle, BundleId, Engine, Entity, EntityRef};
use serde_json::json;

pub const SCHEMA: &str = include_str!("../bundles/jamshid-default/schema.cedarschema");

pub fn bundles_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/bundles")
}

pub fn id() -> BundleId {
    BundleId("0000000000000000000000000000000000000000".into())
}

/// A bundle with the shared schema, one global file and full L3 caps for
/// project jamshid.
pub fn bundle(global: &str) -> Bundle {
    Bundle::new(id(), SCHEMA)
        .with_global("global/test.cedar", global)
        .with_autonomy(FULL_CAPS)
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
    let mut req = damavand_policy::DecisionRequest::new(principal, action, resource);
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
