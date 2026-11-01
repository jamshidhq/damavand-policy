//! Golden bundles: they load, and every case in their cases.yaml holds.
#![cfg(feature = "conformance")]

mod common;

use damavand_policy::conformance::{Suite, run};
use damavand_policy::{Bundle, Engine};

fn run_golden(name: &str) -> usize {
    let dir = common::bundles_dir().join(name);
    let bundle = Bundle::from_dir(&dir, format!("{name}-sha")).expect("bundle reads");
    let engine = Engine::load(&bundle).expect("bundle loads");
    assert_eq!(engine.bundle_label(), format!("{name}-sha"));
    let text = std::fs::read_to_string(dir.join("cases.yaml")).expect("cases.yaml");
    // Through serde_json::Value: cases use the JSON wire shape, where enums
    // are maps ({untrusted: {...}}), not YAML tags.
    let value: serde_json::Value = serde_norway::from_str(&text).expect("cases.yaml parses");
    let suite: Suite = serde_json::from_value(value).expect("cases match the case schema");
    let failures = run(&engine, &suite, &common::broker_seed());
    assert!(
        failures.is_empty(),
        "{name}: failing cases:\n{}",
        failures.join("\n")
    );
    suite.cases.len()
}

#[test]
fn jamshid_default_golden_decisions() {
    assert!(run_golden("jamshid-default") >= 30);
}

#[test]
fn devops_l0_golden_decisions() {
    assert!(run_golden("devops-l0") >= 6);
}

#[test]
fn a_wrong_expectation_is_reported() {
    let dir = common::bundles_dir().join("jamshid-default");
    let engine = Engine::load(&Bundle::from_dir(&dir, "x").unwrap()).unwrap();
    let suite: Suite = serde_json::from_value(serde_json::json!({"cases": [{
        "name": "a detached worker is not allowed",
        "request": {"principal": {"type": "Worker", "id": "w1"}, "action": "j_read",
                    "resource": {"type": "Path", "id": "p"}, "runId": "r", "now": 1},
        "expect": {"outcome": "allow", "rule": "nope", "to": "user", "reason": "noMatch", "param": "x", "notify": true}
    }]}))
    .unwrap();
    let failures = run(&engine, &suite, &common::broker_seed());
    assert_eq!(failures.len(), 1);
    let f = &failures[0];
    assert!(f.starts_with("a detached worker is not allowed: "), "{f}");
    for field in ["outcome", "rule", "reason", "param", "notify"] {
        assert!(
            f.contains(&format!("{field}: want")),
            "{field} missing in {f}"
        );
    }
    // Unknown fields in a case are refused, so typos cannot pass silently.
    assert!(
        serde_json::from_value::<Suite>(serde_json::json!({"cases": [{
        "name": "n", "request": {"principal": {"type": "W", "id": "w"}, "action": "a",
        "resource": {"type": "R", "id": "r"}, "runId": "r", "now": 1}, "expect": {"outcome": "allow", "unknownField": true}}]}))
        .is_err()
    );
}
