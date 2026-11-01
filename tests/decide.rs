//! Engine behaviour that the golden cases do not pin.

mod common;

use common::{NEVER_ACTION, SCHEMA, id, lib, load, r, repo, request, w1};
use damavand_policy::{
    Approver, Autonomy, Budget, Bundle, Decision, DecisionRequest, Engine, EscalateReason, Outcome,
    Param, RuleId,
};

const PERMIT_ALL: &str = r#"@id("all") permit (principal, action, resource);"#;

fn deny_rule(d: &Decision) -> &str {
    match d {
        Decision::Deny { rule, .. } => rule.as_str(),
        other => panic!("expected Deny, got {other:?}"),
    }
}

#[test]
fn eval_error_denies_even_when_a_permit_matches() {
    // The forbid overflows i64 when tokens_left > 0. Cedar skips an erroring
    // policy, so without the error gate this would be Allow.
    let e = load(&format!(
        "{PERMIT_ALL}\n@id(\"overflow\") forbid (principal, action, resource) \
         when {{ context.budget.tokens_left + 9223372036854775807 < 0 }};"
    ));
    let ok = e.decide(&request(w1(), "j_read", lib()));
    assert_eq!(ok.outcome(), Outcome::Allow);
    let d = e.decide(&request(w1(), "j_read", lib()).budget(Budget::new(1, 0)));
    assert_eq!(deny_rule(&d), RuleId::EVAL_ERROR);
}

#[test]
fn missing_entity_attribute_error_denies() {
    // `principal.depth` on an Orchestrator that is not in the entity store.
    let e = load(&format!(
        "{PERMIT_ALL}\n@id(\"depth\") forbid (principal is Damavand::Orchestrator, action, resource) \
         when {{ principal.depth == \"x\" }};"
    ));
    let req = DecisionRequest::new(
        r("Orchestrator", "ghost"),
        "j_read",
        lib(),
        "run-1",
        common::NOW,
    );
    assert_eq!(deny_rule(&e.decide(&req)), RuleId::EVAL_ERROR);
}

#[test]
fn rust_never_gate_needs_no_policy() {
    let e = load(PERMIT_ALL);
    let req = request(w1(), NEVER_ACTION, repo()).autonomy_override(Autonomy::L3ActAndNotify);
    let d = e.decide(&req);
    assert_eq!(deny_rule(&d), RuleId::NEVER);
    assert_eq!(d.record().rule_ids, vec![RuleId(RuleId::NEVER.into())]);
}

#[test]
fn never_class_action_is_denied_by_class() {
    // A bundle-defined action in class:never, not in the built-in list.
    let schema = SCHEMA.replace(
        "action use_secret in [\"class:secret.use\"]",
        "action wipe_db in [\"class:never\"] appliesTo {\n    principal: [Worker], resource: [Repo], context: Ctx };\n  action use_secret in [\"class:secret.use\"]",
    );
    let e = Engine::load(
        &Bundle::new(id(), schema)
            .with_global("g.cedar", PERMIT_ALL)
            .with_autonomy(common::FULL_CAPS),
    )
    .unwrap();
    assert_eq!(
        deny_rule(&e.decide(&request(w1(), "wipe_db", repo()))),
        RuleId::NEVER
    );
}

#[test]
fn permit_all_with_full_caps() {
    let e = load(PERMIT_ALL);
    let read = e.decide(&request(w1(), "j_read", lib()));
    assert_eq!(read.outcome(), Outcome::Allow);
    let draft = e.decide(&request(w1(), "draft_pr", repo()));
    assert_eq!(draft.outcome(), Outcome::Allow);
    let edit = e.decide(&request(w1(), "j_edit", lib()));
    assert_eq!(edit.outcome(), Outcome::AllowNotify);
}

#[test]
fn autonomy_table() {
    let e = load(PERMIT_ALL);
    let at = |action: &str, res, level| {
        e.decide(&request(w1(), action, res).autonomy_override(level))
            .outcome()
    };
    use Autonomy::*;
    use Outcome::*;
    for level in [L0Observe, L1Draft, L2ActWithApproval, L3ActAndNotify] {
        assert_eq!(at("j_read", lib(), level), Allow, "read at {level:?}");
    }
    assert_eq!(at("draft_pr", repo(), L0Observe), Deny);
    assert_eq!(at("draft_pr", repo(), L1Draft), Allow);
    assert_eq!(at("draft_pr", repo(), L3ActAndNotify), Allow);
    assert_eq!(at("j_edit", lib(), L0Observe), Deny);
    assert_eq!(at("j_edit", lib(), L1Draft), Deny);
    assert_eq!(at("j_edit", lib(), L2ActWithApproval), Escalate);
    assert_eq!(at("j_edit", lib(), L3ActAndNotify), AllowNotify);
}

#[test]
fn no_caps_means_l0() {
    let e = Engine::load(&Bundle::new(id(), SCHEMA).with_global("g.cedar", PERMIT_ALL)).unwrap();
    assert_eq!(
        e.decide(&request(w1(), "j_read", lib())).outcome(),
        Outcome::Allow
    );
    let d = e.decide(&request(w1(), "draft_pr", repo()));
    assert_eq!(deny_rule(&d), RuleId::AUTONOMY);
}

#[test]
fn caps_take_the_lowest_matching_entry() {
    let caps =
        "[project.jamshid]\n\"write.worktree\" = 3\n[loop.nightly]\n\"write.worktree\" = 2\n";
    let e = Engine::load(
        &Bundle::new(id(), SCHEMA)
            .with_global("g.cedar", PERMIT_ALL)
            .with_autonomy(caps),
    )
    .unwrap();
    let in_loop = request(r("Worker", "w9"), "j_edit", lib())
        .entity(damavand_policy::Entity::new(r("Worker", "w9")).parent(r("Loop", "nightly")))
        .entity(damavand_policy::Entity::new(r("Loop", "nightly")).parent(r("Project", "jamshid")));
    assert_eq!(e.decide(&in_loop).outcome(), Outcome::Escalate);
    assert_eq!(
        e.decide(&request(w1(), "j_edit", lib())).outcome(),
        Outcome::AllowNotify
    );
}

#[test]
fn empty_bundle_never_allows_beyond_read_class_gates() {
    let e = Engine::load(&Bundle::new(id(), SCHEMA).with_autonomy(common::FULL_CAPS)).unwrap();
    for (action, res) in [("j_read", lib()), ("j_edit", lib()), ("git_push", repo())] {
        let d = e.decide(&request(w1(), action, res));
        assert!(
            matches!(
                d,
                Decision::Escalate { ref reasons, .. } if reasons == &[EscalateReason::NoMatch]
            ),
            "{action}: {d:?}"
        );
    }
}

#[test]
fn reported_rule_prefers_global_then_lexical_id() {
    let b = Bundle::new(id(), SCHEMA)
        .with_autonomy(common::FULL_CAPS)
        .with_global(
            "g.cedar",
            r#"@id("all") permit (principal, action, resource);
               @id("g.z") forbid (principal, action == Damavand::Action::"j_read", resource);
               @id("g.m") forbid (principal, action == Damavand::Action::"j_read", resource);"#,
        )
        .with_project(
            "jamshid",
            "p.cedar",
            r#"@id("a.project") forbid (principal, action, resource in Damavand::Project::"jamshid");"#,
        );
    let e = Engine::load(&b).unwrap();
    let d = e.decide(&request(w1(), "j_read", lib()));
    assert_eq!(deny_rule(&d), "g.m");
    let ids: Vec<&str> = d.record().rule_ids.iter().map(RuleId::as_str).collect();
    assert_eq!(ids, vec!["a.project", "g.m", "g.z"]);
    // Only the project forbid matches j_edit.
    assert_eq!(
        deny_rule(&e.decide(&request(w1(), "j_edit", lib()))),
        "a.project"
    );
}

#[test]
fn hard_forbid_beats_ask() {
    let e = load(
        r#"@id("all") permit (principal, action, resource);
           @id("a.ask") @outcome("ask") forbid (principal, action, resource);
           @id("z.hard") forbid (principal, action, resource);"#,
    );
    assert_eq!(
        deny_rule(&e.decide(&request(w1(), "j_read", lib()))),
        "z.hard"
    );
}

#[test]
fn ask_reports_every_ask_rule_sorted() {
    let e = load(
        r#"@id("all") permit (principal, action, resource);
           @id("c.ask") @outcome("ask") forbid (principal, action, resource);
           @id("b.ask") @outcome("ask") forbid (principal, action, resource);
           @id("a.ask") @outcome("ask") forbid (principal, action, resource);"#,
    );
    let ask = |id: &str| EscalateReason::PolicyAsk(RuleId(id.into()));
    match e.decide(&request(w1(), "j_read", lib())) {
        Decision::Escalate { reasons, to, .. } => {
            assert_eq!(reasons, vec![ask("a.ask"), ask("b.ask"), ask("c.ask")]);
            assert_eq!(to, Approver::User);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn record_carries_bundle_digest_and_uuid_v7() {
    let e = load(PERMIT_ALL);
    let req = request(w1(), "j_read", lib());
    let d = e.decide(&req);
    let rec = d.record();
    assert_eq!(&rec.bundle_id, e.bundle_id());
    assert_eq!(rec.grant_nonce, None);
    assert_eq!(rec.request_digest, req.digest());
    assert_eq!(rec.rule_ids, vec![RuleId("all".into())]);
    assert!(!rec.approved);
    let u: Vec<char> = rec.decision_id.chars().collect();
    assert_eq!(u.len(), 36);
    assert_eq!(u[14], '7', "UUID version 7: {}", rec.decision_id);
    assert_ne!(e.decide(&req).record().decision_id, rec.decision_id);
}

#[test]
fn granted_record_is_marked() {
    let e = load(PERMIT_ALL);
    let req = request(w1(), "j_edit", lib()).autonomy_override(Autonomy::L2ActWithApproval);
    let g = common::grant(&e, &req, Approver::User);
    let granted = req.clone().approval(g.clone());
    let d = e.decide(&granted);
    assert!(matches!(d, Decision::Allow { notify: true, .. }), "{d:?}");
    assert!(d.record().approved);
    assert_eq!(d.record().grant_nonce, Some(g.nonce));
}

#[test]
fn digest_covers_every_bound_field() {
    let base = DecisionRequest::new(w1(), "j_edit", lib(), "run-1", common::NOW)
        .param(Param::clean("a", "1"))
        .param(Param::clean("b", "2"));
    let d0 = base.digest();
    let variants = [
        DecisionRequest::new(r("Worker", "w2"), "j_edit", lib(), "run-1", common::NOW)
            .param(Param::clean("a", "1"))
            .param(Param::clean("b", "2")),
        DecisionRequest::new(r("User", "w1"), "j_edit", lib(), "run-1", common::NOW)
            .param(Param::clean("a", "1"))
            .param(Param::clean("b", "2")),
        DecisionRequest::new(w1(), "j_read", lib(), "run-1", common::NOW)
            .param(Param::clean("a", "1"))
            .param(Param::clean("b", "2")),
        DecisionRequest::new(w1(), "j_edit", repo(), "run-1", common::NOW)
            .param(Param::clean("a", "1"))
            .param(Param::clean("b", "2")),
        DecisionRequest::new(w1(), "j_edit", lib(), "run-1", common::NOW)
            .param(Param::clean("x", "1"))
            .param(Param::clean("b", "2")),
        DecisionRequest::new(w1(), "j_edit", lib(), "run-1", common::NOW)
            .param(Param::clean("a", "9"))
            .param(Param::clean("b", "2")),
        DecisionRequest::new(w1(), "j_edit", lib(), "run-1", common::NOW)
            .param(Param::clean("a", "1")),
        DecisionRequest::new(w1(), "j_edit", lib(), "run-1", common::NOW)
            .param(Param::clean("a", "12"))
            .param(Param::clean("b", "")),
    ];
    for v in &variants {
        assert_ne!(v.digest(), d0, "{v:?}");
    }
    // Fields outside the binding do not change it.
    let same = base
        .clone()
        .autonomy_override(Autonomy::L0Observe)
        .run_id("r")
        .budget(Budget::new(5, 5));
    assert_eq!(same.digest(), d0);
    // Hex round-trip.
    let text = d0.to_string();
    assert_eq!(text.len(), 64);
    assert_eq!(text.parse::<damavand_policy::RequestDigest>().unwrap(), d0);
    assert!("zz".parse::<damavand_policy::RequestDigest>().is_err());
    assert!("ab".parse::<damavand_policy::RequestDigest>().is_err());
    assert!(
        "z".repeat(64)
            .parse::<damavand_policy::RequestDigest>()
            .is_err()
    );
}

#[test]
fn unknown_entity_type_is_request_invalid() {
    let e = load(PERMIT_ALL);
    let req = DecisionRequest::new(r("Martian", "x"), "j_read", lib(), "run-1", common::NOW);
    assert_eq!(deny_rule(&e.decide(&req)), RuleId::REQUEST_INVALID);
    let req = DecisionRequest::new(w1(), "j_read", r("Bad Type", "x"), "run-1", common::NOW);
    assert_eq!(deny_rule(&e.decide(&req)), RuleId::REQUEST_INVALID);
}

#[test]
fn class_group_is_not_an_action() {
    let e = load(PERMIT_ALL);
    assert_eq!(
        deny_rule(&e.decide(&request(w1(), "class:read", lib()))),
        RuleId::UNKNOWN_ACTION
    );
}

#[test]
fn context_carries_taint_and_class() {
    let e = load(
        r#"@id("all") permit (principal, action, resource);
           @id("t") forbid (principal, action, resource)
             when { context.taint_unvalidated && context.tainted_params.contains("p") && context.action_class == "write.worktree" && context.autonomy == 2 && context.run_id == "run-1" };"#,
    );
    let req = request(w1(), "j_edit", lib())
        .autonomy_override(Autonomy::L2ActWithApproval)
        .run_id("run-1")
        .param(Param::untrusted("p", "v", vec!["web".into()]));
    assert_eq!(deny_rule(&e.decide(&req)), "t");
    // A cleared parameter is not reported as tainted.
    let constrained = Engine::load(
        &common::bundle(
            r#"@id("all") permit (principal, action, resource);
               @id("t") forbid (principal, action, resource) when { context.taint_unvalidated };"#,
        )
        .with_constraints("[j_edit.p]\nenum = [\"v\"]\n"),
    )
    .unwrap();
    let cleared = request(w1(), "j_edit", lib())
        .autonomy_override(Autonomy::L2ActWithApproval)
        .param(Param::untrusted("p", "v", vec![]));
    assert_eq!(constrained.decide(&cleared).outcome(), Outcome::Escalate);
    // The same constraint does not clear another action's parameter.
    let other = request(w1(), "j_read", lib()).param(Param::untrusted("p", "v", vec![]));
    assert_eq!(deny_rule(&constrained.decide(&other)), "t");
}

#[test]
fn worker_without_orchestrator_or_loop_is_a_topology_deny() {
    let e = load(
        r#"@id("none") forbid (principal, action == Damavand::Action::"git_push", resource);"#,
    );
    let req = DecisionRequest::new(r("Worker", "lone"), "j_read", lib(), "run-1", common::NOW)
        .entity(damavand_policy::Entity::new(r("Worker", "lone")));
    assert_eq!(deny_rule(&e.decide(&req)), RuleId::TOPOLOGY);
    // Not in the entity list at all: no ancestors either.
    let ghost = DecisionRequest::new(r("Worker", "ghost"), "j_read", lib(), "run-1", common::NOW);
    assert_eq!(deny_rule(&e.decide(&ghost)), RuleId::TOPOLOGY);
    // In a loop only: placed.
    let looped = DecisionRequest::new(r("Worker", "l"), "j_read", lib(), "run-1", common::NOW)
        .entity(damavand_policy::Entity::new(r("Worker", "l")).parent(r("Loop", "nightly")));
    assert!(matches!(
        e.decide(&looped),
        Decision::Escalate {
            to: Approver::User,
            ..
        }
    ));
    let user = DecisionRequest::new(r("User", "max"), "j_read", lib(), "run-1", common::NOW);
    assert!(matches!(
        e.decide(&user),
        Decision::Escalate {
            to: Approver::User,
            ..
        }
    ));
}

#[test]
fn wire_result_shapes() {
    use damavand_policy::wire::decision_result;
    let e = load(
        r#"@id("all") permit (principal, action, resource);
           @id("no") forbid (principal, action == Damavand::Action::"git_push", resource);"#,
    );
    let allow = decision_result(&e.decide(&request(w1(), "j_edit", lib())));
    assert_eq!(allow["outcome"], "allow");
    assert_eq!(allow["notify"], true);
    assert!(allow["decisionId"].is_string());
    let deny = decision_result(&e.decide(&request(w1(), "git_push", repo())));
    assert_eq!(deny["outcome"], "deny");
    assert_eq!(deny["rule"], "no");
    assert!(deny.get("notify").is_none());
    let esc = decision_result(
        &e.decide(&request(w1(), "j_edit", lib()).param(Param::untrusted("content", "x", vec![]))),
    );
    assert_eq!(esc["outcome"], "escalate");
    assert_eq!(esc["reason"], "taintedParam");
    assert_eq!(esc["param"], "content");
    assert_eq!(esc["to"], "user");
    let auto = decision_result(
        &e.decide(&request(w1(), "j_edit", lib()).autonomy_override(Autonomy::L2ActWithApproval)),
    );
    assert_eq!(auto["reason"], "autonomyRequiresApproval");
    let none = load("");
    let nm = decision_result(&none.decide(&request(w1(), "j_read", lib())));
    assert_eq!(nm["reason"], "noMatch");
    assert_eq!(nm["to"], "child");
    let ask = load(
        r#"@id("all") permit (principal, action, resource); @id("q") @outcome("ask") forbid (principal, action, resource);"#,
    );
    let a = decision_result(&ask.decide(&request(w1(), "j_read", lib())));
    assert_eq!(a["reason"], "policyAsk");
    assert_eq!(a["rule"], "q");
}

#[test]
fn wire_codes_are_in_the_policy_block() {
    use damavand_policy::wire::{self, codes};
    for c in [
        codes::BUNDLE_INVALID,
        codes::REQUEST_SCHEMA_MISMATCH,
        codes::UNKNOWN_ACTION,
        codes::UNKNOWN_ENTITY,
        codes::BUNDLE_PIN_MISMATCH,
        codes::GRANT_INVALID,
    ] {
        assert!((1000..2000).contains(&c));
    }
    assert_eq!(wire::METHOD_DECIDE, "policy/decide");
    assert_eq!(wire::METHOD_AUTONOMY_CAPS, "policy/autonomyCaps");
    assert_eq!(wire::METHOD_BUNDLE_INFO, "policy/bundleInfo");
    assert_eq!(wire::CAPABILITY, "policy");
}

#[test]
fn request_round_trips_through_json() {
    let e = load(PERMIT_ALL);
    let base = request(w1(), "j_edit", lib())
        .param(Param::untrusted("p", "v", vec!["web".into()]))
        .autonomy_override(Autonomy::L2ActWithApproval);
    let req = base
        .clone()
        .approval(common::grant(&e, &base, Approver::Main));
    let json = serde_json::to_value(&req).unwrap();
    assert_eq!(json["autonomyOverride"], 2);
    assert_eq!(json["now"], common::NOW);
    assert_eq!(json["approval"]["nonce"].as_str().unwrap().len(), 32);
    assert_eq!(json["approval"]["signature"].as_str().unwrap().len(), 128);
    let back: DecisionRequest = serde_json::from_value(json).unwrap();
    assert_eq!(back, req);
    let minimal = serde_json::json!({
        "principal": {"type": "Worker", "id": "w"}, "action": "a",
        "resource": {"type": "Repo", "id": "r"}, "runId": "run-1", "now": 1
    });
    assert!(serde_json::from_value::<DecisionRequest>(minimal.clone()).is_ok());
    let with = |k: &str, v: serde_json::Value| {
        let mut m = minimal.clone();
        m[k] = v;
        serde_json::from_value::<DecisionRequest>(m)
    };
    assert!(with("autonomyOverride", serde_json::json!(4)).is_err());
    assert!(with("unknownField", serde_json::json!(1)).is_err());
    for required in ["now", "runId"] {
        let mut without = minimal.clone();
        without.as_object_mut().unwrap().remove(required);
        assert!(
            serde_json::from_value::<DecisionRequest>(without).is_err(),
            "{required}"
        );
    }
}

#[test]
fn worker_escalation_follows_its_own_orchestrator() {
    let e = load("");
    let to = |entities: Vec<damavand_policy::Entity>| {
        let mut req = DecisionRequest::new(w1(), "j_read", lib(), "run-1", common::NOW);
        for ent in entities {
            req = req.entity(ent);
        }
        match e.decide(&req) {
            Decision::Escalate { reasons, to, .. } if reasons == [EscalateReason::NoMatch] => to,
            other => panic!("{other:?}"),
        }
    };
    let orch = |id: &str, depth: &str| {
        damavand_policy::Entity::new(r("Orchestrator", id)).attr("depth", serde_json::json!(depth))
    };
    // Directly under main.
    assert_eq!(
        to(vec![
            orch("main", "main"),
            damavand_policy::Entity::new(w1()).parent(r("Orchestrator", "main"))
        ]),
        Approver::Main
    );
    // Another worker under main is listed first; w1 is under child.
    assert_eq!(
        to(vec![
            orch("main", "main"),
            orch("child", "child"),
            damavand_policy::Entity::new(r("Worker", "w0")).parent(r("Orchestrator", "main")),
            damavand_policy::Entity::new(w1()).parent(r("Orchestrator", "child")),
        ]),
        Approver::Child
    );
    // An orchestrator of unknown depth is refused, even off the path.
    for (path, extra) in [("odd", "main"), ("main", "odd")] {
        let mut req = DecisionRequest::new(w1(), "j_read", lib(), "run-1", common::NOW)
            .entity(orch("main", "main"))
            .entity(damavand_policy::Entity::new(w1()).parent(r("Orchestrator", path)));
        req = req.entity(orch(&format!("x{extra}"), extra));
        if path == "odd" {
            req = req.entity(orch("odd", "odd"));
        }
        assert_eq!(
            deny_rule(&e.decide(&req)),
            RuleId::TOPOLOGY,
            "{path}/{extra}"
        );
    }
}

#[test]
fn accessors_and_display() {
    let e = load(PERMIT_ALL);
    assert_eq!(
        e.action_class("j_read"),
        Some(damavand_policy::ActionClass::Read)
    );
    assert_eq!(
        e.action_class("git_push"),
        Some(damavand_policy::ActionClass::WriteRemote)
    );
    assert_eq!(e.action_class("class:read"), None);
    assert_eq!(e.bundle_id().to_string().len(), 64);
    assert_eq!(
        e.bundle_id()
            .to_string()
            .parse::<damavand_policy::BundleId>(),
        Ok(*e.bundle_id())
    );
    assert_eq!(e.bundle_label(), id());
    assert_eq!(RuleId("x.y".into()).to_string(), "x.y");
    let allow = e.decide(&request(w1(), "j_read", lib()));
    assert!(allow.is_allow());
    assert!(!e.decide(&request(w1(), "rm", lib())).is_allow());
}

#[test]
fn wire_caps_and_bundle_info() {
    let dir = common::bundles_dir().join("jamshid-default");
    let e = Engine::load(&Bundle::from_dir(&dir, "abc123").unwrap()).unwrap();
    let caps = damavand_policy::wire::autonomy_caps(&e);
    assert_eq!(caps["projects"]["jamshid"]["write.remote"], 2);
    assert_eq!(caps["projects"]["jamshid"]["read"], 3);
    assert_eq!(caps["loops"]["nightly"]["write.worktree"], 1);
    assert_eq!(caps["projects"].as_object().unwrap().len(), 1);
    assert_eq!(caps["loops"].as_object().unwrap().len(), 1);
    assert_eq!(
        e.autonomy_caps()
            .project("jamshid", damavand_policy::ActionClass::Egress),
        Some(Autonomy::L1Draft)
    );
    assert_eq!(
        e.autonomy_caps()
            .loop_cap("nightly", damavand_policy::ActionClass::Read),
        None
    );
    let info = damavand_policy::wire::bundle_info(&e);
    assert_eq!(
        info,
        serde_json::json!({"bundle": e.bundle_id().to_string(), "label": "abc123", "schemaVersion": 1})
    );
}
