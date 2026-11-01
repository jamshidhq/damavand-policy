//! Property tests over random bundles and requests.

mod common;

use common::{FULL_CAPS, NEVER_ACTION, SCHEMA, id, r, request};
use damavand_policy::{
    Approver, Autonomy, Bundle, Decision, DecisionRequest, Engine, EntityRef, Grant, Outcome,
    Param, ParamConstraint, RuleId,
};
use proptest::prelude::*;
use proptest::test_runner::Config;

fn config() -> Config {
    Config {
        cases: std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(256),
        failure_persistence: None,
        ..Config::default()
    }
}

// --- A small universe with a known entity graph ---------------------------

#[derive(Debug, Clone, Copy)]
enum P {
    Any,
    EqW1,
    InChild,
    InMain,
}
#[derive(Debug, Clone, Copy)]
enum A {
    Any,
    Eq(&'static str),
    InClass(&'static str),
}
#[derive(Debug, Clone, Copy)]
enum R {
    Any,
    EqLib,
    InRepo,
    InProject,
}
#[derive(Debug, Clone, Copy, PartialEq)]
enum Effect {
    Permit,
    Forbid,
    Ask,
}

#[derive(Debug, Clone)]
struct Pol {
    effect: Effect,
    p: P,
    a: A,
    r: R,
}

const VERBS: [(&str, &str, &str); 5] = [
    ("j_read", "read", "lib"),
    ("draft_pr", "draft", "repo"),
    ("j_edit", "write.worktree", "lib"),
    ("git_push", "write.remote", "repo"),
    ("run_command", "write.worktree", "cmd"),
];

fn principal_ancestors(p: &str) -> &'static [&'static str] {
    match p {
        "w1" => &["w1", "child", "main"],
        "child" => &["child", "main"],
        _ => &["main"],
    }
}

fn resource_is(res: &str) -> (bool, bool, bool) {
    // (== lib, in Repo jamshid, in Project jamshid)
    match res {
        "lib" => (true, true, true),
        "repo" => (false, true, true),
        _ => (false, true, true), // cmd is in Repo jamshid
    }
}

impl Pol {
    fn text(&self, n: usize) -> String {
        let effect = match self.effect {
            Effect::Permit => "permit",
            _ => "forbid",
        };
        let ask = if self.effect == Effect::Ask {
            "@outcome(\"ask\") "
        } else {
            ""
        };
        let p = match self.p {
            P::Any => "principal".to_string(),
            P::EqW1 => "principal == Damavand::Worker::\"w1\"".into(),
            P::InChild => "principal in Damavand::Orchestrator::\"child\"".into(),
            P::InMain => "principal in Damavand::Orchestrator::\"main\"".into(),
        };
        let a = match self.a {
            A::Any => "action".to_string(),
            A::Eq(v) => format!("action == Damavand::Action::\"{v}\""),
            A::InClass(c) => format!("action in Damavand::Action::\"class:{c}\""),
        };
        let r = match self.r {
            R::Any => "resource".to_string(),
            R::EqLib => "resource == Damavand::Path::\"jamshid/src/lib.rs\"".into(),
            R::InRepo => "resource in Damavand::Repo::\"jamshid\"".into(),
            R::InProject => "resource in Damavand::Project::\"jamshid\"".into(),
        };
        format!("@id(\"p{n:03}\") {ask}{effect} ({p}, {a}, {r});\n")
    }

    fn matches(&self, principal: &str, verb: (&str, &str, &str)) -> bool {
        let ancestry = principal_ancestors(principal);
        let pm = match self.p {
            P::Any => true,
            P::EqW1 => principal == "w1",
            P::InChild => ancestry.contains(&"child"),
            P::InMain => ancestry.contains(&"main"),
        };
        let am = match self.a {
            A::Any => true,
            A::Eq(v) => v == verb.0,
            A::InClass(c) => c == verb.1,
        };
        let (eq_lib, in_repo, in_proj) = resource_is(verb.2);
        let rm = match self.r {
            R::Any => true,
            R::EqLib => eq_lib,
            R::InRepo => in_repo,
            R::InProject => in_proj,
        };
        pm && am && rm
    }
}

fn pol() -> impl Strategy<Value = Pol> {
    let effect = prop_oneof![
        Just(Effect::Permit),
        Just(Effect::Forbid),
        Just(Effect::Ask)
    ];
    let p = prop_oneof![
        Just(P::Any),
        Just(P::EqW1),
        Just(P::InChild),
        Just(P::InMain)
    ];
    let a = prop_oneof![
        Just(A::Any),
        prop::sample::select(VERBS.iter().map(|v| v.0).collect::<Vec<_>>()).prop_map(A::Eq),
        prop::sample::select(vec!["read", "draft", "write.worktree", "write.remote"])
            .prop_map(A::InClass),
    ];
    let r = prop_oneof![
        Just(R::Any),
        Just(R::EqLib),
        Just(R::InRepo),
        Just(R::InProject)
    ];
    (effect, p, a, r).prop_map(|(effect, p, a, r)| Pol { effect, p, a, r })
}

fn engine(pols: &[Pol]) -> Engine {
    let text: String = pols.iter().enumerate().map(|(i, p)| p.text(i)).collect();
    Engine::load(
        &Bundle::new(id(), SCHEMA)
            .with_global("g.cedar", text)
            .with_autonomy(FULL_CAPS),
    )
    .expect("generated bundle loads")
}

fn resource(kind: &str) -> EntityRef {
    match kind {
        "lib" => common::lib(),
        "repo" => common::repo(),
        _ => r("NamedCommand", "jamshid/test"),
    }
}

fn principal(name: &str) -> EntityRef {
    match name {
        "w1" => common::w1(),
        other => r("Orchestrator", other),
    }
}

fn req(p: &str, verb: (&str, &str, &str)) -> DecisionRequest {
    request(principal(p), verb.0, resource(verb.2)).entity(
        damavand_policy::Entity::new(r("NamedCommand", "jamshid/test"))
            .parent(r("Repo", "jamshid")),
    )
}

fn level() -> impl Strategy<Value = Autonomy> {
    prop::sample::select(vec![
        Autonomy::L0Observe,
        Autonomy::L1Draft,
        Autonomy::L2ActWithApproval,
        Autonomy::L3ActAndNotify,
    ])
}

fn verb() -> impl Strategy<Value = (&'static str, &'static str, &'static str)> {
    prop::sample::select(VERBS.to_vec())
}

fn who() -> impl Strategy<Value = &'static str> {
    prop::sample::select(vec!["w1", "child", "main"])
}

fn approver() -> impl Strategy<Value = Option<Approver>> {
    prop::option::of(prop::sample::select(vec![
        Approver::Child,
        Approver::Main,
        Approver::User,
    ]))
}

fn with_grant(req: DecisionRequest, a: Option<Approver>) -> DecisionRequest {
    match a {
        Some(a) => {
            let d = req.digest();
            req.approval(Grant::new(d, a))
        }
        None => req,
    }
}

proptest! {
    #![proptest_config(config())]

    /// A matching hard forbid always denies, with any autonomy and any grant.
    #[test]
    fn forbid_always_wins(pols in prop::collection::vec(pol(), 0..8), p in who(), v in verb(),
                          lvl in level(), g in approver()) {
        let e = engine(&pols);
        let d = e.decide(&with_grant(req(p, v).autonomy_override(lvl), g));
        if pols.iter().any(|x| x.effect == Effect::Forbid && x.matches(p, v)) {
            prop_assert!(matches!(d, Decision::Deny { .. }), "{d:?}");
        }
        // And no match at all never allows.
        if !pols.iter().any(|x| x.effect == Effect::Permit && x.matches(p, v)) && g.is_none() {
            prop_assert!(!d.is_allow(), "{d:?}");
        }
    }

    /// An uncleared tainted parameter never yields Allow without a grant.
    #[test]
    fn taint_never_auto_allows(pols in prop::collection::vec(pol(), 0..8), p in who(), v in verb(),
                               lvl in level(), value in ".*", pattern in "[a-z.*|()]{0,6}",
                               choices in prop::collection::vec("[a-z]{0,3}", 0..3)) {
        let mut pols = pols;
        pols.push(Pol { effect: Effect::Permit, p: P::Any, a: A::Any, r: R::Any });
        let e = engine(&pols);
        let clears_enum = choices.contains(&value);
        let tainted = Param::untrusted("x", value.clone(), vec!["web".into()]);
        for param in [
            tainted.clone(),
            tainted.clone().with_constraint(ParamConstraint::Enum(choices.clone())),
            tainted.with_constraint(ParamConstraint::Pattern(pattern.clone())),
        ] {
            let constrained = param.constraint.clone();
            let d = e.decide(&req(p, v).autonomy_override(lvl).param(param));
            let cleared = match &constrained {
                None => false,
                Some(ParamConstraint::Enum(_)) => clears_enum,
                Some(_) => regex::Regex::new(&format!(r"\A(?:{pattern})\z")).is_ok_and(|re| re.is_match(&value))
                    && regex::Regex::new(&pattern).is_ok(),
            };
            if !cleared {
                prop_assert!(!d.is_allow(), "{constrained:?} {d:?}");
            }
        }
    }

    /// Never is always denied, whatever the bundle, level or grant.
    #[test]
    fn never_always_denies(pols in prop::collection::vec(pol(), 0..8), p in who(), lvl in level(),
                           g in approver()) {
        let mut pols = pols;
        pols.push(Pol { effect: Effect::Permit, p: P::Any, a: A::Any, r: R::Any });
        let e = engine(&pols);
        let d = e.decide(&with_grant(request(principal(p), NEVER_ACTION, common::repo()).autonomy_override(lvl), g));
        match d {
            Decision::Deny { rule, .. } => prop_assert_eq!(rule.as_str(), RuleId::NEVER),
            other => prop_assert!(false, "{other:?}"),
        }
    }

    /// Lowering autonomy never yields a stronger outcome, grants included.
    #[test]
    fn lower_autonomy_never_stronger(pols in prop::collection::vec(pol(), 0..8), p in who(), v in verb(),
                                     a in level(), b in level(), g in approver(), tainted in any::<bool>()) {
        let e = engine(&pols);
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        let mk = |lvl| {
            let mut q = req(p, v).autonomy_override(lvl);
            if tainted {
                q = q.param(Param::untrusted("x", "y", vec![]));
            }
            with_grant(q, g)
        };
        let dlo = e.decide(&mk(lo)).outcome();
        let dhi = e.decide(&mk(hi)).outcome();
        prop_assert!(dlo <= dhi, "{lo:?} -> {dlo:?}, {hi:?} -> {dhi:?}");
    }

    /// Policy order does not change the decision.
    #[test]
    fn order_does_not_matter(pols in prop::collection::vec(pol(), 0..8), p in who(), v in verb(), lvl in level()) {
        let mut rev = pols.clone();
        rev.reverse();
        // Keep ids attached to the same policy text.
        let a: String = pols.iter().enumerate().map(|(i, x)| x.text(i)).collect();
        let b: String = pols.iter().enumerate().rev().map(|(i, x)| x.text(i)).collect();
        let load = |t: String| Engine::load(&Bundle::new(id(), SCHEMA).with_global("g.cedar", t).with_autonomy(FULL_CAPS)).unwrap();
        let q = req(p, v).autonomy_override(lvl);
        let (da, db) = (load(a).decide(&q), load(b).decide(&q));
        prop_assert_eq!(da.outcome(), db.outcome());
        prop_assert_eq!(&da.record().rule_ids, &db.record().rule_ids);
        if let (Decision::Deny { rule: ra, .. }, Decision::Deny { rule: rb, .. }) = (&da, &db) {
            prop_assert_eq!(ra, rb);
        }
    }

    /// decide never panics on arbitrary input.
    #[test]
    fn decide_never_panics(kind in ".{0,12}", eid in ".{0,12}", action in ".{0,12}",
                           rkind in prop::sample::select(vec!["Path", "Repo", "Host", "x::Y", "", "::"]),
                           attr in any::<i64>(), name in ".*", value in ".*", pattern in ".{0,40}",
                           budget in any::<(i64, i64)>(), lvl in prop::option::of(level())) {
        let e = engine(&[Pol { effect: Effect::Permit, p: P::Any, a: A::Any, r: R::Any }]);
        let mut q = DecisionRequest::new(EntityRef::new(kind.clone(), eid.clone()), action, EntityRef::new(rkind, eid.clone()))
            .entity(damavand_policy::Entity::new(EntityRef::new(kind, eid)).attr("depth", serde_json::json!(attr)))
            .param(Param::untrusted(name, value, vec![]).with_constraint(ParamConstraint::Pattern(pattern)))
            .budget(damavand_policy::Budget::new(budget.0, budget.1));
        if let Some(l) = lvl {
            q = q.autonomy_override(l);
        }
        let _ = e.decide(&q);
        let _ = damavand_policy::wire::decision_result(&e.decide(&q));
    }

    /// Engine::load never panics on arbitrary bundle text.
    #[test]
    fn load_never_panics(schema in prop::option::of(".{0,64}"), policy in ".{0,64}", caps in ".{0,64}",
                         project in "[a-z]{0,4}") {
        let s = schema.unwrap_or_else(|| SCHEMA.to_string());
        let _ = Engine::load(&Bundle::new(id(), s).with_global("g", policy.clone()).with_project(project, "p", policy).with_autonomy(caps));
    }
}

#[test]
fn outcome_order() {
    assert!(Outcome::Deny < Outcome::Escalate);
    assert!(Outcome::Escalate < Outcome::AllowNotify);
    assert!(Outcome::AllowNotify < Outcome::Allow);
}
