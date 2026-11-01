//! Deterministic gates around the Cedar result: meet, autonomy, taint,
//! digest and grants. Pure functions.

use regex::RegexBuilder;
use sha2::{Digest, Sha256};

use crate::types::{
    ActionClass, Approver, Autonomy, DecisionRequest, EscalateReason, Param, ParamConstraint,
    RequestDigest, RuleId, Taint,
};

/// One component's verdict before it becomes a [`crate::Decision`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    Deny(RuleId),
    Escalate(EscalateReason, Approver),
    Allow { notify: bool },
}

impl Verdict {
    fn rank(&self) -> u8 {
        match self {
            Verdict::Deny(_) => 0,
            Verdict::Escalate(..) => 1,
            Verdict::Allow { notify: true } => 2,
            Verdict::Allow { notify: false } => 3,
        }
    }
}

/// Longest pattern accepted, in bytes.
pub(crate) const MAX_PATTERN_LEN: usize = 1024;
/// Compiled-program and lazy-DFA limits for one pattern.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// The weaker of two verdicts: Deny < Escalate < Allow+notify < Allow.
/// Two escalations go to the higher approver; on a tie, and between two
/// denies, the first argument wins.
pub(crate) fn meet(a: Verdict, b: Verdict) -> Verdict {
    match (&a, &b) {
        (Verdict::Escalate(_, ta), Verdict::Escalate(_, tb)) => {
            if tb > ta {
                b
            } else {
                a
            }
        }
        _ => {
            if b.rank() < a.rank() {
                b
            } else {
                a
            }
        }
    }
}

/// min(cap, override): the caller can lower the level, never raise it.
pub(crate) fn effective_autonomy(cap: Autonomy, over: Option<Autonomy>) -> Autonomy {
    match over {
        Some(o) => cap.min(o),
        None => cap,
    }
}

/// What the autonomy level allows for an action class.
pub(crate) fn autonomy_verdict(class: ActionClass, level: Autonomy) -> Verdict {
    let deny = || Verdict::Deny(RuleId(RuleId::AUTONOMY.into()));
    match class {
        ActionClass::Never => Verdict::Deny(RuleId(RuleId::NEVER.into())),
        ActionClass::Read => Verdict::Allow { notify: false },
        ActionClass::Draft => {
            if level >= Autonomy::L1Draft {
                Verdict::Allow { notify: false }
            } else {
                deny()
            }
        }
        _ => match level {
            Autonomy::L0Observe | Autonomy::L1Draft => deny(),
            Autonomy::L2ActWithApproval => {
                Verdict::Escalate(EscalateReason::AutonomyRequiresApproval, Approver::User)
            }
            Autonomy::L3ActAndNotify => Verdict::Allow { notify: true },
        },
    }
}

/// True when the value satisfies the manifest constraint. A pattern must
/// match the whole value. It is compiled on its own first, so a pattern that
/// tries to close the anchoring group (`x)|(.*`) is invalid and clears
/// nothing; then it is wrapped as `\A(?:…)\z`. Oversized patterns clear
/// nothing.
pub(crate) fn constraint_clears(c: &ParamConstraint, value: &str) -> bool {
    match c {
        ParamConstraint::Enum(choices) => choices.iter().any(|v| v == value),
        ParamConstraint::Pattern(pattern) => {
            if pattern.len() > MAX_PATTERN_LEN {
                return false;
            }
            let build = |p: &str| {
                RegexBuilder::new(p)
                    .size_limit(REGEX_SIZE_LIMIT)
                    .dfa_size_limit(REGEX_SIZE_LIMIT)
                    .build()
            };
            if build(pattern).is_err() {
                return false;
            }
            match build(&format!(r"\A(?:{pattern})\z")) {
                Ok(re) => re.is_match(value),
                Err(_) => false,
            }
        }
    }
}

/// Names of untrusted parameters that no constraint clears, in order.
pub(crate) fn uncleared_tainted(params: &[Param]) -> Vec<&str> {
    params
        .iter()
        .filter(|p| matches!(p.taint, Taint::Untrusted { .. }))
        .filter(|p| {
            !p.constraint
                .as_ref()
                .is_some_and(|c| constraint_clears(c, &p.value))
        })
        .map(|p| p.name.as_str())
        .collect()
}

fn feed(h: &mut Sha256, field: &str) {
    h.update((field.len() as u64).to_be_bytes());
    h.update(field.as_bytes());
}

/// SHA-256 over length-prefixed principal, action, resource and each
/// parameter name and value, in order.
pub(crate) fn request_digest(req: &DecisionRequest) -> RequestDigest {
    let mut h = Sha256::new();
    h.update(b"damavand-policy/request/v1");
    feed(&mut h, &req.principal.kind);
    feed(&mut h, &req.principal.id);
    feed(&mut h, &req.action);
    feed(&mut h, &req.resource.kind);
    feed(&mut h, &req.resource.id);
    h.update((req.params.len() as u64).to_be_bytes());
    for p in &req.params {
        feed(&mut h, &p.name);
        feed(&mut h, &p.value);
    }
    RequestDigest(h.finalize().into())
}

/// A grant lifts an escalation when it is for this exact request and its
/// approver is at least the one the escalation goes to.
pub(crate) fn grant_lifts(
    grant_digest: &RequestDigest,
    approver: Approver,
    digest: &RequestDigest,
    to: Approver,
) -> bool {
    grant_digest == digest && approver >= to
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Taint;

    fn deny(r: &str) -> Verdict {
        Verdict::Deny(RuleId(r.into()))
    }
    fn esc(to: Approver) -> Verdict {
        Verdict::Escalate(EscalateReason::NoMatch, to)
    }
    fn esc_r(reason: EscalateReason, to: Approver) -> Verdict {
        Verdict::Escalate(reason, to)
    }
    const ALLOW: Verdict = Verdict::Allow { notify: false };
    const NOTIFY: Verdict = Verdict::Allow { notify: true };

    #[test]
    fn meet_takes_the_weakest() {
        assert_eq!(meet(ALLOW, NOTIFY), NOTIFY);
        assert_eq!(meet(NOTIFY, ALLOW), NOTIFY);
        assert_eq!(meet(ALLOW, ALLOW), ALLOW);
        assert_eq!(meet(NOTIFY, esc(Approver::Main)), esc(Approver::Main));
        assert_eq!(meet(esc(Approver::Main), ALLOW), esc(Approver::Main));
        assert_eq!(meet(esc(Approver::User), deny("d")), deny("d"));
        assert_eq!(meet(deny("d"), esc(Approver::User)), deny("d"));
        assert_eq!(meet(deny("a"), deny("b")), deny("a"));
        assert_eq!(meet(deny("a"), NOTIFY), deny("a"));
        assert_eq!(meet(ALLOW, deny("b")), deny("b"));
    }

    #[test]
    fn meet_of_escalations_goes_to_the_higher_approver() {
        let taint = esc_r(EscalateReason::TaintedParam("p".into()), Approver::User);
        assert_eq!(meet(esc(Approver::Child), taint.clone()), taint);
        assert_eq!(meet(taint.clone(), esc(Approver::Child)), taint);
        // Tie: the first wins.
        let auto = esc_r(EscalateReason::AutonomyRequiresApproval, Approver::User);
        assert_eq!(meet(auto.clone(), taint.clone()), auto);
        assert_eq!(
            meet(esc(Approver::Main), esc(Approver::Child)),
            esc(Approver::Main)
        );
    }

    #[test]
    fn effective_autonomy_is_the_minimum() {
        use Autonomy::*;
        assert_eq!(effective_autonomy(L3ActAndNotify, None), L3ActAndNotify);
        assert_eq!(effective_autonomy(L1Draft, None), L1Draft);
        assert_eq!(effective_autonomy(L3ActAndNotify, Some(L1Draft)), L1Draft);
        assert_eq!(effective_autonomy(L1Draft, Some(L3ActAndNotify)), L1Draft);
        assert_eq!(
            effective_autonomy(L2ActWithApproval, Some(L2ActWithApproval)),
            L2ActWithApproval
        );
    }

    #[test]
    fn autonomy_verdicts() {
        use ActionClass::*;
        use Autonomy::*;
        let d = || deny(RuleId::AUTONOMY);
        let ask = esc_r(EscalateReason::AutonomyRequiresApproval, Approver::User);
        for l in [L0Observe, L1Draft, L2ActWithApproval, L3ActAndNotify] {
            assert_eq!(autonomy_verdict(Read, l), ALLOW);
            assert_eq!(autonomy_verdict(Never, l), deny(RuleId::NEVER));
        }
        assert_eq!(autonomy_verdict(Draft, L0Observe), d());
        assert_eq!(autonomy_verdict(Draft, L1Draft), ALLOW);
        assert_eq!(autonomy_verdict(Draft, L2ActWithApproval), ALLOW);
        assert_eq!(autonomy_verdict(Draft, L3ActAndNotify), ALLOW);
        for c in [WriteWorktree, WriteRemote, Egress, K8sMutate, SecretUse] {
            assert_eq!(autonomy_verdict(c, L0Observe), d());
            assert_eq!(autonomy_verdict(c, L1Draft), d());
            assert_eq!(autonomy_verdict(c, L2ActWithApproval), ask);
            assert_eq!(autonomy_verdict(c, L3ActAndNotify), NOTIFY);
        }
    }

    #[test]
    fn enum_constraint_is_exact() {
        let c = ParamConstraint::Enum(vec!["a".into(), "bc".into()]);
        assert!(constraint_clears(&c, "a"));
        assert!(constraint_clears(&c, "bc"));
        assert!(!constraint_clears(&c, "b"));
        assert!(!constraint_clears(&c, "A"));
        assert!(!constraint_clears(&c, ""));
        assert!(!constraint_clears(&ParamConstraint::Enum(vec![]), ""));
    }

    #[test]
    fn pattern_is_anchored() {
        let p = |s: &str| ParamConstraint::Pattern(s.into());
        assert!(constraint_clears(&p("[a-z]+"), "abc"));
        assert!(!constraint_clears(&p("[a-z]+"), "abc1"));
        assert!(!constraint_clears(&p("[a-z]+"), "1abc"));
        assert!(!constraint_clears(&p("[a-z]+"), "abc\n"));
        assert!(!constraint_clears(&p("a|b"), "xb"));
        assert!(!constraint_clears(&p("a|b"), "ax"));
        assert!(constraint_clears(&p("a|b"), "b"));
        // Breaking out of the anchors fails to compile on its own.
        assert!(!constraint_clears(&p("x)|(.*"), "anything"));
        assert!(!constraint_clears(&p("("), "("));
        assert!(constraint_clears(&p(""), ""));
        assert!(!constraint_clears(&p(""), "a"));
    }

    #[test]
    fn pattern_size_is_limited() {
        let big = "a{1000}{1000}";
        assert!(!constraint_clears(
            &ParamConstraint::Pattern(big.into()),
            &"a".repeat(1_000_000)
        ));
        let long = "a".repeat(MAX_PATTERN_LEN + 1);
        assert!(!constraint_clears(
            &ParamConstraint::Pattern(long.clone()),
            &long
        ));
        let ok = "a".repeat(MAX_PATTERN_LEN);
        assert!(constraint_clears(
            &ParamConstraint::Pattern(ok.clone()),
            &ok
        ));
    }

    #[test]
    fn uncleared_lists_only_tainted_unmatched_params() {
        let params = vec![
            Param::clean("c", "x"),
            Param::untrusted("t1", "v", vec![]),
            Param::untrusted("t2", "ok", vec![])
                .with_constraint(ParamConstraint::Enum(vec!["ok".into()])),
            Param::untrusted("t3", "no", vec![])
                .with_constraint(ParamConstraint::Enum(vec!["ok".into()])),
            Param {
                taint: Taint::Clean,
                ..Param::clean("c2", "x")
            },
        ];
        assert_eq!(uncleared_tainted(&params), vec!["t1", "t3"]);
        assert!(uncleared_tainted(&[]).is_empty());
    }

    #[test]
    fn grant_needs_digest_and_rank() {
        let d = RequestDigest([1; 32]);
        let other = RequestDigest([2; 32]);
        assert!(grant_lifts(&d, Approver::User, &d, Approver::User));
        assert!(grant_lifts(&d, Approver::User, &d, Approver::Child));
        assert!(grant_lifts(&d, Approver::Main, &d, Approver::Main));
        assert!(grant_lifts(&d, Approver::Child, &d, Approver::Child));
        assert!(!grant_lifts(&d, Approver::Main, &d, Approver::User));
        assert!(!grant_lifts(&d, Approver::Child, &d, Approver::Main));
        assert!(!grant_lifts(&other, Approver::User, &d, Approver::Child));
    }

    #[test]
    fn digest_is_stable() {
        let req = DecisionRequest::new(
            crate::EntityRef::new("Worker", "w1"),
            "j_edit",
            crate::EntityRef::new("Path", "p"),
        )
        .param(Param::clean("a", "1"));
        assert_eq!(request_digest(&req), request_digest(&req.clone()));
        assert_ne!(request_digest(&req).0, [0u8; 32]);
    }
}
