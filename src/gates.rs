//! Deterministic gates around the Cedar result: meet, autonomy, taint,
//! constraints and digests. Pure functions.

use std::collections::HashMap;

use regex::{Regex, RegexBuilder};
use regex_syntax::hir::{Class, ClassBytes, ClassBytesRange, ClassUnicode, ClassUnicodeRange};
use regex_syntax::hir::{Hir, HirKind};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::types::{
    ActionClass, Approver, Autonomy, DecisionRequest, Entity, EscalateReason, Param, RequestDigest,
    RuleId, Taint,
};

/// One component's verdict before it becomes a [`crate::Decision`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    Deny(RuleId),
    Escalate(Vec<EscalateReason>, Approver),
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
/// Parser nesting limit for one pattern.
const REGEX_NEST_LIMIT: u32 = 64;

/// The weaker of two verdicts: Deny < Escalate < Allow+notify < Allow.
/// Two escalations merge: every reason is kept (most severe first, no
/// duplicates) and the escalation goes to the higher approver. Between two
/// denies, the first argument wins.
pub(crate) fn meet(a: Verdict, b: Verdict) -> Verdict {
    match (a, b) {
        (Verdict::Escalate(mut ra, ta), Verdict::Escalate(rb, tb)) => {
            for r in rb {
                if !ra.contains(&r) {
                    ra.push(r);
                }
            }
            ra.sort_by_key(|r| std::cmp::Reverse(r.severity()));
            Verdict::Escalate(ra, ta.max(tb))
        }
        (a, b) => {
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
            Autonomy::L2ActWithApproval => Verdict::Escalate(
                vec![EscalateReason::AutonomyRequiresApproval],
                Approver::User,
            ),
            Autonomy::L3ActAndNotify => Verdict::Allow { notify: true },
        },
    }
}

/// A bundle constraint, compiled at load.
#[derive(Debug, Clone)]
pub(crate) enum Constraint {
    Enum(Vec<String>),
    Pattern(Regex),
}

/// Constraints by (action, parameter name).
pub(crate) type Constraints = HashMap<(String, String), Constraint>;

/// Why a pattern is refused at load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PatternError {
    Invalid,
    TooBroad,
}

/// Characters a narrow value never needs and an injection payload does:
/// C0 and C1 controls (newline included), DEL, bidi controls, and the shell
/// and quoting metacharacters `` $ ` ; | & < > \ " ' ``.
fn forbidden_unicode() -> ClassUnicode {
    let mut ranges = vec![
        ClassUnicodeRange::new('\u{0}', '\u{1f}'),
        ClassUnicodeRange::new('\u{7f}', '\u{9f}'),
        ClassUnicodeRange::new('\u{200e}', '\u{200f}'),
        ClassUnicodeRange::new('\u{202a}', '\u{202e}'),
        ClassUnicodeRange::new('\u{2066}', '\u{2069}'),
    ];
    for c in FORBIDDEN_ASCII.chars() {
        ranges.push(ClassUnicodeRange::new(c, c));
    }
    ClassUnicode::new(ranges)
}

const FORBIDDEN_ASCII: &str = "$`;|&<>\\\"'";

fn forbidden_bytes() -> ClassBytes {
    let mut ranges = vec![
        ClassBytesRange::new(0, 0x1f),
        // DEL and every non-ASCII byte: a byte class is not text.
        ClassBytesRange::new(0x7f, 0xff),
    ];
    for b in FORBIDDEN_ASCII.bytes() {
        ranges.push(ClassBytesRange::new(b, b));
    }
    ClassBytes::new(ranges)
}

/// True when some string the pattern matches can hold a forbidden
/// character. It walks the parsed pattern and collects every character any
/// literal or class can produce: an over-approximation, so a `false` is a
/// proof.
fn can_match_forbidden(hir: &Hir, uni: &ClassUnicode, bytes: &ClassBytes) -> bool {
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => false,
        HirKind::Literal(lit) => String::from_utf8_lossy(&lit.0)
            .chars()
            .any(|c| uni.ranges().iter().any(|r| r.start() <= c && c <= r.end())),
        HirKind::Class(Class::Unicode(c)) => {
            let mut c = c.clone();
            c.intersect(uni);
            !c.ranges().is_empty()
        }
        HirKind::Class(Class::Bytes(c)) => {
            let mut c = c.clone();
            c.intersect(bytes);
            !c.ranges().is_empty()
        }
        HirKind::Repetition(r) => can_match_forbidden(&r.sub, uni, bytes),
        HirKind::Capture(c) => can_match_forbidden(&c.sub, uni, bytes),
        HirKind::Concat(hs) | HirKind::Alternation(hs) => {
            hs.iter().any(|h| can_match_forbidden(h, uni, bytes))
        }
    }
}

/// Compile a bundle pattern. It must compile on its own (so `x)|(.*` cannot
/// close the anchoring group), fit the size limits, and be unable to match a
/// forbidden character. It is then anchored as `\A(?:…)\z`.
pub(crate) fn compile_pattern(pattern: &str) -> Result<Regex, PatternError> {
    if pattern.len() > MAX_PATTERN_LEN {
        return Err(PatternError::Invalid);
    }
    let build = |p: &str| {
        RegexBuilder::new(p)
            .size_limit(REGEX_SIZE_LIMIT)
            .dfa_size_limit(REGEX_SIZE_LIMIT)
            .nest_limit(REGEX_NEST_LIMIT)
            .build()
            .map_err(|_| PatternError::Invalid)
    };
    build(pattern)?;
    let hir = regex_syntax::ParserBuilder::new()
        .nest_limit(REGEX_NEST_LIMIT)
        .build()
        .parse(pattern)
        .map_err(|_| PatternError::Invalid)?;
    if can_match_forbidden(&hir, &forbidden_unicode(), &forbidden_bytes()) {
        return Err(PatternError::TooBroad);
    }
    build(&format!(r"\A(?:{pattern})\z"))
}

/// True when the value satisfies the constraint.
pub(crate) fn constraint_clears(c: &Constraint, value: &str) -> bool {
    match c {
        Constraint::Enum(choices) => choices.iter().any(|v| v == value),
        Constraint::Pattern(re) => re.is_match(value),
    }
}

/// Names of tainted parameters that no bundle constraint for this action
/// clears, in order. Anything but `Clean` counts as tainted.
pub(crate) fn uncleared_tainted<'a>(
    params: &'a [Param],
    action: &str,
    constraints: &Constraints,
) -> Vec<&'a str> {
    params
        .iter()
        .filter(|p| !matches!(p.taint, Taint::Clean))
        .filter(|p| {
            !constraints
                .get(&(action.to_string(), p.name.clone()))
                .is_some_and(|c| constraint_clears(c, &p.value))
        })
        .map(|p| p.name.as_str())
        .collect()
}

pub(crate) fn feed(h: &mut Sha256, field: &[u8]) {
    h.update((field.len() as u64).to_be_bytes());
    h.update(field);
}

/// SHA-256 over length-prefixed principal, action, resource and each
/// parameter's name, value and taint (with its sources), in order.
pub(crate) fn request_digest(req: &DecisionRequest) -> RequestDigest {
    let mut h = Sha256::new();
    feed(&mut h, b"damavand-policy/request/v2");
    feed(&mut h, req.principal.kind.as_bytes());
    feed(&mut h, req.principal.id.as_bytes());
    feed(&mut h, req.action.as_bytes());
    feed(&mut h, req.resource.kind.as_bytes());
    feed(&mut h, req.resource.id.as_bytes());
    h.update((req.params.len() as u64).to_be_bytes());
    for p in &req.params {
        feed(&mut h, p.name.as_bytes());
        feed(&mut h, p.value.as_bytes());
        match &p.taint {
            Taint::Clean => h.update([0u8]),
            Taint::Untrusted { sources } => {
                h.update([1u8]);
                h.update((sources.len() as u64).to_be_bytes());
                for s in sources {
                    feed(&mut h, s.as_bytes());
                }
            }
        }
    }
    RequestDigest(h.finalize().into())
}

/// Canonical bytes of a JSON value: type-tagged, length-prefixed, object
/// keys sorted. `None` for a float (Cedar has none; refusing keeps the
/// encoding exact).
fn canonical_value(v: &Value, out: &mut Vec<u8>) -> Option<()> {
    let put = |out: &mut Vec<u8>, b: &[u8]| {
        out.extend_from_slice(&(b.len() as u64).to_be_bytes());
        out.extend_from_slice(b);
    };
    match v {
        Value::Null => out.push(0),
        Value::Bool(b) => out.extend_from_slice(&[1, u8::from(*b)]),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push(2);
                out.extend_from_slice(&i.to_be_bytes());
            } else {
                out.push(3);
                out.extend_from_slice(&n.as_u64()?.to_be_bytes());
            }
        }
        Value::String(s) => {
            out.push(4);
            put(out, s.as_bytes());
        }
        Value::Array(items) => {
            out.push(5);
            out.extend_from_slice(&(items.len() as u64).to_be_bytes());
            for i in items {
                canonical_value(i, out)?;
            }
        }
        Value::Object(map) => {
            out.push(6);
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.extend_from_slice(&(keys.len() as u64).to_be_bytes());
            for k in keys {
                put(out, k.as_bytes());
                canonical_value(&map[k], out)?;
            }
        }
    }
    Some(())
}

fn canonical_entity(e: &Entity) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let r = |out: &mut Vec<u8>, kind: &str, id: &str| {
        for b in [kind.as_bytes(), id.as_bytes()] {
            out.extend_from_slice(&(b.len() as u64).to_be_bytes());
            out.extend_from_slice(b);
        }
    };
    r(&mut out, &e.uid.kind, &e.uid.id);
    let mut parents: Vec<_> = e.parents.iter().collect();
    parents.sort();
    out.extend_from_slice(&(parents.len() as u64).to_be_bytes());
    for p in parents {
        r(&mut out, &p.kind, &p.id);
    }
    canonical_value(&Value::Object(e.attrs.clone()), &mut out)?;
    Some(out)
}

/// SHA-256 over the entity graph, order-independent: entities, parents and
/// attribute keys are sorted. `None` when an attribute holds a float.
pub(crate) fn entities_digest(entities: &[Entity]) -> Option<[u8; 32]> {
    let mut encoded = entities
        .iter()
        .map(canonical_entity)
        .collect::<Option<Vec<_>>>()?;
    encoded.sort();
    let mut h = Sha256::new();
    feed(&mut h, b"damavand-policy/entities/v1");
    h.update((encoded.len() as u64).to_be_bytes());
    for e in &encoded {
        feed(&mut h, e);
    }
    Some(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deny(r: &str) -> Verdict {
        Verdict::Deny(RuleId(r.into()))
    }
    fn esc(to: Approver) -> Verdict {
        Verdict::Escalate(vec![EscalateReason::NoMatch], to)
    }
    fn esc_r(reason: EscalateReason, to: Approver) -> Verdict {
        Verdict::Escalate(vec![reason], to)
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
    fn meet_of_escalations_keeps_every_reason_and_the_higher_approver() {
        let taint = EscalateReason::TaintedParam("p".into());
        let auto = EscalateReason::AutonomyRequiresApproval;
        let ask = EscalateReason::PolicyAsk(RuleId("q".into()));
        let both = Verdict::Escalate(vec![taint.clone(), EscalateReason::NoMatch], Approver::User);
        assert_eq!(
            meet(esc(Approver::Child), esc_r(taint.clone(), Approver::User)),
            both
        );
        assert_eq!(
            meet(esc_r(taint.clone(), Approver::User), esc(Approver::Child)),
            both
        );
        // Tie on the approver: both reasons, most severe first.
        assert_eq!(
            meet(
                esc_r(auto.clone(), Approver::User),
                esc_r(taint.clone(), Approver::User)
            ),
            Verdict::Escalate(vec![taint.clone(), auto.clone()], Approver::User)
        );
        assert_eq!(
            meet(
                esc_r(auto.clone(), Approver::User),
                Verdict::Escalate(vec![ask.clone(), auto.clone()], Approver::User)
            ),
            Verdict::Escalate(vec![ask, auto], Approver::User)
        );
        assert_eq!(
            meet(esc(Approver::Main), esc(Approver::Child)),
            esc(Approver::Main)
        );
        assert_eq!(
            meet(esc(Approver::Child), esc(Approver::Main)),
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
        let c = Constraint::Enum(vec!["a".into(), "bc".into()]);
        assert!(constraint_clears(&c, "a"));
        assert!(constraint_clears(&c, "bc"));
        assert!(!constraint_clears(&c, "b"));
        assert!(!constraint_clears(&c, "A"));
        assert!(!constraint_clears(&c, ""));
    }

    fn clears(p: &str, v: &str) -> bool {
        constraint_clears(&Constraint::Pattern(compile_pattern(p).unwrap()), v)
    }

    #[test]
    fn pattern_is_anchored() {
        assert!(clears("[a-z]+", "abc"));
        assert!(!clears("[a-z]+", "abc1"));
        assert!(!clears("[a-z]+", "1abc"));
        assert!(!clears("[a-z]+", "abc\n"));
        assert!(!clears("a|b", "xb"));
        assert!(!clears("a|b", "ax"));
        assert!(clears("a|b", "b"));
        assert!(clears("", ""));
        assert!(!clears("", "a"));
    }

    #[test]
    fn pattern_that_breaks_out_or_does_not_parse_is_invalid() {
        for p in ["x)|(.*", "(", "a{1000}{1000}"] {
            assert_eq!(
                compile_pattern(p).unwrap_err(),
                PatternError::Invalid,
                "{p}"
            );
        }
        let deep = format!("{}a{}", "(".repeat(100), ")".repeat(100));
        assert_eq!(compile_pattern(&deep).unwrap_err(), PatternError::Invalid);
    }

    #[test]
    fn pattern_length_is_limited() {
        let long = "a".repeat(MAX_PATTERN_LEN + 1);
        assert_eq!(compile_pattern(&long).unwrap_err(), PatternError::Invalid);
        let ok = "a".repeat(MAX_PATTERN_LEN);
        assert!(clears(&ok, &ok));
    }

    #[test]
    fn broad_patterns_are_refused() {
        for p in [
            ".*",
            "(?s).*",
            ".+",
            r"[\s\S]*",
            r"\S+",
            "[^x]*",
            ".*x",
            "[[:print:]]+",
            ".{0,999}",
            "a|.",
            "(a|b;)",
            r"\$",
            "[\u{202e}]",
            r"\x7f",
            r"(?-u:[\x00-\x7f])",
            r"(?i)[a-z|]+",
            "\u{0}",
        ] {
            assert_eq!(
                compile_pattern(p).unwrap_err(),
                PatternError::TooBroad,
                "{p:?}"
            );
        }
        for p in [
            "[a-z0-9/._-]+",
            r"\w+",
            "[a-z ]{1,40}",
            "append|replace",
            r"(?-u:[a-z])+",
            r"\bx\b",
            "é",
        ] {
            assert!(compile_pattern(p).is_ok(), "{p:?}");
        }
    }

    #[test]
    fn uncleared_lists_only_tainted_unmatched_params() {
        let mut cs = Constraints::new();
        cs.insert(
            ("act".into(), "t2".into()),
            Constraint::Enum(vec!["ok".into()]),
        );
        cs.insert(
            ("act".into(), "t3".into()),
            Constraint::Enum(vec!["ok".into()]),
        );
        cs.insert(
            ("other".into(), "t1".into()),
            Constraint::Enum(vec!["v".into()]),
        );
        let params = vec![
            Param::clean("c", "x"),
            Param::untrusted("t1", "v", vec![]),
            Param::untrusted("t2", "ok", vec![]),
            Param::untrusted("t3", "no", vec![]),
        ];
        assert_eq!(uncleared_tainted(&params, "act", &cs), vec!["t1", "t3"]);
        assert_eq!(uncleared_tainted(&params, "other", &cs), vec!["t2", "t3"]);
        assert!(uncleared_tainted(&[], "act", &cs).is_empty());
    }

    #[test]
    fn digest_is_stable_and_covers_taint() {
        let mk = |p: Param| {
            DecisionRequest::new(
                crate::EntityRef::new("Worker", "w1"),
                "j_edit",
                crate::EntityRef::new("Path", "p"),
                0,
            )
            .param(p)
        };
        let req = mk(Param::clean("a", "1"));
        assert_eq!(request_digest(&req), request_digest(&req.clone()));
        assert_ne!(request_digest(&req).0, [0u8; 32]);
        let t = request_digest(&mk(Param::untrusted("a", "1", vec![])));
        assert_ne!(request_digest(&req), t);
        assert_ne!(
            t,
            request_digest(&mk(Param::untrusted("a", "1", vec!["web".into()])))
        );
    }

    #[test]
    fn entities_digest_ignores_order_and_refuses_floats() {
        use crate::{Entity, EntityRef};
        let a = Entity::new(EntityRef::new("A", "1"))
            .parent(EntityRef::new("P", "1"))
            .parent(EntityRef::new("P", "2"))
            .attr("x", serde_json::json!(1))
            .attr("y", serde_json::json!({"k": [true, null, "s"], "j": -2}));
        let b = Entity::new(EntityRef::new("B", "1"));
        let a2 = Entity::new(EntityRef::new("A", "1"))
            .parent(EntityRef::new("P", "2"))
            .parent(EntityRef::new("P", "1"))
            .attr("y", serde_json::json!({"j": -2, "k": [true, null, "s"]}))
            .attr("x", serde_json::json!(1));
        let d = entities_digest(&[a.clone(), b.clone()]).unwrap();
        assert_eq!(d, entities_digest(&[b.clone(), a2]).unwrap());
        assert_ne!(d, entities_digest(std::slice::from_ref(&a)).unwrap());
        for v in [
            serde_json::json!(2),
            serde_json::json!(u64::MAX),
            serde_json::json!("1"),
            serde_json::json!([1]),
            serde_json::json!(false),
            serde_json::json!(null),
        ] {
            let changed = a.clone().attr("x", v.clone());
            assert_ne!(d, entities_digest(&[changed, b.clone()]).unwrap(), "{v}");
        }
        let float = a.attr("x", serde_json::json!(1.5));
        assert!(entities_digest(&[float]).is_none());
    }
}
