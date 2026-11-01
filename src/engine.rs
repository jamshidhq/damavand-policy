//! The engine: load a bundle, decide requests.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::str::FromStr;

use cedar_policy::{
    ActionConstraint, Authorizer, Context, Decision as CedarDecision, Effect, Entities, EntityId,
    EntityTypeName, EntityUid, PolicyId, PolicySet, Request, ResourceConstraint, Schema,
    ValidationMode, Validator,
};
use ed25519_dalek::VerifyingKey;
use serde_json::{Value, json};

use crate::bundle::{Bundle, LoadError, PolicyFile};
use crate::gates::{
    Constraint, Constraints, PatternError, Verdict, autonomy_verdict, compile_pattern,
    effective_autonomy, meet, uncleared_tainted,
};
use crate::grant::{grant_lifts, verifying_key};
use crate::types::{
    ActionClass, Approver, Autonomy, BundleId, Decision, DecisionRecord, DecisionRequest,
    EntityRef, EscalateReason, RuleId,
};

/// Built-in Never actions, defined by name because their danger does not
/// depend on the bundle. Class `class:never` is the main mechanism; this
/// list only stops a bundle from moving these verbs out of it. The engine
/// denies them whatever the bundle says, and refuses a bundle that puts one
/// in a class other than `class:never`.
pub const NEVER_ACTIONS: &[&str] = &[
    "terraform_apply",
    "terraform_destroy",
    "terraform_import",
    "tofu_apply",
    "tofu_destroy",
    "tofu_import",
];

/// The global forbid the loader adds to every bundle whose schema has
/// `class:never`.
const NEVER_FORBID: &str =
    r#"forbid (principal, action in Damavand::Action::"class:never", resource);"#;

/// Orchestrator depths the core builds.
const DEPTHS: &[&str] = &["main", "child"];

const NAMESPACE: &str = "Damavand";
const CLASS_PREFIX: &str = "class:";

/// Autonomy caps from `autonomy.toml`, per (project or loop, action class).
///
/// ```toml
/// [project.jamshid]
/// read = 3
/// "write.worktree" = 2
///
/// [loop.nightly]
/// "write.worktree" = 1
/// ```
///
/// The cap for a request is the lowest entry over every project and loop the
/// principal is in. No entry means L0.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AutonomyCaps {
    projects: BTreeMap<String, BTreeMap<ActionClass, Autonomy>>,
    loops: BTreeMap<String, BTreeMap<ActionClass, Autonomy>>,
}

impl AutonomyCaps {
    /// Every project row.
    pub fn projects(&self) -> &BTreeMap<String, BTreeMap<ActionClass, Autonomy>> {
        &self.projects
    }

    /// Every loop row.
    pub fn loops(&self) -> &BTreeMap<String, BTreeMap<ActionClass, Autonomy>> {
        &self.loops
    }

    /// The cap for a project and class, if `autonomy.toml` sets one.
    pub fn project(&self, project: &str, class: ActionClass) -> Option<Autonomy> {
        self.projects.get(project)?.get(&class).copied()
    }

    /// The cap for a loop and class, if `autonomy.toml` sets one.
    pub fn loop_cap(&self, loop_id: &str, class: ActionClass) -> Option<Autonomy> {
        self.loops.get(loop_id)?.get(&class).copied()
    }

    fn parse(text: &str) -> Result<AutonomyCaps, LoadError> {
        let bad = |message: String| LoadError::Autonomy { message };
        let table: toml::Table = toml::from_str(text).map_err(|e| bad(e.message().to_string()))?;
        let mut caps = AutonomyCaps::default();
        for (scope, entries) in table {
            let target = match scope.as_str() {
                "project" => &mut caps.projects,
                "loop" => &mut caps.loops,
                _ => {
                    return Err(bad(format!(
                        "unknown table [{scope}]; use [project.<id>] or [loop.<id>]"
                    )));
                }
            };
            let entries = entries
                .as_table()
                .ok_or_else(|| bad(format!("[{scope}] must hold tables")))?;
            for (id, classes) in entries {
                let classes = classes
                    .as_table()
                    .ok_or_else(|| bad(format!("[{scope}.{id}] must be a table")))?;
                let row = target.entry(id.clone()).or_default();
                for (class, level) in classes {
                    let c = ActionClass::from_name(class)
                        .filter(|c| *c != ActionClass::Never)
                        .ok_or_else(|| {
                            bad(format!("[{scope}.{id}]: no cap for class {class:?}"))
                        })?;
                    let l = level
                        .as_integer()
                        .and_then(|n| u8::try_from(n).ok())
                        .and_then(Autonomy::from_level)
                        .ok_or_else(|| bad(format!("[{scope}.{id}] {class}: level must be 0-3")))?;
                    row.insert(c, l);
                }
            }
        }
        Ok(caps)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Tier {
    Global,
    Project,
}

#[derive(Debug, Clone)]
struct Meta {
    tier: Tier,
    rule: RuleId,
    ask: bool,
}

/// A loaded, validated bundle. Immutable; share it across threads.
#[derive(Debug)]
pub struct Engine {
    bundle_id: BundleId,
    label: String,
    constraints: Constraints,
    broker_keys: Vec<VerifyingKey>,
    schema: Schema,
    policies: PolicySet,
    meta: HashMap<PolicyId, Meta>,
    classes: HashMap<String, ActionClass>,
    caps: AutonomyCaps,
    action_entities: Entities,
}

fn qualify(kind: &str) -> String {
    if kind.contains("::") {
        kind.to_string()
    } else {
        format!("{NAMESPACE}::{kind}")
    }
}

fn uid(r: &EntityRef) -> Option<EntityUid> {
    let ty = EntityTypeName::from_str(&qualify(&r.kind)).ok()?;
    Some(EntityUid::from_type_name_and_id(ty, EntityId::new(&r.id)))
}

fn action_uid(name: &str) -> Option<EntityUid> {
    uid(&EntityRef::new("Action", name))
}

fn is_damavand_action(u: &EntityUid) -> bool {
    u.type_name().to_string() == format!("{NAMESPACE}::Action")
}

/// `[a-z][a-z0-9_.]*`
fn valid_action_id(id: &str) -> bool {
    let mut chars = id.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.')
}

/// Parse `constraints.toml` against the classified actions and compile
/// every pattern.
fn parse_constraints(
    text: &str,
    classes: &HashMap<String, ActionClass>,
) -> Result<Constraints, LoadError> {
    let bad = |message: String| LoadError::Constraints { message };
    let table: toml::Table = toml::from_str(text).map_err(|e| bad(e.message().to_string()))?;
    let mut out = Constraints::new();
    for (action, params) in table {
        if !classes.contains_key(&action) {
            return Err(bad(format!("unknown action {action:?}")));
        }
        let params = params
            .as_table()
            .ok_or_else(|| bad(format!("[{action}] must hold tables")))?;
        for (param, entry) in params {
            let shape = || bad(format!("[{action}.{param}]: use one enum or one pattern"));
            let entry = entry.as_table().ok_or_else(shape)?;
            if entry.len() != 1 {
                return Err(shape());
            }
            let c = match (entry.get("enum"), entry.get("pattern")) {
                (Some(toml::Value::Array(items)), None) if !items.is_empty() => {
                    let choices = items
                        .iter()
                        .map(|v| v.as_str().map(str::to_string))
                        .collect::<Option<Vec<_>>>()
                        .ok_or_else(shape)?;
                    Constraint::Enum(choices)
                }
                (None, Some(toml::Value::String(p))) => {
                    let err = |e| match e {
                        PatternError::Invalid => LoadError::PatternInvalid {
                            action: action.clone(),
                            param: param.clone(),
                        },
                        PatternError::TooBroad => LoadError::PatternTooBroad {
                            action: action.clone(),
                            param: param.clone(),
                        },
                    };
                    Constraint::Pattern(compile_pattern(p).map_err(err)?)
                }
                _ => return Err(shape()),
            };
            out.insert((action.clone(), param.clone()), c);
        }
    }
    Ok(out)
}

/// The context record the engine sends; `load` checks every action accepts it.
fn context_json(
    level: Autonomy,
    class: ActionClass,
    req: &DecisionRequest,
    tainted: &[&str],
) -> Value {
    json!({
        "autonomy": i64::from(level.level()),
        "action_class": class.name(),
        "taint_unvalidated": !tainted.is_empty(),
        "tainted_params": tainted,
        "budget": {
            "tokens_left": req.budget.tokens_left,
            "actions_left": req.budget.actions_left,
        },
        "run_id": req.run_id,
    })
}

impl Engine {
    /// Load and strictly validate a bundle.
    pub fn load(bundle: &Bundle) -> Result<Engine, LoadError> {
        let (schema, _warnings) =
            Schema::from_cedarschema_str(&bundle.schema).map_err(|_| LoadError::Schema)?;
        let action_entities = schema.action_entities().map_err(|_| LoadError::Schema)?;
        let classes = Self::classify(&schema, &action_entities)?;

        let mut policies = PolicySet::new();
        let mut meta = HashMap::new();
        for file in &bundle.global {
            Self::add_file(&mut policies, &mut meta, file, None, &classes)?;
        }
        for (project, files) in &bundle.projects {
            for file in files {
                Self::add_file(&mut policies, &mut meta, file, Some(project), &classes)?;
            }
        }
        // Never as a global forbid, next to the Rust gate in decide().
        let never_group = action_uid(&format!("{CLASS_PREFIX}never"));
        if schema.actions().any(|a| Some(a) == never_group.as_ref()) {
            let forbid = PolicySet::from_str(NEVER_FORBID)
                .ok()
                .and_then(|p| p.policies().next().cloned())
                .ok_or(LoadError::Schema)?;
            let pid = PolicyId::new(RuleId::NEVER);
            policies
                .add(forbid.new_id(pid.clone()))
                .map_err(|_| LoadError::Schema)?;
            meta.insert(
                pid,
                Meta {
                    tier: Tier::Global,
                    rule: RuleId(RuleId::NEVER.into()),
                    ask: false,
                },
            );
        }

        let result = Validator::new(schema.clone()).validate(&policies, ValidationMode::Strict);
        if !result.validation_passed() {
            let ids: BTreeSet<String> = result
                .validation_errors()
                .map(|e| e.policy_id().to_string())
                .collect();
            return Err(LoadError::Validation {
                ids: ids.into_iter().collect(),
            });
        }

        let caps = AutonomyCaps::parse(&bundle.autonomy)?;
        let constraints = parse_constraints(&bundle.constraints, &classes)?;
        let broker_keys = bundle
            .broker_keys
            .iter()
            .enumerate()
            .map(|(index, k)| verifying_key(k).ok_or(LoadError::BrokerKey { index }))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Engine {
            bundle_id: bundle.digest(),
            label: bundle.label.clone(),
            constraints,
            broker_keys,
            schema,
            policies,
            meta,
            classes,
            caps,
            action_entities,
        })
    }

    /// Map every verb to its single class group, and check each verb
    /// accepts the engine's context record.
    fn classify(
        schema: &Schema,
        action_entities: &Entities,
    ) -> Result<HashMap<String, ActionClass>, LoadError> {
        let groups: HashSet<&EntityUid> = schema.action_groups().collect();
        let mut actions: Vec<&EntityUid> =
            schema.actions().filter(|a| is_damavand_action(a)).collect();
        actions.sort_by_key(|a| a.id().unescaped().to_string());
        let class_of = |a: &EntityUid| -> Vec<String> {
            action_entities
                .ancestors(a)
                .map(|it| {
                    it.filter(|p| is_damavand_action(p))
                        .map(|p| p.id().unescaped().to_string())
                        .filter(|id| id.starts_with(CLASS_PREFIX))
                        .collect()
                })
                .unwrap_or_default()
        };
        let mut classes = HashMap::new();
        for a in actions {
            let id = a.id().unescaped().to_string();
            let refuse = || LoadError::ActionClass { action: id.clone() };
            if let Some(name) = id.strip_prefix(CLASS_PREFIX) {
                if ActionClass::from_name(name).is_none() || !class_of(a).is_empty() {
                    return Err(refuse());
                }
                continue;
            }
            if !valid_action_id(&id) {
                return Err(LoadError::ActionId { action: id });
            }
            if groups.contains(a) {
                continue;
            }
            let parents = class_of(a);
            let [only] = parents.as_slice() else {
                return Err(refuse());
            };
            let class = only
                .strip_prefix(CLASS_PREFIX)
                .and_then(ActionClass::from_name)
                .ok_or_else(refuse)?;
            if NEVER_ACTIONS.contains(&id.as_str()) && class != ActionClass::Never {
                return Err(LoadError::NeverReclassified { action: id });
            }
            let sample =
                DecisionRequest::new(EntityRef::new("", ""), "", EntityRef::new("", ""), 0);
            let ctx = context_json(Autonomy::L0Observe, class, &sample, &["p"]);
            if Context::from_json_value(ctx, Some((schema, a))).is_err() {
                return Err(LoadError::ContextShape { action: id });
            }
            classes.insert(id, class);
        }
        Ok(classes)
    }

    fn add_file(
        policies: &mut PolicySet,
        meta: &mut HashMap<PolicyId, Meta>,
        file: &PolicyFile,
        project: Option<&String>,
        classes: &HashMap<String, ActionClass>,
    ) -> Result<(), LoadError> {
        let parsed = PolicySet::from_str(&file.text).map_err(|_| LoadError::Parse {
            file: file.name.clone(),
        })?;
        if parsed.templates().next().is_some() {
            return Err(LoadError::Template {
                file: file.name.clone(),
            });
        }
        let mut list: Vec<_> = parsed.policies().cloned().collect();
        // policies() has no defined order; sort by source id for stable errors.
        list.sort_by_key(|p| p.id().to_string());
        for policy in list {
            let id = match policy.annotation("id") {
                Some(id) if !id.is_empty() => id.to_string(),
                _ => {
                    return Err(LoadError::MissingId {
                        file: file.name.clone(),
                    });
                }
            };
            if id.starts_with("damavand.") {
                return Err(LoadError::ReservedId { id });
            }
            if policy.effect() == Effect::Permit {
                let scope = policy.action_constraint();
                let named: Vec<&EntityUid> = match &scope {
                    ActionConstraint::Any => Vec::new(),
                    ActionConstraint::Eq(u) => vec![u],
                    ActionConstraint::In(us) => us.iter().collect(),
                };
                let never = |u: &&EntityUid| {
                    let name = u.id().unescaped();
                    is_damavand_action(u)
                        && (name == "class:never"
                            || NEVER_ACTIONS.contains(&name)
                            || classes.get(name) == Some(&ActionClass::Never))
                };
                if named.iter().any(never) {
                    return Err(LoadError::PermitsNever { id });
                }
            }
            let ask = match policy.annotation("outcome") {
                None => false,
                Some("ask") if policy.effect() == Effect::Forbid => true,
                Some(_) => return Err(LoadError::BadOutcome { id }),
            };
            if let Some(project) = project {
                let target = uid(&EntityRef::new("Project", project.as_str()));
                let scoped = match policy.resource_constraint() {
                    ResourceConstraint::In(u)
                    | ResourceConstraint::Eq(u)
                    | ResourceConstraint::IsIn(_, u) => Some(u) == target,
                    _ => false,
                };
                if !scoped {
                    return Err(LoadError::ProjectScope {
                        project: project.clone(),
                        id,
                    });
                }
            }
            let pid = PolicyId::new(&id);
            if meta.contains_key(&pid) {
                return Err(LoadError::DuplicateId { id });
            }
            policies
                .add(policy.new_id(pid.clone()))
                .map_err(|_| LoadError::DuplicateId { id: id.clone() })?;
            let tier = if project.is_some() {
                Tier::Project
            } else {
                Tier::Global
            };
            meta.insert(
                pid,
                Meta {
                    tier,
                    rule: RuleId(id),
                    ask,
                },
            );
        }
        Ok(())
    }

    /// Decide a request. Never fails and never panics: any problem is a Deny.
    pub fn decide(&self, req: &DecisionRequest) -> Decision {
        let digest = req.digest();
        let mut record = DecisionRecord {
            decision_id: uuid::Uuid::now_v7().to_string(),
            bundle_id: self.bundle_id,
            rule_ids: Vec::new(),
            request_digest: digest,
            approved: false,
            grant_nonce: None,
        };
        let builtin = |rule: &str, mut record: DecisionRecord| {
            record.rule_ids = vec![RuleId(rule.into())];
            Decision::Deny {
                rule: RuleId(rule.into()),
                record,
            }
        };

        // Never gate: before Cedar, so no bundle content can reach it.
        if NEVER_ACTIONS.contains(&req.action.as_str()) {
            return builtin(RuleId::NEVER, record);
        }
        let Some(&class) = self.classes.get(&req.action) else {
            return builtin(RuleId::UNKNOWN_ACTION, record);
        };
        if class == ActionClass::Never {
            return builtin(RuleId::NEVER, record);
        }

        let Some((request, entities, level)) = self.cedar_request(req, class) else {
            return builtin(RuleId::REQUEST_INVALID, record);
        };
        if !Self::topology_ok(req, &entities) {
            return builtin(RuleId::TOPOLOGY, record);
        }
        let response = Authorizer::new().is_authorized(&request, &self.policies, &entities);
        // Cedar skips a policy that errors; a skipped forbid must not fail open.
        if response.diagnostics().errors().next().is_some() {
            return builtin(RuleId::EVAL_ERROR, record);
        }

        let mut determining: Vec<&Meta> = response
            .diagnostics()
            .reason()
            .filter_map(|id| self.meta.get(id))
            .collect();
        determining.sort_by(|a, b| (a.tier, &a.rule).cmp(&(b.tier, &b.rule)));
        let mut ids: Vec<RuleId> = determining.iter().map(|m| m.rule.clone()).collect();
        ids.sort();
        record.rule_ids = ids;

        let cedar = match response.decision() {
            CedarDecision::Allow => Verdict::Allow { notify: false },
            CedarDecision::Deny => {
                if let Some(hard) = determining.iter().find(|m| !m.ask) {
                    Verdict::Deny(hard.rule.clone())
                } else if let Some(ask) = determining.first() {
                    Verdict::Escalate(
                        vec![EscalateReason::PolicyAsk(ask.rule.clone())],
                        Approver::User,
                    )
                } else {
                    Verdict::Escalate(vec![EscalateReason::NoMatch], self.next_level(req))
                }
            }
        };
        let tainted = uncleared_tainted(&req.params, &req.action, &self.constraints);
        let taint = if tainted.is_empty() {
            Verdict::Allow { notify: false }
        } else {
            let reasons = tainted
                .iter()
                .map(|n| EscalateReason::TaintedParam(n.to_string()))
                .collect();
            Verdict::Escalate(reasons, Approver::User)
        };
        let mut verdict = meet(meet(cedar, autonomy_verdict(class, level)), taint);

        // A grant lifts Escalate only. It is never consulted for Deny.
        if let (Verdict::Escalate(reasons, to), Some(grant)) = (&verdict, &req.approval)
            && grant_lifts(&self.broker_keys, &self.bundle_id, req, grant, reasons, *to)
        {
            verdict = Verdict::Allow { notify: true };
            record.approved = true;
            record.grant_nonce = Some(grant.nonce);
        }
        match verdict {
            Verdict::Deny(rule) => Decision::Deny { rule, record },
            Verdict::Escalate(reasons, to) => Decision::Escalate {
                reasons,
                to,
                record,
            },
            Verdict::Allow { notify } => Decision::Allow { notify, record },
        }
    }

    /// The topology checks the engine can make on what the core sent: every
    /// orchestrator has a known depth, and a worker principal is in an
    /// orchestrator or a loop. Loop membership itself is the core's to get
    /// right; an omitted Loop edge is not visible here.
    fn topology_ok(req: &DecisionRequest, entities: &Entities) -> bool {
        let orchestrator = qualify("Orchestrator");
        let depths_ok = req
            .entities
            .iter()
            .filter(|e| qualify(&e.uid.kind) == orchestrator)
            .all(|e| {
                e.attrs
                    .get("depth")
                    .and_then(Value::as_str)
                    .is_some_and(|d| DEPTHS.contains(&d))
            });
        if !depths_ok {
            return false;
        }
        if qualify(&req.principal.kind) != qualify("Worker") {
            return true;
        }
        let Some(principal) = uid(&req.principal) else {
            return false;
        };
        let placed = [orchestrator, qualify("Loop")];
        entities
            .ancestors(&principal)
            .is_some_and(|mut a| a.any(|p| placed.contains(&p.type_name().to_string())))
    }

    /// Build the Cedar request and entity store, and the effective autonomy
    /// level. `None` when the request does not fit the schema.
    fn cedar_request(
        &self,
        req: &DecisionRequest,
        class: ActionClass,
    ) -> Option<(Request, Entities, Autonomy)> {
        let principal = uid(&req.principal)?;
        let resource = uid(&req.resource)?;
        let action = action_uid(&req.action)?;
        let json_ref = |r: &EntityRef| json!({"type": qualify(&r.kind), "id": r.id});
        let ents: Vec<Value> = req
            .entities
            .iter()
            .map(|e| {
                json!({
                    "uid": json_ref(&e.uid),
                    "parents": e.parents.iter().map(json_ref).collect::<Vec<_>>(),
                    "attrs": e.attrs,
                })
            })
            .collect();
        let entities = Entities::from_json_value(Value::Array(ents), Some(&self.schema))
            .ok()?
            .add_entities(self.action_entities.clone(), Some(&self.schema))
            .ok()?;

        let level = effective_autonomy(
            self.cap(&entities, &principal, class),
            req.autonomy_override,
        );
        let tainted = uncleared_tainted(&req.params, &req.action, &self.constraints);
        let ctx = Context::from_json_value(
            context_json(level, class, req, &tainted),
            Some((&self.schema, &action)),
        )
        .ok()?;
        let request = Request::new(principal, action, resource, ctx, Some(&self.schema)).ok()?;
        Some((request, entities, level))
    }

    /// The lowest cap over every project and loop the principal is in; L0
    /// when none is set.
    fn cap(&self, entities: &Entities, principal: &EntityUid, class: ActionClass) -> Autonomy {
        let project_ty = qualify("Project");
        let loop_ty = qualify("Loop");
        let mut cap: Option<Autonomy> = None;
        if let Some(ancestors) = entities.ancestors(principal) {
            for a in ancestors {
                let ty = a.type_name().to_string();
                let id = a.id().unescaped();
                let found = if ty == project_ty {
                    self.caps.project(id, class)
                } else if ty == loop_ty {
                    self.caps.loop_cap(id, class)
                } else {
                    None
                };
                if let Some(f) = found {
                    cap = Some(cap.map_or(f, |c| c.min(f)));
                }
            }
        }
        cap.unwrap_or(Autonomy::L0Observe)
    }

    /// Who a NoMatch goes to: the next level above the principal. Unknown
    /// structure goes to the user.
    fn next_level(&self, req: &DecisionRequest) -> Approver {
        let depth = |r: &EntityRef| {
            req.entities
                .iter()
                .find(|e| qualify(&e.uid.kind) == qualify(&r.kind) && e.uid.id == r.id)
                .and_then(|e| e.attrs.get("depth"))
                .and_then(Value::as_str)
                .map(str::to_string)
        };
        let orchestrator = qualify("Orchestrator");
        match qualify(&req.principal.kind).as_str() {
            "Damavand::Worker" => {
                let parent = req
                    .entities
                    .iter()
                    .find(|e| {
                        qualify(&e.uid.kind) == "Damavand::Worker" && e.uid.id == req.principal.id
                    })
                    .and_then(|e| e.parents.iter().find(|p| qualify(&p.kind) == orchestrator));
                match parent.and_then(depth).as_deref() {
                    Some("child") => Approver::Child,
                    Some("main") => Approver::Main,
                    _ => Approver::User,
                }
            }
            "Damavand::Orchestrator" => match depth(&req.principal).as_deref() {
                Some("child") => Approver::Main,
                _ => Approver::User,
            },
            _ => Approver::User,
        }
    }

    /// The id of the loaded bundle: SHA-256 over its canonical content.
    pub fn bundle_id(&self) -> &BundleId {
        &self.bundle_id
    }

    /// The bundle's human label (a commit sha).
    pub fn bundle_label(&self) -> &str {
        &self.label
    }

    /// The autonomy caps from `autonomy.toml`.
    pub fn autonomy_caps(&self) -> &AutonomyCaps {
        &self.caps
    }

    /// The action class of a verb in the schema.
    pub fn action_class(&self, action: &str) -> Option<ActionClass> {
        self.classes.get(action).copied()
    }
}
