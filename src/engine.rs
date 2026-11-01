//! The engine: load a bundle, decide requests.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision as CedarDecision, Effect, Entities, EntityId, EntityTypeName,
    EntityUid, PolicyId, PolicySet, Request, ResourceConstraint, Schema, ValidationMode, Validator,
};
use serde_json::{Value, json};

use crate::bundle::{Bundle, LoadError, PolicyFile};
use crate::gates::{
    Verdict, autonomy_verdict, effective_autonomy, grant_lifts, meet, uncleared_tainted,
};
use crate::types::{
    ActionClass, Approver, Autonomy, BundleId, Decision, DecisionRecord, DecisionRequest,
    EntityRef, EscalateReason, RuleId,
};

/// Built-in Never actions. The engine denies them whatever the bundle says,
/// and refuses a bundle that puts one in a class other than `class:never`.
pub const NEVER_ACTIONS: &[&str] = &["terraform_apply"];

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
            Self::add_file(&mut policies, &mut meta, file, None)?;
        }
        for (project, files) in &bundle.projects {
            for file in files {
                Self::add_file(&mut policies, &mut meta, file, Some(project))?;
            }
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
        Ok(Engine {
            bundle_id: bundle.id.clone(),
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
            let sample = DecisionRequest::new(EntityRef::new("", ""), "", EntityRef::new("", ""));
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
            bundle_id: self.bundle_id.clone(),
            rule_ids: Vec::new(),
            request_digest: digest,
            approved: false,
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
                    Verdict::Escalate(EscalateReason::PolicyAsk(ask.rule.clone()), Approver::User)
                } else {
                    Verdict::Escalate(EscalateReason::NoMatch, self.next_level(req))
                }
            }
        };
        let tainted = uncleared_tainted(&req.params);
        let taint = match tainted.first() {
            Some(name) => Verdict::Escalate(
                EscalateReason::TaintedParam(name.to_string()),
                Approver::User,
            ),
            None => Verdict::Allow { notify: false },
        };
        let mut verdict = meet(meet(cedar, autonomy_verdict(class, level)), taint);

        // A grant lifts Escalate only. It is never consulted for Deny.
        if let (Verdict::Escalate(_, to), Some(grant)) = (&verdict, &req.approval)
            && grant_lifts(&grant.request_digest, grant.approver, &digest, *to)
        {
            verdict = Verdict::Allow { notify: true };
            record.approved = true;
        }
        match verdict {
            Verdict::Deny(rule) => Decision::Deny { rule, record },
            Verdict::Escalate(reason, to) => Decision::Escalate { reason, to, record },
            Verdict::Allow { notify } => Decision::Allow { notify, record },
        }
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
        let tainted = uncleared_tainted(&req.params);
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

    /// The id of the loaded bundle.
    pub fn bundle_id(&self) -> &BundleId {
        &self.bundle_id
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
