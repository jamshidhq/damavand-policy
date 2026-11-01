//! Request and decision types. None of them exposes a Cedar type.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The id of a policy bundle: the git commit sha it was loaded from.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BundleId(pub String);

impl fmt::Display for BundleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The id of the rule that determined a decision: a policy's `@id`, or a
/// built-in `damavand.*` rule.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RuleId(pub String);

impl RuleId {
    /// Built-in rule: a Cedar evaluation error made the decision fail closed.
    pub const EVAL_ERROR: &'static str = "damavand.eval_error";
    /// Built-in rule: the action is in the Never class.
    pub const NEVER: &'static str = "damavand.never";
    /// Built-in rule: the effective autonomy level does not allow the action.
    pub const AUTONOMY: &'static str = "damavand.autonomy";
    /// Built-in rule: the action is not in the bundle schema.
    pub const UNKNOWN_ACTION: &'static str = "damavand.unknown_action";
    /// Built-in rule: the request does not match the bundle schema.
    pub const REQUEST_INVALID: &'static str = "damavand.request_invalid";

    /// The rule id as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A reference to an entity: a type name and an id.
///
/// A type name without `::` is in the `Damavand` namespace. A type name with
/// `::` (a product extension namespace) is used as given.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EntityRef {
    /// Entity type name, for example `Worker` or `Path`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Entity id.
    pub id: String,
}

impl EntityRef {
    /// Make an entity reference.
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            id: id.into(),
        }
    }
}

/// An entity in the request's entity graph: its parents and attributes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Entity {
    /// The entity.
    pub uid: EntityRef,
    /// Direct parents of the entity.
    #[serde(default)]
    pub parents: Vec<EntityRef>,
    /// Attributes, in Cedar's JSON entity format.
    #[serde(default)]
    pub attrs: serde_json::Map<String, serde_json::Value>,
}

impl Entity {
    /// Make an entity with no parents and no attributes.
    pub fn new(uid: EntityRef) -> Self {
        Self {
            uid,
            parents: Vec::new(),
            attrs: serde_json::Map::new(),
        }
    }

    /// Add a parent.
    pub fn parent(mut self, parent: EntityRef) -> Self {
        self.parents.push(parent);
        self
    }

    /// Set an attribute.
    pub fn attr(mut self, name: impl Into<String>, value: serde_json::Value) -> Self {
        self.attrs.insert(name.into(), value);
        self
    }
}

/// Where a parameter value came from.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum Taint {
    /// From the user or the policy bundle.
    #[default]
    Clean,
    /// From anything else: repo files, tool output, web content.
    Untrusted {
        /// Free-form labels of the untrusted sources.
        #[serde(default)]
        sources: Vec<String>,
    },
}

/// A manifest constraint that clears a tainted parameter when its value
/// matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum ParamConstraint {
    /// The value must equal one of these strings.
    Enum(Vec<String>),
    /// The whole value must match this regex (`regex` crate syntax). The
    /// engine anchors it; an invalid or oversized pattern clears nothing.
    Pattern(String),
}

/// One parameter of the proposed action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Param {
    /// Parameter name.
    pub name: String,
    /// Parameter value.
    pub value: String,
    /// Provenance of the value.
    #[serde(default)]
    pub taint: Taint,
    /// Manifest constraint, if the manifest declares one.
    #[serde(default)]
    pub constraint: Option<ParamConstraint>,
}

impl Param {
    /// A clean parameter.
    pub fn clean(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            taint: Taint::Clean,
            constraint: None,
        }
    }

    /// An untrusted parameter with the given source labels.
    pub fn untrusted(
        name: impl Into<String>,
        value: impl Into<String>,
        sources: Vec<String>,
    ) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            taint: Taint::Untrusted { sources },
            constraint: None,
        }
    }

    /// Set the manifest constraint.
    pub fn with_constraint(mut self, constraint: ParamConstraint) -> Self {
        self.constraint = Some(constraint);
        self
    }
}

/// Autonomy level. Ordered: `L0Observe` is the lowest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
#[non_exhaustive]
pub enum Autonomy {
    /// L0: read only.
    L0Observe,
    /// L1: read and draft.
    L1Draft,
    /// L2: act after approval by the user.
    L2ActWithApproval,
    /// L3: act and notify.
    L3ActAndNotify,
}

impl Autonomy {
    /// The level as a number, 0 to 3.
    pub fn level(self) -> u8 {
        match self {
            Autonomy::L0Observe => 0,
            Autonomy::L1Draft => 1,
            Autonomy::L2ActWithApproval => 2,
            Autonomy::L3ActAndNotify => 3,
        }
    }

    /// The level for a number, 0 to 3.
    pub fn from_level(level: u8) -> Option<Self> {
        match level {
            0 => Some(Autonomy::L0Observe),
            1 => Some(Autonomy::L1Draft),
            2 => Some(Autonomy::L2ActWithApproval),
            3 => Some(Autonomy::L3ActAndNotify),
            _ => None,
        }
    }
}

impl TryFrom<u8> for Autonomy {
    type Error = String;
    fn try_from(level: u8) -> Result<Self, String> {
        Autonomy::from_level(level).ok_or_else(|| format!("autonomy level {level} is not 0-3"))
    }
}

impl From<Autonomy> for u8 {
    fn from(a: Autonomy) -> u8 {
        a.level()
    }
}

/// Action class. Each action in the schema is in exactly one class group
/// (`class:<name>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ActionClass {
    /// `class:read`
    #[serde(rename = "read")]
    Read,
    /// `class:draft`
    #[serde(rename = "draft")]
    Draft,
    /// `class:write.worktree`
    #[serde(rename = "write.worktree")]
    WriteWorktree,
    /// `class:write.remote`
    #[serde(rename = "write.remote")]
    WriteRemote,
    /// `class:egress`
    #[serde(rename = "egress")]
    Egress,
    /// `class:k8s.mutate`
    #[serde(rename = "k8s.mutate")]
    K8sMutate,
    /// `class:secret.use`
    #[serde(rename = "secret.use")]
    SecretUse,
    /// `class:never`
    #[serde(rename = "never")]
    Never,
}

impl ActionClass {
    /// Every class.
    pub const ALL: [ActionClass; 8] = [
        ActionClass::Read,
        ActionClass::Draft,
        ActionClass::WriteWorktree,
        ActionClass::WriteRemote,
        ActionClass::Egress,
        ActionClass::K8sMutate,
        ActionClass::SecretUse,
        ActionClass::Never,
    ];

    /// The class name without the `class:` prefix.
    pub fn name(self) -> &'static str {
        match self {
            ActionClass::Read => "read",
            ActionClass::Draft => "draft",
            ActionClass::WriteWorktree => "write.worktree",
            ActionClass::WriteRemote => "write.remote",
            ActionClass::Egress => "egress",
            ActionClass::K8sMutate => "k8s.mutate",
            ActionClass::SecretUse => "secret.use",
            ActionClass::Never => "never",
        }
    }

    /// The class for a name without the `class:` prefix.
    pub fn from_name(name: &str) -> Option<Self> {
        ActionClass::ALL.into_iter().find(|c| c.name() == name)
    }
}

/// Remaining budget, passed to policies as context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Budget {
    /// Tokens left in the run.
    pub tokens_left: i64,
    /// Actions left in the run.
    pub actions_left: i64,
}

impl Budget {
    /// Make a budget.
    pub fn new(tokens_left: i64, actions_left: i64) -> Self {
        Self {
            tokens_left,
            actions_left,
        }
    }
}

/// Who an escalation goes to. Ordered: `Child` is the lowest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum Approver {
    /// A child orchestrator.
    Child,
    /// The main orchestrator.
    Main,
    /// The human user.
    User,
}

/// SHA-256 digest of a request's principal, action, resource and parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestDigest(pub [u8; 32]);

impl fmt::Display for RequestDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl std::str::FromStr for RequestDigest {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("a request digest is 64 hex characters".into());
        }
        let mut out = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hex = std::str::from_utf8(chunk).map_err(|e| e.to_string())?;
            out[i] = u8::from_str_radix(hex, 16).map_err(|e| e.to_string())?;
        }
        Ok(RequestDigest(out))
    }
}

impl Serialize for RequestDigest {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for RequestDigest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// An approval, re-sent with the request it approves.
///
/// The caller authenticates the approver; the engine checks only the digest
/// and that the approver is high enough for the escalation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Grant {
    /// Digest of the approved request.
    pub request_digest: RequestDigest,
    /// Who approved.
    pub approver: Approver,
}

impl Grant {
    /// Make a grant.
    pub fn new(request_digest: RequestDigest, approver: Approver) -> Self {
        Self {
            request_digest,
            approver,
        }
    }
}

/// A request for a decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct DecisionRequest {
    /// Who acts.
    pub principal: EntityRef,
    /// The action verb, for example `j_read` (an action id in the schema).
    pub action: String,
    /// What the action acts on.
    pub resource: EntityRef,
    /// The entity graph of principal and resource (parents and attributes).
    #[serde(default)]
    pub entities: Vec<Entity>,
    /// Parameters of the action.
    #[serde(default)]
    pub params: Vec<Param>,
    /// Lower the autonomy level for this request. It never raises it.
    #[serde(default)]
    pub autonomy_override: Option<Autonomy>,
    /// Remaining budget.
    #[serde(default)]
    pub budget: Budget,
    /// Run id, passed to policies as context.
    #[serde(default)]
    pub run_id: String,
    /// An approval for this request.
    #[serde(default)]
    pub approval: Option<Grant>,
}

impl DecisionRequest {
    /// Make a request with no entities, parameters, override or approval.
    pub fn new(principal: EntityRef, action: impl Into<String>, resource: EntityRef) -> Self {
        Self {
            principal,
            action: action.into(),
            resource,
            entities: Vec::new(),
            params: Vec::new(),
            autonomy_override: None,
            budget: Budget::default(),
            run_id: String::new(),
            approval: None,
        }
    }

    /// Add an entity to the entity graph.
    pub fn entity(mut self, entity: Entity) -> Self {
        self.entities.push(entity);
        self
    }

    /// Add a parameter.
    pub fn param(mut self, param: Param) -> Self {
        self.params.push(param);
        self
    }

    /// Set the autonomy override.
    pub fn autonomy_override(mut self, level: Autonomy) -> Self {
        self.autonomy_override = Some(level);
        self
    }

    /// Set the budget.
    pub fn budget(mut self, budget: Budget) -> Self {
        self.budget = budget;
        self
    }

    /// Set the run id.
    pub fn run_id(mut self, run_id: impl Into<String>) -> Self {
        self.run_id = run_id.into();
        self
    }

    /// Attach an approval.
    pub fn approval(mut self, grant: Grant) -> Self {
        self.approval = Some(grant);
        self
    }

    /// The digest an approval of this request must carry. It covers the
    /// principal, action, resource and every parameter name and value, in
    /// order.
    pub fn digest(&self) -> RequestDigest {
        crate::gates::request_digest(self)
    }
}

/// Why a request escalates.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EscalateReason {
    /// No permit matched (precedence tier 5, "ask").
    NoMatch,
    /// Only `@outcome("ask")` forbids determined the result.
    PolicyAsk(RuleId),
    /// Autonomy L2: the action needs approval.
    AutonomyRequiresApproval,
    /// This tainted parameter matched no manifest constraint.
    TaintedParam(String),
}

/// Audit data for one decision.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DecisionRecord {
    /// UUIDv7 of this decision.
    pub decision_id: String,
    /// Bundle that made the decision.
    pub bundle_id: BundleId,
    /// Rules that determined the Cedar result (permits on allow, forbids on
    /// deny), sorted; built-in rules when the engine decided alone.
    pub rule_ids: Vec<RuleId>,
    /// Digest of the request.
    pub request_digest: RequestDigest,
    /// True when an approval lifted an escalation to Allow.
    pub approved: bool,
}

/// The decision for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Decision {
    /// The action may run.
    Allow {
        /// Tell the user after the action runs.
        notify: bool,
        /// Audit data.
        record: DecisionRecord,
    },
    /// The action must not run.
    Deny {
        /// The rule that denied.
        rule: RuleId,
        /// Audit data.
        record: DecisionRecord,
    },
    /// The action needs an approval first.
    Escalate {
        /// Why.
        reason: EscalateReason,
        /// Who must approve.
        to: Approver,
        /// Audit data.
        record: DecisionRecord,
    },
}

/// The strength of a decision. Ordered: `Deny` is the weakest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Outcome {
    /// Deny.
    Deny,
    /// Escalate.
    Escalate,
    /// Allow with notify.
    AllowNotify,
    /// Allow.
    Allow,
}

impl Decision {
    /// The strength of this decision.
    pub fn outcome(&self) -> Outcome {
        match self {
            Decision::Deny { .. } => Outcome::Deny,
            Decision::Escalate { .. } => Outcome::Escalate,
            Decision::Allow { notify: true, .. } => Outcome::AllowNotify,
            Decision::Allow { notify: false, .. } => Outcome::Allow,
        }
    }

    /// True for any Allow.
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow { .. })
    }

    /// The audit record.
    pub fn record(&self) -> &DecisionRecord {
        match self {
            Decision::Allow { record, .. }
            | Decision::Deny { record, .. }
            | Decision::Escalate { record, .. } => record,
        }
    }
}
