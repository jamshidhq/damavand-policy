# damavand-policy: design

2026-11-01. Crate 2 of 8, Apache-2.0. Section 9 records the decisions on the
open questions; section 10 records where v0.1 differs from sections 0-8.

## 0. Decided by owner

- Engine: Cedar, through the `cedar-policy` crate.
- Precedence: global deny > project deny > project allow > global allow > ask.
- Escalation chain: worker → child → main → user.
- A classifier is never the sole path to allow.
- Deny by default, policies in git, every decision audited with a rule id.
- Autonomy L0-L3 plus Never, per loop and action class. Tainted parameters need approval unless they match a manifest enum or pattern.
- MSRV target 1.85 (superseded: 1.89, see section 9, decision 1).

Below: **proposed** by this doc.

Verified 2026-11-01: `cedar-policy` 4.14.0, Apache-2.0, MSRV **1.89**; last 1.85 release 4.7.1. API used: `Authorizer::is_authorized`, `diagnostics().reason()` and `.errors()`, `PolicySet::annotation()`, strict `Validator`. String matching: `like` with `*` only.

## 1. Cedar schema

One namespace `Damavand` serves both products. Product extensions use their own namespace.

| Kind | Types |
|---|---|
| Principal | `Worker in [Orchestrator, Loop]`, `Orchestrator in [Orchestrator, Project]` (attr `depth`: main/child), `Loop in [Project]`, `User` |
| Resource | `Project`, `Repo in Project`, `Path in Repo`, `Host`, `K8sObject in K8sNamespace in Cluster`, `SecretRef in Project`, `Tool`, `NamedCommand in Repo` |
| Action groups (= action classes) | `class:read`, `class:draft`, `class:write.worktree`, `class:write.remote`, `class:egress`, `class:k8s.mutate`, `class:secret.use`, `class:never` |
| Actions | Fixed verbs, each in exactly one class: `j_read`, `j_edit`, `run_command`, `git_push`, `http_request`, `k8s_apply`, `terraform_apply`, … MCP tools: `mcp_call` on a `Tool`, class from the manifest. |
| Context | `autonomy: Long` (0-3, effective), `action_class: String`, `taint_unvalidated: Bool`, `tainted_params: Set<String>`, `budget: {tokens_left: Long, actions_left: Long}`, `run_id: String` |

Bundle = git dir (`schema.cedarschema`, `global/`, `projects/<id>/`, `autonomy.toml`); id = commit sha. The loader validates strictly and refuses policies without `@id` or project policies not scoped `in Project::"<id>"`.

## 2. Precedence and "ask"

Every pairwise tier conflict is allow against deny, and deny always wins. So the tiers reduce to Cedar's forbid-beats-permit plus a fallback:

| Cedar result | Outcome |
|---|---|
| Deny, a hard `forbid` determined it | `Deny{rule}` |
| Deny, only `@outcome("ask")` forbids determined it | `Escalate{PolicyAsk}` |
| Deny, no determining policy (no permit matched) | `Escalate{NoMatch}`: tier 5 "ask" |
| Allow | candidate Allow, goes to the gates in section 3-4 |
| Any entry in `errors()` | `Deny{rule: "damavand.eval_error"}` |

Cedar skips a policy that errors, so without the last row a broken forbid fails open.

Tiers only pick the reported rule id: strongest tier, then lexical `@id`. Side effect of ask rules: a global ask beats a project allow.

## 3. Autonomy and Never

- Caps live in git (`autonomy.toml`), per (loop or project, action class).
- The caller sends an optional override; the policy part stays stateless. Effective level = min(cap, override), so the UI can lower but never raise.
- Autonomy only downgrades a candidate Allow: L0 allows `class:read` only, else Deny. L1 adds `class:draft`, else Deny. L2 gives `Escalate{AutonomyRequiresApproval, to: User}`. L3 gives `Allow{notify: true}`.
- Never: a global forbid on `class:never`, plus a Rust Deny gate that no bundle can remove.

## 4. Taint

- Policy consumes taint. It does not propagate taint.
- The producer (core router, quarantine reader, tools part) sets taint. A parameter a model proposes after it read untrusted text is tainted.
- Data: `Param {name, value, taint: Clean | Untrusted{sources}, constraint: Option<Enum(Vec) | Pattern(..)>}`.
- Rust checks the constraint before Cedar (`like` cannot). A match clears that parameter only.
- A gate after Cedar: any uncleared tainted parameter turns Allow into `Escalate{TaintedParam, to: User}`. Policy content cannot change this.
- Approval: `Grant{request_digest, approver}` on the re-sent request. The digest covers principal, action, resource and all parameters. A matching grant turns Escalate into Allow, never Deny.
- A classifier has no input to `decide()` in v0.1, so it cannot allow.

## 5. Public API sketch

```rust
pub struct Engine { /* private: cedar PolicySet, Schema, caps */ }
impl Engine {
    pub fn load(bundle: &Bundle) -> Result<Engine, LoadError>;
    pub fn decide(&self, req: &DecisionRequest) -> Decision; // infallible, fail-closed
    pub fn bundle_id(&self) -> &BundleId;
}
#[non_exhaustive] pub struct DecisionRequest { principal, action: ActionRef,
    resource: ResourceRef, params: Vec<Param>, autonomy_override: Option<Autonomy>,
    budget: Budget, run_id: RunId, approval: Option<Grant> }
#[non_exhaustive] pub enum Decision {
    Allow    { notify: bool, record: DecisionRecord },
    Deny     { rule: RuleId, record: DecisionRecord },
    Escalate { reason: EscalateReason, to: Approver, record: DecisionRecord } }
#[non_exhaustive] pub enum EscalateReason { NoMatch, PolicyAsk(RuleId),
    AutonomyRequiresApproval, TaintedParam(String) }
#[non_exhaustive] pub enum Approver { Child, Main, User }
#[non_exhaustive] pub enum Autonomy { L0Observe, L1Draft, L2ActWithApproval, L3ActAndNotify }
```

- No Cedar type is public, so a Cedar upgrade is not a breaking change.
- Outcome = meet(Cedar, autonomy, taint); Deny < Escalate < Allow+notify < Allow.
- `to` for NoMatch is the next level above the principal. For L2 and taint, `to` is User.

## 6. Wire (damavand-proto)

- Capability `policy`, params `{"bundle": "<sha>"}`. Method names use `policy/<verb>`, in MCP style.
- `policy/decide`: all three outcomes are successful results `{outcome, rule?, reason?, to?, decisionId}`.
- `policy/autonomyCaps` (git caps, for the UI) and `policy/bundleInfo` (sha, schema version).
- An enforcer treats any error or timeout as Deny.

| Code | Name |
|---|---|
| 1000 | `BUNDLE_INVALID` |
| 1001 | `REQUEST_SCHEMA_MISMATCH` |
| 1002 | `UNKNOWN_ACTION` |
| 1003 | `UNKNOWN_ENTITY` |
| 1004 | `BUNDLE_PIN_MISMATCH` |
| 1005 | `GRANT_INVALID` |

## 7. Test plan

- Conformance: YAML cases (bundle + request → outcome + rule id), feature `conformance`, runnable over the wire.
- Properties (proptest): matching hard forbid → never Allow; uncleared taint → never Allow, any level, any bundle; `class:never` → always Deny; lower autonomy → never a higher outcome; empty bundle → only Escalate; policy order does not change results; `decide` never panics.
- Golden fixtures: `jamshid-default` and `devops-l0` bundles with golden decisions; invalid bundles with exact `LoadError`s.
- Mutation targets (`cargo-mutants`): meet, tier order, constraint matching, autonomy min, error-to-Deny, grant digest.

## 8. Dependencies and scope

- Depends on: `damavand-proto` (not in v0.1, see section 10), `cedar-policy` (default features, no `experimental`), `serde`, `serde_json`, `regex`.
- Manifest and audit come later. v0.1 keeps local types: `ParamConstraint`, the action-to-class map, `DecisionRecord` (UUIDv7, sha, rule ids, outcome).
- v0.1: schema v1, loader, `decide`, the three gates, grants, `policy/decide|autonomyCaps|bundleInfo`, conformance suite. Two consumers: the jamshid test harness and the DevOps L0 loop.
- Later: hot reload, `policy/explain`, signed bundles, budget accounting, a deny-only classifier hint, manifest and audit types.

## 9. Decisions

The owner accepted every recommendation of the former open questions.

1. **MSRV.** The family MSRV is 1.89. This crate uses the latest
   `cedar-policy` 4.x, pinned exactly (4.14.0 at first release).
2. **Who approves.** L2 actions and tainted parameters escalate straight to
   the user. Only NoMatch with clean parameters goes up the chain
   worker → child → main.
3. **Pattern syntax.** Anchored regex (`regex` crate, RE2 semantics), with
   size limits through `RegexBuilder`. No globs.
4. **What is untrusted.** Everything not from the user or the policy
   bundle, repo files and tool output included.
5. **Ask rules.** `@outcome("ask")` forbids are allowed in v0.1. A global ask
   beats a project allow.
6. **Policy and audit.** The audit crate owns the event schema later. v0.1
   keeps its own `DecisionRecord`.

## 10. Implementation notes (v0.1)

Where the code makes a choice that sections 0-8 leave open or state in two
ways:

- **Meet applies the autonomy ceiling to every outcome.** Section 3 says
  autonomy only downgrades a candidate Allow; section 5 says the outcome is
  meet(Cedar, autonomy, taint). The code follows section 5: an L0 write that
  matches no permit is Deny, not Escalate, so no grant can lift it past the
  cap.
- **A granted Allow notifies.** An escalation lifted by a grant becomes
  `Allow { notify: true }`. With `notify: false`, L2 plus a grant would be
  stronger than L3, and lower autonomy would yield a stronger outcome.
- **"Empty bundle gives only Escalate"** (section 7) holds only where the
  autonomy cap allows the class; the tested property is "never Allow".
- **Never** is a Rust gate on the class `class:never` and on a built-in list
  (`NEVER_ACTIONS`). The loader refuses a bundle that puts a built-in Never
  action in another class, so a bundle cannot reclassify it away.
- **Grants** lift an escalation only when the grant's approver ranks at least
  as high as the escalation's `to` (child < main < user).
- **NoMatch target.** A worker escalates by the `depth` of its orchestrator
  parent (`child` → Child, `main` → Main); a child orchestrator to Main;
  anything else, or unknown structure, to the user.
- **Caps.** The cap is the lowest entry over every project and loop the
  principal is in; no entry is L0. `autonomy.toml` has no `never` key.
- **Policy ids.** `@id` is required, unique across the bundle, and the
  `damavand.` prefix is reserved for built-in rules. Project policies are
  scoped with `resource in`, `resource ==` or `resource is … in`
  `Project::"<id>"`.
- **Context.** `tainted_params` lists only uncleared tainted parameters.
- **MCP tools.** `mcp_call` with a class from the manifest is not in v0.1; it
  waits for the manifest crate.
- **damavand-proto.** Not a dependency in v0.1 (it is unpublished). The wire
  method names, `decision_result` and the error codes 1000-1005 are defined
  locally in `wire`; moving them onto damavand-proto is a follow-up.
- **Conformance cases** use the wire JSON shape, so they run in process or
  against a server; the golden YAML files go through `serde_json::Value`.
