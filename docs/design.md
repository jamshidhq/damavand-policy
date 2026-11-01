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

### Trust boundary

The engine is a pure function of the bundle and one request. It trusts the
bundle (git, reviewed) and the **core** that builds the request. It trusts
nothing an agent wrote.

| Input | Who sets it | What the engine checks |
|---|---|---|
| Principal, entity graph (orchestrator `depth`, Loop and Project membership) | The core, from its own state machine. Never from agent input. | Schema validation; every `Orchestrator` has `depth` `main` or `child`; a `Worker` principal is in an orchestrator or a loop. Anything else is `Deny(damavand.topology)`. |
| Parameter values | The agent proposes them. | Nothing; they are data. |
| Parameter `taint` | The producer (core router, quarantine reader, tools part). | Required on the wire; no default. Anything but `clean` is tainted. |
| Constraints that clear taint | The bundle (`constraints.toml`). | Compiled at load; a request cannot carry one (unknown field). |
| Grants | The approval broker in the core, signing with Ed25519. | Signature by a broker key from the bundle, over every bound field; expiry against `now`. |
| `now` | The core's clock. | Required; the engine has no clock. |

Limits the engine cannot close and the core owns:

- An omitted edge is invisible. A worker that sits in a loop and under an
  orchestrator, sent without its Loop parent, gets the project cap. Only the
  core can know the worker is in a loop.
- Grant nonces are single-use only if the core consumes them (section 4).

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

Bundle = git dir (`schema.cedarschema`, `global/`, `projects/<id>/`, `autonomy.toml`, `constraints.toml`, `approval.toml`). Bundle id = SHA-256 over the canonical content (length-prefixed, domain-separated; files sorted by name, projects by id; broker keys included), computed by `Engine::load`; the max grant TTL is in it too. The commit sha is kept as a human label. The loader validates strictly and refuses policies without `@id` or project policies not scoped `in Project::"<id>"`. Action ids match `[a-z][a-z0-9_.]*`.

## 2. Precedence and "ask"

Every pairwise tier conflict is allow against deny, and deny always wins. So the tiers reduce to Cedar's forbid-beats-permit plus a fallback:

| Cedar result | Outcome |
|---|---|
| Deny, a hard `forbid` determined it | `Deny{rule}` |
| Deny, only `@outcome("ask")` forbids determined it | `Escalate{PolicyAsk}`, one reason per determining ask rule, sorted by `@id` |
| Deny, no determining policy (no permit matched) | `Escalate{NoMatch}`: tier 5 "ask" |
| Allow | candidate Allow, goes to the gates in section 3-4 |
| Any entry in `errors()` | `Deny{rule: "damavand.eval_error"}` |

Cedar skips a policy that errors, so without the last row a broken forbid fails open.

Tiers only pick the reported rule id: strongest tier, then lexical `@id`. Side effect of ask rules: a global ask beats a project allow.

## 3. Autonomy and Never

- Caps live in git (`autonomy.toml`), per (loop or project, action class).
- The caller sends an optional override; the policy part stays stateless. Effective level = min(cap, override), so the UI can lower but never raise.
- Autonomy only downgrades a candidate Allow: L0 allows `class:read` only, else Deny. L1 adds `class:draft`, else Deny. L2 gives `Escalate{AutonomyRequiresApproval, to: User}`. L3 gives `Allow{notify: true}`.
- Never: a global forbid on `class:never` that the loader injects (`@id damavand.never`), plus a Rust Deny gate that no bundle can remove. The loader refuses a permit whose action scope names a Never action or `class:never`. Built-in Never verbs (`NEVER_ACTIONS`: apply, destroy and import for terraform and tofu) cannot leave `class:never`; any other verb is Never by class.

## 4. Taint

- Policy consumes taint. It does not propagate taint.
- The producer (core router, quarantine reader, tools part) sets taint. A parameter a model proposes after it read untrusted text is tainted.
- Data: `Param {name, value, taint: Clean | Untrusted{sources}}`. `taint` is required; a request with any unknown field (such as `constraint`) is refused.
- Constraints live in the bundle, `constraints.toml`, keyed by (action, parameter): one non-empty `enum` or one `pattern`. A parameter with no bundle constraint stays tainted.
- Patterns are compiled at load: `regex` syntax, at most 1024 bytes, size and nest limits, compiled alone first (so `x)|(.*` fails), then anchored `\A(?:…)\z`. A pattern that can match a forbidden character is refused (`PatternTooBroad`): every character in Unicode general category `Cc` (C0/C1 controls, newline, DEL), `Cf` (bidi controls, zero-width space and joiners, U+061C, U+FEFF, tag characters), `Zl` and `Zp` (line and paragraph separators), taken from the `regex-syntax` Unicode tables, and `` $ ` ; | & < > \ " ' ``. The check walks the parsed pattern and collects every character a literal or class can produce, so it over-approximates: `.*`, `(?s).*`, `.+`, `[\s\S]*`, `.*x`, `[^a]*` and `\w+` (it admits U+200C and U+200D) are refused; `[a-z0-9/._-]+` and `[a-z0-9_]+` load. Bundle authors write explicit ranges. A pattern that matches the empty string is refused (`PatternMatchesEmpty`), and an empty tainted value is never cleared, by an enum either. It does not judge breadth over safe characters: `[a-z ]+` loads and clears plain English. The bundle author owns that choice.
- Rust checks the constraint before Cedar (`like` cannot). A match clears that parameter only.
- A gate after Cedar: any uncleared tainted parameter turns Allow into `Escalate{TaintedParam, to: User}`. Policy content cannot change this.
- A classifier has no input to `decide()` in v0.1, so it cannot allow.

### Grant protocol

1. `decide` returns `Escalate{reasons, to}`. `reasons` lists every reason, most severe first: TaintedParam > PolicyAsk > AutonomyRequiresApproval > NoMatch.
2. The core shows the approver the request and all reasons. On approval, the **approval broker** in the core signs `grant_signing_bytes(bundle_id, request, reasons, approver, expires_at, nonce)` with its Ed25519 key. The bytes are canonical and length-prefixed (no maps, no floats): domain tag, bundle id, run id, request digest (principal, action, resource, every parameter's name, value and taint), entities digest (sorted entities, parents and attribute keys; a float attribute has no digest, so no grant), every reason with its rule id or parameter name, approver, `expires_at`, nonce.
3. The core re-sends the request with `approval: {approver, expiresAt, nonce, signature}`.
4. The engine recomputes the bytes from **its own** bundle id, the request and its own reasons, and lifts Escalate to `Allow{notify: true}` only when one bundle broker key verifies the signature (`verify_strict`), the approver ranks at least `to`, and `now < expiresAt <= now + max_grant_ttl` (`approval.toml`, default 3600 seconds; a longer grant does not lift). A grant never lifts Deny. A bundle with no broker key accepts no grant.
5. The Allow carries the nonce (`DecisionRecord::grant_nonce`, wire `grantNonce`). **The engine is stateless and cannot see a replay.** The core must consume the nonce atomically (insert-if-absent in its store) before it acts, and treat a nonce it has seen as Deny.

The engine holds only public keys (`approval.toml`, in the bundle and so in the bundle id). `DecisionRequest::digest()` stays public: knowing it does not let anyone sign.

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
    budget: Budget, run_id: String /* required, non-empty */, now: u64,
    approval: Option<Grant> }
#[non_exhaustive] pub enum Decision {
    Allow    { notify: bool, record: DecisionRecord },
    Deny     { rule: RuleId, record: DecisionRecord },
    Escalate { reasons: Vec<EscalateReason>, to: Approver, record: DecisionRecord } }
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
- `policy/decide`: all three outcomes are successful results `{outcome, notify?, grantNonce?, rule?, reason?, param?, reasons?, to?, decisionId}`. On Escalate, `reason` is the most severe reason and `reasons` lists all.
- `policy/autonomyCaps` (git caps, for the UI) and `policy/bundleInfo` (bundle id, label, schema version).
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
- Properties also cover: a missing `taint` never parses; forged, expired or tampered grants never lift and a valid one exposes its nonce on replay; a caller-chosen `depth`; an omitted Loop parent of a loop-only worker; a loaded pattern never clears a forbidden character.
- Mutation targets (`cargo-mutants`): meet, tier order, constraint matching, autonomy min, error-to-Deny, grant signing bytes and verification, bundle digest, topology.

## 8. Dependencies and scope

- Depends on: `damavand-proto` (not in v0.1, see section 10), `cedar-policy` (default features, no `experimental`), `serde`, `serde_json`, `regex`.
- Manifest and audit come later. v0.1 keeps local types: bundle constraints (`constraints.toml`), the action-to-class map, `DecisionRecord` (UUIDv7, bundle id, rule ids, grant nonce).
- v0.1: schema v1, loader, `decide`, the three gates, grants, `policy/decide|autonomyCaps|bundleInfo`, conformance suite. Two consumers: the jamshid test harness and the DevOps L0 loop.
- Later: hot reload, `policy/explain`, signed bundles, budget accounting, a deny-only classifier hint, manifest and audit types.

## 9. Decisions

The owner accepted every recommendation of the former open questions.

1. **MSRV.** The family MSRV is 1.89. This crate uses the latest
   `cedar-policy` 4.x at `~4.14.0` (patch updates only); `Cargo.lock` is
   committed.
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
  (`NEVER_ACTIONS`), plus a loader-injected global forbid. The loader refuses
  a bundle that puts a built-in Never action in another class, and a permit
  that names a Never action or `class:never`. An unscoped permit
  (`action` alone) still loads; the injected forbid beats it.
- **Grants** are Ed25519-signed by the core's approval broker (section 4,
  grant protocol). Section 4 first said `Grant{request_digest, approver}`;
  anyone who could hash a request could mint that, so v0.1 signs. A grant
  lifts an escalation only when its approver ranks at least as high as the
  escalation's `to` (child < main < user).
- **Tied escalations** keep every reason, most severe first, and go to the
  highest approver. Section 5 had one `reason`; one reason hid taint behind
  an autonomy escalation.
- **Constraints** live in the bundle, not the request (section 4 put them on
  `Param`). A caller-supplied constraint let the caller clear its own taint.
- **Bundle id** is a content digest, not the commit sha (section 1); the sha
  is the label.
- **Topology.** The engine refuses an orchestrator `depth` other than `main`
  or `child`, and a worker principal in neither an orchestrator nor a loop
  (`damavand.topology`). Before, an unknown depth escalated to the user and a
  detached worker escalated by NoMatch.
- **NoMatch target.** A worker escalates by the `depth` of its orchestrator
  parent (`child` → Child, `main` → Main); a child orchestrator to Main;
  anything else to the user.
- **Caps.** The cap is the lowest entry over every project and loop the
  principal is in; no entry is L0. `autonomy.toml` has no `never` key.
- **Policy ids.** `@id` is required, unique across the bundle, and the
  `damavand.` prefix is reserved for built-in rules. Project policies are
  scoped with `resource in`, `resource ==` or `resource is … in`
  `Project::"<id>"`.
- **Context.** `tainted_params` lists only uncleared tainted parameters.
- **Dependencies.** `ed25519-dalek` 2.2.0 (BSD-3-Clause, MSRV 1.81), not
  3.0.0: 3.0.0 pulls `sha2`/`digest` 0.11 next to cedar's build-time
  `digest` 0.10, a duplicate `cargo deny` refuses. `regex-syntax` (already in
  the tree through `regex`) parses patterns for the breadth check.
- **Run id.** `runId` is required on the wire and must not be empty; an
  empty one is `Deny(damavand.request_invalid)`, checked after the Never and
  unknown-action gates. A grant signs the run id, and an empty one bound a
  grant to no run.
- **Ask reasons.** Every determining `@outcome("ask")` rule is its own
  `PolicyAsk` reason, sorted by `@id`, so the approver sees each rule and the
  grant signs each one. Before, only the lowest id was reported.
- **Pattern breadth.** The forbidden set is the Unicode categories `Cc`,
  `Cf`, `Zl` and `Zp` plus the shell metacharacters, built from the
  `regex-syntax` property tables rather than a hand list of ranges. `\w` is
  refused because it admits ZWJ and ZWNJ. Patterns that match the empty
  string are refused at load, and an empty tainted value never clears.
- **Grant TTL.** `approval.toml` may set `max_grant_ttl` (seconds, at least
  1; default 3600). A grant with `expiresAt - now` above it does not lift,
  so a broker bug that mints a far-future expiry is bounded. The value is in
  the bundle id (domain tag `bundle/v2`).
- **Not signed: `budget` and `autonomyOverride`.** Both come from the core,
  not the agent (section 0), and neither is in the grant bytes. The override
  only lowers the level: a lower level yields a weaker outcome or Deny, and a
  grant never lifts Deny. A change to either that alters the escalation's
  reasons or approver breaks the signature, because both are signed. What
  remains is a change that keeps the same reasons, for example a budget an
  ask rule reads that moved between the approval and the re-send. The
  approver approved exactly those reasons for this request, the nonce is
  single-use and the grant lives at most `max_grant_ttl`, so the gap is one
  re-send of an approved action under a budget the core itself reports.
- **MCP tools.** `mcp_call` with a class from the manifest is not in v0.1; it
  waits for the manifest crate.
- **damavand-proto.** Not a dependency in v0.1 (it is unpublished). The wire
  method names, `decision_result` and the error codes 1000-1005 are defined
  locally in `wire`; moving them onto damavand-proto is a follow-up.
- **Conformance cases** use the wire JSON shape, so they run in process or
  against a server; the golden YAML files go through `serde_json::Value`.
