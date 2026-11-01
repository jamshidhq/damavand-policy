# damavand-policy

The deterministic policy gateway for the damavand agent-safety crates.
Models propose actions; this crate decides them, with
[Cedar](https://www.cedarpolicy.com/) (`cedar-policy` crate) plus three gates
in Rust. A classifier has no input, so it can never allow.

[docs/design.md](docs/design.md) is the design, with the decisions taken.

## Stability

- **Rust API:** can change in any release before 1.0. No Cedar type is in the
  public API, so a Cedar upgrade is not a breaking change.
- `serde_json` is a public dependency (entity attributes, wire results).
- MSRV: Rust 1.89 (the `cedar-policy` 4.x MSRV).

## How a decision is made

```rust
use damavand_policy::{Bundle, DecisionRequest, Engine, EntityRef};

let bundle = Bundle::from_dir("policy".as_ref(), "<commit sha>")?;
let engine = Engine::load(&bundle)?; // strict validation; refuses bad bundles
let req = DecisionRequest::new(
    EntityRef::new("Worker", "w1"),
    "j_edit",
    EntityRef::new("Path", "jamshid/src/lib.rs"),
    now_unix_seconds, // the core's clock; required
);
let decision = engine.decide(&req); // infallible, fails closed
```

`decide` returns `Allow { notify }`, `Deny { rule }` or
`Escalate { reasons, to }`, each with a `DecisionRecord` (UUIDv7, bundle id,
rule ids, request digest, grant nonce). The outcome is the meet, weakest wins
(Deny < Escalate < Allow with notify < Allow), of:

| Part | Rule |
| --- | --- |
| Cedar | Forbid beats permit. No permit → `Escalate(NoMatch)` up worker → child → main → user. Only `@outcome("ask")` forbids → `Escalate(PolicyAsk)` to the user, one reason per ask rule. Any evaluation error → `Deny(damavand.eval_error)`. |
| Autonomy | Effective level = min(git cap, caller override). L0: read only. L1: plus draft. L2: escalate to the user. L3: allow and notify. |
| Taint | `taint` is required on every parameter. An untrusted parameter that the bundle's enum or anchored regex for (action, parameter) does not clear → `Escalate(TaintedParam)` to the user. A request cannot carry a constraint. |

Escalations list every reason, most severe first (TaintedParam > PolicyAsk >
AutonomyRequiresApproval > NoMatch). Never actions (`class:never`, and the
built-in `NEVER_ACTIONS`) are denied before Cedar runs and by a global
forbid the loader injects.

## Trust boundary and grants

The core builds every request: the entity graph (orchestrator depth, loop
and project membership) comes from its state machine, never from agent
input. The engine refuses topology it cannot have built
(`damavand.topology`), but it cannot see an edge the core left out.

A `Grant` is an Ed25519 signature by the core's approval broker over
`grant_signing_bytes`: bundle id, run id, request digest, entities digest,
all escalation reasons, approver, `expiresAt` and a nonce. The bundle holds
only the broker's public keys (`approval.toml`). A grant lifts Escalate to
`Allow { notify: true }`, never Deny, when the signature verifies, the
approver ranks high enough, the request's `now` is before `expiresAt`, and
`expiresAt` is at most `max_grant_ttl` (default 3600 s) past `now`. Every
request carries a non-empty `runId`; an empty one is
`Deny(damavand.request_invalid)`.

**Contract for the core:** the engine is stateless. When a grant lifts an
escalation, the Allow carries the nonce (`record.grant_nonce`, wire
`grantNonce`). Consume it atomically (insert-if-absent) before acting; a
nonce already consumed is Deny.

## Bundle layout

A bundle is a git directory. Its id is SHA-256 over its content
(`Engine::bundle_id`); the commit sha is a label.

| Path | Contents |
| --- | --- |
| `schema.cedarschema` | Namespace `Damavand`. Every action is in exactly one `class:<name>` group. |
| `global/*.cedar` | Global policies. Every policy has a unique `@id`. |
| `projects/<id>/*.cedar` | Project policies, each scoped `resource in Damavand::Project::"<id>"`. |
| `autonomy.toml` | Caps, `[project.<id>]` / `[loop.<id>]`, class = 0-3. |
| `constraints.toml` | `[<action>.<param>]` with one `enum = [...]` or one `pattern = "..."` (anchored; refused if it can match the empty string, a character in Unicode category `Cc`, `Cf`, `Zl` or `Zp`, or a shell metacharacter; `\w` is refused, spell out `[a-z0-9_]`). An empty tainted value is never cleared. |
| `approval.toml` | `broker_keys = ["<hex Ed25519 public key>"]`, optional `max_grant_ttl = <seconds>` (default 3600). No key, no grant. |

Golden bundles: [tests/bundles](tests/bundles) (`jamshid-default`,
`devops-l0`), each with its expected decisions in `cases.yaml`.

## Wire (damavand-proto)

Capability `policy`; methods `policy/decide`, `policy/autonomyCaps`,
`policy/bundleInfo`; error codes 1000-1005 (`wire::codes`). An enforcer treats
any error or timeout as Deny. Until this crate depends on damavand-proto, the
names live in the `wire` module.

## Conformance suite

```toml
[dev-dependencies]
damavand-policy = { version = "0.1", features = ["conformance"] }
```

`conformance::Suite` reads cases (request → expected `policy/decide` fields)
from any serde format; `Expect::check` compares a wire result, so the cases
run in process (`conformance::run`) or against a server.

## Not yet in the crate

- Hot reload, `policy/explain`, signed bundles, budget accounting.
- Nonce storage: the core owns single use of grant nonces.
- `mcp_call` with a class from the module manifest.
- The audit event schema (the audit crate will own it).

## License

Apache-2.0. See [LICENSE](LICENSE).
