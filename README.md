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
use damavand_policy::{Bundle, BundleId, DecisionRequest, Engine, EntityRef};

let bundle = Bundle::from_dir("policy".as_ref(), BundleId("<commit sha>".into()))?;
let engine = Engine::load(&bundle)?; // strict validation; refuses bad bundles
let req = DecisionRequest::new(
    EntityRef::new("Worker", "w1"),
    "j_edit",
    EntityRef::new("Path", "jamshid/src/lib.rs"),
);
let decision = engine.decide(&req); // infallible, fails closed
```

`decide` returns `Allow { notify }`, `Deny { rule }` or
`Escalate { reason, to }`, each with a `DecisionRecord` (UUIDv7, bundle id,
rule ids, request digest). The outcome is the meet, weakest wins
(Deny < Escalate < Allow with notify < Allow), of:

| Part | Rule |
| --- | --- |
| Cedar | Forbid beats permit. No permit → `Escalate(NoMatch)` up worker → child → main → user. Only `@outcome("ask")` forbids → `Escalate(PolicyAsk)` to the user. Any evaluation error → `Deny(damavand.eval_error)`. |
| Autonomy | Effective level = min(git cap, caller override). L0: read only. L1: plus draft. L2: escalate to the user. L3: allow and notify. |
| Taint | An untrusted parameter that its manifest enum or anchored regex does not clear → `Escalate(TaintedParam)` to the user. |

Never actions (`class:never`, and the built-in `NEVER_ACTIONS`) are denied
before Cedar runs. A `Grant` bound to the request digest lifts Escalate to
Allow, never Deny, and only when the approver ranks high enough.

## Bundle layout

A bundle is a git directory; its id is the commit sha.

| Path | Contents |
| --- | --- |
| `schema.cedarschema` | Namespace `Damavand`. Every action is in exactly one `class:<name>` group. |
| `global/*.cedar` | Global policies. Every policy has a unique `@id`. |
| `projects/<id>/*.cedar` | Project policies, each scoped `resource in Damavand::Project::"<id>"`. |
| `autonomy.toml` | Caps, `[project.<id>]` / `[loop.<id>]`, class = 0-3. |

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
- `mcp_call` with a class from the module manifest.
- The audit event schema (the audit crate will own it).

## License

Apache-2.0. See [LICENSE](LICENSE).
