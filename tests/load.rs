//! Loader: invalid bundles fail with an exact LoadError.

mod common;

use common::{FULL_CAPS, SCHEMA, id};
use damavand_policy::{Bundle, BundleId, Engine, LoadError};

fn err(bundle: Bundle) -> LoadError {
    Engine::load(&bundle).expect_err("bundle must not load")
}

const READ: &str =
    r#"@id("g.read") permit (principal, action in Damavand::Action::"class:read", resource);"#;

#[test]
fn golden_dirs_load() {
    for name in ["jamshid-default", "devops-l0"] {
        let b = Bundle::from_dir(&common::bundles_dir().join(name), id()).unwrap();
        Engine::load(&b).unwrap();
    }
}

#[test]
fn missing_dir_is_io_error() {
    let e = Bundle::from_dir(std::path::Path::new("/nonexistent/bundle"), id()).unwrap_err();
    assert!(
        matches!(e, LoadError::Io { ref path, .. } if path.ends_with("schema.cedarschema")),
        "{e:?}"
    );
}

#[test]
fn empty_bundle_loads() {
    Engine::load(&Bundle::new(id(), SCHEMA)).unwrap();
}

#[test]
fn bad_schema() {
    assert_eq!(err(Bundle::new(id(), "namespace {")), LoadError::Schema);
}

#[test]
fn bad_policy_text() {
    let b = Bundle::new(id(), SCHEMA).with_global("global/x.cedar", "permit (principal");
    assert_eq!(
        err(b),
        LoadError::Parse {
            file: "global/x.cedar".into()
        }
    );
}

#[test]
fn template_refused() {
    let b = Bundle::new(id(), SCHEMA).with_global(
        "global/t.cedar",
        r#"@id("t") permit (principal == ?principal, action, resource);"#,
    );
    assert_eq!(
        err(b),
        LoadError::Template {
            file: "global/t.cedar".into()
        }
    );
}

#[test]
fn missing_id() {
    let b = Bundle::new(id(), SCHEMA)
        .with_global("global/a.cedar", READ)
        .with_global("global/b.cedar", "permit (principal, action, resource);");
    assert_eq!(
        err(b),
        LoadError::MissingId {
            file: "global/b.cedar".into()
        }
    );
}

#[test]
fn duplicate_id_across_tiers() {
    let b = Bundle::new(id(), SCHEMA).with_global("global/a.cedar", READ).with_project(
        "jamshid",
        "projects/jamshid/a.cedar",
        r#"@id("g.read") permit (principal, action, resource in Damavand::Project::"jamshid");"#,
    );
    assert_eq!(
        err(b),
        LoadError::DuplicateId {
            id: "g.read".into()
        }
    );
}

#[test]
fn reserved_id() {
    let b = Bundle::new(id(), SCHEMA).with_global(
        "global/a.cedar",
        r#"@id("damavand.never") permit (principal, action, resource);"#,
    );
    assert_eq!(
        err(b),
        LoadError::ReservedId {
            id: "damavand.never".into()
        }
    );
}

#[test]
fn ask_on_permit_refused() {
    let b = Bundle::new(id(), SCHEMA).with_global(
        "global/a.cedar",
        r#"@id("p") @outcome("ask") permit (principal, action, resource);"#,
    );
    assert_eq!(err(b), LoadError::BadOutcome { id: "p".into() });
}

#[test]
fn unknown_outcome_refused() {
    let b = Bundle::new(id(), SCHEMA).with_global(
        "global/a.cedar",
        r#"@id("f") @outcome("maybe") forbid (principal, action, resource);"#,
    );
    assert_eq!(err(b), LoadError::BadOutcome { id: "f".into() });
}

#[test]
fn project_policy_must_be_scoped() {
    let b = Bundle::new(id(), SCHEMA).with_project(
        "jamshid",
        "projects/jamshid/a.cedar",
        r#"@id("j.any") permit (principal, action, resource);"#,
    );
    assert_eq!(
        err(b),
        LoadError::ProjectScope {
            project: "jamshid".into(),
            id: "j.any".into()
        }
    );
}

#[test]
fn project_policy_scoped_to_another_project() {
    let b = Bundle::new(id(), SCHEMA).with_project(
        "jamshid",
        "projects/jamshid/a.cedar",
        r#"@id("j.other") permit (principal, action, resource in Damavand::Project::"other");"#,
    );
    assert_eq!(
        err(b),
        LoadError::ProjectScope {
            project: "jamshid".into(),
            id: "j.other".into()
        }
    );
}

#[test]
fn project_scope_forms_accepted() {
    let b = Bundle::new(id(), SCHEMA)
        .with_project(
            "jamshid",
            "projects/jamshid/a.cedar",
            r#"@id("j.in") permit (principal, action, resource in Damavand::Project::"jamshid");
               @id("j.isin") permit (principal, action, resource is Damavand::Repo in Damavand::Project::"jamshid");"#,
        );
    Engine::load(&b).unwrap();
}

#[test]
fn strict_validation_failure_names_policies() {
    let b = Bundle::new(id(), SCHEMA).with_global(
        "global/a.cedar",
        r#"@id("z.bad") permit (principal, action, resource) when { principal.nope == 1 };
           @id("a.bad") permit (principal, action == Damavand::Action::"j_read", resource) when { context.autonomy == "x" };
           @id("ok") permit (principal, action, resource);"#,
    );
    assert_eq!(
        err(b),
        LoadError::Validation {
            ids: vec!["a.bad".into(), "z.bad".into()]
        }
    );
}

#[test]
fn action_without_class() {
    let schema = SCHEMA.replace("action draft_pr in [\"class:draft\"]", "action draft_pr");
    assert_eq!(
        err(Bundle::new(id(), schema)),
        LoadError::ActionClass {
            action: "draft_pr".into()
        }
    );
}

#[test]
fn action_in_two_classes() {
    let schema = SCHEMA.replace(
        "action draft_pr in [\"class:draft\"]",
        "action draft_pr in [\"class:draft\", \"class:read\"]",
    );
    assert_eq!(
        err(Bundle::new(id(), schema)),
        LoadError::ActionClass {
            action: "draft_pr".into()
        }
    );
}

#[test]
fn unknown_class_group() {
    let schema = SCHEMA.replace(
        "action draft_pr in [\"class:draft\"]",
        "action \"class:bogus\";\n  action draft_pr in [\"class:bogus\"]",
    );
    assert_eq!(
        err(Bundle::new(id(), schema)),
        LoadError::ActionClass {
            action: "class:bogus".into()
        }
    );
}

#[test]
fn nested_class_groups_refused() {
    let schema = SCHEMA.replace(
        "action \"class:read\",",
        "action \"class:read\" in [\"class:draft\"];\n  action",
    );
    assert_eq!(
        err(Bundle::new(id(), schema)),
        LoadError::ActionClass {
            action: "class:read".into()
        }
    );
}

#[test]
fn never_action_cannot_be_reclassified() {
    let schema = SCHEMA.replace(
        &format!("action {} in [\"class:never\"]", common::NEVER_ACTION),
        &format!(
            "action {} in [\"class:write.remote\"]",
            common::NEVER_ACTION
        ),
    );
    assert_eq!(
        err(Bundle::new(id(), schema)),
        LoadError::NeverReclassified {
            action: common::NEVER_ACTION.into()
        }
    );
}

#[test]
fn context_shape_mismatch() {
    let schema = SCHEMA.replace(
        "action git_push in [\"class:write.remote\"] appliesTo {\n    principal: [Worker, Orchestrator, User], resource: [Repo], context: Ctx };",
        "action git_push in [\"class:write.remote\"] appliesTo {\n    principal: [Worker, Orchestrator, User], resource: [Repo], context: { branch: String } };",
    );
    assert_ne!(schema, SCHEMA);
    assert_eq!(
        err(Bundle::new(id(), schema)),
        LoadError::ContextShape {
            action: "git_push".into()
        }
    );
}

fn caps_err(toml: &str) -> LoadError {
    err(Bundle::new(id(), SCHEMA).with_autonomy(toml))
}

#[test]
fn autonomy_level_out_of_range() {
    assert!(matches!(
        caps_err("[project.jamshid]\nread = 4\n"),
        LoadError::Autonomy { .. }
    ));
    assert!(matches!(
        caps_err("[project.jamshid]\nread = -1\n"),
        LoadError::Autonomy { .. }
    ));
    assert!(matches!(
        caps_err("[project.jamshid]\nread = \"3\"\n"),
        LoadError::Autonomy { .. }
    ));
}

#[test]
fn autonomy_unknown_class() {
    assert!(matches!(
        caps_err("[project.jamshid]\nwrite = 1\n"),
        LoadError::Autonomy { .. }
    ));
}

#[test]
fn autonomy_never_has_no_cap() {
    assert!(matches!(
        caps_err("[project.jamshid]\nnever = 3\n"),
        LoadError::Autonomy { .. }
    ));
}

#[test]
fn autonomy_unknown_scope() {
    assert!(matches!(
        caps_err("[team.x]\nread = 1\n"),
        LoadError::Autonomy { .. }
    ));
    assert!(matches!(caps_err("read = 1\n"), LoadError::Autonomy { .. }));
    assert!(matches!(
        caps_err("[project]\nread = 1\n"),
        LoadError::Autonomy { .. }
    ));
    assert!(matches!(caps_err("not toml ["), LoadError::Autonomy { .. }));
}

#[test]
fn autonomy_valid() {
    Engine::load(&Bundle::new(id(), SCHEMA).with_autonomy(FULL_CAPS)).unwrap();
    Engine::load(&Bundle::new(id(), SCHEMA).with_autonomy("[loop.nightly]\nread = 0\n")).unwrap();
}

#[test]
fn bundle_accessors() {
    let b = Bundle::new("abc", SCHEMA);
    assert_eq!(b.label(), "abc");
    assert_eq!(Engine::load(&b).unwrap().bundle_label(), "abc");
}

fn digest(b: &Bundle) -> BundleId {
    *Engine::load(b).unwrap().bundle_id()
}

#[test]
fn bundle_id_is_a_content_digest() {
    let base = Bundle::new("a", SCHEMA);
    let d = digest(&base);
    // The label is not content.
    assert_eq!(digest(&Bundle::new("b", SCHEMA)), d);
    // Every part of the content is.
    let variants = [
        Bundle::new("a", format!("{SCHEMA}\n")),
        base.clone().with_global("g.cedar", READ),
        base.clone().with_global("h.cedar", ""),
        base.clone().with_project("jamshid", "p.cedar", ""),
        base.clone().with_project("other", "p.cedar", ""),
        base.clone().with_autonomy("[loop.x]\nread = 0\n"),
        base.clone()
            .with_constraints("[j_edit.p]\nenum = [\"a\"]\n"),
        base.clone().with_broker_key(common::broker_key()),
    ];
    let mut seen = std::collections::HashSet::new();
    seen.insert(d);
    for v in &variants {
        assert!(seen.insert(digest(v)), "{v:?}");
    }
    // File order does not matter; the name does.
    let first = base
        .clone()
        .with_global("a.cedar", READ)
        .with_global("b.cedar", "");
    let second = base
        .clone()
        .with_global("b.cedar", "")
        .with_global("a.cedar", READ);
    assert_eq!(digest(&first), digest(&second));
    // Fields are length-prefixed: moving text between name and body changes it.
    let one = base.clone().with_global("a", "//b//");
    let two = base.clone().with_global("a//b", "//");
    assert_ne!(digest(&one), digest(&two));
}

#[test]
fn action_ids_are_lower_case_identifiers() {
    for bad in [
        "\"Draft PR\"",
        "\"draftPR\"",
        "\"9pr\"",
        "\"pr-x\"",
        "\"_pr\"",
    ] {
        let schema = SCHEMA.replace("action draft_pr in", &format!("action {bad} in"));
        assert_ne!(schema, SCHEMA);
        assert_eq!(
            err(Bundle::new(id(), schema)),
            LoadError::ActionId {
                action: bad.trim_matches('"').into()
            },
            "{bad}"
        );
    }
    let ok = SCHEMA.replace("action draft_pr in", "action \"draft.pr_2\" in");
    Engine::load(&Bundle::new(id(), ok)).unwrap();
}

#[test]
fn permits_naming_never_are_refused() {
    let never = common::NEVER_ACTION;
    for scope in [
        format!(r#"action == Damavand::Action::"{never}""#),
        r#"action in Damavand::Action::"class:never""#.to_string(),
        format!(r#"action in [Damavand::Action::"j_read", Damavand::Action::"{never}"]"#),
        r#"action in [Damavand::Action::"class:never"]"#.to_string(),
    ] {
        let b = Bundle::new(id(), SCHEMA).with_global(
            "g.cedar",
            format!(r#"@id("p") permit (principal, {scope}, resource);"#),
        );
        assert_eq!(
            err(b),
            LoadError::PermitsNever { id: "p".into() },
            "{scope}"
        );
    }
    // A bundle-defined Never action is caught by class, not by name.
    let schema = SCHEMA.replace(
        "action use_secret in [\"class:secret.use\"]",
        "action wipe_db in [\"class:never\"] appliesTo {\n    principal: [Worker], resource: [Repo], context: Ctx };\n  action use_secret in [\"class:secret.use\"]",
    );
    let b = Bundle::new(id(), schema).with_global(
        "g.cedar",
        r#"@id("w") permit (principal, action == Damavand::Action::"wipe_db", resource);"#,
    );
    assert_eq!(err(b), LoadError::PermitsNever { id: "w".into() });
    // Forbids may name it, and an unscoped permit still loads.
    Engine::load(&Bundle::new(id(), SCHEMA).with_global(
        "g.cedar",
        format!(
            r#"@id("f") forbid (principal, action == Damavand::Action::"{never}", resource);
               @id("a") permit (principal, action, resource);"#
        ),
    ))
    .unwrap();
}

#[test]
fn builtin_never_actions_cannot_be_reclassified() {
    for verb in damavand_policy::NEVER_ACTIONS {
        let schema = if *verb == common::NEVER_ACTION {
            SCHEMA.replace(
                &format!("action {verb} in [\"class:never\"]"),
                &format!("action {verb} in [\"class:write.remote\"]"),
            )
        } else {
            SCHEMA.replace(
                "action use_secret in",
                &format!(
                    "action {verb} in [\"class:write.remote\"] appliesTo {{\n    principal: [Worker], resource: [Repo], context: Ctx }};\n  action use_secret in"
                ),
            )
        };
        assert_ne!(schema, SCHEMA);
        assert_eq!(
            err(Bundle::new(id(), schema)),
            LoadError::NeverReclassified {
                action: verb.to_string()
            }
        );
    }
}

fn constraints_err(toml: &str) -> LoadError {
    err(Bundle::new(id(), SCHEMA).with_constraints(toml))
}

#[test]
fn constraints_file_is_strict() {
    for bad in [
        "not toml [",
        "[nope.p]\nenum = [\"a\"]\n",
        "j_edit = 1\n",
        "[j_edit]\np = 1\n",
        "[j_edit.p]\n",
        "[j_edit.p]\nenum = []\n",
        "[j_edit.p]\nenum = [1]\n",
        "[j_edit.p]\nenum = \"a\"\n",
        "[j_edit.p]\npattern = 1\n",
        "[j_edit.p]\nenum = [\"a\"]\npattern = \"a\"\n",
        "[j_edit.p]\nregex = \"a\"\n",
    ] {
        assert!(
            matches!(constraints_err(bad), LoadError::Constraints { .. }),
            "{bad}"
        );
    }
    Engine::load(&Bundle::new(id(), SCHEMA).with_constraints(
        "[j_edit.mode]\nenum = [\"append\"]\n[j_edit.path]\npattern = \"[a-z/]+\"\n",
    ))
    .unwrap();
}

#[test]
fn constraint_patterns_are_checked_at_load() {
    let pat = |p: &str| constraints_err(&format!("[j_edit.p]\npattern = '{p}'\n"));
    let at = || ("j_edit".to_string(), "p".to_string());
    for p in ["x)|(.*", "(", "a{1000}{1000}"] {
        let (action, param) = at();
        assert_eq!(pat(p), LoadError::PatternInvalid { action, param }, "{p}");
    }
    for p in [".*", "(?s).*", ".+", r"[\s\S]*", ".{0,999}", ".*x"] {
        let (action, param) = at();
        assert_eq!(pat(p), LoadError::PatternTooBroad { action, param }, "{p}");
    }
}

#[test]
fn approval_file_and_broker_keys() {
    let dir = std::env::temp_dir().join(format!("damavand-approval-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("schema.cedarschema"), SCHEMA).unwrap();
    let with = |text: &str| {
        std::fs::write(dir.join("approval.toml"), text).unwrap();
        Bundle::from_dir(&dir, "x")
    };
    let key = common::broker_key().to_string();
    let b = with(&format!("broker_keys = [\"{key}\"]\n")).unwrap();
    Engine::load(&b).unwrap();
    for bad in [
        "broker_keys = \"x\"\n",
        "broker_keys = [\"zz\"]\n",
        "broker_keys = [1]\n",
        "keys = []\n",
        "[",
    ] {
        assert!(
            matches!(with(bad), Err(LoadError::Approval { .. })),
            "{bad}"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
    // A key that is not a curve point, and a weak (small-order) key.
    let not_point = (2u8..=255)
        .map(|b| {
            let mut k = [0u8; 32];
            k[0] = b;
            k
        })
        .find(|k| ed25519_dalek::VerifyingKey::from_bytes(k).is_err())
        .expect("some y has no curve point");
    let identity = {
        let mut k = [0u8; 32];
        k[0] = 1;
        k
    };
    for (i, k) in [not_point, identity].into_iter().enumerate() {
        let b = Bundle::new(id(), SCHEMA)
            .with_broker_key(common::broker_key())
            .with_broker_key(damavand_policy::BrokerKey(k));
        assert_eq!(err(b), LoadError::BrokerKey { index: 1 }, "case {i}");
    }
}

#[test]
fn load_error_display_names_the_problem() {
    let e = LoadError::ProjectScope {
        project: "jamshid".into(),
        id: "j.any".into(),
    };
    assert!(e.to_string().contains("j.any"));
}

#[test]
fn empty_id_is_missing() {
    let b = Bundle::new(id(), SCHEMA).with_global(
        "global/a.cedar",
        r#"@id("") permit (principal, action, resource);"#,
    );
    assert_eq!(
        err(b),
        LoadError::MissingId {
            file: "global/a.cedar".into()
        }
    );
}

#[test]
fn extension_namespace_actions_are_left_alone() {
    let schema = format!(
        "{SCHEMA}\nnamespace Ext {{\n  entity Thing;\n  action ping appliesTo {{ principal: [Thing], resource: [Thing] }};\n}}\n"
    );
    let e = Engine::load(&Bundle::new(id(), schema)).unwrap();
    assert_eq!(e.action_class("ping"), None);
}

#[test]
fn never_forbid_is_injected_only_when_the_schema_has_class_never() {
    let schema: String = SCHEMA
        .lines()
        .filter(|l| !l.contains(common::NEVER_ACTION))
        .collect::<Vec<_>>()
        .join("\n")
        .replace(", \"class:never\";", ";");
    let schema = schema.replace(
        "  action use_secret in [\"class:secret.use\"] appliesTo {\n    principal: [Worker, Orchestrator, User], resource: [SecretRef], context: Ctx };\n    principal: [Worker, Orchestrator, User], resource: [Repo], context: Ctx };",
        "  action use_secret in [\"class:secret.use\"] appliesTo {\n    principal: [Worker, Orchestrator, User], resource: [SecretRef], context: Ctx };",
    );
    assert!(!schema.contains("class:never"), "{schema}");
    let e = Engine::load(&Bundle::new(id(), schema).with_global("g.cedar", READ)).unwrap();
    assert_eq!(
        e.action_class("j_read"),
        Some(damavand_policy::ActionClass::Read)
    );
}
