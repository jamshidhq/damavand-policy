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
    let b = Bundle::new(BundleId("abc".into()), SCHEMA);
    assert_eq!(b.id(), &BundleId("abc".into()));
    assert_eq!(
        Engine::load(&b).unwrap().bundle_id(),
        &BundleId("abc".into())
    );
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
