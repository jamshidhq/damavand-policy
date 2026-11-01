// Global tier. Forbid beats permit everywhere.

@id("global.never")
forbid (principal, action in Damavand::Action::"class:never", resource);

@id("global.read")
permit (principal, action in Damavand::Action::"class:read", resource);

@id("global.no-vault-read")
forbid (principal, action == Damavand::Action::"j_read", resource in Damavand::Repo::"vault");

@id("global.budget-exhausted")
forbid (principal, action, resource)
when { context.budget.actions_left < 0 };

// Pushing a release branch always asks, even where a project allows pushes.
@id("global.ask-push-release")
@outcome("ask")
forbid (principal, action == Damavand::Action::"git_push", resource == Damavand::Repo::"jamshid-release");

@id("global.egress-crates-io")
permit (principal, action == Damavand::Action::"http_request", resource == Damavand::Host::"crates.io");
