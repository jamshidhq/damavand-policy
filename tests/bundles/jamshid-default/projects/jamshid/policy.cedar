// Project tier for jamshid. Every policy is scoped to the project.

@id("jamshid.worktree")
permit (
  principal,
  action in [Damavand::Action::"class:write.worktree", Damavand::Action::"class:draft"],
  resource in Damavand::Project::"jamshid"
);

@id("jamshid.push")
permit (principal, action == Damavand::Action::"git_push", resource in Damavand::Project::"jamshid");

@id("jamshid.no-read-env")
forbid (principal, action == Damavand::Action::"j_read", resource in Damavand::Project::"jamshid")
when { resource == Damavand::Path::"jamshid/.env" };
