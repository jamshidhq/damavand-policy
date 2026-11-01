// DevOps L0 loop: observe only.

@id("global.never")
forbid (principal, action in Damavand::Action::"class:never", resource);

@id("global.read")
permit (principal, action in Damavand::Action::"class:read", resource);

@id("global.no-secrets")
forbid (principal, action in Damavand::Action::"class:secret.use", resource);

// Permitted by policy, but the L0 caps deny it.
@id("global.k8s-apply")
permit (principal, action == Damavand::Action::"k8s_apply", resource);
