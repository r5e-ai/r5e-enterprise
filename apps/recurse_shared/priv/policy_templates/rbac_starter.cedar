// RBAC starter — role-based access control.
//
// Pattern: principals are placed in `Role::"<name>"` groups; permits are
// written against roles and action sets, not individual principals.
// Customize by:
//   (a) renaming roles to your org's taxonomy
//   (b) curating the action allowlist per role
//   (c) narrowing resource scopes with `when { resource is <Kind> }` guards
//
// Recurse's entity store expects principals to carry a `parents` attribute
// listing the `Role` entities they belong to — see `contracts/attestation.schema.json`
// for the IdentityContext shape feeding Cedar evaluation.

// Admins may perform any action on any resource. Keep the admin group small.
permit (
  principal in Role::"admin",
  action,
  resource
);

// Operators may read any resource and write to Dataset-kind resources only.
permit (
  principal in Role::"operator",
  action in [Action::"read", Action::"list"],
  resource
);

permit (
  principal in Role::"operator",
  action == Action::"write",
  resource
)
when { resource is Dataset };

// Readers may only read, and only from Dataset or Document resources.
permit (
  principal in Role::"reader",
  action == Action::"read",
  resource
)
when { resource is Dataset || resource is Document };

// Agents acting on behalf of humans must have the human-OBO context attribute
// present. Enforces zero-service-account-agents posture when combined with
// `denylist_pattern.cedar`.
permit (
  principal in Role::"agent",
  action,
  resource
)
when {
  context has acting_for_human &&
  context.acting_for_human == true
};
