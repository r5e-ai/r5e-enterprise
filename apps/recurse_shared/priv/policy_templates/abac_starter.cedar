// ABAC starter — attribute-based access control.
//
// Pattern: permits are conditioned on attributes of the principal, resource,
// and evaluation context — not on group membership alone. Customize by:
//   (a) picking which resource attributes govern access (owner, tenant,
//       classification, etc.)
//   (b) picking which principal attributes feed the decision (department,
//       clearance, human-OBO flag)
//   (c) picking which context attributes the Gateway MUST inject to allow
//       (business_justification, ticket_id, etc.)
//
// All ABAC policies below are `permit` rules — pair with `denylist_pattern.cedar`
// for defense-in-depth.

// A principal may update a Document they own, provided the document is not
// frozen and the request carries an audit-ready business justification.
permit (
  principal,
  action == Action::"update",
  resource
)
when {
  resource is Document &&
  resource.owner == principal &&
  resource.frozen == false &&
  context has business_justification &&
  context.business_justification != ""
};

// Same-tenant access — principals may read resources within their tenant.
// Resource must carry a `tenant` attribute; principal must carry one too.
permit (
  principal,
  action == Action::"read",
  resource
)
when {
  principal has tenant &&
  resource has tenant &&
  principal.tenant == resource.tenant
};

// Clearance-gated read — principals may read classified resources only when
// their clearance level meets or exceeds the resource's classification.
permit (
  principal,
  action == Action::"read",
  resource
)
when {
  principal has clearance_level &&
  resource has classification_level &&
  principal.clearance_level >= resource.classification_level
};

// Human-OBO allowlist — Gateway's RFC 8693 token-exchange path injects the
// acting_for_human=true context flag when an agent call is bound to a human
// JWT. Disallow autonomous agent access to production resources.
permit (
  principal,
  action,
  resource
)
when {
  resource has environment &&
  resource.environment == "production" &&
  context has acting_for_human &&
  context.acting_for_human == true
};
