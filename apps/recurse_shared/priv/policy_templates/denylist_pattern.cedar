// Denylist pattern — explicit forbids layered over broad permits.
//
// Cedar evaluation semantics: any matching `forbid` wins over any matching
// `permit`. Use this template ALONGSIDE one of the permit-based starters
// (rbac_starter / abac_starter / llm_calls_only) to carve out guaranteed-deny
// classes of behavior regardless of role membership.
//
// Common uses: block sensitive resources, block destructive actions outside
// business hours, block cross-tenant leakage, block non-human-OBO agents
// from reaching privileged APIs.

// Forbid ALL actions against any resource tagged "sensitive", unless the
// request carries an explicit break-glass flag signed by an operator.
forbid (
  principal,
  action,
  resource
)
when {
  resource has tags &&
  resource.tags.contains("sensitive")
}
unless {
  context has break_glass &&
  context.break_glass == true
};

// Forbid destructive actions on any resource that carries a legal-hold tag.
// No break-glass escape — legal hold is hard-blocking.
forbid (
  principal,
  action in [Action::"delete", Action::"write", Action::"update"],
  resource
)
when {
  resource has legal_hold &&
  resource.legal_hold == true
};

// Forbid autonomous agents (no acting_for_human context) from calling any
// resource in the "production" environment. Service accounts must be
// explicitly exempted by role — see rbac_starter::Role::"service_account".
forbid (
  principal,
  action,
  resource
)
when {
  resource has environment &&
  resource.environment == "production" &&
  (!(context has acting_for_human) || context.acting_for_human == false)
}
unless {
  principal in Role::"service_account"
};

// Forbid cross-tenant access. Defense-in-depth on top of the BEAM-per-customer
// isolation — even if a tenant_id slips through, Cedar refuses the call.
forbid (
  principal,
  action,
  resource
)
when {
  principal has tenant &&
  resource has tenant &&
  principal.tenant != resource.tenant
};
