// Cedar stability fixture (research D2 / FR-039 / Deliverable O).
//
// Four representative policies covering the RBAC + ABAC + denylist patterns
// Recurse Phase-1 expects customers to ship. This file is INPUT to
// `canonical_hash/1`; any edit here forces a fresh bake of `expected_hash.txt`
// and a documented transition window per T091 (contracts/cedar_pin.md).

// 1. RBAC — admins may perform any action on any resource.
permit (
  principal in Role::"admin",
  action,
  resource
);

// 2. RBAC scoped by resource namespace — operators may read any Dataset.
permit (
  principal in Role::"operator",
  action == Action::"read",
  resource
)
when { resource is Dataset };

// 3. ABAC — a principal may update a Document they own, provided the
//    document is not frozen.
permit (
  principal,
  action == Action::"update",
  resource
)
when {
  resource is Document &&
  resource.owner == principal &&
  resource.frozen == false
};

// 4. Denylist — forbid all actions on resources tagged `sensitive` unless
//    the request explicitly carries a break-glass context flag.
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
