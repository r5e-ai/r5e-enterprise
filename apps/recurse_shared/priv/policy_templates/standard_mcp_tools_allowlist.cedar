// Standard MCP tools allowlist — curated safe-default tool-calling posture.
//
// Permits a small, review-approved set of MCP tool calls against common
// enterprise integrations. Intended to drop into a Governance-shape
// deployment (VPC Runner or Managed SaaS) as the starting allowlist;
// customers extend it via the Discovery-to-Policy flow (FR-049 surface 2)
// as real agent usage exposes additional legitimate calls.
//
// Pattern: resource is the MCP tool URI (`mcp://<service>/<tool>`); action
// is the tool invocation verb. Read-only tools are permitted broadly;
// write-capable tools require human-OBO context.
//
// Cedar note: `resource in [...]` accepts a set of groups, not a set of
// individual entity UIDs. We therefore write one permit per read-only tool
// cluster (via action-kind) and narrow with a resource `==` check where
// per-tool precision matters.

// -- Jira (read-only) --
permit (
  principal,
  action == Action::"tool_call",
  resource == Resource::"mcp://jira/search_issues"
);

permit (
  principal,
  action == Action::"tool_call",
  resource == Resource::"mcp://jira/get_issue"
);

permit (
  principal,
  action == Action::"tool_call",
  resource == Resource::"mcp://jira/list_projects"
);

// -- Confluence (read-only) --
permit (
  principal,
  action == Action::"tool_call",
  resource == Resource::"mcp://confluence/search_pages"
);

permit (
  principal,
  action == Action::"tool_call",
  resource == Resource::"mcp://confluence/get_page"
);

// -- Slack (read-only) --
permit (
  principal,
  action == Action::"tool_call",
  resource == Resource::"mcp://slack/list_channels"
);

permit (
  principal,
  action == Action::"tool_call",
  resource == Resource::"mcp://slack/search_messages"
);

// -- GitHub (read-only) --
permit (
  principal,
  action == Action::"tool_call",
  resource == Resource::"mcp://github/search_code"
);

permit (
  principal,
  action == Action::"tool_call",
  resource == Resource::"mcp://github/get_file"
);

permit (
  principal,
  action == Action::"tool_call",
  resource == Resource::"mcp://github/list_pulls"
);

// -- Write-capable tools — require human-OBO context AND business justification.
// Tighten further by role once deployment is past the discovery phase.
permit (
  principal,
  action == Action::"tool_call",
  resource == Resource::"mcp://jira/create_issue"
)
when {
  context has acting_for_human &&
  context.acting_for_human == true &&
  context has business_justification &&
  context.business_justification != ""
};

permit (
  principal,
  action == Action::"tool_call",
  resource == Resource::"mcp://slack/post_message"
)
when {
  context has acting_for_human &&
  context.acting_for_human == true &&
  context has business_justification &&
  context.business_justification != ""
};

permit (
  principal,
  action == Action::"tool_call",
  resource == Resource::"mcp://github/create_pr"
)
when {
  context has acting_for_human &&
  context.acting_for_human == true &&
  context has business_justification &&
  context.business_justification != ""
};
