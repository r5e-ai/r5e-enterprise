// permissive.cedar — the null policy, stated out loud.
//
// Cedar is deny-by-default, so "allow everything" has to be written down.
// The fold's demo admits this as PolicyBundle/active first, so that the
// step that follows (a destructive ToolCall, admitted) and the step after
// the swap (the same ToolCall, denied) differ in exactly one thing: the
// policy on the chain.

permit (
  principal,
  action,
  resource
);
