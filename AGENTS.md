# Agent Instructions

## Version Control

- Use JJ for this repository. Do not use git for local status, diff, restore, or commit workflows unless the user explicitly asks for git.
- Treat the working copy as shared. Do not revert unrelated changes.

## Code intelligence

- `r5e-enterprise` is an Elixir umbrella. Indexers that look for a root
  `lib/` directory find nothing here; point them at the child apps under
  `apps/` instead.

## Runtime/Deploy Work

- For runtime and deploy configuration, avoid VM-shaped defaults in production paths. Container/Kubernetes deploys should use explicit env, mounted secrets, or service URLs.
- Keep `config/runtime.exs` and your deployment's values aligned when changing required runtime env.

---

The operator-specific half of this file — the internal code-intelligence
service, its localhost endpoint, absolute checkout paths, and the private
manifests repository this deployment keeps beside the code — is not part
of the public tree. `docs/release/public-tree.md` lists what is excluded
and why.
