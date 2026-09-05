# r5e policy repo

For an operator running the r5e compose stack who wants the Cedar bundle to come from a
git repository instead of the checkout's `policy/bundle.cedar`.

Copy this directory into a repository of your own, and copy freely: it is MIT-0
([LICENSE](LICENSE)), not the AGPL that covers the rest of this repository. Your Cedar
rules are your configuration, not a derivative of the gateway.

The stack's `policy-sync` sidecar fetches one file from it and hands it to the gateway;
a push becomes the active bundle within about 35 seconds at the default 30-second
interval, and every receipt records the bundle hash that decided it.

## Layout

| Path | Purpose |
|---|---|
| `policy/bundle.cedar` | The bundle. Same content as the stack's default; the comments in it explain the rule shapes. |
| `.gitlab-ci.yml` | Parses the bundle on every push (GitLab). |
| `.github/workflows/validate.yml` | Same check for GitHub. |

## Validate locally

The CI jobs use the Cedar CLI at the version the gateway embeds. Install it once
(Rust toolchain required):

```
cargo install cedar-policy-cli --version 4.9.1 --locked
cedar --version
```

```
cedar-policy-cli 4.9.1
```

Then, from the repository root:

```
cedar check-parse --policies policy/bundle.cedar
```

Silence and exit status 0 mean the bundle parses. A bundle that does not parse is never
activated: the gateway keeps the previous one and reports the error on `/readyz`.

Schema validation (`cedar validate`) is not part of the check. The gateway's entity
schema, `apps/recurse_gateway/priv/cedar/schema.cedarschema.json` in the r5e
repository, is written in the gateway's own JSON dialect, which the CLI's schema parser
rejects, and the `tool_args` record a tool-call rule inspects is not declared in it.
Parse checking is what the gateway itself does on reload.

## Point the stack at this repository

In the `.env` of your r5e checkout:

```
R5E_POLICY_GIT_URL=https://gitlab.com/your-org/r5e-policy.git
```

Then start with the profile:

```
docker compose --profile git-policy up -d
```

| Variable | Default | Meaning |
|---|---|---|
| `R5E_POLICY_GIT_REF` | `main` | Branch, tag, or full commit sha to follow. |
| `R5E_POLICY_GIT_PATH` | `policy/bundle.cedar` | File in this repository that becomes the bundle. |
| `R5E_POLICY_GIT_INTERVAL` | `30` | Seconds between fetches. |
| `R5E_POLICY_GIT_TOKEN` | unset | Read-only token for a private https repository. Set in `.env`, never in this repository. |

The gateway reports the bundle it is enforcing:

```
curl -s http://localhost:4000/readyz
```

`policy.active_hash` is the canonical hash of the active bundle and matches the
`policy_canonical_hash` on receipts issued under it. `policy.last_error` is set when the
most recent push did not parse.
