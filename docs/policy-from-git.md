# Policy from a git repository

For an operator running the local stack who wants the Cedar bundle to come from a git repository instead of the checkout's `policy/bundle.cedar`. Assumes the quickstart worked.

Merge rights on that repository become the right to change what the gateway enforces. Every receipt records the hash of the bundle that decided it.

## Create the repository

Copy `policy-starter/` into a repository of your own and push it. It holds the same `policy/bundle.cedar` the stack ships, plus a CI job for GitLab and one for GitHub that parse the bundle on every push. Its [README](../policy-starter/README.md) explains the layout.

## Point the stack at it

Add the URL to `.env`. For a private `https://` repository add a read-only token as well; it reaches git through a credential helper and is not logged.

```
R5E_POLICY_GIT_URL=https://gitlab.com/your-org/r5e-policy.git
#R5E_POLICY_GIT_TOKEN=
```

Start the stack with the profile that adds the `policy-sync` sidecar:

```
docker compose --profile git-policy up -d
```

A push becomes the active bundle within about 35 seconds at the default 30-second interval: the sidecar fetches the branch every 30 seconds and copies `policy/bundle.cedar` into the volume the gateway reads when its content changes, and the gateway checks that file every 5 seconds. Ref, path, and interval are [environment variables](reference/env.md).

## Confirm

```
docker compose --profile git-policy logs policy-sync
```

The output below was captured against a local `git daemon`, which is why the URL is `git://`; with an `https://` repository the first line shows that URL instead. The daemon setup is in the last section.

```
[policy-sync] watching git://host.docker.internal:9418/policy-repo ref=main path=policy/bundle.cedar every 30s -> /policy/bundle.cedar (current sha256=none)
[policy-sync] updated /policy/bundle.cedar from commit=46a80062758d8f61c22c9399b00950f03c72cd8f bundle_sha256=41b8370541572e93c425c440d97404dce59b633cb2c7ee08a35faa7d8071a6db
```

```
curl -s http://localhost:4000/readyz | jq .policy
```

```
{"active_hash":"2973992108fb76adaf641b0886c8c4d46d16634699e3f7e0d7abd35e8c673cdf","last_error":null,"last_error_at":null,"last_reload_at":"2026-09-02T20:49:39.472657Z"}
```

`active_hash` is the canonical hash of the bundle in force, the same value receipts carry as `policy_canonical_hash`. It is computed from the parsed policy, not the file bytes.

Push a change, wait, and read `.policy` again. Adding one `forbid` rule moved `active_hash` to `b691e6396714f5098824d19b54bdceb6285096b5b6064dea4b44847b2a55089e` here.

## A push that does not parse

The sidecar validates nothing. The gateway parses the new file, and when parsing fails it keeps the previous bundle in force and reports the failure:

```
{"active_hash":"2973992108fb76adaf641b0886c8c4d46d16634699e3f7e0d7abd35e8c673cdf","last_error":"{:bundle_parse_failure, \"cedar parse error: unexpected token `cedar`\"}","last_error_at":"2026-09-02T20:55:39.249091Z","last_reload_at":"2026-09-02T20:49:39.472657Z"}
```

```
docker compose logs gateway | grep 'policy bundle'
```

```
20:55:39.248 [warning] policy bundle reload (poll) failed; keeping previous bundle 2973992108fb76adaf641b0886c8c4d46d16634699e3f7e0d7abd35e8c673cdf active. reason={:bundle_parse_failure, "cedar parse error: unexpected token `cedar`"}
```

`/readyz` stays ready; `last_error` is the signal. Push a bundle that parses and `last_error` returns to `null` with the new `active_hash`. The starter repository's CI job runs the same parse check on every push.

## Back to the checkout's file

Remove `R5E_POLICY_GIT_URL` from `.env`, then:

```
docker compose --profile git-policy down
docker compose up -d
```

The gateway entrypoint logs `policy: R5E_POLICY_GIT_URL unset; linking /policy/bundle.cedar -> /policy-default/bundle.cedar (the checkout's ./policy)` and `active_hash` returns to the checkout bundle's hash.

## How this page was tested

Against a bare repository on the same machine, served with `git daemon` and reached from the sidecar as `git://host.docker.internal:9418/policy-repo`; the output above is from that run. An `https://` repository with a token differs only in the URL and the token line.

```
cp -R policy-starter/. policy-src/ && cd policy-src && git init && git checkout -b main && git add -A && git commit -m 'policy starter' && cd ..
git clone --bare policy-src policy-repo && touch policy-repo/git-daemon-export-ok
git daemon --base-path="$PWD" --export-all --reuseaddr --port=9418 --detach policy-repo
```
