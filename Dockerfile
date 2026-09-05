# Enterprise requires the kernel and core verifier.
# Prepare a frozen three-repository context with scripts/prepare-release.py.
# Build using docker compose; no checkout state or secret files are copied.

# ---------------------------------------------------------------------- #
# R4-F6 (RC review 2026-09-05): the embedded manifest, as a measurement.
#
# `repos.lock.json` records a `commit` and an `archiveSha256` per source
# tree. The build used to `COPY` it and assert it was non-empty, which
# made `embedded_manifest_match=PASS` self-asserted: an image built from
# arbitrary sources plus a hand-written manifest passed. This stage
# recomputes all three `archiveSha256` values from the build context
# itself and fails the build on a mismatch, so the manifest is a claim
# the image can be held to.
#
# It is a stage of its own so that its `COPY . .` (the whole context, by
# necessity — the hash is over the whole tree) invalidates only this
# stage's cache. The build stage below takes the manifest **from here**,
# so this check is load-bearing rather than a dangling stage a builder
# would skip.
#
# The context must therefore carry exactly the trees the manifest hashes;
# `docker-compose/fold-context.dockerignore` excludes artifacts and state
# only, and says so.
# ---------------------------------------------------------------------- #
FROM hexpm/elixir:1.19.5-erlang-28.5-debian-bookworm-20260421 AS verify-sources

RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends python3 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /context
COPY . .
RUN python3 r5e-enterprise/scripts/verify-source-archive.py \
        --manifest repos.lock.json .

FROM hexpm/elixir:1.19.5-erlang-28.5-debian-bookworm-20260421 AS build

ENV MIX_ENV=prod \
    LANG=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

# System deps. Pinned to the apt repo's current state; bumped manually
# when we need a newer libssl / build-essential.
RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
        build-essential curl git pkg-config libssl-dev zstd ca-certificates \
        gnupg && \
    rm -rf /var/lib/apt/lists/*

# Node.js 20 + pnpm. Same versions as build:release (.gitlab-ci.yml).
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/* && \
    corepack enable && \
    corepack prepare pnpm@9.15.0 --activate && \
    node --version && pnpm --version

# Rust toolchain — pinned via .tool-versions (same as build:release).
COPY r5e-enterprise/.tool-versions ./.tool-versions
RUN RUST_VERSION=$(grep '^rust' .tool-versions | awk '{print $2}') && \
    curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- --default-toolchain "$RUST_VERSION" --profile minimal -y && \
    rustc --version && cargo --version

RUN mix local.hex --force && mix local.rebar --force

# S9a: the two sibling trees the path deps point at, at the same relative
# positions they have on disk. Small (lib/priv/config/mix.*) and rarely
# changing, so they sit above the deps layer.
COPY r5e-core/verifier /src/r5e-core/verifier
COPY r5e-kernel        /src/r5e-kernel

# S9a: the standalone verifier escript, built once from that copy.
WORKDIR /src/r5e-core/verifier
RUN mix deps.get && mix escript.build && test -x recurse_verify

WORKDIR /src/r5e-enterprise

# ---------------------------------------------------------------------- #
# Layer: mix dependencies. Invalidates only on mix.lock or per-app
# mix.exs change, so nine-out-of-ten code edits hit cache here.
# ---------------------------------------------------------------------- #
COPY r5e-enterprise/mix.exs r5e-enterprise/mix.lock ./
COPY r5e-enterprise/apps/recurse_shared/mix.exs      apps/recurse_shared/mix.exs
COPY r5e-enterprise/apps/recurse_providers/mix.exs   apps/recurse_providers/mix.exs
COPY r5e-enterprise/apps/recurse_gateway/mix.exs     apps/recurse_gateway/mix.exs
COPY r5e-enterprise/apps/recurse_runtime/mix.exs     apps/recurse_runtime/mix.exs
COPY r5e-enterprise/apps/recurse_integration/mix.exs apps/recurse_integration/mix.exs
COPY r5e-enterprise/apps/recurse_broker/mix.exs      apps/recurse_broker/mix.exs
# S9a: the fold's mix.exs — its path dep on /src/r5e-kernel resolves here.
COPY r5e-enterprise/apps/recurse_fold/mix.exs        apps/recurse_fold/mix.exs

RUN mix deps.get --only prod && \
    mix deps.compile

# Preserve license and notice texts found in the production Mix dependencies.
# Keep the package-relative paths so same-named files do not collide.
RUN mkdir -p /opt/dependency-licenses/mix && \
    find deps -mindepth 2 -maxdepth 4 -type f \
      \( -iname 'LICENSE*' -o -iname 'LICENCE*' -o -iname 'NOTICE*' -o -iname 'COPYING*' -o -iname 'COPYRIGHT*' \) \
      -exec sh -c 'for file do \
        relative=${file#deps/}; dependency=${relative%%/*}; item=${relative#*/}; \
        destination=/opt/dependency-licenses/mix/$dependency/$item; \
        mkdir -p "$(dirname "$destination")"; cp "$file" "$destination"; \
      done' sh {} + && \
    test -n "$(find /opt/dependency-licenses/mix -type f -print -quit)"

# ---------------------------------------------------------------------- #
# Layer: SPA. Invalidates only on ui/ source change.
#
# `mkdir -p apps/recurse_gateway/priv/static` runs BEFORE sync-to-priv
# because the apps/ tree hasn't been COPYed at this layer (that's the
# next layer for cache hit-rate reasons). sync-to-priv's `cp -r dist
# ../apps/recurse_gateway/priv/static/admin` requires the parent path
# to exist.
# ---------------------------------------------------------------------- #
COPY r5e-enterprise/ui ./ui
RUN mkdir -p apps/recurse_gateway/priv/static && \
    cd ui && \
    pnpm install --frozen-lockfile && \
    pnpm run build && \
    pnpm run sync-to-priv && \
    test -f ../apps/recurse_gateway/priv/static/admin/index.html && \
    mkdir -p /opt/dependency-licenses/npm && \
    find node_modules -mindepth 2 -maxdepth 8 -type f \
      \( -iname 'LICENSE*' -o -iname 'LICENCE*' -o -iname 'NOTICE*' -o -iname 'COPYING*' -o -iname 'COPYRIGHT*' \) \
      -exec sh -c 'for file do \
        relative=${file#node_modules/}; destination=/opt/dependency-licenses/npm/$relative; \
        mkdir -p "$(dirname "$destination")"; cp "$file" "$destination"; \
      done' sh {} + && \
    test -n "$(find /opt/dependency-licenses/npm -type f -print -quit)"

# ---------------------------------------------------------------------- #
# Layer: native NIFs + Elixir compile + release. Invalidates on app or
# NIF source change; the cedar + spiffe crates compile from scratch in
# this layer (no BuildKit cache mounts, see the header).
# ---------------------------------------------------------------------- #
COPY r5e-enterprise/native ./native
COPY r5e-enterprise/config ./config
COPY r5e-enterprise/rel ./rel
COPY r5e-enterprise/apps ./apps
# S9a: the one file under specs/ the fold cites at boot (derivedFrom of
# the nine KindDefinitions). The rest of specs/ is in the context (the
# manifest hashes it) and out of the image.
COPY r5e-enterprise/specs/010-gateway-api-group/spec.md ./specs/010-gateway-api-group/spec.md
# Exact source revisions and per-repository archive digests used for this
# build — taken from the stage that recomputed them, not from the context,
# so an image cannot carry a manifest that was never checked.
COPY --from=verify-sources /context/repos.lock.json /src/repos.lock.json
COPY r5e-enterprise/LICENSE /opt/project-licenses/r5e-enterprise/LICENSE
COPY r5e-kernel/LICENSE /opt/project-licenses/r5e-kernel/LICENSE
COPY r5e-core/LICENSE /opt/project-licenses/r5e-core/LICENSE
COPY r5e-core/LICENSE.md /opt/project-licenses/r5e-core/LICENSE.md

RUN mix compile && \
    mkdir -p /opt/dependency-licenses/cargo && \
    cd "$CARGO_HOME" && \
    find registry/src -mindepth 3 -maxdepth 7 -type f \
      \( -iname 'LICENSE*' -o -iname 'LICENCE*' -o -iname 'NOTICE*' -o -iname 'COPYING*' -o -iname 'COPYRIGHT*' \) \
      -exec sh -c 'for file do \
        destination=/opt/dependency-licenses/cargo/$file; \
        mkdir -p "$(dirname "$destination")"; cp "$file" "$destination"; \
      done' sh {} + && \
    test -n "$(find /opt/dependency-licenses/cargo -type f -print -quit)" && \
    cd /src/r5e-enterprise && \
    mix release --overwrite audit_console && \
    cp -r _build/prod/rel/audit_console /opt/release && \
    # S9a: the fold's boot-time inputs, at the paths config/runtime.exs
    # defaults to (R5E_FOLD_NATLANG_SPEC_PATH / R5E_FOLD_CARGO_LOCK_PATH),
    # plus the verifier escript on the release's own ERTS.
    mkdir -p /opt/release/etc/fold && \
    cp specs/010-gateway-api-group/spec.md /opt/release/etc/fold/spec-010.md && \
    cp native/recurse_cedar/Cargo.lock    /opt/release/etc/fold/Cargo.lock && \
    cp /src/r5e-kernel/native/r5e_cedar/Cargo.lock /opt/release/etc/fold/kernel-Cargo.lock && \
    cp /src/repos.lock.json /opt/release/etc/fold/repos.lock.json && \
    mkdir -p /opt/release/share/licenses/dependencies && \
    cp -R /opt/project-licenses/. /opt/release/share/licenses/ && \
    cp -R /opt/dependency-licenses/. /opt/release/share/licenses/dependencies/ && \
    cp /src/r5e-core/verifier/recurse_verify /opt/release/etc/fold/recurse_verify.escript && \
    cp "$(erl -noshell -eval 'io:format("~s",[code:root_dir()]),halt().')/bin/no_dot_erlang.boot" \
       /opt/release/bin/no_dot_erlang.boot && \
    printf '#!/bin/sh\nexec /app/erts-*/bin/escript /app/etc/fold/recurse_verify.escript "$@"\n' \
       > /opt/release/bin/recurse_verify && \
    chmod +x /opt/release/bin/recurse_verify

# Fail-fast architecture assertion, arch-agnostic (spec 012 D7). ELF
# bytes 18-19 = e_machine (little-endian): 0x003e = amd64, 0x00b7 =
# arm64. BuildKit populates TARGETARCH from `--platform`; the legacy
# builder leaves it unset and `uname -m` stands in. Either way the image
# builds natively on Apple Silicon AND under `--platform linux/amd64`, and
# still refuses to ship an ERTS that does not match the manifest it will
# be tagged with.
ARG TARGETARCH
RUN ERLEXEC=$(find /opt/release/erts-*/bin -name erlexec -type f | head -1) && \
    [ -n "$ERLEXEC" ] || { echo "FATAL: erlexec not found in /opt/release" >&2; exit 1; } && \
    MACHINE=$(od -An -t x1 -N 2 -j 18 "$ERLEXEC" | tr -d ' ') && \
    case "${TARGETARCH:-$(uname -m)}" in \
        amd64|x86_64) EXPECTED=3e00 ;; \
        arm64|aarch64) EXPECTED=b700 ;; \
        *) echo "FATAL: unsupported TARGETARCH '${TARGETARCH:-$(uname -m)}'" >&2; exit 1 ;; \
    esac && \
    if [ "$MACHINE" = "$EXPECTED" ]; then \
        echo "[assert] OK: ERTS matches build platform ${TARGETARCH:-$(uname -m)} (ELF e_machine=$MACHINE at $ERLEXEC)"; \
    else \
        echo "FATAL: ERTS architecture mismatch — expected $EXPECTED for ${TARGETARCH:-$(uname -m)}, got $MACHINE for $ERLEXEC" >&2; \
        exit 1; \
    fi

# Belt-and-suspenders SPA + NIF presence asserts (same shape as
# build:release's release-tarball checks; we run them on the staged
# release dir directly here).
RUN test -f /opt/release/lib/recurse_gateway-*/priv/static/admin/index.html || \
        { echo "FATAL: SPA missing from staged release" >&2; exit 1; } && \
    test -f /opt/release/lib/recurse_gateway-*/priv/static/admin/vs/loader.js || \
        { echo "FATAL: Monaco bundle (vs/loader.js) missing — Policy Simulator will hang" >&2; exit 1; } && \
    test -f /opt/release/lib/recurse_shared-*/priv/native/recurse_cedar.so || \
        { echo "FATAL: cedar NIF missing from staged release" >&2; exit 1; } && \
    test -f /opt/release/lib/recurse_shared-*/priv/native/recurse_spiffe.so || \
        { echo "FATAL: spiffe NIF missing from staged release" >&2; exit 1; } && \
    test -f /opt/release/lib/recurse_gateway-*/priv/cedar/schema.cedarschema.json || \
        { echo "FATAL: Cedar entity schema missing from staged release" >&2; exit 1; } && \
    test -d /opt/release/lib/recurse_fold-*/priv/kinds || \
        { echo "FATAL: the fold (recurse_fold) missing from staged release" >&2; exit 1; } && \
    test -d /opt/release/lib/r5e-*/priv/kinds || \
        { echo "FATAL: the kernel (r5e) missing from staged release" >&2; exit 1; } && \
    test -d /opt/release/lib/recurse_verify-*/ebin || \
        { echo "FATAL: recurse_verify missing from staged release" >&2; exit 1; } && \
    test -s /opt/release/etc/fold/spec-010.md && \
    test -s /opt/release/etc/fold/Cargo.lock && \
    test -s /opt/release/etc/fold/kernel-Cargo.lock && \
    test -s /opt/release/etc/fold/repos.lock.json && \
    test -s /opt/release/share/licenses/r5e-enterprise/LICENSE && \
    test -s /opt/release/share/licenses/r5e-kernel/LICENSE && \
    test -s /opt/release/share/licenses/r5e-core/LICENSE && \
    test -s /opt/release/share/licenses/r5e-core/LICENSE.md && \
    test -n "$(find /opt/release/share/licenses/dependencies/mix -type f -print -quit)" && \
    test -n "$(find /opt/release/share/licenses/dependencies/npm -type f -print -quit)" && \
    test -n "$(find /opt/release/share/licenses/dependencies/cargo -type f -print -quit)" || \
        { echo "FATAL: release inputs or license texts missing from staged release" >&2; exit 1; } && \
    echo "[assert] OK: SPA + Monaco + NIFs + Cedar schema + fold + kernel + license texts present in staged release"

# Stable, version-independent path for the Cedar entity schema so
# RECURSE_POLICY_SCHEMA_PATH does not have to encode the
# `recurse_gateway-<version>` lib directory name.
RUN mkdir -p /opt/release/etc/cedar && \
    cp /opt/release/lib/recurse_gateway-*/priv/cedar/schema.cedarschema.json \
       /opt/release/etc/cedar/schema.cedarschema.json

# ---------------------------------------------------------------------- #
# Runtime stage — debian:bookworm-slim. ABI matches the build stage.
# No support/openssl/lib/ bundling: the BEAM's crypto.so was linked
# against this same libssl3 / libcrypto3 that we apt-install here.
# ---------------------------------------------------------------------- #
FROM debian:bookworm-slim AS runtime

RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
        openssl libstdc++6 libgcc-s1 ca-certificates curl bash && \
    rm -rf /var/lib/apt/lists/*

# Non-root runtime user (spec 012 §13 container hardening). uid/gid 1000
# so a single-user host's bind mounts line up. `/secrets`, `/data/cas`
# and `/policy` are created here, owned by that user, so the named
# volumes compose mounts there inherit the ownership on first creation
# and the entrypoint can write first-boot key material (and the policy
# volume's seed link, spec 012 S5) without root.
RUN groupadd --gid 1000 recurse && \
    useradd --uid 1000 --gid recurse --home-dir /app --no-create-home \
            --shell /usr/sbin/nologin recurse && \
    mkdir -p /secrets /data/cas /data/kernel /policy && \
    chown recurse:recurse /secrets /data/cas /data/kernel /policy && \
    chmod 700 /secrets /data/kernel

WORKDIR /app

COPY --from=build --chown=recurse:recurse /opt/release/ ./
COPY --chown=recurse:recurse r5e-enterprise/docker-compose/gateway-entrypoint.sh /app/bin/entrypoint.sh
RUN chmod +x /app/bin/entrypoint.sh

# Baked Cedar entity schema (copied to a version-independent path in the
# build stage). Operators supply the policy bundle; the schema ships with
# the image because it is part of the gateway's contract, not policy.
#
# RELEASE_TMP: the release script writes its runtime sys.config under
# this dir; pointing it at /tmp lets the root filesystem be mounted
# read-only (compose: `read_only: true` + tmpfs /tmp). Crash dumps go
# there too.
ENV HOME=/app \
    LANG=C.UTF-8 \
    RECURSE_POLICY_SCHEMA_PATH=/app/etc/cedar/schema.cedarschema.json \
    RELEASE_TMP=/tmp \
    ERL_CRASH_DUMP=/tmp/erl_crash.dump

USER recurse

# 4000 = audit plane (dashboard + API); 4443 = LLM proxy listener.
EXPOSE 4000 4443

# The entrypoint generates first-boot secrets + runs migrations, then
# exec's `bin/audit_console <cmd>` (spec 012 S1). Override CMD for
# `eval` / `remote` / `rpc` — the entrypoint passes arguments through.
ENTRYPOINT ["/app/bin/entrypoint.sh"]
CMD ["start"]
