#!/usr/bin/env bash
# Build a linux-arm64 release tarball of the `audit_console` release for
# deploying to the runr5e dogfood box (Graviton2 t4g.large EC2 instance).
#
# Output:
#   /tmp/r5e-enterprise-linux-arm64-release.tar.gz
#   /tmp/r5e-enterprise-linux-arm64-release.sbom.cdx.json
#   /tmp/r5e-enterprise-linux-arm64-release.sbom.cdx.json.sha256
#   /tmp/r5e-enterprise-repo.tar.gz   (repo snapshot — minus build artifacts)
#   /tmp/r5e-source-snapshot.tar.gz   (reproducible core + kernel + enterprise sources)
#   /tmp/r5e-source-snapshot.tar.gz.sha256
#
# The two tarballs are what the `aws-dedicated-beam` Terraform module's
# `beam_instances[].release_archive_path` + `repo_archive_path` expect. The
# SBOM is also embedded inside the release under support/sbom/.
#
# Build runs inside a Docker container (linux/arm64 platform) because:
#   1. ERTS is bundled in the release (`include_erts: true` in mix.exs)
#   2. ERTS is platform-specific — building on macOS-arm64 produces a
#      tarball that won't run on linux-arm64 (different libc, different
#      shared object loader)
#   3. The Cedar + SPIFFE Rustler NIFs also compile to .so files that
#      need to match the target's libc + glibc version
#
# Requires:
#   - docker (with buildx; default on Docker Desktop 4.x+)
#   - Roughly 4GB free disk for the temporary build container layers
#
# Usage:
#   ./scripts/build-release.sh
#
# Optional env:
#   RELEASE_TAG    — appended to tarball filenames (default: timestamp)
#   BUILD_TIMESTAMP — SBOM metadata timestamp (default: current UTC time)
#   VCS_REF        — SBOM source revision (default: jj @ commit id, git fallback)
#   ELIXIR_VERSION — Elixir version in the build container (default: pinned to .tool-versions)
#   OTP_VERSION    — Erlang/OTP version (default: pinned to .tool-versions)
#   RUST_VERSION   — Rust toolchain version for NIF builds (default: pinned to .tool-versions)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

# ------------------------------------------------------------------ #
# Pin versions from .tool-versions (single source of truth)
# ------------------------------------------------------------------ #

ELIXIR_VERSION="${ELIXIR_VERSION:-$(grep '^elixir' .tool-versions | awk '{print $2}')}"
OTP_VERSION="${OTP_VERSION:-$(grep '^erlang' .tool-versions | awk '{print $2}')}"
RUST_VERSION="${RUST_VERSION:-$(grep '^rust' .tool-versions | awk '{print $2}')}"

if [[ -z "${ELIXIR_VERSION}" || -z "${OTP_VERSION}" ]]; then
  echo "FATAL: could not resolve Elixir/OTP versions from .tool-versions" >&2
  exit 1
fi

# `.tool-versions` uses asdf/mise's `1.19.5-otp-28` form to pin the OTP target;
# hexpm/elixir Docker tags use plain `1.19.5`. Strip the suffix.
ELIXIR_BASE_VERSION="${ELIXIR_VERSION%-otp-*}"

# hexpm/elixir publishes images only for the latest OTP patch in each minor
# series. `.tool-versions` says `erlang 28.0` but only `28.5` has a published
# image; 28.5 is forward-compatible with 28.0-targeted code, so we build
# against 28.5 and let the host runtime pin to whatever OTP was bundled.
DOCKER_OTP_VERSION="${DOCKER_OTP_VERSION:-28.5}"
DOCKER_BASE_DATE="${DOCKER_BASE_DATE:-20260421}"

RELEASE_TAG="${RELEASE_TAG:-$(date -u +%Y%m%dT%H%M%SZ)}"
BUILD_TIMESTAMP="${BUILD_TIMESTAMP:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
RELEASE_TARBALL="/tmp/r5e-enterprise-linux-arm64-release.tar.gz"
SBOM_PATH="/tmp/r5e-enterprise-linux-arm64-release.sbom.cdx.json"
SBOM_SHA256_PATH="${SBOM_PATH}.sha256"
REPO_TARBALL="/tmp/r5e-enterprise-repo.tar.gz"
SOURCE_TARBALL="/tmp/r5e-source-snapshot.tar.gz"
SOURCE_SHA256_PATH="${SOURCE_TARBALL}.sha256"
# Tier-config YAMLs that need an integrity sidecar generated. The dogfood
# variant is REQUIRED because the live BEAM loads it (env
# RECURSE_TIER_CONFIG=...dogfood.yaml on the box); the customer-shaped
# reference is included so other deploys that ship the same repo tarball
# but boot from .standalone_gateway.yaml don't get the same `:warn` log
# noise. The IntegrityCheck loader (apps/.../config/integrity_check.ex)
# expects the sidecar to live ADJACENT to the YAML
# (`<name>.sha256`), not at any env-overridden path.
TIER_CONFIG_YAMLS=(
  "${REPO_ROOT}/config/reference/tier-config.dogfood.yaml"
  "${REPO_ROOT}/config/reference/tier-config.standalone_gateway.yaml"
)
VCS_REF="${VCS_REF:-$(jj log -r @ --no-graph --template 'commit_id' 2>/dev/null || echo unknown)}"

# ------------------------------------------------------------------ #
# Stage A — repo snapshot tarball (uploaded by Terraform to S3 CAS,
#           extracted into per-instance `repo_root` on the EC2 host).
#           Excludes build artifacts so the tarball stays small.
# ------------------------------------------------------------------ #

echo "[build-release] (A0) tier-config integrity sidecars"
for yaml in "${TIER_CONFIG_YAMLS[@]}"; do
  if [ -f "${yaml}" ]; then
    "${REPO_ROOT}/scripts/compute-tier-config-hash.sh" "${yaml}"
  else
    echo "[build-release] (A0) skip: ${yaml} not present"
  fi
done

echo "[build-release] (A) repo snapshot → ${REPO_TARBALL}"
SOURCE_STAGE=$(mktemp -d -t r5e-source-XXXXXX)
python3 "${REPO_ROOT}/scripts/prepare-release.py" \
  --output "${SOURCE_STAGE}/context" \
  --archive "${SOURCE_TARBALL}"
# R4-F6: recompute the three archiveSha256 values from the context that is
# about to be built, before anything downstream treats the manifest as a
# fact. The image build runs the same check inside its own `verify-sources`
# stage; this one runs first and fails cheaply.
python3 "${REPO_ROOT}/scripts/verify-source-archive.py" \
  --manifest "${SOURCE_STAGE}/context/repos.lock.json" \
  "${SOURCE_STAGE}/context"
python3 "${REPO_ROOT}/scripts/release-snapshot.py" \
  --repo "${REPO_ROOT}" --output "${REPO_TARBALL}"
cp "${SOURCE_STAGE}/context/repos.lock.json" "${REPO_TARBALL}.repos.lock.json"
SOURCE_SHA256=$(shasum -a 256 "${SOURCE_TARBALL}" | awk '{print $1}')
printf '%s' "${SOURCE_SHA256}" > "${SOURCE_SHA256_PATH}"

REPO_SIZE=$(du -h "${REPO_TARBALL}" | awk '{print $1}')
echo "[build-release] (A) repo snapshot done — ${REPO_SIZE}"
echo "[build-release] (A) coordinated source snapshot — ${SOURCE_SHA256}"

# ------------------------------------------------------------------ #
# Stage B — release build inside linux/arm64 Docker container
#           Output: a release tarball that runs natively on Graviton2.
# ------------------------------------------------------------------ #

echo "[build-release] (B) release build (linux/arm64 in Docker)"
echo "[build-release]     elixir=${ELIXIR_BASE_VERSION} otp-image=${DOCKER_OTP_VERSION} (target ${OTP_VERSION}) rust=${RUST_VERSION}"

# We use the official hexpm/elixir image which bundles a known-good
# Elixir+OTP pair on top of debian-bookworm (libc 2.36+; matches what
# Amazon Linux 2023 ships, so the resulting binary will load cleanly
# on the t4g host).
DOCKER_IMAGE="hexpm/elixir:${ELIXIR_BASE_VERSION}-erlang-${DOCKER_OTP_VERSION}-debian-bookworm-${DOCKER_BASE_DATE}"

# Output volume — the container drops the tarball here so the host
# can pick it up after the container exits.
OUT_DIR="$(mktemp -d -t r5e-release-XXXXXX)"
# Cache restore/save dir — populated from S3 before docker run, archived
# back to S3 after. Mounted into the container as /work-cache.
CACHE_DIR="$(mktemp -d -t r5e-build-cache-XXXXXX)"
trap 'rm -rf "${OUT_DIR}" "${CACHE_DIR}" "${SOURCE_STAGE}"' EXIT

# ------------------------------------------------------------------ #
# Stage B0 — S3-backed build cache (lock-file-keyed)
#
# Cache key = the coordinated source snapshot SHA-256. Any change in core,
# kernel, or enterprise gets a fresh cache; an identical three-source input
# can restore _build / deps / native/*/target trees.
#
# Skipped when:
#   - R5E_BUILD_CACHE_DISABLED=1 (force cold build)
#   - aws CLI not on PATH (no-op cleanly; no error)
#   - aws sts get-caller-identity fails (no creds — local dev without OIDC)
# ------------------------------------------------------------------ #

CACHE_BUCKET="${R5E_BUILD_CACHE_BUCKET:-runr5e-platform-cas}"
CACHE_PREFIX="${R5E_BUILD_CACHE_PREFIX:-ci-cache}"
CACHE_KEY="${SOURCE_SHA256}"
CACHE_S3="s3://${CACHE_BUCKET}/${CACHE_PREFIX}/${CACHE_KEY}/build-cache.tar.zst"

if [ "${R5E_BUILD_CACHE_DISABLED:-1}" = "1" ]; then
  echo "[build-release] (B0) cache DISABLED via R5E_BUILD_CACHE_DISABLED=1"
elif ! command -v aws >/dev/null 2>&1; then
  echo "[build-release] (B0) cache SKIPPED — aws CLI not found"
elif ! aws sts get-caller-identity >/dev/null 2>&1; then
  echo "[build-release] (B0) cache SKIPPED — no AWS creds (local dev path)"
elif aws s3 ls "${CACHE_S3}" >/dev/null 2>&1; then
  echo "[build-release] (B0) cache HIT — pulling ${CACHE_S3}"
  aws s3 cp "${CACHE_S3}" "${CACHE_DIR}/cache.tar.zst" --quiet --no-progress
  if command -v zstd >/dev/null 2>&1; then
    tar --use-compress-program=zstd -xf "${CACHE_DIR}/cache.tar.zst" -C "${CACHE_DIR}"
  else
    # Fallback: zstd may be absent on the host; container has it
    cp "${CACHE_DIR}/cache.tar.zst" "${CACHE_DIR}/cache.tar.zst.deferred"
  fi
  rm -f "${CACHE_DIR}/cache.tar.zst"
  echo "[build-release] (B0) cache restored to ${CACHE_DIR}"
else
  echo "[build-release] (B0) cache MISS — cold build (key: ${CACHE_KEY})"
fi

# Build inside container. The whole repo is mounted read-only; only
# /out is writable. The build itself happens in /work which is a
# container-local copy so the host's _build/deps are untouched.
docker run --rm \
  --platform linux/arm64 \
  -v "${SOURCE_STAGE}/context:/repo:ro" \
  -v "${OUT_DIR}:/out" \
  -v "${CACHE_DIR}:/work-cache:rw" \
  -e MIX_ENV=prod \
  -e RELEASE_TAG="${RELEASE_TAG}" \
  -e BUILD_TIMESTAMP="${BUILD_TIMESTAMP}" \
  -e VCS_REF="${VCS_REF}" \
  -e RELEASE_TARBALL_BASENAME="$(basename "${RELEASE_TARBALL}")" \
  -e ELIXIR_VERSION="${ELIXIR_VERSION}" \
  -e OTP_VERSION="${OTP_VERSION}" \
  -e RUST_VERSION="${RUST_VERSION}" \
  "${DOCKER_IMAGE}" \
  bash -euxc '
    apt-get update -qq
    apt-get install -y -qq \
      build-essential \
      curl \
      git \
      pkg-config \
      libssl-dev \
      zstd

    # If a deferred cache tarball was passed (host had no zstd), unpack now.
    if [ -f /work-cache/cache.tar.zst.deferred ]; then
      tar --use-compress-program=zstd -xf /work-cache/cache.tar.zst.deferred -C /work-cache
      rm /work-cache/cache.tar.zst.deferred
    fi

    # Rust toolchain for the Cedar + SPIFFE NIFs
    curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- --default-toolchain "${RUST_VERSION}" --profile minimal -y
    export PATH="${HOME}/.cargo/bin:${PATH}"

    # Copy repo CONTENTS into /work. `cp -a /repo /work` would create
    # /work/repo/ if /work pre-exists (some Docker images / runner
    # configurations set WORKDIR /work), which silently breaks `mix`
    # later ("Could not find a Mix.Project"). Use the `/repo/.` form
    # to copy contents regardless of /work pre-existence.
    mkdir -p /work
    cp -a /repo/r5e-enterprise/. /work/
    cp -a /repo/r5e-kernel /r5e-kernel
    cp -a /repo/r5e-core /r5e-core
    cd /work

    # Build UI from the same frozen source; ignored local dist is never an input.
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y -qq nodejs
    corepack enable
    corepack prepare pnpm@9.15.0 --activate
    (cd ui && pnpm install --frozen-lockfile && pnpm run build && pnpm run sync-to-priv)
    # Cold-build hygiene: only nuke caches that were NOT restored from S3.
    # If /work-cache/_build was populated by Stage B0, copy it in; otherwise
    # rm the empty/missing tree to force a clean build.
    for cache_path in _build deps native/recurse_cedar/target native/recurse_spiffe/target; do
      if [ -d "/work-cache/${cache_path}" ]; then
        echo "[container] cache restore: ${cache_path}"
        mkdir -p "$(dirname /work/${cache_path})"
        cp -a "/work-cache/${cache_path}" "/work/${cache_path}"
      else
        rm -rf "/work/${cache_path}"
      fi
    done

    # Mix builds — these no-op for unchanged deps when cache is warm.
    mix local.hex --force
    mix local.rebar --force
    mix deps.get --only prod
    mix deps.compile
    mix compile

    # After build: stage the cache contents into /work-cache so the
    # outer script can archive them to S3.
    for cache_path in _build deps native/recurse_cedar/target native/recurse_spiffe/target; do
      if [ -d "/work/${cache_path}" ]; then
        rm -rf "/work-cache/${cache_path}"
        mkdir -p "$(dirname /work-cache/${cache_path})"
        cp -a "/work/${cache_path}" "/work-cache/${cache_path}"
      fi
    done

    # Release assemble + tar (steps: [:assemble, :tar] in mix.exs)
    mix release audit_console
    RELEASE_VERSION=$(elixir -e "Mix.start(); Code.require_file(\"mix.exs\"); IO.write(Recurse.MixProject.project()[:version])")
    ERTS_VERSION=$(erl -noshell -eval "io:format(\"~s\", [erlang:system_info(version)]), halt().")
    OPENSSL_VERSION=$(openssl version)

    # Mix release writes to _build/prod/rel/audit_console/audit_console-VERSION.tar.gz
    # Find it (the version comes from project[:version]) and copy to /out
    RELEASE_TGZ=$(ls /work/_build/prod/audit_console-*.tar.gz | head -1)
    if [[ -z "${RELEASE_TGZ}" ]]; then
      echo "FATAL: mix release did not produce a tarball under _build/prod/" >&2
      ls -la /work/_build/prod/ >&2
      exit 1
    fi

    # Bundle the build containers OpenSSL libs into the release. The crypto
    # NIF (`crypto.so`) was linked against the build hosts libssl/libcrypto
    # which has SM4 cipher support (`EVP_sm4_cbc@OPENSSL_3.0.0`). Amazon
    # Linux 2023 strips SM4 from its OpenSSL package, so loading crypto.so
    # against system libcrypto fails with `undefined symbol: EVP_sm4_cbc`.
    # Bundling the build hosts libs and pointing the runtime
    # `LD_LIBRARY_PATH` (set in beam-user-data.sh.tftpl) at them resolves
    # the NIF without needing SM4 in the host OpenSSL.
    STAGE_DIR=$(mktemp -d /tmp/release-restage-XXXXXX)
    tar -xzf "${RELEASE_TGZ}" -C "${STAGE_DIR}"
    mkdir -p "${STAGE_DIR}/etc/fold"
    cp specs/010-gateway-api-group/spec.md "${STAGE_DIR}/etc/fold/spec-010.md"
    cp native/recurse_cedar/Cargo.lock "${STAGE_DIR}/etc/fold/Cargo.lock"
    cp /r5e-kernel/native/r5e_cedar/Cargo.lock "${STAGE_DIR}/etc/fold/kernel-Cargo.lock"
    cp /repo/repos.lock.json "${STAGE_DIR}/etc/fold/repos.lock.json"
    mkdir -p "${STAGE_DIR}/share/licenses/r5e-enterprise" \
      "${STAGE_DIR}/share/licenses/r5e-kernel" \
      "${STAGE_DIR}/share/licenses/r5e-core"
    cp /work/LICENSE "${STAGE_DIR}/share/licenses/r5e-enterprise/LICENSE"
    cp /r5e-kernel/LICENSE "${STAGE_DIR}/share/licenses/r5e-kernel/LICENSE"
    cp /r5e-core/LICENSE "${STAGE_DIR}/share/licenses/r5e-core/LICENSE"
    cp /r5e-core/LICENSE.md "${STAGE_DIR}/share/licenses/r5e-core/LICENSE.md"
    copy_license_tree() {
      local source_root="$1"
      local destination_root="$2"
      local max_depth="$3"
      mkdir -p "${destination_root}"
      while IFS= read -r -d "" license_file; do
        relative="${license_file#${source_root}/}"
        destination="${destination_root}/${relative}"
        mkdir -p "$(dirname "${destination}")"
        cp "${license_file}" "${destination}"
      done < <(find "${source_root}" -mindepth 1 -maxdepth "${max_depth}" -type f \
        \( -iname "LICENSE*" -o -iname "LICENCE*" -o -iname "NOTICE*" \
          -o -iname "COPYING*" -o -iname "COPYRIGHT*" \) -print0)
      test -n "$(find "${destination_root}" -type f -print -quit)"
    }
    copy_license_tree /work/deps "${STAGE_DIR}/share/licenses/dependencies/mix" 4
    copy_license_tree /work/ui/node_modules "${STAGE_DIR}/share/licenses/dependencies/npm" 8
    copy_license_tree "${CARGO_HOME:-${HOME}/.cargo}/registry/src" \
      "${STAGE_DIR}/share/licenses/dependencies/cargo" 7
    mkdir -p "${STAGE_DIR}/support/openssl/lib"
    for libname in libssl.so.3 libcrypto.so.3; do
      libpath=$(find /usr/lib /usr/lib64 -name "${libname}" 2>/dev/null | head -1)
      if [[ -z "${libpath}" ]]; then
        echo "FATAL: could not locate ${libname} in build container" >&2
        exit 1
      fi
      cp -L "${libpath}" "${STAGE_DIR}/support/openssl/lib/"
    done
    if [[ -d /usr/lib/aarch64-linux-gnu/ossl-modules ]]; then
      cp -aL /usr/lib/aarch64-linux-gnu/ossl-modules "${STAGE_DIR}/support/openssl/lib/"
    elif [[ -d /usr/lib/ossl-modules ]]; then
      cp -aL /usr/lib/ossl-modules "${STAGE_DIR}/support/openssl/lib/"
    fi

    mkdir -p "${STAGE_DIR}/support/sbom"
    elixir -pa _build/prod/lib/recurse_shared/ebin scripts/generate-release-sbom.exs \
      --output "${STAGE_DIR}/support/sbom/audit_console.sbom.cdx.json" \
      --release-root "${STAGE_DIR}" \
      --release-name audit_console \
      --release-version "${RELEASE_VERSION}" \
      --release-tag "${RELEASE_TAG}" \
      --vcs-ref "${VCS_REF}" \
      --build-time "${BUILD_TIMESTAMP}" \
      --elixir-version "${ELIXIR_VERSION}" \
      --otp-version "${OTP_VERSION}" \
      --erts-version "${ERTS_VERSION}" \
      --rust-version "${RUST_VERSION}" \
      --openssl-version "${OPENSSL_VERSION}"

    tar -czf /out/release.tar.gz -C "${STAGE_DIR}" .
    RELEASE_SHA256=$(sha256sum /out/release.tar.gz | awk "{print \$1}")

    # The embedded copy is useful in-place release metadata. The canonical
    # sidecar is emitted after tarball creation so it can bind the final
    # release archive digest without creating a self-referential tarball hash.
    elixir -pa _build/prod/lib/recurse_shared/ebin scripts/generate-release-sbom.exs \
      --output /out/audit_console.sbom.cdx.json \
      --release-root "${STAGE_DIR}" \
      --release-name audit_console \
      --release-version "${RELEASE_VERSION}" \
      --release-tag "${RELEASE_TAG}" \
      --vcs-ref "${VCS_REF}" \
      --build-time "${BUILD_TIMESTAMP}" \
      --elixir-version "${ELIXIR_VERSION}" \
      --otp-version "${OTP_VERSION}" \
      --erts-version "${ERTS_VERSION}" \
      --rust-version "${RUST_VERSION}" \
      --openssl-version "${OPENSSL_VERSION}" \
      --release-tarball-path /out/release.tar.gz \
      --release-tarball-name "${RELEASE_TARBALL_BASENAME}"
    SBOM_SHA256=$(sha256sum /out/audit_console.sbom.cdx.json | awk "{print \$1}")
    printf "%s" "${SBOM_SHA256}" > /out/audit_console.sbom.cdx.json.sha256

    rm -rf "${STAGE_DIR}"
    echo "release tarball: $(du -h /out/release.tar.gz | awk "{print \$1}")"
    echo "release tarball sha256: ${RELEASE_SHA256}"
    echo "bundled openssl libs:"
    tar -tzf /out/release.tar.gz | grep "^./support/openssl/" | head -10
    echo "release sbom:"
    tar -tzf /out/release.tar.gz | grep "^./support/sbom/audit_console.sbom.cdx.json$"
  '

cp "${OUT_DIR}/release.tar.gz" "${RELEASE_TARBALL}"
cp "${OUT_DIR}/audit_console.sbom.cdx.json" "${SBOM_PATH}"
cp "${OUT_DIR}/audit_console.sbom.cdx.json.sha256" "${SBOM_SHA256_PATH}"
RELEASE_SIZE=$(du -h "${RELEASE_TARBALL}" | awk '{print $1}')
SBOM_SIZE=$(du -h "${SBOM_PATH}" | awk '{print $1}')
SBOM_SHA256=$(cat "${SBOM_SHA256_PATH}")
echo "[build-release] (B) release build done — ${RELEASE_SIZE}"
echo "[build-release] (C) release SBOM done — ${SBOM_SIZE}"

# ------------------------------------------------------------------ #
# Stage B1 — push warm cache to S3 so the NEXT build can skip
#            deps + NIF compile.
#
# Uses the same lock-keyed key as the restore step. We tar with zstd
# (-19 for ratio; runtime decompress is the hot path, compress is one-
# shot per build). Skipped under the same conditions as the restore
# (disabled, no aws, no creds).
# ------------------------------------------------------------------ #

if [ "${R5E_BUILD_CACHE_DISABLED:-1}" = "1" ]; then
  : # skip
elif ! command -v aws >/dev/null 2>&1; then
  : # skip
elif ! aws sts get-caller-identity >/dev/null 2>&1; then
  : # skip
elif [ -d "${CACHE_DIR}/_build" ] && [ -d "${CACHE_DIR}/deps" ]; then
  echo "[build-release] (B1) cache SAVE — packing ${CACHE_DIR} → ${CACHE_S3}"
  if command -v zstd >/dev/null 2>&1; then
    tar --use-compress-program='zstd -19 -T0' \
        -cf "${CACHE_DIR}/cache.tar.zst" \
        -C "${CACHE_DIR}" \
        _build deps native 2>/dev/null || true
  else
    # Container always has zstd; if host lacks it, skip the save.
    # (The container can't reach back out to push to S3 without AWS
    # creds — those live in the host shell. Future: pass STS creds
    # into the container so save can happen there.)
    echo "[build-release] (B1) cache SAVE SKIPPED — host lacks zstd"
    return 0 2>/dev/null || true
  fi
  if [ -f "${CACHE_DIR}/cache.tar.zst" ]; then
    PACK_SIZE=$(du -h "${CACHE_DIR}/cache.tar.zst" | awk '{print $1}')
    aws s3 cp "${CACHE_DIR}/cache.tar.zst" "${CACHE_S3}" --quiet --no-progress
    echo "[build-release] (B1) cache SAVED (${PACK_SIZE}) → ${CACHE_S3}"
  fi
fi

# ------------------------------------------------------------------ #
# Done.
# ------------------------------------------------------------------ #

cat <<EOF

[build-release] OK
  repo snapshot:    ${REPO_TARBALL} (${REPO_SIZE})
  source snapshot:  ${SOURCE_TARBALL} (${SOURCE_SHA256})
  source digest:    ${SOURCE_SHA256_PATH}
  release tarball:  ${RELEASE_TARBALL} (${RELEASE_SIZE})
  release SBOM:     ${SBOM_PATH} (${SBOM_SIZE})
  release SBOM sha: ${SBOM_SHA256_PATH} (${SBOM_SHA256})
  release tag:      ${RELEASE_TAG}
  vcs ref:          ${VCS_REF}

Next:
  1. Confirm Terraform tfvars in r5e-ai/core/infra/terraform/aws-dedicated-beam/
     point at these paths (beam_release_archive_path + beam_repo_archive_path).
  2. cd ~/repos/r5e-ai/core/infra/terraform/aws-dedicated-beam && terraform apply
     — uploads both tarballs to S3 CAS and reboots the audit-dev instance.

EOF
