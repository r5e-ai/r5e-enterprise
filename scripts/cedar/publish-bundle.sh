#!/usr/bin/env bash
#
# Publish a Cedar policy bundle to ECR as a cosign-verified OCI artifact.
#
# This is the OPERATOR-side companion to the CI job
# `cedar-bundle:publish` (.gitlab-ci.yml line ~706). The CI job is
# scoped to `apps/recurse_gateway/priv/reference_policies/*.cedar`;
# this script generalizes the same pipeline to bundles that live
# elsewhere (e.g. spec-009's eddy_smoke fixture under
# `specs/009-llm-api-proxy/fixtures/cedar/eddy_smoke/`).
#
# Follow-on Linear issues will:
#   1. Provision `cedar-policies/<bundle-name>` ECR repos via Terraform
#      in `r5e-platform-config` (so the future CI job can assume they
#      exist).
#   2. Generalize the CI job to a matrix over bundle name + policy file
#      + ECR repo (auto-discovers bundles in
#      `apps/recurse_gateway/priv/reference_policies/` AND
#      `specs/*/fixtures/cedar/*/`).
#
# Tonight's path was time-boxed for spec-009 demo readiness; this
# script is the runbook today, CI generalization replaces it cleanly.
#
# Usage:
#   AWS_PROFILE=r5e-platform-admin \
#     scripts/cedar/publish-bundle.sh <bundle-name> <policy-file> [--dry-run]
#
# Examples:
#   # eddy_smoke fixture (spec-009 demo)
#   AWS_PROFILE=r5e-platform-admin scripts/cedar/publish-bundle.sh \
#     eddy-smoke specs/009-llm-api-proxy/fixtures/cedar/eddy_smoke/bundle.cedar
#
#   # platform-roles (mirror of the CI job, for emergency manual publishes)
#   AWS_PROFILE=r5e-platform-admin scripts/cedar/publish-bundle.sh \
#     platform-roles apps/recurse_gateway/priv/reference_policies/platform_roles.cedar
#
# Output:
#   - Pushes OCI artifact to
#       $R5E_ECR_REGISTRY/cedar-policies/<bundle-name>:<version>
#     where <version> = "<bundle-name>-<8-hex-content-hash>-<git-short-sha>"
#     and R5E_ECR_REGISTRY is your own registry, e.g.
#       123456789012.dkr.ecr.us-west-2.amazonaws.com
#   - Cosign-signs via KMS key alias `awskms:///alias/r5e-cosign`
#   - Prints BUNDLE_REF / BUNDLE_DIGEST / BUNDLE_VERSION on stdout
#
# Prerequisites:
#   - AWS CLI v2 + active session (AWS_PROFILE set; aws sts
#     get-caller-identity must succeed)
#   - oras (https://oras.land) v1.2+
#   - cosign (https://docs.sigstore.dev/cosign/) v2+
#   - jq, sha256sum, docker (for cosign's docker config.json auth)
#
# Reference:
#   - .gitlab-ci.yml :: cedar-bundle:publish (the CI version)
#   - apps/recurse_providers/lib/recurse_providers/impls/oci_policy_provider.ex
#     (consumer — pulls + cosign-verifies + canonicalizes the bundle)
#   - apps/recurse_gateway/lib/recurse_gateway/policy/oci_bundle_manager.ex
#     (per-deploy bundle manager that wires init/activate)
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------

if [ $# -lt 2 ]; then
  echo "usage: $0 <bundle-name> <policy-file> [--dry-run]" >&2
  echo "  bundle-name : ECR repo suffix under cedar-policies/" >&2
  echo "  policy-file : path to .cedar source" >&2
  echo "  --dry-run   : skip ECR push + cosign sign" >&2
  exit 64
fi

BUNDLE_NAME="$1"
POLICY_FILE="$2"
DRY_RUN="${3:-}"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# Resolve POLICY_FILE relative to repo root if it isn't absolute.
case "$POLICY_FILE" in
  /*) ABS_POLICY="$POLICY_FILE" ;;
  *)  ABS_POLICY="$REPO_ROOT/$POLICY_FILE" ;;
esac

if [ ! -f "$ABS_POLICY" ]; then
  echo "[err] policy file not found: $ABS_POLICY" >&2
  exit 66
fi

SCHEMA_FILE="$REPO_ROOT/apps/recurse_gateway/priv/cedar/schema.cedarschema.json"
if [ ! -f "$SCHEMA_FILE" ]; then
  echo "[err] schema file not found: $SCHEMA_FILE" >&2
  exit 66
fi

# ---------------------------------------------------------------------------
# Config — must mirror the CI job exactly so OciPolicyProvider can pull
# bundles produced by either pipeline interchangeably.
# ---------------------------------------------------------------------------

# The registry, the signing key and the region are this deployment's, not
# this repository's: set them in the environment. The CI job that mirrors
# this script sets the same three.
ECR_REGISTRY="${R5E_ECR_REGISTRY:?set R5E_ECR_REGISTRY, e.g. 123456789012.dkr.ecr.us-west-2.amazonaws.com}"
ECR_REPO="cedar-policies/${BUNDLE_NAME}"
COSIGN_KMS_KEY="${R5E_COSIGN_KMS_KEY:-awskms:///alias/r5e-cosign}"
AWS_REGION="${AWS_REGION:-us-west-2}"

# ---------------------------------------------------------------------------
# Tooling preflight
# ---------------------------------------------------------------------------

require_bin() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[err] required tool not on PATH: $1" >&2
    exit 67
  fi
}

require_bin aws
require_bin oras
require_bin cosign
require_bin jq
require_bin sha256sum
require_bin docker

if ! aws sts get-caller-identity --region "$AWS_REGION" >/dev/null 2>&1; then
  echo "[err] AWS credentials not active. Set AWS_PROFILE (e.g. r5e-platform-admin) and run 'aws sso login'." >&2
  exit 68
fi

# ---------------------------------------------------------------------------
# Build bundle artifact (3 layers: policy + schema + manifest sidecar)
# ---------------------------------------------------------------------------

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

cp "$ABS_POLICY"    "$WORKDIR/policy.cedar"
cp "$SCHEMA_FILE"   "$WORKDIR/entities.cedarschema.json"

# Content-hash matches the CI job exactly: policy bytes || schema bytes.
CONTENT_HASH=$(cat "$WORKDIR/policy.cedar" "$WORKDIR/entities.cedarschema.json" | sha256sum | awk '{print $1}')
CONTENT_HASH_PREFIX_8="${CONTENT_HASH:0:8}"

# Local commit short-sha (operator-time analog of $CI_COMMIT_SHORT_SHA).
# We want the working-copy commit (`@`) so the bundle version embeds
# the in-flight feature work. Falls back to git, then to "operator".
if command -v jj >/dev/null 2>&1; then
  GIT_SHORT_SHA=$(jj log -r '@' --no-graph -T 'commit_id.short()' 2>/dev/null || echo "")
fi
if [ -z "${GIT_SHORT_SHA:-}" ] && command -v git >/dev/null 2>&1; then
  GIT_SHORT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "00000000")
fi
GIT_SHORT_SHA="${GIT_SHORT_SHA:-operator}"

VERSION="${BUNDLE_NAME}-${CONTENT_HASH_PREFIX_8}-${GIT_SHORT_SHA}"
BUNDLE_REF="${ECR_REGISTRY}/${ECR_REPO}:${VERSION}"
CREATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
AUTHOR="${USER:-operator}"

cat > "$WORKDIR/manifest.json" <<MANIFEST
{
  "name": "${BUNDLE_NAME}",
  "version": "${VERSION}",
  "author": "${AUTHOR}",
  "created_at": "${CREATED_AT}",
  "git_sha": "${GIT_SHORT_SHA}",
  "content_hash": "sha256:${CONTENT_HASH}",
  "source": "operator-script",
  "source_file": "${POLICY_FILE}"
}
MANIFEST

echo "[bundle] built artifact:"
echo "  name         : ${BUNDLE_NAME}"
echo "  ref          : ${BUNDLE_REF}"
echo "  content-hash : sha256:${CONTENT_HASH}"
echo "  policy file  : ${POLICY_FILE}"
echo "  schema file  : apps/recurse_gateway/priv/cedar/schema.cedarschema.json"
echo "  author       : ${AUTHOR}"

if [ "$DRY_RUN" = "--dry-run" ]; then
  echo "[bundle] --dry-run set; skipping ECR push + cosign sign."
  echo "[bundle] artifact staged in $WORKDIR (deleted on exit)."
  exit 0
fi

# ---------------------------------------------------------------------------
# Ensure ECR repo exists (operator-time analog of Terraform IaC).
#
# Safe to run repeatedly: aws ecr create-repository returns
# RepositoryAlreadyExistsException which we tolerate.
# ---------------------------------------------------------------------------

if ! aws ecr describe-repositories --region "$AWS_REGION" \
     --repository-names "$ECR_REPO" >/dev/null 2>&1; then
  echo "[ecr] creating repo $ECR_REPO (immutable tags, AES256)..."
  aws ecr create-repository \
    --region "$AWS_REGION" \
    --repository-name "$ECR_REPO" \
    --image-tag-mutability IMMUTABLE \
    --encryption-configuration encryptionType=AES256 \
    --tags Key=managed-by,Value=publish-bundle.sh Key=spec,Value=009-llm-api-proxy \
    >/dev/null
fi

# ---------------------------------------------------------------------------
# Login to ECR for both oras (push) and docker (cosign reads ~/.docker/config.json).
# ---------------------------------------------------------------------------

echo "[auth] logging in to ECR..."

ECR_PASSWORD=$(aws ecr get-login-password --region "$AWS_REGION")

echo "$ECR_PASSWORD" | oras login --username AWS --password-stdin "$ECR_REGISTRY" >/dev/null
echo "$ECR_PASSWORD" | docker login --username AWS --password-stdin "$ECR_REGISTRY" >/dev/null

# ---------------------------------------------------------------------------
# Idempotency guard — skip push if same VERSION already in ECR.
# ---------------------------------------------------------------------------

if aws ecr describe-images --region "$AWS_REGION" \
     --repository-name "$ECR_REPO" \
     --image-ids "imageTag=${VERSION}" >/dev/null 2>&1; then
  echo "[ecr] bundle ${BUNDLE_REF} already in ECR — skipping push (idempotent)."
else
  echo "[ecr] pushing ${BUNDLE_REF}..."
  cd "$WORKDIR"
  oras push "$BUNDLE_REF" \
    --artifact-type "application/vnd.cedar.policy.v1" \
    "policy.cedar:application/vnd.cedar.policy.v1.layer" \
    "entities.cedarschema.json:application/vnd.cedar.policy.v1.layer" \
    "manifest.json:application/vnd.cedar.policy.v1.manifest" \
    --annotation "org.opencontainers.image.title=${BUNDLE_NAME}" \
    --annotation "org.opencontainers.image.version=${VERSION}" \
    --annotation "org.opencontainers.image.created=${CREATED_AT}" \
    --annotation "org.opencontainers.image.authors=${AUTHOR}" \
    --annotation "org.opencontainers.image.source=operator-script:scripts/cedar/publish-bundle.sh"
  cd - >/dev/null
fi

# ---------------------------------------------------------------------------
# Cosign sign (idempotent — cosign signs by digest; same digest → same sig).
# ---------------------------------------------------------------------------

echo "[cosign] signing ${BUNDLE_REF} with ${COSIGN_KMS_KEY}..."
cosign sign --yes --key "$COSIGN_KMS_KEY" "$BUNDLE_REF"

# ---------------------------------------------------------------------------
# Resolve final manifest digest + emit summary.
# ---------------------------------------------------------------------------

DIGEST=$(oras manifest fetch --descriptor "$BUNDLE_REF" | jq -r .digest)

echo
echo "[done] published Cedar bundle"
echo "  BUNDLE_REF=${BUNDLE_REF}"
echo "  BUNDLE_VERSION=${VERSION}"
echo "  BUNDLE_DIGEST=${DIGEST}"
echo "  BUNDLE_CONTENT_HASH=sha256:${CONTENT_HASH}"
echo
echo "  R5E_CEDAR_BUNDLE_REF for argo-cd-app-manifests/values/audit-dev.yaml:"
echo "    ${BUNDLE_REF}"
echo
echo "  Or pin by digest (preferred — content-addressed, no tag mutation risk):"
echo "    ${ECR_REGISTRY}/${ECR_REPO}@${DIGEST}"
