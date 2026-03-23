#!/usr/bin/env bash
#
# Build envoy-contrib binary using the same devcontainer environment.
# Uses a persistent Docker volume (envoy-build) for bazel cache,
# so subsequent builds are fast.
#
# Usage:
#   ./build_envoy.sh                    # Build contrib binary
#   BAZEL_EXTRA="--config=debug" ./build_envoy.sh  # With extra bazel flags
#
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$DIR/.." && pwd)"
OUTPUT="$DIR/envoy-contrib"

cd "$REPO_ROOT"

# Generate the devcontainer Dockerfile (same as .devcontainer/init.sh).
export ENVOY_BUILD_VARIANT="${ENVOY_BUILD_VARIANT:-}"
. ci/envoy_build_sha.sh
IMAGE_NAME="envoy-devcontainer:${BUILD_TAG}"

# Build the devcontainer image if not cached.
if [ "$(docker images -q "$IMAGE_NAME" 2>/dev/null)" = "" ]; then
  echo "[+] Building devcontainer image from ${BUILD_CONTAINER}..."
  sed "s|%%ENVOY_BUILD_IMAGE%%|${BUILD_CONTAINER}|g" \
    .devcontainer/Dockerfile.in > .devcontainer/Dockerfile
  docker build -t "$IMAGE_NAME" -f .devcontainer/Dockerfile .devcontainer/
fi

echo "[+] Building //contrib/exe:envoy-static inside devcontainer..."
echo "[+] Bazel cache persisted in Docker volume 'envoy-build'"

docker run --rm \
  --entrypoint bash \
  --volume="${REPO_ROOT}:/source" \
  --volume=envoy-build:/build \
  --workdir=/source \
  --env="HOME=/build" \
  --env="USER=root" \
  "$IMAGE_NAME" \
  -c "set -e; \
    apt-get update -qq && apt-get install -y -qq lld >/dev/null 2>&1; \
    ln -sf /usr/bin/ld.lld /usr/bin/ld; \
    bazel build //contrib/exe:envoy-static ${BAZEL_EXTRA:-}; \
    cp -f bazel-bin/contrib/exe/envoy-static /source/test_with_docker/envoy-contrib; \
    echo BUILD_SUCCESS"

if [ -f "$OUTPUT" ]; then
  echo "[+] Binary ready: $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
else
  echo "[-] Build failed — no binary produced"
  exit 1
fi
