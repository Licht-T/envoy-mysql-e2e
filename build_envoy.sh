#!/usr/bin/env bash
#
# Build envoy-contrib binary using Envoy's devcontainer environment.
# Uses a persistent Docker volume (envoy-build) for bazel cache,
# so subsequent builds are fast.
#
# Usage:
#   ENVOY_SRCDIR=../envoy ./build_envoy.sh             # Specify Envoy source path
#   ENVOY_SRCDIR=../envoy BAZEL_EXTRA="--config=debug" ./build_envoy.sh
#
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT="$DIR/envoy-contrib"

# Locate the Envoy source tree.
ENVOY_SRCDIR="${ENVOY_SRCDIR:-../envoy}"
if [ ! -f "$ENVOY_SRCDIR/ci/envoy_build_sha.sh" ]; then
  echo "[-] Envoy source not found at: $ENVOY_SRCDIR"
  echo "    Set ENVOY_SRCDIR to the path of your envoy checkout."
  echo "    Example: ENVOY_SRCDIR=../envoy ./build_envoy.sh"
  exit 1
fi
ENVOY_SRCDIR="$(cd "$ENVOY_SRCDIR" && pwd)"

cd "$ENVOY_SRCDIR"

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
echo "[+] Envoy source: $ENVOY_SRCDIR"
echo "[+] Bazel cache persisted in Docker volume 'envoy-build'"

docker run --rm \
  --entrypoint bash \
  --volume="${ENVOY_SRCDIR}:/source" \
  --volume="${DIR}:/output" \
  --volume=envoy-build:/build \
  --workdir=/source \
  --env="HOME=/build" \
  --env="USER=root" \
  "$IMAGE_NAME" \
  -c "set -e; \
    apt-get update -qq && apt-get install -y -qq lld >/dev/null 2>&1; \
    ln -sf /usr/bin/ld.lld /usr/bin/ld; \
    bazel build //contrib/exe:envoy-static ${BAZEL_EXTRA:-}; \
    cp -f bazel-bin/contrib/exe/envoy-static /output/envoy-contrib; \
    echo BUILD_SUCCESS"

if [ -f "$OUTPUT" ]; then
  echo "[+] Binary ready: $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
else
  echo "[-] Build failed — no binary produced"
  exit 1
fi
