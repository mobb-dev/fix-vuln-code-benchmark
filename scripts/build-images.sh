#!/usr/bin/env bash
# Build the four container images, one per language. Safe to re-run.
set -uo pipefail
cd "$(dirname "$0")/.."
for lang in go python node java; do
  echo "=== building vfb-$lang ==="
  docker build -t "vfb-$lang" -f "docker/Dockerfile.$lang" docker/ || { echo "BUILD FAILED: vfb-$lang"; exit 1; }
done
echo "=== all images built ==="; docker images | grep '^vfb-'
