#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACK_DIR="$(mktemp -d)"
INSTALL_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "$PACK_DIR" "$INSTALL_DIR"
}

trap cleanup EXIT

cd "$ROOT"

VERSION_VALUE="$(tr -d '[:space:]' < VERSION)"

node - "$VERSION_VALUE" <<'NODE'
const fs = require("node:fs");

const expectedVersion = process.argv[2];
const manifests = [
  "package.json",
  "packages/core/package.json",
  "packages/rules/package.json",
  "packages/sarif/package.json",
  "packages/cli/package.json",
];

for (const manifestPath of manifests) {
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));

  if (manifest.version !== expectedVersion) {
    console.error(
      `error: ${manifestPath} version ${manifest.version} does not match VERSION ${expectedVersion}`,
    );
    process.exit(1);
  }
}
NODE

bun run build

for package in core rules sarif cli; do
  (
    cd "packages/$package"
    bun pm pack --destination "$PACK_DIR" >/dev/null
  )
done

for tarball in "$PACK_DIR"/*.tgz; do
  manifest="$(tar -xOf "$tarball" package/package.json)"

  if grep -q "workspace:" <<<"$manifest"; then
    echo "error: packed manifest contains workspace: dependency: $tarball" >&2
    exit 1
  fi
done

mkdir -p "$INSTALL_DIR/project"
cd "$INSTALL_DIR/project"

npm init -y >/dev/null
npm install --ignore-scripts "$PACK_DIR"/*.tgz >/dev/null

ACTUAL_VERSION="$(./node_modules/.bin/skillguard --version)"

if [[ "$ACTUAL_VERSION" != "$VERSION_VALUE" ]]; then
  echo "error: skillguard --version returned $ACTUAL_VERSION, expected $VERSION_VALUE" >&2
  exit 1
fi

./node_modules/.bin/skillguard scan "$ROOT/fixtures/benign/basic" \
  --preset standard \
  --policy standard \
  >/dev/null

echo "Pack verification passed for @stll/skillguard $VERSION_VALUE."
