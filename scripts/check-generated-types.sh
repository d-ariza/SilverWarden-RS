#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GENERATED_DIR="$REPO_ROOT/crates/sw-gui/src/lib/types/generated"

EXPECTED_FILES=(
  "AgentStatus.ts"
  "ConfigView.ts"
  "LoginDetail.ts"
  "LoginSummary.ts"
  "PinChangeResult.ts"
  "SshKeySummary.ts"
  "SyncResult.ts"
)

if [[ ! -d "$GENERATED_DIR" ]]; then
  echo "ERROR: no existe el directorio $GENERATED_DIR" >&2
  exit 1
fi

TMP_BEFORE="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_BEFORE"
}
trap cleanup EXIT

cp -a "$GENERATED_DIR/." "$TMP_BEFORE/"

restore_before() {
  rm -rf "$GENERATED_DIR"/*
  cp -a "$TMP_BEFORE/." "$GENERATED_DIR/"
}

cd "$REPO_ROOT"
cargo test -p sw-ipc --features ts export --quiet

for file in "${EXPECTED_FILES[@]}"; do
  if [[ ! -f "$GENERATED_DIR/$file" ]]; then
    echo "ERROR: falta tipo generado esperado: $file" >&2
    restore_before
    exit 1
  fi
done

if grep -En '\bany\b' "$GENERATED_DIR"/*.ts; then
  echo "ERROR: se detectó 'any' en tipos TypeScript generados" >&2
  restore_before
  exit 1
fi

if ! diff -ru "$TMP_BEFORE" "$GENERATED_DIR"; then
  echo "ERROR: los tipos TS en crates/sw-gui/src/lib/types/generated están desactualizados o modificados manualmente." >&2
  echo "Ejecuta: cargo test -p sw-ipc --features ts export" >&2
  restore_before
  exit 1
fi

echo "OK: tipos TS generados actualizados y sin 'any' (${#EXPECTED_FILES[@]} archivos)"
