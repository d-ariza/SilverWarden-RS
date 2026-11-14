#!/usr/bin/env bash
set -euo pipefail

# Nota (plan §1.5.3 / ADR-0008): la dependencia `sw-cli -> sw-agent` es esperada
# y aceptada por diseño porque `sw-cli agent start` es el entrypoint del daemon
# e invoca `sw_agent::run_agent`. Centralizar rutas en `sw-config` no la elimina.

if cargo tree -p sw-agent --edges normal | grep -q sw-ssh-agent; then
  echo "ERROR: sw-agent no debe depender de sw-ssh-agent"
  exit 1
fi

if cargo tree -p sw-vault-agent | grep -q sw-ssh-agent; then
  echo "ERROR: sw-vault-agent no debe depender de sw-ssh-agent"
  exit 1
fi

echo "OK: dirección de dependencias correcta"

