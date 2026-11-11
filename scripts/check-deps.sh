#!/usr/bin/env bash
set -euo pipefail

if cargo tree -p sw-agent --edges normal | grep -q sw-ssh-agent; then
  echo "ERROR: sw-agent no debe depender de sw-ssh-agent"
  exit 1
fi

if cargo tree -p sw-vault-agent | grep -q sw-ssh-agent; then
  echo "ERROR: sw-vault-agent no debe depender de sw-ssh-agent"
  exit 1
fi

echo "OK: dirección de dependencias correcta"

