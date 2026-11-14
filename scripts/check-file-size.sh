#!/usr/bin/env bash
# Gate P6: ningún archivo de producción supera 800 líneas.
#
# Producción = líneas antes de la primera declaración `mod tests`
# (con o sin `pub`, con o sin `#[cfg(test)]` encima). Los archivos de test
# separados (`tests.rs`, `tests/`, `fuzz/`) no se miden.
#
# Uso:
#   ./scripts/check-file-size.sh            # mide el repo, exit 1 si algo viola
#   ./scripts/check-file-size.sh --self-test # prueba el propio script
set -euo pipefail

LIMIT=800
WARN=500
ROOT="${CHECK_FILE_SIZE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

production_lines() {
    local file="$1"
    # Corta en el `#[cfg(test)]` (si lo hay) que precede al módulo de tests,
    # o directamente en `mod tests` cuando el módulo no lleva atributo.
    awk '
        {
            if ($0 ~ /^[[:space:]]*#\[cfg\(test\)\][[:space:]]*$/) { attr = NR; next }
            if ($0 ~ /^[[:space:]]*(pub[[:space:]]+)?mod[[:space:]]+[A-Za-z0-9_]*tests[[:space:]]*[{;]/) {
                if (attr) { print attr - 1 } else { print NR - 1 }
                found = 1; exit
            }
            attr = 0
            last = NR
        }
        END { if (!found) print last + 0 }
    ' "$file"
}

collect_files() {
    find "$ROOT/crates" -type f -name '*.rs' \
        -not -path '*/target/*' \
        -not -path '*/fuzz/*' \
        -not -path '*/tests/*' \
        -not -name 'tests.rs' \
        -not -name '*_tests.rs' \
        -not -name 'manual_*.rs' \
        | sort
}

run_check() {
    local violations=0
    local warnings=0
    local checked=0
    local file lines

    while IFS= read -r file; do
        checked=$((checked + 1))
        lines=$(production_lines "$file")
        if (( lines > LIMIT )); then
            printf 'ERROR  %5d líneas  %s\n' "$lines" "${file#"$ROOT"/}"
            violations=$((violations + 1))
        elif (( lines > WARN )); then
            printf 'WARN   %5d líneas  %s\n' "$lines" "${file#"$ROOT"/}"
            warnings=$((warnings + 1))
        fi
    done < <(collect_files)

    echo "---"
    echo "Archivos medidos: $checked · violaciones: $violations · avisos: $warnings"

    if (( violations > 0 )); then
        echo "FALLO: $violations archivo(s) superan $LIMIT líneas de producción."
        return 1
    fi
    echo "OK: ningún archivo de producción supera $LIMIT líneas."
    return 0
}

self_test() {
    local tmp1 tmp2
    tmp1="$(mktemp -d)"
    tmp2="$(mktemp -d)"

    mkdir -p "$tmp1/crates/demo/src" "$tmp1/crates/demo/tests" "$tmp2/crates/demo/src"
    {
        seq 1 600
        echo 'mod tests {'
        seq 1 200
        echo '}'
    } > "$tmp1/crates/demo/src/big.rs"
    {
        seq 1 900
    } > "$tmp1/crates/demo/src/tests.rs"
    {
        seq 1 900
    } > "$tmp1/crates/demo/tests/integration.rs"
    {
        seq 1 801
        echo 'mod tests {'
        seq 1 50
        echo '}'
    } > "$tmp2/crates/demo/src/violation.rs"

    local output status failures=0

    # Caso 1: 600 líneas de producción → WARN, exit 0.
    output=$(trap - EXIT; CHECK_FILE_SIZE_ROOT="$tmp1" "$0" --check-only 2>&1) && status=0 || status=$?
    if (( status != 0 )) || ! grep -q 'WARN.*600' <<<"$output"; then
        echo "SELF-TEST FALLO: 600 líneas debía avisar y salir 0"
        echo "$output"
        failures=1
    fi

    # Caso 2: 801 líneas de producción → exit 1.
    output=$(trap - EXIT; CHECK_FILE_SIZE_ROOT="$tmp2" "$0" --check-only 2>&1) && status=0 || status=$?
    if (( status != 1 )) || ! grep -q 'ERROR.*801' <<<"$output"; then
        echo "SELF-TEST FALLO: 801 líneas debía fallar con exit 1"
        echo "$output"
        failures=1
    fi

    # Caso 3: los archivos de test no se miden.
    if grep -qE 'tests\.rs|tests/integration\.rs' <<<"$output"; then
        echo "SELF-TEST FALLO: los archivos de test no debían medirse"
        echo "$output"
        failures=1
    fi

    rm -rf "$tmp1" "$tmp2"

    if (( failures > 0 )); then
        return 1
    fi
    echo "SELF-TEST OK: 600 avisa, 801 falla, tests excluidos"
    return 0
}

case "${1:-}" in
    --self-test)
        self_test
        ;;
    --check-only)
        run_check
        ;;
    "")
        run_check
        ;;
    *)
        echo "Uso: $0 [--self-test]" >&2
        exit 2
        ;;
esac
