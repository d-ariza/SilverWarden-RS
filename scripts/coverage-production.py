#!/usr/bin/env python3
"""Cobertura de producción de SilverWarden-RS.

Mide solo el código de producción dentro de `crates/`: ignora `tests.rs`,
`*_tests.rs`, `tests/` y `fuzz/`, filtrando rutas por prefijo relativo respecto
a la raíz del repositorio (sin depender de `os.path.exists`). Falla si la
cobertura de líneas baja del umbral (90 % por defecto).

Por defecto limpia artefactos previos con `cargo llvm-cov clean --workspace`
para no depender del estado de `target/` y verifica reproducibilidad con una
tolerancia de 0.01 %.

Códigos de salida:
    0  cobertura >= umbral y medición determinista
    1  cobertura < umbral
    2  falta `cargo` o `cargo-llvm-cov`
    3  error al ejecutar `cargo llvm-cov`, salida inválida o medición no determinista

Uso:
    python3 scripts/coverage-production.py
    python3 scripts/coverage-production.py --threshold 101
    python3 scripts/coverage-production.py --reuse
    python3 scripts/coverage-production.py --clean --clean
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from typing import NoReturn

# Se aplica sobre la ruta relativa dentro del repositorio (`crates/...`).
IGNORE_REGEX = r"(^|/)(tests?\.rs|[^/]*_tests\.rs|tests/|fuzz/)"
IGNORE_PATTERN = re.compile(IGNORE_REGEX)
DETERMINISM_TOLERANCE = 0.01


def fail(message: str, code: int) -> NoReturn:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(code)


def check_tool() -> None:
    if shutil.which("cargo") is None:
        fail("no se encontró `cargo` en PATH", 2)
    result = subprocess.run(
        ["cargo", "llvm-cov", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        fail(
            "falta `cargo-llvm-cov`. Instálalo con "
            "`cargo install cargo-llvm-cov` y `rustup component add llvm-tools-preview`.",
            2,
        )


def resolve_repo_root() -> str:
    """Resuelve la raíz del repositorio usando `CARGO_MANIFEST_DIR` o la ruta del script."""
    manifest_dir = os.environ.get("CARGO_MANIFEST_DIR", "").strip()
    if manifest_dir:
        base = os.path.abspath(manifest_dir)
        candidates = (
            base,
            os.path.dirname(base),
            os.path.dirname(os.path.dirname(base)),
        )
        for candidate in candidates:
            if os.path.isdir(os.path.join(candidate, "crates")):
                return candidate
        return base
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def relativize_to_crates(filename: str, repo_root: str) -> str | None:
    """Normaliza léxicamente `filename` respecto a `repo_root` y exige prefijo `crates/`."""
    raw = filename[3:].strip() if filename.startswith("SF:") else filename.strip()
    if not raw:
        return None

    normalized_raw = os.path.normpath(raw)
    if os.path.isabs(raw):
        rel = os.path.relpath(normalized_raw, os.path.normpath(repo_root))
    else:
        rel = normalized_raw

    rel = rel.replace("\\", "/")
    if not rel.startswith("crates/"):
        return None
    return rel


def clean_workspace(repo_root: str, verbose: bool = False) -> None:
    cmd = ["cargo", "llvm-cov", "clean", "--workspace"]
    if verbose:
        print("Ejecutando:", " ".join(cmd), file=sys.stderr)
    result = subprocess.run(
        cmd,
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        if result.stderr:
            sys.stderr.write(result.stderr)
        fail(f"`cargo llvm-cov clean --workspace` falló con código {result.returncode}", 3)


def run_coverage(repo_root: str, reuse: bool = False, verbose: bool = False) -> dict:
    if reuse:
        cmd = [
            "cargo",
            "llvm-cov",
            "report",
            "--json",
            "--summary-only",
            "--ignore-filename-regex",
            IGNORE_REGEX,
        ]
    else:
        cmd = [
            "cargo",
            "llvm-cov",
            "--workspace",
            "--all-targets",
            "--ignore-filename-regex",
            IGNORE_REGEX,
            "--json",
            "--summary-only",
        ]
    print("Ejecutando:", " ".join(cmd), file=sys.stderr)
    result = subprocess.run(
        cmd,
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        fail(f"`cargo llvm-cov` falló con código {result.returncode}", 3)
    if verbose and result.stderr:
        sys.stderr.write(result.stderr)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        fail(f"la salida de llvm-cov no es JSON válido: {exc}", 3)


def lines_percent(report: dict, repo_root: str, verbose: bool = False) -> tuple[float, int]:
    """Calcula el porcentaje de líneas solo sobre archivos bajo `crates/`.

    Filtra las entradas por ruta relativa a `repo_root` sin consultar el sistema
    de archivos (`os.path.exists`), descartando rutas externas o no válidas.
    """
    try:
        files = report["data"][0]["files"]
    except (KeyError, IndexError, TypeError):
        fail("el JSON de llvm-cov no contiene `data[0].files`", 3)

    total = 0
    covered = 0
    invalid_paths = 0
    for entry in files:
        filename = entry.get("filename", "")
        rel = (
            relativize_to_crates(filename, repo_root)
            if isinstance(filename, str) and filename
            else None
        )
        if rel is None:
            invalid_paths += 1
            if verbose:
                print(f"Descartando entrada por ruta no válida: {filename!r}", file=sys.stderr)
            continue
        if IGNORE_PATTERN.search(rel):
            if verbose:
                print(f"Excluyendo archivo de tests/fuzz: {rel}", file=sys.stderr)
            continue

        lines = entry.get("summary", {}).get("lines", {})
        total += int(lines.get("count", 0))
        covered += int(lines.get("covered", 0))

    if total == 0:
        fail("no hay líneas medidas en los archivos de `crates/`", 3)
    return 100.0 * covered / total, invalid_paths


def compute_source_fingerprint(repo_root: str) -> str:
    """Calcula una huella determinista del árbol fuente (`Cargo.*` y `crates/`)."""
    hasher = hashlib.sha256()
    top_files = ("Cargo.toml", "Cargo.lock")
    for rel in top_files:
        path = os.path.join(repo_root, rel)
        if os.path.isfile(path):
            hasher.update(rel.encode("utf-8"))
            with open(path, "rb") as fh:
                hasher.update(fh.read())

    crates_dir = os.path.join(repo_root, "crates")
    collected: list[tuple[str, str]] = []
    for root, dirs, filenames in os.walk(crates_dir):
        dirs[:] = sorted(d for d in dirs if d not in {"target", "node_modules", ".git"})
        for name in sorted(filenames):
            if name.endswith(".rs") or name == "Cargo.toml":
                full_path = os.path.join(root, name)
                rel_path = os.path.relpath(full_path, repo_root).replace("\\", "/")
                collected.append((rel_path, full_path))

    for rel_path, full_path in sorted(collected):
        hasher.update(rel_path.encode("utf-8"))
        with open(full_path, "rb") as fh:
            hasher.update(fh.read())
    return hasher.hexdigest()


def state_file_path(repo_root: str) -> str:
    return os.path.join(repo_root, "target", ".coverage-production-last.json")


def load_previous_percent(state_path: str, fingerprint: str) -> float | None:
    if not os.path.isfile(state_path):
        return None
    try:
        with open(state_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError, TypeError):
        return None
    if data.get("fingerprint") != fingerprint:
        return None
    percent = data.get("percent")
    return float(percent) if isinstance(percent, (int, float)) else None


def save_last_result(state_path: str, fingerprint: str, percent: float, invalid_paths: int) -> None:
    os.makedirs(os.path.dirname(state_path), exist_ok=True)
    payload = {
        "fingerprint": fingerprint,
        "percent": percent,
        "invalid_paths": invalid_paths,
    }
    with open(state_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")


def assert_deterministic(
    first: float,
    second: float,
    label: str,
    verbose: bool = False,
) -> None:
    diff = abs(first - second)
    if verbose:
        print(
            f"Determinismo ({label}): {first:.4f}% vs {second:.4f}% "
            f"(diferencia {diff:.4f}%, tolerancia {DETERMINISM_TOLERANCE:.2f}%)",
            file=sys.stderr,
        )
    if diff > DETERMINISM_TOLERANCE:
        fail(
            f"medición no determinista ({label}): {first:.2f}% vs {second:.2f}% "
            f"(diferencia {diff:.4f}% > {DETERMINISM_TOLERANCE:.2f}%)",
            3,
        )


def measure_once(
    repo_root: str,
    should_clean: bool,
    reuse: bool,
    verbose: bool,
) -> tuple[float, int]:
    if should_clean:
        clean_workspace(repo_root, verbose=verbose)
    report = run_coverage(repo_root, reuse=reuse, verbose=verbose)
    return lines_percent(report, repo_root, verbose=verbose)


def main() -> int:
    parser = argparse.ArgumentParser(description="Cobertura de producción (sin tests).")
    parser.add_argument(
        "--threshold",
        type=float,
        default=90.0,
        help="mínimo aceptado en porcentaje (por defecto 90)",
    )
    parser.add_argument(
        "--reuse",
        action="store_true",
        help="reutiliza los datos de la última ejecución (no limpia ni vuelve a correr tests)",
    )
    parser.add_argument(
        "--clean",
        action="count",
        default=0,
        help=(
            "ejecuta `cargo llvm-cov clean --workspace` antes de medir (activo por defecto; "
            "pásalo dos veces `--clean --clean` para verificar determinismo en la misma invocación)"
        ),
    )
    parser.add_argument(
        "--no-clean",
        action="store_true",
        help="omite `cargo llvm-cov clean --workspace` antes de medir",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="muestra comandos completos, entradas descartadas y detalles de determinismo",
    )
    args = parser.parse_args()

    check_tool()
    repo_root = resolve_repo_root()
    fingerprint = compute_source_fingerprint(repo_root)
    state_path = state_file_path(repo_root)
    prev_percent = load_previous_percent(state_path, fingerprint)

    should_clean = (not args.reuse) and (not args.no_clean)
    passes = 2 if (args.clean >= 2 and not args.reuse) else 1

    percent, invalid_paths = measure_once(
        repo_root,
        should_clean=should_clean,
        reuse=args.reuse,
        verbose=args.verbose,
    )
    if passes == 2:
        second_percent, second_invalid = measure_once(
            repo_root,
            should_clean=should_clean,
            reuse=False,
            verbose=args.verbose,
        )
        assert_deterministic(percent, second_percent, "doble ejecución", verbose=args.verbose)
        percent = second_percent
        invalid_paths = second_invalid

    if prev_percent is not None:
        assert_deterministic(prev_percent, percent, "ejecución previa", verbose=args.verbose)

    save_last_result(state_path, fingerprint, percent, invalid_paths)

    print(f"cobertura producción: {percent:.2f}% (umbral {args.threshold:.2f}%)")
    print(f"Entradas ignoradas por ruta no válida: {invalid_paths}")

    if percent < args.threshold:
        print(
            f"FALLO: la cobertura de producción {percent:.2f}% "
            f"está por debajo del umbral {args.threshold:.2f}%",
            file=sys.stderr,
        )
        return 1
    print("OK: cobertura de producción por encima del umbral.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
