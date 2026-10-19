# 04 — Validación (Fase 4 — Testing y aseguramiento de calidad)

**Proyecto:** silverWarden-rs
**Alcance:** Milestone M1 — Núcleo criptográfico (`sw-crypto`)
**Commit validado:** `6d2e27b` (rama `develop`)
**Fecha de ejecución:** 2026-10-18
**Entorno:** Manjaro Linux, rustc 1.99.0, cargo 1.99.0, Node v22.22.3, webkit2gtk-4.1
**Rol de la IA:** Ingeniero de QA / Calidad y seguridad

---

## 1. Identificación de la validación

| Campo            | Valor                                               |
| ---------------- | --------------------------------------------------- |
| Versión / commit | `6d2e27b`                                           |
| Rama             | `develop`                                           |
| Alcance          | Milestone M1: SW-001 a SW-007                       |
| Entorno          | Manjaro Linux, rustc/cargo 1.99.0                   |
| Limitaciones     | `sw-gui` excluido del build de M1 (Tauri, post-MVP) |

---

## 2. Resumen ejecutivo

**Estado global: ✅ Aprobado**

M1 (Núcleo criptográfico) cumple todos los criterios de cierre:

- 61 tests pasan, 0 fallan.
- Cobertura 93.49% líneas en `sw-crypto` (umbral: ≥90%).
- Clippy 0 warnings, fmt 0 diffs.
- `cargo audit` sin vulnerabilidades (exit code 0).
- Fuzzing: 8.522.414 runs, 0 crashes.
- Paridad criptográfica Go↔Rust re-verificada en KDF, stretch, cipher y RSA.

**Riesgos residuales:** excepción documentada de `RUSTSEC-2023-0071` (rsa, Marvin Attack) y 5 advisories de crates unmaintained (proc-macro-error, glib, zbus_names, zvariant, zvariant_derive), todas ellas dependencias transitivas fuera del camino criptográfico del MVP.

---

## 3. Matriz de controles

| Control           | Herramienta      | Comando                                                                  | Resultado real                       | Evidencia        | Estado   |
| ----------------- | ---------------- | ------------------------------------------------------------------------ | ------------------------------------ | ---------------- | -------- |
| Build desde cero  | cargo            | `cargo clean && cargo build --workspace --exclude sw-gui`                | `Finished` en 2m 56s                 | Salida en sesión | Aprobado |
| Tests unitarios   | cargo test       | `cargo test --workspace --exclude sw-gui`                                | 61 passed, 0 failed                  | Salida en sesión | Aprobado |
| Cobertura         | cargo-llvm-cov   | `cargo llvm-cov -p sw-crypto --summary-only`                             | 93.49% líneas / 93.68% regiones      | Salida en sesión | Aprobado |
| Linter            | clippy           | `cargo clippy --workspace --exclude sw-gui --all-targets -- -D warnings` | 0 warnings                           | Salida en sesión | Aprobado |
| Formato           | rustfmt          | `cargo fmt --all -- --check`                                             | 0 diffs                              | Salida en sesión | Aprobado |
| Auditoría de deps | cargo-audit      | `cargo audit`                                                            | 0 vulns, exit 0                      | Salida en sesión | Aprobado |
| Fuzzing           | cargo-fuzz       | 4 targets × 60s                                                          | 8.522.414 runs, 0 crashes            | Salida en sesión | Aprobado |
| Paridad Go↔Rust   | tests en repo Go | `go run ./tools/parity`, `go test -tags=parity`                          | KDF, stretch, cipher y RSA coinciden | Salida en sesión | Aprobado |

### 3.1 Detalle de cobertura por archivo (`sw-crypto`)

| Archivo           | Regiones   | Líneas     |
| ----------------- | ---------- | ---------- |
| `asymmetric.rs`   | 92.38%     | 94.21%     |
| `cipher.rs`       | 94.62%     | 90.17%     |
| `encstring.rs`    | 90.34%     | 91.84%     |
| `kdf.rs`          | 93.88%     | 94.31%     |
| `keyhierarchy.rs` | 96.38%     | 97.02%     |
| `mem.rs`          | 95.06%     | 94.48%     |
| **TOTAL**         | **93.68%** | **93.49%** |

---

## 4. Paridad criptográfica Go ↔ Rust

Re-ejecutada sobre el estado final de M1 (no se confía en evidencia previa).

### KDF (SW-003)

PBKDF2: f4de0e1196ff2e80ac327345d9e035ddbb6fb8c6129acdf1cbf9991c63f16370
Argon2id: 8fc048a537cbda3e8b6c8596a13ec3a879b929a1a0304dddffec8df18a06222f

Rust produce los mismos valores. ✅

### Jerarquía de claves (SW-004)

PBKDF2 stretch enc: 4259e08507dbfad827ca1c49441249ddff3456f09e7827522e197917d9449928
PBKDF2 stretch mac: b552622d1da25d3fe35e9a9718d76e996e344156195fe903f0eb2018c695f557
Argon2id stretch enc: f7f449446a3e586d480c4aa83a4640c180a8737fcc6efd7a483645e39761b008
Argon2id stretch mac: 6911da83c0e785d2a32217600ecf67fa4006e59a04760f311dd2c55724ee1ee3

Coinciden byte a byte. ✅

### Cifrado simétrico (SW-005)

CT: edcfa3ee3645667d5e9b3b4fbbcce520
MAC: 56105a93e5dbd81bcdf3f030182b109ba2d7fa99108e0fda4b468c2322a30ca4
Wire: 2.JCQkJCQkJCQkJCQkJCQkJA==|7c+j7jZFZn1emztPu8zlIA==|VhBak+Xb2BvN8/AwGCsQm6LX+pkQjg/aS0aMIyKjDKQ=
Type 0 Wire: (vacío, len 0)
Tampered MAC: error "decrypt: MAC mismatch"

Coinciden byte a byte. Tipo 0 devuelve wire vacío (D21). MAC verificada antes de descifrar. ✅

### RSA legacy (SW-006)

- Go cifra → Rust descifra: `Roundtrip succeeded`.
- Rust cifra → Go descifra: `INTEROP SUCCESS`.

Interop bidireccional verificada. ✅

---

## 5. Fuzzing (SW-007)

| Target                         | Runs (60s)    | Crashes |
| ------------------------------ | ------------- | ------- |
| `fuzz_encstring_parse`         | 2.601.553     | 0       |
| `fuzz_pkcs7_unpad`             | 4.706.740     | 0       |
| `fuzz_decrypt_with`            | 1.190.793     | 0       |
| `fuzz_decrypt_with_asymmetric` | 23.328        | 0       |
| **Total**                      | **8.522.414** | **0**   |

Cero crashes en 8.5M ejecuciones. ✅

---

## 6. Excepciones y riesgos residuales

### RUSTSEC-2023-0071 — rsa 0.9.10 (Marvin Attack)

- **Severidad:** 5.9 (medium).
- **Estado:** Excepción aprobada, documentada en `.cargo/audit.toml`.
- **Justificación:** `rsa` es la única implementación madura en Rust para RSA-OAEP-SHA1, requerida para descifrar `encKey` legacy de Bitwarden (SW-006). Uso estrictamente local, sin exposición a atacantes remotos que puedan medir tiempos.

### Advisories de crates unmaintained

| ID                | Crate            | Justificación                   |
| ----------------- | ---------------- | ------------------------------- |
| RUSTSEC-2024-0370 | proc-macro-error | Transitiva de build de Tauri    |
| RUSTSEC-2024-0429 | glib             | Transitiva de Tauri/GTK         |
| RUSTSEC-2026-0370 | zvariant         | Transitiva de zbus 5 (Tauri v2) |
| RUSTSEC-2026-0371 | zbus_names       | Transitiva de zbus 5 (Tauri v2) |
| RUSTSEC-2026-0372 | zvariant_derive  | Transitiva de zbus 5 (Tauri v2) |

Todas documentadas en `.cargo/audit.toml`. Se eliminarán cuando Tauri migre a zbus 6.

---

## 7. Conclusión y aprobación

**Criterios de cierre cumplidos:**

- [x] Build desde cero exitoso.
- [x] Tests obligatorios pasan (61/61).
- [x] Cobertura ≥90% en `sw-crypto` (93.49%).
- [x] Clippy 0 warnings.
- [x] Formato 0 diffs.
- [x] `cargo audit` sin vulnerabilidades (exit 0).
- [x] Fuzzing sin crashes (8.5M runs).
- [x] Paridad Go↔Rust re-verificada.
- [x] Excepciones documentadas y aprobadas.
- [x] Evidencia rastreable en sesión y `03-ejecucion.md`.

**Estado: ✅ M1 APROBADO.**

**Siguiente milestone:** M2 — Configuración y migración (`sw-config`).
