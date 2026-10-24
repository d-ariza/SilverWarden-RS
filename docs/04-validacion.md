# 04 — Validación (Fase 4 — Testing y aseguramiento de calidad)

**Proyecto:** silverWarden-rs  
**Alcance:** Milestones M1 + M2 + M3 (Núcleo criptográfico, Configuración/Migración, Agente/IPC)  
**Commit validado:** `0c60879` (rama `develop`)  
**Fecha de ejecución:** 2026-10-24  
**Entorno:** Manjaro Linux, rustc 1.99.0, cargo 1.99.0, Node v22.22.3, webkit2gtk-4.1  
**Rol de la IA:** Ingeniero de QA / Calidad y seguridad  

---

## 1. Identificación de la validación

| Campo | Valor |
|---|---|
| Versión / commit | `0c60879` |
| Rama | `develop` |
| Alcance | M1 (SW-001 a SW-007), M2 (SW-010 a SW-013), M3 (SW-020 a SW-025) |
| Entorno | Manjaro Linux, rustc/cargo 1.99.0 |
| Limitaciones | `sw-gui` excluido del build de M1–M3 (Tauri, post-MVP) |

---

## 2. Resumen ejecutivo

**Estado global: ✅ Aprobado**

M1, M2 y M3 cumplen todos los criterios de cierre:

- 163 tests pasan, 0 fallan (61 sw-crypto, 25 sw-config, 5 sw-ipc, 22 sw-agent, 18 sw-systemauth, 32 sw-cli).
- Cobertura global workspace: 92.26% líneas / 91.97% regiones.
- Todos los crates ≥85% de cobertura en líneas (excepto stubs de post-MVP como `sw-ssh-agent` y `sw-vault`, que son `todo!()`).
- Clippy 0 warnings, fmt 0 diffs.
- `cargo audit` sin vulnerabilidades (exit code 0).
- Paridad criptográfica Go↔Rust verificada en KDF, stretch, cipher y RSA (M1).

**Riesgos residuales:** excepción documentada de `RUSTSEC-2023-0071` (rsa, Marvin Attack) y 7 advisories de crates unmaintained/unsound/timing (proc-macro-error, glib, zbus_names, zvariant, zvariant_derive, tokio, crypto-bigint).

---

## 3. Matriz de controles

| Control | Herramienta | Comando | Resultado real | Estado |
|---|---|---|---|---|
| Tests | cargo test | `cargo test --workspace --exclude sw-gui` | 163 pass, 0 fail | Aprobado |
| Cobertura (global) | cargo-llvm-cov | `cargo llvm-cov --workspace --exclude sw-gui --summary-only` | 92.26% líneas / 91.97% regiones | Aprobado |
| Cobertura (`sw-cli`) | cargo-llvm-cov | `cargo llvm-cov -p sw-cli --summary-only` | 92.82% líneas / 90.57% regiones | Aprobado |
| Linter | clippy | `cargo clippy --workspace --exclude sw-gui --all-targets -- -D warnings` | 0 warnings | Aprobado |
| Formato | rustfmt | `cargo fmt --all -- --check` | 0 diffs | Aprobado |
| Auditoría | cargo-audit | `cargo audit` | 0 vulns, exit 0 | Aprobado |

### 3.1 Detalle de cobertura por crate

| Crate | Líneas | Regiones | Estado |
|---|---|---|---|
| `sw-crypto` | 93.49% | 93.68% | ✅ |
| `sw-config` | 94.04% | 92.51% | ✅ |
| `sw-ipc` | 100.00% | 94.92% | ✅ |
| `sw-agent` | 90.29% | 90.23% | ✅ |
| `sw-systemauth` | 95.72% | 95.93% | ✅ |
| `sw-cli` | 92.82% | 90.57% | ✅ |

Los crates `sw-ssh-agent`, `sw-vault`, `sw-bitwarden-api`, `sw-notify`, `sw-autotype`, `sw-browserbiometrics` tienen 0% porque son stubs `todo!()` para M4/M5 y post-MVP.

---

## 4. Paridad criptográfica Go ↔ Rust (M1)

Re-ejecutada sobre el estado final de M1 antes de M2.

### KDF (SW-003)
```text
PBKDF2: f4de0e1196ff2e80ac327345d9e035ddbb6fb8c6129acdf1cbf9991c63f16370
Argon2id: 8fc048a537cbda3e8b6c8596a13ec3a879b929a1a0304dddffec8df18a06222f
```

### Jerarquía de claves (SW-004)
```text
PBKDF2 stretch enc: 4259e08507dbfad827ca1c49441249ddff3456f09e7827522e197917d9449928
PBKDF2 stretch mac: b552622d1da25d3fe35e9a9718d76e996e344156195fe903f0eb2018c695f557
Argon2id stretch enc: f7f449446a3e586d480c4aa83a4640c180a8737fcc6efd7a483645e39761b008
Argon2id stretch mac: 6911da83c0e785d2a32217600ecf67fa4006e59a04760f311dd2c55724ee1ee3
```

### Cifrado simétrico (SW-005)
```text
CT: edcfa3ee3645667d5e9b3b4fbbcce520
MAC: 56105a93e5dbd81bcdf3f030182b109ba2d7fa99108e0fda4b468c2322a30ca4
Wire: 2.JCQkJCQkJCQkJCQkJCQkJA==|7c+j7jZFZn1emztPu8zlIA==|VhBak+Xb2BvN8/AwGCsQm6LX+pkQjg/aS0aMIyKjDKQ=
```

### RSA legacy (SW-006)
Interop bidireccional verificada (Go cifra → Rust descifra, Rust cifra → Go descifra).

### Configuración (M2)
- Argon2i con PIN `521212` y `DeviceUUID` real: key `46d690a9...`.
- SHA3-256: `e65f3b70...` (coincide con `ConfigKeyHash`).
- Token descifrado con el wire format de Tink: verificado.

---

## 5. Cobertura de flujos críticos

### M2 — Migración
- Migración de path viejo: OK.
- Backup con timestamp antes de migrar: OK.
- Idempotencia: OK (si el archivo nuevo ya existe, no sobrescribe).
- Validación de `ConfigKeyHash` no vacío: OK.
- Bug de Go arreglado (D34): migración exitosa devuelve `Ok(())` sin error.

### M3 — Agente + IPC
- Socket Unix en `~/.silverwarden.sock` con permisos `0600`: OK.
- Detección de socket huérfano y limpieza: OK.
- Protocolo IPC (JSON + framing u32): OK, cobertura 100%.
- `CallingContext` con `SO_PEERCRED` + `/proc` + anclaje git: OK.
- Rechazo de `uid == 0` (root): OK, mejora sobre Go.
- Session store endurecido (D36): OK.
- Actions registry con 6 acciones: OK.
- CLI con subcomandos funcionales: OK.
- Detección de conflicto con Goldwarden Go: OK.

---

## 6. Excepciones y riesgos residuales

### RUSTSEC-2023-0071 — rsa 0.9.10 (Marvin Attack)
Excepción aprobada. `rsa` es la única implementación madura para RSA-OAEP-SHA1 (necesaria para `encKey` legacy de Bitwarden en SW-006). Uso local, sin exposición remota.

### Advisories de crates unmaintained/unsound
| ID | Crate | Tipo | Justificación |
|---|---|---|---|
| RUSTSEC-2024-0370 | proc-macro-error | unmaintained | Transitiva de build de Tauri |
| RUSTSEC-2024-0429 | glib | unsound | Transitiva de Tauri/GTK |
| RUSTSEC-2026-0370 | zvariant | unmaintained | Transitiva de zbus 5 (Tauri v2) |
| RUSTSEC-2026-0371 | zbus_names | unmaintained | Transitiva de zbus 5 (Tauri v2) |
| RUSTSEC-2026-0372 | zvariant_derive | unmaintained | Transitiva de zbus 5 (Tauri v2) |
| RUSTSEC-2026-0386 | tokio 1.53.2 | unsound | `AsyncFd::new` (no usado en el MVP); evaluar en M4 |
| RUSTSEC-2026-0387 | crypto-bigint 0.5.5 | timing variability | Transitiva de `ssh-key 0.6.7` (SW-025); uso local en SSH agent |

Todos en `.cargo/audit.toml` con justificación. Se eliminarán cuando Tauri migre a zbus 6 y tokio publique un parche.

---

## 7. Conclusión y aprobación

**Criterios de cierre cumplidos:**

- [x] Build desde cero exitoso.
- [x] Tests pasan (163/163).
- [x] Cobertura global ≥85% (92.26%).
- [x] Todos los crates del MVP ≥85%.
- [x] Clippy 0 warnings.
- [x] Formato 0 diffs.
- [x] `cargo audit` sin vulnerabilidades (exit 0).
- [x] Paridad Go↔Rust re-verificada (M1).
- [x] Migración de Goldwarden Go funciona (M2).
- [x] Agente + IPC funcional (M3).
- [x] Excepciones documentadas y aprobadas.
- [x] Evidencia rastreable en `03-ejecucion.md`.

**Estado: ✅ M1 + M2 + M3 APROBADOS.**

**Siguiente milestone:** M4 — Vault + API Bitwarden (`sw-vault`, `sw-bitwarden-api`).
