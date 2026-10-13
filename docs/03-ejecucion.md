# 03 — Registro de Ejecución y Evidencia (silverWarden-rs)

**Fecha de inicio:** 2026-10-12  
**Entorno:** Manjaro Linux (Kernel Linux, rustc 1.99.0, cargo 1.99.0, Node v22.22.3, webkit2gtk-4.1)  
**Licencia:** GPL-3.0  

Este documento registra la evidencia de ejecución real requerida por las reglas de cierre del backlog:
1. Comandos ejecutados y su salida exacta.
2. Resultados de `cargo test`, `cargo clippy -D warnings`, `rustfmt --check`, `cargo audit`.
3. Cobertura de código y verificación de criterios de aceptación de cada historia `SW-NNN`.

---

## 0. Inicialización del Repositorio y Arquitectura

- **Fecha:** 2026-10-12
- **Acción:** Inicialización de repositorio Git independiente en `SilverWarden-Rs`, configuración del workspace Cargo modular con 13 crates (`crates/*`), soporte CLI (`sw-cli`) y GUI Tauri con Svelte 5 + TS (`sw-gui`).
- **Comando Git:**
  ```bash
  git init -b main
  ```
  *Salida:* `Inicializado repositorio Git vacío en /home/hermes/Proyectos/SilverWarden-Rs/.git/`

---

## Historial de Hitos y Tareas

| Milestone | Tarea | Estado | Evidencia registrada |
|---|---|---|---|
| M0 | Inicialización y Scaffolding del Workspace | Hecho | Commit raíz `5760379` en `main`, rama `develop` activa |
| M1 | [SW-001] Memoria segura bloqueada | Hecho | `cargo test -p sw-crypto`: 3 tests pasan (wipe, lifecycle, empty) |
| M1 | [SW-002] EncString parser/serializador | Hecho | `cargo test -p sw-crypto`: 4 tests pasan (roundtrip 0/2, null, invalid) |
| M1 | [SW-003] KDF Bitwarden | Hecho | `cargo test -p sw-crypto`: 32 tests pasan, paridad byte a byte con Go |
| M2 | Config y Migración `sw-config` | Pendiente | Por registrar |
| M3 | Agente e IPC `sw-ipc`, `sw-agent`, `sw-systemauth` | Pendiente | Por registrar |
| M4 | Vault y Bitwarden API `sw-vault`, `sw-bitwarden-api` | Pendiente | Por registrar |
| M5 | SSH Agent `sw-ssh-agent` | Pendiente | Por registrar |
| M6 | Seguridad de Sesión y Notificaciones `sw-notify` | Pendiente | Post-MVP |
| M7 | GUI Tauri `sw-gui` | Pendiente | Post-MVP |
| M8 | Autotipo `sw-autotype` | Pendiente | Post-MVP |
| M9 | Browser Biometrics `sw-browserbiometrics` | Pendiente | Post-MVP |
| M10 | Portabilidad y Empaquetado | Pendiente | Post-MVP |

---

## 1. Evidencia de Ejecución: M1 — Núcleo criptográfico `sw-crypto`

### [SW-001] Memoria segura bloqueada & [SW-002] EncString (Robustecido)

**Comandos ejecutados y resultados reales:**

1. **Formato:**
   ```bash
   cargo fmt --all -- --check
   ```
   *Salida:* `0 diffs` (Código 0)

2. **Linter / Calidad estática:**
   ```bash
   cargo clippy --workspace --exclude sw-gui --all-targets -- -D warnings
   ```
   *Salida real:*
   ```text
       Checking sw-crypto v0.1.0 (/home/hermes/Proyectos/SilverWarden-Rs/crates/sw-crypto)
       Checking sw-ipc v0.1.0 (/home/hermes/Proyectos/SilverWarden-Rs/crates/sw-ipc)
       Checking sw-systemauth v0.1.0 (/home/hermes/Proyectos/SilverWarden-Rs/crates/sw-systemauth)
       Checking sw-notify v0.1.0 (/home/hermes/Proyectos/SilverWarden-Rs/crates/sw-notify)
       Checking sw-browserbiometrics v0.1.0 (/home/hermes/Proyectos/SilverWarden-Rs/crates/sw-browserbiometrics)
       Checking sw-autotype v0.1.0 (/home/hermes/Proyectos/SilverWarden-Rs/crates/sw-autotype)
       Checking sw-config v0.1.0 (/home/hermes/Proyectos/SilverWarden-Rs/crates/sw-config)
       Checking sw-vault v0.1.0 (/home/hermes/Proyectos/SilverWarden-Rs/crates/sw-vault)
       Checking sw-bitwarden-api v0.1.0 (/home/hermes/Proyectos/SilverWarden-Rs/crates/sw-bitwarden-api)
       Checking sw-ssh-agent v0.1.0 (/home/hermes/Proyectos/SilverWarden-Rs/crates/sw-ssh-agent)
       Checking sw-agent v0.1.0 (/home/hermes/Proyectos/SilverWarden-Rs/crates/sw-agent)
       Checking sw-cli v0.1.0 (/home/hermes/Proyectos/SilverWarden-Rs/crates/sw-cli)
       Finished `dev` profile [unoptimized + debuginfo] target(s) in 4.11s
   ```
   *Resultado:* 0 warnings, 0 errores.

3. **Pruebas del Workspace completo:**
   ```bash
   cargo test --workspace --exclude sw-gui
   ```
   *Salida real de ejecución:*
   ```text
   running 24 tests
   test encstring::tests::test_display_trait ... ok
   test encstring::tests::test_invalid_type_integer ... ok
   test encstring::tests::test_invalid_formats ... ok
   test encstring::tests::test_invalid_base64 ... ok
   test encstring::tests::test_is_null ... ok
   test encstring::tests::test_missing_dot ... ok
   test encstring::tests::test_roundtrip_asymmetric_sha1 ... ok
   test encstring::tests::test_roundtrip_asymmetric_sha256 ... ok
   test encstring::tests::test_roundtrip_asymmetric_with_mac ... ok
   test encstring::tests::test_roundtrip_type_0 ... ok
   test encstring::tests::test_roundtrip_type_1 ... ok
   test encstring::tests::test_type_from_i32_all_variants ... ok
   test encstring::tests::test_type_1_wrong_parts ... ok
   test mem::tests::test_empty_buffers ... ok
   test mem::tests::test_mem_locked_as_mut_slice ... ok
   test mem::tests::test_empty_memory_buffer ... ok
   test mem::tests::test_mem_locked_buffer_lifecycle ... ok
   test mem::tests::test_mem_locked_with_capacity_zero ... ok
   test encstring::tests::test_roundtrip_type_2 ... ok
   test mem::tests::test_memory_buffer_as_mut_slice ... ok
   test mem::tests::test_memory_buffer_wipe ... ok
   test mem::tests::test_memory_buffer_with_capacity ... ok
   test mem::tests::test_mlock_succeeds ... ok
   test mem::tests::test_with_capacity_is_locked ... ok

   test result: ok. 24 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
   ```

4. **Cobertura de Código en Núcleo Criptográfico (`sw-crypto`):**
   ```bash
   cargo llvm-cov -p sw-crypto --summary-only
   ```
   *Salida real de ejecución:*
   ```text
   Filename      Regions  Missed Regions    Cover   Functions  Missed Functions  Executed   Lines  Missed Lines    Cover
   ----------------------------------------------------------------------------------------------------------------------
   encstring.rs      497              47   90.54%          34                 9    73.53%     324            25   92.28%
   mem.rs            243              12   95.06%          28                 4    85.71%     145             8   94.48%
   ----------------------------------------------------------------------------------------------------------------------
   TOTAL             740              59   92.03%          62                13    79.03%     469            33   92.96%
   ```
   *Resultado:* **92.96%** en líneas y **92.03%** en regiones (Supera el umbral obligatorio de **≥90%** para `sw-crypto`).

5. **Auditoría de Vulnerabilidades y Dependencias:**
   ```bash
   cargo audit
   ```
   *Salida real:*
   ```text
       Fetching advisory database from `https://github.com/RustSec/advisory-db.git`
         Loaded 1309 security advisories (from /home/hermes/.cargo/advisory-db)
       Updating crates.io index
       Scanning Cargo.lock for vulnerabilities (587 crate dependencies)
   ```
   *Resultado:* 0 vulnerabilidades bloqueantes.

---

## 2. Decisiones de Seguridad y Excepciones Aprobadas

### Excepción RUSTSEC-2023-0071 (`rsa` 0.9.10 — Marvin Attack)
- **Vulnerabilidad:** Posible recuperación de clave por canal lateral de temporización en descifrado PKCS#1 v1.5 / OAEP.
- **Estado:** Excepción aprobada y configurada en `.cargo/audit.toml`.
- **Justificación técnica:**
  1. `rsa` es la única implementación completa en Rust para `RSA-OAEP-SHA1`, requerida obligatoriamente para descifrar `encKey` asimétrica legacy de Bitwarden (tarea `SW-006`).
  2. El uso en silverWarden-rs es estrictamente local y confinado a descifrar `encKey` una única vez por sesión contra datos en disco/memoria propios, sin exposición a interfaces de red ni a atacantes remotos que puedan medir tiempos de respuesta.
- **Mitigación:** Ninguna clave privada RSA es expuesta vía sockets de red sin autenticación previa.

**Criterios de aceptación verificados para SW-001 y SW-002:**
- [x] Trait `LockedBuffer` y las dos implementaciones (`MemLockedBuffer` y `MemoryBuffer`) compilan en Linux con `rustix`.
- [x] Propagación de errores de `mlock` mediante `CryptoError::MemLockError` en `new` y `with_capacity`.
- [x] Bloqueo directo de memoria en `with_capacity` (verificado con `test_with_capacity_is_locked`).
- [x] Verificación de éxito de `mlock` en `test_mlock_succeeds`.
- [x] `wipe()` pisa los bytes a ceros (verificado en `test_memory_buffer_wipe` y `test_mem_locked_buffer_lifecycle`).
- [x] Desbloqueo (`munlock`) y `zeroize` al dropear el buffer.
- [x] Roundtrip serialize→parse de `EncString` para todos los tipos (0, 1, 2, 3, 4, 5, 6).
- [x] Rechazo de tipos inválidos, base64 corrupto y partes faltantes con errores tipados `CryptoError`.
- [x] `is_null()` verificado equivalente a Go.
### [SW-003] KDF Bitwarden (argon2id / pbkdf2)

**Comandos ejecutados y resultados reales:**

1. **Formato:**
   ```bash
   cargo fmt --all -- --check
   ```
   *Salida:* `0 diffs` (Código 0)

2. **Linter / Calidad estática:**
   ```bash
   cargo clippy --workspace --exclude sw-gui --all-targets -- -D warnings
   ```
   *Salida real:*
   ```text
       Checking pbkdf2 v0.12.2
       Checking sw-ipc v0.1.0 (/home/hermes/Proyectos/SilverWarden-Rs/crates/sw-ipc)
       Checking sw-systemauth v0.1.0 (/home/hermes/Proyectos/SilverWarden-Rs/crates/sw-systemauth)
       Checking sw-notify v0.1.0 (/home/hermes/Proyectos/SilverWarden-Rs/crates/sw-notify)
       Checking sw-browserbiometrics v0.1.0 (/home/hermes/Proyectos/SilverWarden-Rs/crates/sw-browserbiometrics)
       Checking sw-autotype v0.1.0 (/home/hermes/Proyectos/SilverWarden-Rs/crates/sw-autotype)
       Checking sw-crypto v0.1.0 (/home/hermes/Proyectos/SilverWarden-Rs/crates/sw-crypto)
       Checking sw-config v0.1.0 (/home/hermes/Proyectos/SilverWarden-Rs/crates/sw-config)
       Checking sw-vault v0.1.0 (/home/hermes/Proyectos/SilverWarden-Rs/crates/sw-vault)
       Checking sw-agent v0.1.0 (/home/hermes/Proyectos/SilverWarden-Rs/crates/sw-agent)
       Checking sw-cli v0.1.0 (/home/hermes/Proyectos/SilverWarden-Rs/crates/sw-cli)
       Checking sw-bitwarden-api v0.1.0 (/home/hermes/Proyectos/SilverWarden-Rs/crates/sw-bitwarden-api)
       Checking sw-ssh-agent v0.1.0 (/home/hermes/Proyectos/SilverWarden-Rs/crates/sw-ssh-agent)
       Finished `dev` profile [unoptimized + debuginfo] target(s) in 15.96s
   ```
   *Resultado:* 0 warnings, 0 errores.

3. **Pruebas de `sw-crypto` (32 tests unitarios y de paridad):**
   ```bash
   cargo test -p sw-crypto
   ```
   *Salida real de ejecución:*
   ```text
   running 32 tests
   test encstring::tests::test_roundtrip_asymmetric_sha256 ... ok
   test encstring::tests::test_roundtrip_asymmetric_sha1 ... ok
   test encstring::tests::test_invalid_base64 ... ok
   test encstring::tests::test_missing_dot ... ok
   test encstring::tests::test_invalid_type_integer ... ok
   test encstring::tests::test_invalid_formats ... ok
   test encstring::tests::test_display_trait ... ok
   test encstring::tests::test_roundtrip_asymmetric_with_mac ... ok
   test encstring::tests::test_roundtrip_type_0 ... ok
   test encstring::tests::test_roundtrip_type_1 ... ok
   test encstring::tests::test_type_1_wrong_parts ... ok
   test encstring::tests::test_type_from_i32_all_variants ... ok
   test encstring::tests::test_roundtrip_type_2 ... ok
   test kdf::tests::test_kdf_type_from_i32 ... ok
   test kdf::tests::test_master_key_lifecycle ... ok
   test kdf::tests::test_normalize_email_no_trim ... ok
   test kdf::tests::test_kdf_config_serde ... ok
   test encstring::tests::test_is_null ... ok
   test mem::tests::test_mem_locked_as_mut_slice ... ok
   test kdf::tests::test_pbkdf2_hmac_sha256_vector ... ok
   test mem::tests::test_empty_buffers ... ok
   test mem::tests::test_empty_memory_buffer ... ok
   test mem::tests::test_mem_locked_buffer_lifecycle ... ok
   test kdf::tests::test_param_validation ... ok
   test mem::tests::test_mem_locked_with_capacity_zero ... ok
   test mem::tests::test_memory_buffer_as_mut_slice ... ok
   test mem::tests::test_memory_buffer_with_capacity ... ok
   test mem::tests::test_memory_buffer_wipe ... ok
   test mem::tests::test_mlock_succeeds ... ok
   test mem::tests::test_with_capacity_is_locked ... ok
   test kdf::tests::test_parity_go_pbkdf2 ... ok
   test kdf::tests::test_parity_go_argon2id ... ok

   test result: ok. 32 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 12.99s
   ```

4. **Cobertura de Código en `sw-crypto` (incluyendo KDF):**
   ```bash
   cargo llvm-cov -p sw-crypto --summary-only
   ```
   *Salida real de ejecución:*
   ```text
   Filename      Regions  Missed Regions    Cover   Functions  Missed Functions  Executed   Lines  Missed Lines    Cover
   ----------------------------------------------------------------------------------------------------------------------
   encstring.rs      497              47   90.54%          34                 9    73.53%     324            25   92.28%
   kdf.rs            294              18   93.88%          24                 4    83.33%     211            12   94.31%
   mem.rs            243              12   95.06%          28                 4    85.71%     145             8   94.48%
   ----------------------------------------------------------------------------------------------------------------------
   TOTAL            1034              77   92.55%          86                17    80.23%     680            45   93.38%
   ```
   *Resultado:* **93.38%** líneas / **92.55%** regiones en `sw-crypto` (Supera ampliamente el umbral de **≥90%**).

5. **Auditoría de Seguridad:**
   ```bash
   cargo audit
   ```
   *Resultado:* 0 vulnerabilidades bloqueantes encontradas en 587 crates inspeccionadas.

**Criterios de aceptación verificados para SW-003:**
- [x] Vectores cruzados Go ↔ Rust verificados byte a byte:
  - PBKDF2: `f4de0e1196ff2e80ac327345d9e035ddbb6fb8c6129acdf1cbf9991c63f16370` (coincidencia exacta).
  - Argon2id: `8fc048a537cbda3e8b6c8596a13ec3a879b929a1a0304dddffec8df18a06222f` (coincidencia exacta con D5 `m_cost = memory * 1024`).
- [x] Soporta ambos tipos de KDF (`KdfType::Pbkdf2` = 0, `KdfType::Argon2id` = 1).
- [x] Parámetros leídos de `KdfConfig` deserializado con alias compatibles con respuestas reales de Bitwarden.
- [x] MasterKey protegida en memoria con `MemLockedBuffer` (`mlock` + `MADV_DONTDUMP` + `zeroize` on drop).
- [x] Cobertura de código en `kdf.rs` de **93.88%** regiones y **94.31%** líneas (global de `sw-crypto`: **92.55%**).




