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
| M1 | [SW-004] Jerarquía de claves (HKDF stretch) | Hecho | `cargo test -p sw-crypto`: 42 tests pasan, stretch_key y SymmetricKey verificados Go↔Rust |
| M1 | [SW-005] Cifrado simétrico EncryptWith/DecryptWith | Hecho | `cargo test -p sw-crypto`: 51 tests pasan, paridad exacta en Tipo 0 y Tipo 2, mitigación padding oracle |
| M1 | [SW-006] RSA legacy OAEP-SHA1 | Hecho | `cargo test -p sw-crypto`: 61 tests pasan, interop bidireccional Go↔Rust, clave privada en memoria bloqueada |
| M1 | [SW-007] Suite de fuzzing en sw-crypto | Hecho | cargo-fuzz con 4 targets (EncString, pkcs7_unpad, decrypt_with, decrypt_asym), corpus semilla, CI job, 0 crashes |
| M2 | [SW-010] Estructura ConfigFile con serde | Hecho | `cargo test -p sw-config`: 4 tests pasan (12 campos PascalCase, LoginToken, roundtrip, parseo de goldwarden.json real) |
| M2 | [SW-011] Cifrado de campos de config | Hecho | `cargo test -p sw-config`: 10 tests pasan (Argon2i, Tink ChaCha20-Poly1305, SHA3-256, descifrado token Go real, update_pin) |
| M2 | [SW-012] Lectura + migración de path viejo | Pendiente | Detección legacy ~/.config/goldwarden.json -> ~/.config/goldwarden/, 0700/0600, fix Go bug |
| M2 | [SW-013] Comando silverwarden migrate con backup | Pendiente | Backup .bak-<timestamp>, migración estado local, instrucción sync M4 |
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
### 1.2 [SW-003] KDF Bitwarden (PBKDF2 / Argon2id)

**Commit:** `c0e95a3` (implementación) + verificación de paridad posterior (2026-10-13).

#### Implementación

- `crates/sw-crypto/src/kdf.rs`: `KdfType`, `KdfConfig` (serde compatible con prelogin de Bitwarden), `MasterKey` (envuelve `MemLockedBuffer` de SW-001), `derive_master_key()`.
- `crates/sw-crypto/src/error.rs`: variante `InvalidKdfParams(String)`.
- `crates/sw-crypto/src/lib.rs`: re-exportaciones.
- `Cargo.toml` raíz: feature `hmac` en `pbkdf2`.
- `crates/sw-crypto/Cargo.toml`: `serde` como dependencia, `serde_json` como dev-dependency.

#### Paridad criptográfica Go ↔ Rust (verificada)

**Herramienta:** `~/Proyectos/goldwarden/tools/parity/main.go` (no commiteado), que importa `github.com/quexten/goldwarden/cli/agent/bitwarden/crypto` y llama a `crypto.DeriveMasterKey`.

**Inputs comunes:**
- password = `password123`
- email = `user@example.com`
- PBKDF2: iterations = 100000
- Argon2id: iterations = 3, memory = 64 (MB), parallelism = 4

**Salida real de Go (2026-10-13):**
```text
PBKDF2:   f4de0e1196ff2e80ac327345d9e035ddbb6fb8c6129acdf1cbf9991c63f16370
Argon2id: 8fc048a537cbda3e8b6c8596a13ec3a879b929a1a0304dddffec8df18a06222f
```

**Resultado en Rust:**
- `test_parity_go_pbkdf2`: esperado `f4de0e...` → coincide ✅
- `test_parity_go_argon2id`: esperado `8fc048...` → coincide ✅

*Nota de proceso:* la primera ejecución del `main.go` de paridad pasó `memory = 65536` (KiB) en lugar de `64` (MB), lo que hizo que Go intentara reservar 64 GiB y crasheara con out of memory. La verificación Argon2id quedó pendiente en ese momento. Se corrigió el input a `memory = 64` y se obtuvo la salida real. La paridad Argon2id no se declaró Hecho hasta contar con esta evidencia.

#### Criterios de aceptación
- [x] PBKDF2 paridad byte a byte Go↔Rust verificada.
- [x] Argon2id paridad byte a byte Go↔Rust verificada.
- [x] Soporta ambos tipos de KDF (`KdfType::Pbkdf2` = 0, `KdfType::Argon2id` = 1).
- [x] Parámetros leídos de `KdfConfig` (deserialización compatible con prelogin real).
- [x] `MasterKey` protegida con `MemLockedBuffer` (`mlock` + `MADV_DONTDUMP` + `zeroize` on drop).
- [x] Normalización de email en minúsculas sin trim (paridad con `strings.ToLower(email)`).
- [x] Validación de params (iterations > 0, memory/parallelism obligatorios en Argon2id, límite de 4 GiB).

#### Controles obligatorios (2026-10-13)

| Control | Comando | Resultado real |
|---|---|---|
| Pruebas unitarias | `cargo test --workspace --exclude sw-gui` | 32 pasan, 0 fallan, 0 ignorados |
| Linter | `cargo clippy --workspace --exclude sw-gui --all-targets -- -D warnings` | 0 warnings |
| Formato | `cargo fmt --all -- --check` | 0 diffs |
| Auditoría | `cargo audit` | 0 vulnerabilidades (3 advisories con excepción en `.cargo/audit.toml`) |
| Cobertura `sw-crypto` | `cargo llvm-cov -p sw-crypto --summary-only` | 93.38% líneas / 92.55% regiones |

**Cobertura por archivo (`sw-crypto`):**

| Archivo | Regiones | Líneas |
|---|---|---|
| `encstring.rs` | 90.54% | 92.28% |
| `kdf.rs` | 93.88% | 94.31% |
| `mem.rs` | 95.06% | 94.48% |
| **TOTAL `sw-crypto`** | **92.55%** | **93.38%** |

**Estado:** ✅ SW-003 — Hecho (2026-10-13).

---

### 1.3 [SW-004] Jerarquía de claves (stretch_key + SymmetricKey + Keyring)

**Commit:** `f810869` (implementación) + `b9fb1bc` (correcciones).

**Alcance:** Opción A — `stretch_key`, `SymmetricKey`, `Keyring` (estructura). Las funciones que descifran (`InitKeyringFrom*`, `get_symmetric_key_for_organization`) quedan como stubs `NotImplemented` hasta SW-005/SW-006.

#### Paridad criptográfica Go ↔ Rust (verificada)

**Herramienta:** `crypto.StretchKeyForParity` (archivo local `keyhierarchy_export_test.go`, no commiteado) ejecutada vía `go test -tags=parity`.

**Salida real de Go (2026-10-13):**
```text
PBKDF2 MasterKey:  f4de0e1196ff2e80ac327345d9e035ddbb6fb8c6129acdf1cbf9991c63f16370
PBKDF2 stretch enc: 4259e08507dbfad827ca1c49441249ddff3456f09e7827522e197917d9449928
PBKDF2 stretch mac: b552622d1da25d3fe35e9a9718d76e996e344156195fe903f0eb2018c695f557
PBKDF2 stretch all: 4259e08507dbfad827ca1c49441249ddff3456f09e7827522e197917d9449928b552622d1da25d3fe35e9a9718d76e996e344156195fe903f0eb2018c695f557
Argon2id MasterKey: 8fc048a537cbda3e8b6c8596a13ec3a879b929a1a0304dddffec8df18a06222f
Argon2id stretch enc: f7f449446a3e586d480c4aa83a4640c180a8737fcc6efd7a483645e39761b008
Argon2id stretch mac: 6911da83c0e785d2a32217600ecf67fa4006e59a04760f311dd2c55724ee1ee3
Argon2id stretch all: f7f449446a3e586d480c4aa83a4640c180a8737fcc6efd7a483645e39761b0086911da83c0e785d2a32217600ecf67fa4006e59a04760f311dd2c55724ee1ee3
```

**Resultado en Rust:** los cuatro vectores coinciden byte a byte. `test_parity_go_stretch_pbkdf2` y `test_parity_go_stretch_argon2id` pasan. ✅

*Nota:* `stretch_key` usa `Hkdf::<Sha256>::from_prk` (no `new`), con `info = b"enc"` / `b"mac"`. Paridad verificada.

#### Correcciones aplicadas (commit `b9fb1bc`)
- `impl Clone for SymmetricKey` eliminado. Usaba `.expect()` y podía panicar si `mlock` fallaba. Reemplazado por `try_clone() -> Result<Self, CryptoError>`.
- `StretchKeyForParity` fuera de producción. Movido a archivo con build tag `parity` en el repo Go (referencia local, no commiteado).
- Tests de stubs no-mutantes. Verifican que `Keyring` no cambia de estado tras llamar a los stubs.

#### Criterios de aceptación
- [x] `stretch_key` produce bytes idénticos a Go (enc y mac, PBKDF2 y Argon2id).
- [x] `SymmetricKey::from_bytes` / `bytes()` roundtrip (64 bytes).
- [x] `Keyring` lock/unlock con wipe.
- [x] `stretch_key` usa `from_prk` (verificado por paridad).
- [x] Stubs devuelven `NotImplemented`, sin mutar estado.
- [x] Cobertura `keyhierarchy.rs` ≥90% (97.02% líneas).

#### Controles obligatorios (2026-10-13)

| Control | Comando | Resultado real |
|---|---|---|
| Pruebas unitarias | `cargo test --workspace --exclude sw-gui` | 42 pasan, 0 fallan |
| Linter | `cargo clippy --workspace --exclude sw-gui --all-targets -- -D warnings` | 0 warnings |
| Formato | `cargo fmt --all -- --check` | 0 diffs |
| Auditoría | `cargo audit` | 0 vulnerabilidades |
| Cobertura `sw-crypto` | `cargo llvm-cov -p sw-crypto --summary-only` | 93.79% regiones / 94.50% líneas |

**Cobertura por archivo (`sw-crypto`):**

| Archivo | Regiones | Líneas |
|---|---|---|
| `encstring.rs` | 90.54% | 92.28% |
| `kdf.rs` | 93.88% | 94.31% |
| `keyhierarchy.rs` | 96.38% | 97.02% |
| `mem.rs` | 95.06% | 94.48% |
| **TOTAL `sw-crypto`** | **93.79%** | **94.50%** |

**Estado:** ✅ SW-004 — Hecho (2026-10-13).

---

### 1.4 [SW-005] Cifrado simétrico (EncryptWith / DecryptWith)

**Commit:** `e7c5328` (implementación) + verificación de paridad (2026-10-13).

**Alcance:** Cifrado y descifrado simétrico AES-256-CBC con padding PKCS#7 y autenticación HMAC-SHA256 (`encrypt_with`, `encrypt_with_to_string`, `decrypt_with`). Soporte de Tipo 0 (`AesCbc256_B64`) y Tipo 2 (`AesCbc256_HmacSha256_B64`). Corrección D20 (unpad completo) y D21 (Tipo 0 serializa a cadena vacía).

#### Implementación

- `crates/sw-crypto/src/cipher.rs`:
  - `pkcs7_pad` / `pkcs7_unpad`: padding PKCS#7 con validación estricta de uniformidad en todos los bytes de relleno (decisión D20, corrigiendo el defecto de validación parcial de Go).
  - `is_mac_valid`: verificación HMAC-SHA256 en tiempo constante con `subtle::ConstantTimeEq`.
  - `encrypt_aes_cbc_256`: cifrado AES-256-CBC usando `cbc::Encryptor<aes::Aes256>` con IV aleatorio de `rand::thread_rng()` u opcionalmente fijo para pruebas deterministas.
  - `decrypt_aes_cbc_256`: descifrado AES-256-CBC con validaciones de tamaño de bloque y desacolchado PKCS#7.
  - `encrypt_with` / `encrypt_with_to_string`: construcción de `EncString` (con cálculo de MAC sobre `IV || CT` para Tipo 2).
  - `decrypt_with`: verificación del MAC previa a cualquier intento de descifrado (mitigación anti padding-oracle), logging de advertencia para Tipo 0 insecure (`tracing::warn!`).
- `crates/sw-crypto/src/encstring.rs`:
  - Corrección D21: `EncString::to_string_repr()` devuelve `Ok(String::new())` para Tipo 0 (`AesCbc256B64`), asegurando paridad exacta con `MarshalText()` de Go.
- `crates/sw-crypto/src/error.rs`:
  - Variantes `InvalidPadding(String)`, `MacMismatch(String)`, `InvalidCiphertext(String)`.
- `crates/sw-crypto/src/lib.rs`:
  - Re-exportación de `encrypt_with`, `encrypt_with_to_string`, `decrypt_with`.

#### Paridad criptográfica Go ↔ Rust (verificada)

**Herramienta:** `cli/agent/bitwarden/crypto/parity_test.go` ejecutada vía `go test -v -tags=parity ./cli/agent/bitwarden/crypto -run TestCipherParity` en Goldwarden.

**Inputs comunes:**
- Plaintext = `hello world`
- EncKey = `0x42` × 32 bytes (`42424242...`)
- MacKey = `0x43` × 32 bytes (`43434343...`)
- IV fijo = `0x24` × 16 bytes (`24242424...`)

**Salida real de Go (2026-10-13):**
```text
=== RUN   TestCipherParity
=== CIPHER TYPE 2 PARITY ===
Plaintext:  hello world
EncKey:     4242424242424242424242424242424242424242424242424242424242424242
MacKey:     4343434343434343434343434343434343434343434343434343434343434343
IV:         24242424242424242424242424242424
CT:         edcfa3ee3645667d5e9b3b4fbbcce520
MAC:        56105a93e5dbd81bcdf3f030182b109ba2d7fa99108e0fda4b468c2322a30ca4
Wire:       2.JCQkJCQkJCQkJCQkJCQkJA==|7c+j7jZFZn1emztPu8zlIA==|VhBak+Xb2BvN8/AwGCsQm6LX+pkQjg/aS0aMIyKjDKQ=

[WRN] [18:46] [Goldwarden > Crypto] >>> WARNING: VAULT CONTAINS	INSECURE AesCbc256_B64 CIPHER, PLEASE ROTATE YOUR VAULT	KEYS IN	THE	WEB	VAULT
=== CIPHER TYPE 0 PARITY ===
CT (type 0): edcfa3ee3645667d5e9b3b4fbbcce520
Wire (type 0): 
Wire len (type 0): 0
Tampered MAC error: decrypt: MAC mismatch
--- PASS: TestCipherParity (0.00s)
PASS
```

**Resultado en Rust:**
- `test_parity_go_cipher_type_2`: CT, MAC y wire string coinciden exactamente byte a byte ✅
- `test_parity_go_cipher_type_0`: CT coincide y wire string devuelve cadena vacía de 0 bytes (D21) ✅
- `test_mac_mismatch_fails_before_decrypt`: MAC alterada falla inmediatamente con `CryptoError::MacMismatch` sin ejecutar descifrado ✅
- Descifrado cruzado: el wire string generado por Go es descifrado correctamente por Rust produciendo `hello world` ✅

#### Criterios de aceptación
- [x] `encrypt_with` produce CT + MAC idénticos a Go para mismo plaintext, key, IV y tipo 2.
- [x] `decrypt_with` descifra a plaintext idéntico a Go para strings cifrados por Go.
- [x] MAC inválida es rechazada con `CryptoError::MacMismatch` antes de descifrar.
- [x] Tipo 0 descifra correctamente emitiendo advertencia (`tracing::warn!`).
- [x] `pkcs7_unpad` valida el relleno completo byte a byte (D20).
- [x] `to_string_repr` para Tipo 0 devuelve `""` (D21).
- [x] Cobertura en `cipher.rs` ≥90% (**94.62%** regiones / **90.17%** líneas).

#### Controles obligatorios (2026-10-13)

| Control | Comando | Resultado real |
|---|---|---|
| Pruebas unitarias | `cargo test --workspace --exclude sw-gui` | 51 pasan, 0 fallan, 0 ignorados |
| Linter | `cargo clippy --workspace --exclude sw-gui --all-targets -- -D warnings` | 0 warnings |
| Formato | `cargo fmt --all -- --check` | 0 diffs |
| Auditoría | `cargo audit` | 0 vulnerabilidades (3 advisories con excepción en `.cargo/audit.toml`) |
| Cobertura `sw-crypto` | `cargo llvm-cov -p sw-crypto --summary-only` | 93.93% regiones / 93.38% líneas |

**Cobertura por archivo (`sw-crypto`):**

| Archivo | Regiones | Líneas |
|---|---|---|
| `cipher.rs` | 94.62% | 90.17% |
| `encstring.rs` | 90.34% | 91.84% |
| `kdf.rs` | 93.88% | 94.31% |
| `keyhierarchy.rs` | 96.38% | 97.02% |
| `mem.rs` | 95.06% | 94.48% |
| **TOTAL `sw-crypto`** | **93.93%** | **93.38%** |

**Estado:** ✅ SW-005 — Hecho (2026-10-13).

---

### 1.5 [SW-006] RSA legacy OAEP-SHA1

**Commit:** `8411191` (implementación) + verificación de interoperabilidad (2026-10-13).

**Alcance:** Cifrado y descifrado asimétrico RSA-2048 OAEP con SHA-1 (`encrypt_with_asymmetric`, `decrypt_with_asymmetric`), generación de pares de claves (`AsymmetricKey::generate`) con entropía del SO (`OsRng`), parseo de claves privadas PKCS#8 DER en memoria bloqueada (`MemLockedBuffer`), exportación de clave pública en formato PKIX/SPKI DER (`public_bytes`), soporte de formato en cable `4.<base64>` (Tipo 4 de Bitwarden). Corrección conceptual del RNG en cifrado simétrico migrado a `OsRng`.

#### Implementación

- `crates/sw-crypto/src/asymmetric.rs`:
  - `AsymmetricKey`: envuelve la clave privada PKCS#8 en `MemLockedBuffer` (`mlock` + `MADV_DONTDUMP` + `zeroize` on drop). Implementa `generate()`, `from_pkcs8()`, `private_bytes()`, `public_bytes()`, `try_clone()`, `wipe()` y `Debug` redactado.
  - `encrypt_with_asymmetric`: cifra con RSAES-OAEP-SHA1 y serializa a `4.<base64>`.
  - `decrypt_with_asymmetric`: valida prefijo `4.`, decodifica base64 y descifra con RSAES-OAEP-SHA1.
- `crates/sw-crypto/src/cipher.rs`:
  - Migración de `rand::thread_rng()` a `rand::rngs::OsRng` para generación de IV aleatorio en `encrypt_aes_cbc_256` (paridad conceptual con `crypto/rand` de Go).
- `crates/sw-crypto/src/error.rs`:
  - Nuevas variantes tipadas: `InvalidAsymmetricKey(String)`, `AsymmetricDecryptionFailed(String)`, `InvalidPrefix(String)`.
- `crates/sw-crypto/src/lib.rs`:
  - Re-exportación de `AsymmetricKey`, `encrypt_with_asymmetric`, `decrypt_with_asymmetric`.
- `Cargo.toml` (raíz y `sw-crypto`):
  - Inclusión de dependencia `sha1 = "0.10"`.

#### Interoperabilidad Criptográfica Go ↔ Rust (verificada)

**Herramienta:** `cli/agent/bitwarden/crypto/parity_test.go` (`TestAsymmetricParity` y `TestDecryptRustCiphertext`).

**1. Go genera clave y cifra fixture $\rightarrow$ Rust descifra:**
- Plaintext: `symmetric-org-key-secret-payload-64-bytes-long-padding-test-1234`
- Go Wire Ciphertext: `4.EyXlIUCwHtcE34SrfzHPFpTMGXnqWeSl/b8Zr3p4UVekQQ4YrSEkW5EC4odCU2dZZ3lniP/5avOmfv/13AlFFpaV85BVOf2PUO0brEy+KHz5F7VhjLSE4VwDwnpQEtDOD8OsdXs0T16mPoHaCDcV8eNiNAw5honLLXZfvJI7HXp7EnK4SPFtcJVQk+dbOZ+9KPLB1+faxjTz7LFKXACVBZs2g7m4xiWrybOawPQ8J3vqgOhU3QQmFwXbu9hlNvUq4MSBHA42XsMHnBVUcCPUxDrSpzDgDKDbSLR/PLaYeV+Xm7SdAkO8ZNrb4B2GJ+BL+1IFEyghkBHy4e3kFJsUNA==`
- Resultado en Rust (`test_parity_decrypt_go_fixture`): Descifra exitosamente el texto original. ✅

**2. Rust cifra con clave pública de Go $\rightarrow$ Go descifra:**
- Plaintext: `testing rust encryption with go public key`
- Rust Wire Ciphertext: `4.xIYUaJTv5P5fMNvi7OV0lu8vnk88BTGjnw6LF+lNJWeclCmRssSE2j20dOAfGT6VrdBXQsZYhpzxwkGkQR/XZ4gn0DY2QyH1Vw6eK986rBZskQjZl5qF8R7bJiA6M0+GIzcfSAfe25VqDKA0ECvK2okXbmtMbH2abHq3OF9Bo8Am01ISApyIJUlgV7UKShlaxZD9QFDw1sTj60bKr7E4z+JKmN3jvUhJuGwle9gFp2ctMRXghSOxX6BVqJMYuoFVYCGzKt3b4Xi9WNVAY6T9NBUAZYexgYI2HIG0kit9ddP/Un25kwLC6J/3sSWJ+DkgOiVDwQevR3tnjyhlGKcizQ==`
- Salida real de Go (`TestDecryptRustCiphertext`):
```text
=== RUN   TestDecryptRustCiphertext
=== INTEROP SUCCESS: Go successfully decrypted Rust ciphertext! ===
Decrypted: "testing rust encryption with go public key"
--- PASS: TestDecryptRustCiphertext (0.01s)
PASS
```
- Resultado: Interoperabilidad bidireccional Go ↔ Rust 100% verificada. ✅

#### Criterios de aceptación
- [x] `generate()` produce clave RSA-2048 válida y `from_pkcs8()` la reparsea.
- [x] `encrypt_with_asymmetric` produce prefijo `"4."` + base64 válido.
- [x] `decrypt_with_asymmetric` descifra el output de Go (interop).
- [x] Go descifra el output de Rust (interop).
- [x] OAEP-SHA1 correcto (paridad de algoritmo con Bitwarden).
- [x] Clave privada alojada en memoria bloqueada (`MemLockedBuffer`).
- [x] Cobertura en `asymmetric.rs` ≥90% (**92.38%** regiones / **94.21%** líneas).
- [x] Clippy, fmt y audit limpios sin advertencias.

#### Controles obligatorios (2026-10-13)

| Control | Comando | Resultado real |
|---|---|---|
| Pruebas unitarias | `cargo test --workspace --exclude sw-gui` | 61 pasan en sw-crypto, 0 fallan, 0 ignorados |
| Linter | `cargo clippy --workspace --exclude sw-gui --all-targets -- -D warnings` | 0 warnings |
| Formato | `cargo fmt --all -- --check` | 0 diffs |
| Auditoría | `cargo audit` | 0 vulnerabilidades (3 advisories con excepción en `.cargo/audit.toml`) |
| Cobertura `sw-crypto` | `cargo llvm-cov -p sw-crypto --summary-only` | 93.68% regiones / 93.49% líneas |

**Cobertura por archivo (`sw-crypto`):**

| Archivo | Regiones | Líneas |
|---|---|---|
| `asymmetric.rs` | 92.38% | 94.21% |
| `cipher.rs` | 94.62% | 90.17% |
| `encstring.rs` | 90.34% | 91.84% |
| `kdf.rs` | 93.88% | 94.31% |
| `keyhierarchy.rs` | 96.38% | 97.02% |
| `mem.rs` | 95.06% | 94.48% |
| **TOTAL `sw-crypto`** | **93.68%** | **93.49%** |

**Estado:** ✅ SW-006 — Hecho (2026-10-13).

---

### 1.6 [SW-007] Suite de fuzzing en sw-crypto

**Commit:** `8290831` (implementación) + verificación de fuzzing (2026-10-13).

**Alcance:** Infraestructura completa de fuzzing continuo con `cargo-fuzz` y `libFuzzer` para los parsers criptográficos de `sw-crypto`. Cuatro targets implementados (`fuzz_encstring_parse`, `fuzz_pkcs7_unpad`, `fuzz_decrypt_with`, `fuzz_decrypt_with_asymmetric`), corpus semilla estructurado versionado, job de CI de 5 minutos por target en `main`, y reglas `.gitignore` para aislar corpus y artefactos generados. Cierre de Milestone M1.

#### Implementación

- `fuzz/Cargo.toml`: workspace propio para fuzz targets con dependencia a `sw-crypto` (`path = "../crates/sw-crypto"`) y `libfuzzer-sys = "0.4"`.
- `fuzz/.gitignore`: reglas para ignorar `target/`, `artifacts/`, `coverage/` y corpus generados dinámicamente (`corpus/*/*`), preservando los archivos de corpus semilla (`!corpus/*/valid*`, `!corpus/*/invalid*`, `!corpus/*/seed*`).
- `crates/sw-crypto/src/lib.rs`: re-exportación pública de `pkcs7_pad` y `pkcs7_unpad`.
- `.github/workflows/ci.yml`: job `fuzz` automatizado en pushes a rama `main` (5 min por target, total 20 min).

#### Fuzz Targets Implementados

1. **`fuzz_encstring_parse`** (`fuzz/fuzz_targets/fuzz_encstring_parse.rs`):
   - Ejercita el parser `EncString::from_str` con bytes UTF-8 arbitrarios.
   - Cero panics en entradas malformadas, faltantes de delimitadores (`.`, `|`), o bases64 inválidos.
2. **`fuzz_pkcs7_unpad`** (`fuzz/fuzz_targets/fuzz_pkcs7_unpad.rs`):
   - Ejercita la función de desacolchado PKCS#7 estricta (`pkcs7_unpad(data, 16)`).
   - Valida resistencia ante paddings truncados, nulos, o inconsistentes sin desbordamientos de buffer.
3. **`fuzz_decrypt_with`** (`fuzz/fuzz_targets/fuzz_decrypt_with.rs`):
   - Parsea `EncString` y ejecuta `decrypt_with` contra una clave simétrica de 64 bytes (`SymmetricKey`).
   - Verifica que alteraciones de MAC, IVs inválidos o payloads corruptos retornen errores tipados sin panic.
4. **`fuzz_decrypt_with_asymmetric`** (`fuzz/fuzz_targets/fuzz_decrypt_with_asymmetric.rs`):
   - Ejecuta `decrypt_with_asymmetric` con clave privada RSA-2048 PKCS#8 válida contra entradas arbitrarias.
   - Verifica manejo de prefijos inválidos, decodificación base64 y fallos de descifrado OAEP-SHA1 sin pánico.

#### Corpus Semilla

- `fuzz/corpus/fuzz_encstring_parse/`: `valid_type_0`, `valid_type_2`, `invalid_no_dot`, `invalid_type`.
- `fuzz/corpus/fuzz_pkcs7_unpad/`: `valid_16`, `invalid_padding`.
- `fuzz/corpus/fuzz_decrypt_with/`: `valid_type_2`, `valid_type_0`, `invalid_tampered`.
- `fuzz/corpus/fuzz_decrypt_with_asymmetric/`: `valid_go_wire`, `invalid_prefix`, `invalid_short`.

#### Evidencia Real de Ejecución de Fuzzing (2026-10-13)

| Target | Ejecuciones locales | Tiempo | Crashes | Cobertura alcanzada |
|---|---|---|---|---|
| `fuzz_encstring_parse` | 462,130 runs | 16s | **0** | cov: 496, ft: 1262 |
| `fuzz_pkcs7_unpad` | 732,109 runs | 16s | **0** | cov: 38, ft: 49 |
| `fuzz_decrypt_with` | 211,817 runs | 16s | **0** | cov: 725, ft: 1441 |
| `fuzz_decrypt_with_asymmetric` | 4,779 runs | 16s | **0** | cov: 1327, ft: 2281 |
| **TOTAL** | **1,410,835 runs** | **64s** | **0 crashes** | Robusto |

#### Criterios de Aceptación
- [x] `cargo-fuzz` configurado y funcional en `fuzz/` con workspace independiente.
- [x] 4 targets implementados y compilados exitosamente.
- [x] Corpus semilla estructurado y versionado en git.
- [x] Cada target ejecutado localmente sin crashes (>1.4 millones de ejecuciones acumuladas).
- [x] Job `fuzz` añadido a `.github/workflows/ci.yml` (5 min por target en `main`).
- [x] `.gitignore` aísla target, artefactos y corpus generados sin omitir el corpus semilla.
- [x] Evidencia real documentada en `03-ejecucion.md`.

#### Controles obligatorios (2026-10-13)

| Control | Comando | Resultado real |
|---|---|---|
| Pruebas unitarias | `cargo test --workspace --exclude sw-gui` | 61 pasan en sw-crypto, 0 fallan, 0 ignorados |
| Linter | `cargo clippy --workspace --exclude sw-gui --all-targets -- -D warnings` | 0 warnings |
| Formato | `cargo fmt --all -- --check` | 0 diffs |
| Auditoría | `cargo audit` | 0 vulnerabilidades (3 advisories con excepción en `.cargo/audit.toml`) |
| Cobertura `sw-crypto` | `cargo llvm-cov -p sw-crypto --summary-only` | 93.68% regiones / 93.49% líneas |

**Estado:** ✅ SW-007 — Hecho (2026-10-13).  
**Hito:** 🏁 **Milestone M1 (Criptografía y Memoria Segura) COMPLETADO al 100%.**

---

## 2. Milestone M2: Configuración y Migración (sw-config)

### 2.0 Plan Definitivo y Decisiones Técnicas Aplicadas

- **D30 (KDF de Config):** Derivación de clave desde PIN usando **Argon2i** (variante `i`, no `id`), parámetros $t=2, m=2048\text{ (2 GiB según semántica Go/Tink)}, p=8$, con salt = bytes de `DeviceUUID`.
- **D31 (Cifrado de Campos en Formato Tink Exacto):** ChaCha20-Poly1305 con cabecera de 5 bytes (`0x00` + ID de clave 4 bytes `0x00000000`) + nonce de 12 bytes + ciphertext + tag Poly1305 de 16 bytes. Serializado en base64 estándar en los campos string del archivo `goldwarden.json`. Usaremos la crate `tink-rust` o implementaremos el wrapper `TinkChaCha20Poly1305` sobre RustCrypto.
- **D32 (Hash de Clave de Config):** `ConfigKeyHash` = `hex(SHA3-256(key_derivado))` con verificación y comparación en tiempo constante (`subtle::ConstantTimeEq`).
- **D33 (Escritura Atómica):** Escritura a archivo temporal y rename atómico (`tempfile` + `rename`) en el mismo directorio para evitar el bug de pérdida y truncado de archivo identificado en el writer de Go ante interrupciones abruptas.
- **D34 (Corrección de Migración de Ruta Legacy):** Si `~/.config/goldwarden.json` existe, el nuevo path no existe, y el rename es exitoso, devolver `Ok(())` (arreglando el bug de Go que devolvía error al buscar el archivo viejo inexistente). Directorio creado con permisos 0700, archivo con 0600.
- **D35 (Alcance de SW-013 y Delimitación con M4):** SW-013 migra el estado local con backup (`goldwarden.json.bak-<timestamp>`) y verifica el desbloqueo con el PIN. Dado que las claves SSH y ciphers del vault no residen en texto claro en disco (o no deben presumirse locales), SW-013 concluye con el mensaje informativo: *"Configuración migrada. Ejecuta silverwarden sync (M4) para descargar tus claves SSH y contraseñas."* La sincronización y descarga completa se realiza en M4 a partir del export de Bitwarden.

### 2.1 Desglose de Historias M2

1. **[SW-010] Estructura ConfigFile con serde:**
   - Struct `ConfigFile`: con los 13 campos exactos de Go (`IdentityUrl`, `ApiUrl`, `NotificationsUrl`, `VaultUrl`, `DeviceUUID`, `EncryptedClientID`, `EncryptedClientSecret`, `EncryptedPin`, `ConfigKeyHash`, `LoginToken`, `RuntimeConfig`, `DeviceName`, `LastSynced`).
   - Struct `LoginToken`: los 5 campos JSON (`AccessToken`, `ExpiresIn`, `TokenType`, `RefreshToken`, `Key`).
   - Struct `RuntimeConfig`: configuración en memoria / runtime.
   - Serde: `#[serde(rename_all = "PascalCase")]` para paridad con Go.
   - Defaults: URLs por defecto (`vault.bitwarden.com`, etc.), `DeviceUUID` v4 aleatorio, campos cifrados vacíos.
   - Tests: parsear `goldwarden.json` real. Verificar que el JSON se serializa y deserializa sin perder datos (roundtrip).

2. **[SW-011] Cifrado de campos de config:**
   - Derivación de clave: Argon2i(password=PIN, salt=DeviceUUID_bytes, t=2, m=2048, p=8).
   - Hash del PIN: hex(SHA3-256(key)) y comparación en tiempo constante (`subtle::ConstantTimeEq`).
   - Cifrado Tink ChaCha20-Poly1305 (blob binario a base64).
   - Métodos: `encrypt_string`, `decrypt_string`, `VerifyPin`, `UpdatePin`, `Unlock`.
   - Tests: desbloquear `goldwarden.json` real con PIN correcto. Verificar que PIN incorrecto falla.

3. **[SW-012] Lectura + migración de path viejo:**
   - Buscar `~/.config/goldwarden.json` y moverlo a `~/.config/goldwarden/goldwarden.json`.
   - Crear directorio padre con permisos 0700; archivo con permisos 0600.
   - Arreglo de bug: retornar `Ok(())` si el rename es exitoso.
   - Tests: probar con directorio simulado.

4. **[SW-013] Comando silverwarden migrate con backup:**
   - Backup: crear `goldwarden.json.bak-<timestamp>` antes de tocar nada.
   - Migración local: importar el config al nuevo path y verificar que se puede desbloquear.
   - Mensaje terminal a M4: *"Configuración migrada. Ejecuta silverwarden sync (M4) para descargar tus claves SSH y contraseñas."*
   - Tests: simular una migración desde cero con archivo de prueba.

### 2.2 Evidencia de Ejecución: [SW-010] Estructura ConfigFile con serde

**Fecha:** 2026-10-18  
**Archivos modificados:**
- `crates/sw-config/src/lib.rs`: structs `ConfigFile` (12 campos string serializados, `rename_all = "PascalCase"`, con soporte para `EncryptedClientID` y `DeviceUUID`), `LoginToken` (5 campos, `rename_all = "snake_case"`, derive `Default`), tests unitarios y de integración local.
- `crates/sw-agent/src/lib.rs`: reemplazo de referencia a campo inexistente `config.version` por `env!("CARGO_PKG_VERSION")`.

#### Controles obligatorios y resultados reales

| Control | Comando | Resultado real |
|---|---|---|
| Pruebas unitarias `sw-config` | `cargo test -p sw-config` | 4 pasan, 0 fallan (test JSON custom, LoginToken roundtrip, ConfigFile Default roundtrip, parseo de ~/.config/goldwarden/goldwarden.json real) |
| Pruebas workspace | `cargo test --workspace --exclude sw-gui` | 65 tests pasan en total (61 en `sw-crypto`, 4 en `sw-config`), 0 fallan |
| Linter | `cargo clippy --workspace --exclude sw-gui --all-targets -- -D warnings` | 0 warnings |
| Formato | `cargo fmt --all -- --check` | 0 diffs |
| Auditoría | `cargo audit` | 0 vulnerabilidades (exit 0) |
| Cobertura `sw-config` | `cargo llvm-cov -p sw-config --summary-only` | 98.87% regiones / 98.37% líneas |

**Estado:** ✅ SW-010 — Hecho (2026-10-18).

### 2.3 Evidencia de Ejecución: [SW-011] Cifrado de campos de config

**Fecha:** 2026-10-18  
**Archivos modificados:**
- `Cargo.toml`: adición de `hex = "0.4"` a `workspace.dependencies` y perfil optimizado `[profile.dev.package.argon2]` / `[profile.test.package.argon2]` (`opt-level = 3`).
- `crates/sw-config/Cargo.toml`: dependencias `argon2`, `sha3`, `chacha20poly1305`, `base64`, `subtle`, `hex`, `rand`.
- `crates/sw-config/src/lib.rs`:
  - `derive_config_key`: KDF con `Argon2i` (v1.3), $t=2, m=2\text{ GiB (2048 MiB / } 2\times 1024\times 1024\text{ KiB)}, p=8$ (paridad byte a byte con Go `KDFMemory`).
  - `hash_config_key`: hash `SHA3-256` en formato hexadecimal.
  - `verify_pin`: comparación en tiempo constante con `subtle::ConstantTimeEq`.
  - `encrypt_string` / `decrypt_string`: wire format Tink ChaCha20-Poly1305 compatible tanto con cabecera Tink Keyset (`[0, 0, 0, 0, 0]`) como con Tink `subtle` de Go (`nonce 12B || ciphertext + tag 16B`).
  - Métodos `verify_pin`, `unlock`, `update_pin`, `decrypt_token` en `ConfigFile`.
  - Tests unitarios y de integración: paridad SHA3-256, roundtrip Tink, verificación de PIN, `update_pin` y descifrado verificado del token real de Goldwarden Go.

#### Controles obligatorios y resultados reales

| Control | Comando | Resultado real |
|---|---|---|
| Pruebas unitarias `sw-config` | `cargo test -p sw-config -- --test-threads=1` | 10 pasan, 0 fallan (roundtrip Tink, SHA3-256 parity, token Go descifrado a `{"access_token":"eyJ0eXAi...`, update_pin, verify_pin) |
| Linter | `cargo clippy --workspace --exclude sw-gui --all-targets -- -D warnings` | 0 warnings |
| Formato | `cargo fmt --all -- --check` | 0 diffs |
| Auditoría | `cargo audit` | 0 vulnerabilidades (exit 0) |
| Cobertura `sw-config` | `cargo llvm-cov -p sw-config --summary-only -- --test-threads=1` | 91.99% regiones / 92.92% líneas (umbral: ≥85%) |

**Estado:** ✅ SW-011 — Hecho (2026-10-18).

### 2.4 Evidencia de Ejecución: [SW-012] Lectura + migración de path viejo

**Fecha:** 2026-10-18  
**Archivos modificados:**
- `crates/sw-config/src/lib.rs`:
  - `get_old_config_path(home: &Path) -> PathBuf`: resuelve `~/.config/goldwarden.json`.
  - `get_new_config_path(home: &Path) -> PathBuf`: resuelve `~/.config/goldwarden/goldwarden.json`.
  - `migrate_old_path_in(home: &Path) -> Result<(), ConfigError>`: verifica existencia del path viejo y no existencia del nuevo. Crea directorio padre con permisos Unix `0700`, mueve archivo con `rename`, asigna permisos Unix `0600` al archivo migrado y devuelve `Ok(())`.
  - **Corrección de bug de Go (D34):** Go intentaba leer el archivo viejo después de renombrarlo y devolvía error innecesario; nuestra implementación devuelve `Ok(())` de forma limpia e idempotente si el archivo nuevo ya existía.
  - `migrate_old_path() -> Result<(), ConfigError>`: resuelve el `$HOME` del entorno del usuario.

### 2.5 Evidencia de Ejecución: [SW-013] Comando `silverwarden migrate` con backup

**Fecha:** 2026-10-18  
**Archivos modificados:**
- `crates/sw-config/src/lib.rs`:
  - `backup_config(path: &Path) -> Result<PathBuf, ConfigError>`: genera copia preventiva `<path>.bak-<timestamp>` con permisos `0600` antes de cualquier modificación.
  - `run_migration_in(home: &Path) -> Result<String, ConfigError>`: orquesta el backup, llama a `migrate_old_path_in`, deserializa el archivo de configuración migrado con `#[serde(default)]` y valida la presencia de `ConfigKeyHash` no vacío.
  - Constante de mensaje de éxito: `"Config migrado. Ejecuta 'silverwarden sync' para descargar claves SSH y contraseñas."`.
  - `run_migration() -> Result<String, ConfigError>`: punto de entrada usando `$HOME` del sistema.
  - Tests exhaustivos con directorios temporales (`tempfile`):
    - `test_migrate_old_path_success`: verifica migración de archivo, creación de directorio `0700` y permisos `0600`.
    - `test_migrate_old_path_new_already_exists`: garantiza idempotencia sin sobreescritura destructiva.
    - `test_migrate_old_path_no_old_path_is_noop`: verifica no-op limpio cuando no existe archivo previo.
    - `test_backup_config_creates_timestamped_file`: valida creación de respaldo `goldwarden.json.bak-<timestamp>`.
    - `test_backup_config_non_existent`: valida error cuando el archivo a respaldar no existe.
    - `test_run_migration_full_flow`: valida el flujo integral con backup, migración, verificación de estructura y mensaje de retorno.
    - `test_run_migration_new_already_exists`: valida migración cuando el destino ya existe previamente.
    - `test_run_migration_missing_hash_fails`: valida rechazo cuando `ConfigKeyHash` no existe o está vacío.
    - `test_run_migration_no_config_found`: valida rechazo cuando no existe ningún archivo de configuración.
    - `test_env_home_migration_wrappers`: valida wrappers de entorno `migrate_old_path()` y `run_migration()`.
    - `test_verify_pin_mismatched_length`: valida rechazo temprano ante discrepancia de longitud en hash.
    - `test_decrypt_string_errors`: cubre errores de base64 inválido, payload corto y tag corrupto.
    - `test_config_file_unlock_and_decrypt_token_errors`: cubre errores de PIN inválido, token vacío y JSON corrupto.
    - `test_decrypt_token_synthetic_success`: roundtrip verificado de `LoginToken` sintético descifrado.
    - `test_config_error_display_coverage`: cubre el formateo y representación de todas las variantes de `ConfigError`.
- `crates/sw-cli/src/main.rs`:
  - Subcomando `Commands::Migrate { source }` configurado con `clap`.
  - Invocación de `sw_config::run_migration()`, impresión de mensaje exitoso o salida con código de error 1.
  - Tests unitarios de parseo CLI: `test_cli_parse_migrate_default` y `test_cli_parse_status`.
- `crates/sw-config/Cargo.toml` & `Cargo.toml`: adición de `tempfile = "3.12"` en dev-dependencies.

#### Controles obligatorios y resultados reales

| Control | Comando | Resultado real |
|---|---|---|
| Pruebas unitarias `sw-config` | `cargo test -p sw-config -- --test-threads=1` | 25 pasan, 0 fallan (migración de ruta, idempotencia, backup con timestamp, flujo completo de migración, validación de hash, ramas de error y synthetic token) |
| Pruebas unitarias `sw-cli` | `cargo test -p sw-cli` | 2 pasan, 0 fallan (parseo de comando migrate y status) |
| Pruebas workspace | `cargo test --workspace --exclude sw-gui -- --test-threads=1` | 88 tests pasan en total (61 `sw-crypto`, 25 `sw-config`, 2 `sw-cli`), 0 fallan |
| Linter | `cargo clippy --workspace --exclude sw-gui --all-targets -- -D warnings` | 0 warnings |
| Formato | `cargo fmt --all -- --check` | 0 diffs |
| Auditoría | `cargo audit` | 0 vulnerabilidades (exit 0) |
| Cobertura `sw-config` | `cargo llvm-cov -p sw-config --summary-only -- --test-threads=1` | **94.06% regiones / 95.33% líneas** (objetivo: ≥93%, superado) |

**Estado:** ✅ SW-012 y SW-013 — Hecho (2026-10-18).  
**Hito:** 🏁 **Milestone M2 (Configuración y Migración) COMPLETADO al 100%.**


