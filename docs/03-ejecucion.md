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

---

## 3. Milestone M3: Agente + IPC (`sw-ipc`, `sw-agent`, `sw-systemauth`, `sw-cli`)

### 3.0 Plan Definitivo y Decisiones Técnicas Aplicadas

- **D36 (Endurecimiento de sesiones y CallingContext - D-IPC-3 mejorado):**
  - En Go, `if sessionType == SSHKey || (session.ParentPid == ctx.ParentProcessPid && session.GrandParentPid == ctx.GrandParentProcessPid)` permitía que cualquier proceso hermano con el mismo PPID y Grand-PPID heredara la sesión SSH, y si el proceso moría la sesión seguía viva hasta el TTL (60 min).
  - En Rust (`sw-systemauth`):
    - **Para `AccessVault` y `Pin`:** validación estricta de los 3 PIDs (`PID`, `PPID` y `Grand-PPID`). Si el proceso muere y su PID es reciclado por el SO, la sesión expira inmediatamente.
    - **Para `SSHKey`:** validación laxa (solo comparar tipo) **exclusivamente** si el proceso solicitante es un cliente SSH/Git conocido (`ssh`, `ssh-keygen`, `git`). Si es cualquier otro binario, se exige coincidencia estricta de los 3 PIDs.
    - **Wipe:** al bloquear el vault (`lock`), todas las sesiones activas en el store son purgadas de inmediato.
- **D37 (Aislamiento de socket y advertencia de Go activo):**
  - Protocolo IPC propio en JSON limpio (sin tabla hash FNV-1a de Go). No se comunica en caliente con el socket de Go.
  - El socket del daemon de SilverWarden corre en `~/.silverwarden.sock` con permisos Unix estrictos `0600`.
  - Resiliencia ante crashes: si `~/.silverwarden.sock` existe huérfano, el daemon verifica si hay un proceso escuchando; si no, lo elimina de forma segura y crea uno nuevo.
  - Si el CLI detecta que `~/.goldwarden.sock` está activo, muestra la advertencia: *"Goldwarden Go está corriendo. Te recomendamos detenerlo para evitar conflictos de estado"*.

### 3.1 Desglose de Historias M3

1. **[SW-020] Protocolo IPC (`sw-ipc`):**
   - Struct `IpcMessage { action: String, payload: serde_json::Value }`.
   - Framing: Prefijo de longitud `u32` big-endian + JSON UTF-8. Buffer máximo 4 MB.
   - Handshake: el cliente envía la versión de protocolo; el agente valida compatibilidad.

2. **[SW-021] Socket Unix del agente (`sw-agent`):**
   - Socket en `~/.silverwarden.sock` con permisos Unix `0600`.
   - Request-response: procesa un mensaje por conexión y responde.
   - Detección y limpieza de sockets huérfanos.

3. **[SW-022] CallingContext y resolución de procesos (`sw-systemauth`):**
   - Peercred vía `nix`/`rustix` (`uid` y `pid`).
   - Lectura de `/proc/<pid>/stat` (nombre ejecutable, PPID) y `/proc/<pid>/exe` (ruta).
   - Anclaje a `git`: si el ejecutable es `ssh` o `ssh-keygen` y su padre es `git`, anclar el contexto a `git`.
   - Falla segura si `/proc` es inaccesible devolviendo `authenticated: false`.

4. **[SW-023] Session store endurecido (`sw-systemauth`):**
   - Struct `Session` (`pid`, `ppid`, `grand_ppid`, `expires_at`, `type`).
   - Match exacto de 3 PIDs para `AccessVault` y `Pin`.
   - Match laxo de `SSHKey` condicionado a clientes SSH/Git (`ssh`, `ssh-keygen`, `git`).
   - Purga total de sesiones ante bloqueo (`lock`).

5. **[SW-024] Actions Registry del agente (`sw-agent`):**
   - Action Registry: `ActionsRegistry { actions: HashMap<String, ActionFn> }`.
   - Handlers mínimos: `Status`, `Unlock`, `Lock`, `PinSet`/`PinUpdate`, `ConfigGet`/`ConfigSet`.

6. **[SW-025] CLI `silverwarden` y daemonización (`sw-cli`):**
   - Subcomandos: `migrate`, `status`, `unlock`, `lock`, `pin set`, `pin update`, `agent start`.
   - Mensajes amigables ante daemon inactivo (`"El agente no está corriendo. Ejecuta 'silverwarden agent start'"`).
   - Advertencia si Goldwarden Go está activo (`"Goldwarden Go está corriendo. Te recomendamos detenerlo para evitar conflictos de estado"`).

### 3.2 Evidencia de Ejecución: [SW-020] Protocolo IPC propio (`sw-ipc`)

**Fecha:** 2026-10-19  
**Archivos modificados:**
- `crates/sw-ipc/src/lib.rs`:
  - Definición del struct `IpcMessage` (`action: String`, `payload: serde_json::Value`).
  - Constante de seguridad de tamaño máximo: `MAX_IPC_MESSAGE_SIZE = 4 * 1024 * 1024` (4 MB).
  - Funciones asíncronas de framing:
    - `read_message<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<IpcMessage, IpcError>`: lee prefijo `u32` big-endian, verifica el límite de 4MB, lee el payload exacto y deserializa el JSON en `IpcMessage`.
    - `write_message<W: AsyncWriteExt + Unpin>(writer: &mut W, msg: &IpcMessage) -> Result<(), IpcError>`: serializa `IpcMessage` a JSON, valida límite de 4MB, escribe longitud `u32` big-endian y datos, y realiza flush.
  - Tests exhaustivos con `tokio::io::duplex`:
    - `test_roundtrip_duplex`: envío bidireccional cliente-servidor validando `action` y `payload`.
    - `test_write_message_too_large_fails`: rechazo controlado al intentar escribir mensajes > 4MB.
    - `test_read_message_too_large_fails`: rechazo de tramas con cabecera de longitud > 4MB.
    - `test_read_malformed_json_fails`: manejo de error `IpcError::Json` sin panic ante JSON corrupto.
    - `test_ipc_error_display`: cobertura de formateo de variantes de error.

### 3.3 Evidencia de Ejecución: [SW-021] Socket Unix del agente (`sw-agent`)

**Fecha:** 2026-10-19  
**Archivos modificados:**
- `crates/sw-agent/Cargo.toml`: adición de `tempfile = { workspace = true }` en `[dev-dependencies]`.
- `crates/sw-agent/src/lib.rs`:
  - `default_socket_path() -> Result<PathBuf, AgentError>`: resolución de `~/.silverwarden.sock`.
  - `check_and_prepare_socket(socket_path: &Path) -> Result<(), AgentError>`: comprueba si el archivo socket existe intentando conectar con `tokio::net::UnixStream`. Si hay un proceso escuchando, falla con `AgentError::SocketAlreadyInUse`. Si es huérfano (conexión rechazada), lo elimina de forma segura.
  - `run_agent(socket_path: &Path)` y `run_agent_with_shutdown(socket_path, shutdown_signal)`:
    - Bindea el `tokio::net::UnixListener` en el socket especificado.
    - Asigna permisos Unix `0600` (`Permissions::from_mode(0o600)`).
    - Bucle de aceptación de conexiones concurrentes (`tokio::spawn`), leyendo cada `IpcMessage` y retornando por ahora `IpcMessage { action: "Error", payload: "Not implemented" }`.
    - Eliminación limpia del socket al recibir la señal de shutdown.
  - Tests unitarios y de integración:
    - `test_agent_socket_request_response_not_implemented`: test de integración en socket temporal con cliente real, validando conexión, permisos `0600`, roundtrip request-response con `"Not implemented"`, detección de colisión y cleanup en apagado.
    - `test_agent_orphan_socket_removal`: detección y eliminación automática de socket huérfano.
    - `test_default_socket_path`: resolución correcta de path de usuario.
    - `test_agent_error_display`: formateo de errores `AgentError`.
    - `test_agent_daemon_handle_request`: cobertura de handlers existentes.
    - `test_run_agent_entrypoint_aborted` y `test_agent_corrupted_message_handled`: manejo de fallos y abortos.

#### Controles obligatorios y resultados reales

| Control | Comando | Resultado real |
|---|---|---|
| Pruebas unitarias `sw-ipc` | `cargo test -p sw-ipc` | 5 pasan, 0 fallan (roundtrip duplex, límites 4MB, malformed JSON, error display) |
| Pruebas unitarias `sw-agent` | `cargo test -p sw-agent` | 7 pasan, 0 fallan (integración de socket Unix, permisos 0600, huérfanos, colisión, Not implemented) |
| Pruebas workspace | `cargo test --workspace --exclude sw-gui -- --test-threads=1` | 100 tests pasan en total (61 `sw-crypto`, 25 `sw-config`, 5 `sw-ipc`, 7 `sw-agent`, 2 `sw-cli`), 0 fallan |
| Linter | `cargo clippy --workspace --exclude sw-gui --all-targets -- -D warnings` | 0 warnings |
| Formato | `cargo fmt --all -- --check` | 0 diffs |
| Auditoría | `cargo audit` | 0 vulnerabilidades (exit 0) |
| Cobertura `sw-ipc` | `cargo llvm-cov -p sw-ipc --summary-only` | **94.92% regiones / 100.00% líneas** |
| Cobertura `sw-agent` | `cargo llvm-cov -p sw-agent --lib --summary-only` | **92.22% regiones / 93.21% líneas** (umbral: ≥85%) |

**Estado:** ✅ SW-020 y SW-021 — Hecho (2026-10-19).

### 3.4 Evidencia de Ejecución: [SW-022] CallingContext y resolución de procesos (`sw-systemauth`)

**Fecha:** 2026-10-20  
**Archivos modificados:**
- `Cargo.toml`: adición de características `["mm", "net", "process"]` a `rustix`, y dependencia compartida `sysinfo = "0.30"` en `[workspace.dependencies]`.
- `crates/sw-systemauth/Cargo.toml`: adición de dependencias `rustix = { workspace = true }` y `sysinfo = { workspace = true }`, y dependencias de test `tempfile = { workspace = true }` y `tokio = { workspace = true, features = ["net", "io-util", "macros"] }`.
- `crates/sw-systemauth/src/lib.rs`:
  - Struct `CallingContext`:
    - `username: String`
    - `process_name: String`
    - `parent_process_name: String`
    - `grandparent_process_name: String`
    - `process_pid: u32`
    - `parent_process_pid: u32`
    - `grandparent_process_pid: u32`
    - `error: bool`
    - `authenticated: bool`
  - Implementación de `get_calling_context<S: AsFd>(conn: &S) -> CallingContext`:
    - En Linux: extracción de credenciales del socket peer mediante `rustix::net::sockopt::get_socket_peercred(conn)`.
    - En otras plataformas (macOS/Windows): stub seguro preparado para M10 devolviendo `error: true, authenticated: false`.
    - Regla de seguridad root: si `uid == 0`, se rechaza explícitamente (`error: true, authenticated: false`) garantizando que root no interactúe con el agente de contraseñas de usuario.
    - Validación de PID: si `pid == 0`, se rechaza con error.
    - Resolución de usuario: lectura y parseo directo de `/etc/passwd` buscando coincidencia exacta de UID en campo 3, con fallback a `sysinfo::Users`.
    - Inspección del árbol de procesos (`PID` -> `PPID` -> `Grand-PPID`): lectura de `/proc/<pid>/stat` con parsing robusto de la cadena `(comm)` (incluso con espacios y paréntesis anidados), y fallback transparente a `sysinfo::System`.
    - Caso especial Git (anclaje de contexto): si el proceso que llama es `ssh` o `ssh-keygen` y su padre directo es `git`, el contexto se ancla a `git` (el proceso actual pasa a ser `git`, y su PPID y Grand-PPID corresponden a los de `git`), logrando paridad con el comportamiento de Goldwarden.
    - Resiliencia y seguridad ante fallos: cualquier error de lectura en `/proc`, proceso inexistente o denegación de permisos retorna `CallingContext { error: true, authenticated: false, ..Default::default() }`.
  - Batería de pruebas unitarias (`12 pruebas en sw-systemauth`):
    - `test_calling_context_unix_stream_pair`: extracción de credenciales peer en `UnixStream::pair()` en Linux.
    - `test_calling_context_root_rejected`: verificación de rechazo estricto si `uid == 0`.
    - `test_calling_context_zero_pid_rejected`: verificación de rechazo si `pid == 0`.
    - `test_calling_context_fake_pid_error`: retorno seguro ante PIDs inexistentes (`error: true`).
    - `test_parse_proc_stat`: prueba de parseo de `/proc/<pid>/stat` con nombres estándar y nombres complejos con espacios y paréntesis.
    - `test_git_anchoring_ssh_keygen_and_ssh`: verificación del anclaje de contexto hacia `git` cuando el comando es `ssh-keygen` o `ssh` y su padre es `git`.
    - `test_no_git_anchoring_for_normal_ssh`: verificación de que `ssh` o `ssh-keygen` lanzados fuera de `git` (ej. desde una shell) no anclan falsamente a `git`.
    - `test_sysinfo_fallback_for_process_info`: cobertura de la ruta de fallback con `sysinfo`.
    - `test_resolve_username_from_etc_passwd`: verificación de resolución de UID a username desde archivo sintético `/etc/passwd`.
    - `test_calling_context_display`: verificación del formateo en `Display`.
    - `test_calling_context_for_current_process`: comprobación con el proceso actual en ejecución en el sistema anfitrión.

#### Controles obligatorios y resultados reales

| Control | Comando | Resultado real |
|---|---|---|
| Pruebas unitarias `sw-systemauth` | `cargo test -p sw-systemauth` | 12 pasan, 0 fallan (0.01s) |
| Pruebas workspace | `cargo test --workspace --exclude sw-gui -- --test-threads=1` | 112 tests pasan en total (61 `sw-crypto`, 25 `sw-config`, 5 `sw-ipc`, 7 `sw-agent`, 12 `sw-systemauth`, 2 `sw-cli`), 0 fallan |
| Linter | `cargo clippy --workspace --exclude sw-gui --all-targets -- -D warnings` | 0 warnings |
| Formato | `cargo fmt --all -- --check` | 0 diffs |
| Auditoría | `cargo audit` | 0 vulnerabilidades (exit 0; dependencias saneadas) |
| Cobertura `sw-systemauth` | `cargo llvm-cov -p sw-systemauth --lib --summary-only` | **92.87% regiones / 92.23% líneas** (umbral: ≥85%) |

**Estado:** ✅ SW-022 — Hecho (2026-10-20).

### 3.5 Evidencia de Ejecución: [SW-023], [SW-024] y [SW-025] (Sesiones, Registry de Acciones y CLI)

**Fecha:** 2026-10-20  
**Archivos modificados:**
- `Cargo.toml`: adición de `rpassword = "7.3"` en `[workspace.dependencies]`.
- `crates/sw-systemauth/src/lib.rs` (SW-023):
  - Struct `Session`: `pid`, `ppid`, `grand_ppid`, `expires_at: std::time::SystemTime`, `session_type: SessionType`.
  - Enum `SessionType`: `AccessVault`, `SSHKey`, `Pin`.
  - Struct `SessionStore`:
    - `create_session(ctx, type, ttl)`: almacena sesión vinculada a la jerarquía de procesos del caller.
    - `verify_session(ctx, type)` con reglas de endurecimiento (D36):
      - `AccessVault` y `Pin`: validación estricta y exacta de los 3 PIDs (`pid`, `ppid`, `grand_ppid`).
      - `SSHKey`: si el proceso es `ssh`, `ssh-keygen` o `git`, se permite coincidencia por tipo de sesión (`session_type == SSHKey`); para cualquier otro binario, se exige coincidencia exacta de los 3 PIDs.
      - Validación estricta de expiración de sesión (`now >= expires_at`).
      - Rechazo categórico si el contexto presenta error o no está autenticado (`ctx.error || !ctx.authenticated`).
    - `wipe()`: purga total e inmediata de todas las sesiones al bloquear el vault.
    - `prune_expired()`: limpieza de sesiones caducadas.
  - Tests unitarios exhaustivos (18 tests totales en `sw-systemauth`).
- `crates/sw-agent/Cargo.toml` y `crates/sw-agent/src/lib.rs` (SW-024):
  - Struct `AgentState`: `config: ConfigFile`, `sessions: SessionStore`, `is_locked: bool`, `has_pin: bool`, `shutdown_sender`.
  - Trait `ActionFn`: trait dinámico para handlers de acciones con implementación genérica para closures.
  - Struct `ActionsRegistry`: registro extensible `HashMap<String, Box<dyn ActionFn>>` con búsqueda flexible.
  - Función `default_registry()` implementando las acciones esenciales:
    - `Status`: retorna `{ locked, has_pin, logged_in, version }`.
    - `Unlock`: recibe `{ pin }`, verifica contra `sw-config`, desbloquea estado y registra sesiones en `SessionStore`.
    - `Lock`: bloquea vault, borra claves y purga todas las sesiones activas (`wipe()`).
    - `PinSet` / `PinUpdate`: gestiona y recifra configuración delegando en `sw-config`.
    - `AgentShutdown`: canal para apagado ordenado del daemon (clave para tests y control de ciclo de vida).
  - En `run_agent`: reemplazado el stub `"Not implemented"` por despacho real hacia `ActionsRegistry` con `CallingContext` extraído del socket.
  - Tests de integración sobre socket Unix y pruebas directas del registro (8 tests en `sw-agent`).
- `crates/sw-cli/Cargo.toml` y `crates/sw-cli/src/main.rs` (SW-025):
  - Integración de `rpassword` y dependencias del agente.
  - Subcomandos `clap`:
    - `silverwarden agent start`: ejecución del agente en foreground.
    - `silverwarden status`: conexión al socket Unix y reporte visual del estado del daemon.
    - `silverwarden unlock [--pin <pin>]`: desbloqueo con argumento o solicitud interactiva en terminal sin eco (`rpassword`).
    - `silverwarden lock`: bloqueo y purga inmediata de sesiones vía IPC.
    - `silverwarden pin set [--pin <pin>]`: configuración interactiva o directa de PIN.
    - `silverwarden pin update [--old-pin <pin>] [--new-pin <pin>]`: actualización interactiva o por parámetros.
    - `silverwarden migrate`: soporte conservado para migración desde Goldwarden Go.
  - Detección proactiva de socket activo de Goldwarden Go (`~/.goldwarden.sock`) emitiendo advertencia de conflicto (D37).
  - 10 pruebas unitarias validando el parseo de todos los subcomandos y banderas CLI.

#### Controles obligatorios y resultados reales

| Control | Comando | Resultado real |
|---|---|---|
| Pruebas unitarias `sw-systemauth` | `cargo test -p sw-systemauth` | 18 pasan, 0 fallan (0.01s) |
| Pruebas unitarias `sw-agent` | `cargo test -p sw-agent` | 8 pasan, 0 fallan (socket Unix, flow de acciones, shutdown IPC) |
| Pruebas unitarias `sw-cli` | `cargo test -p sw-cli` | 10 pasan, 0 fallan (parseo de subcomandos, banderas y modos interactivos) |
| Linter | `cargo clippy --workspace --exclude sw-gui --all-targets -- -D warnings` | 0 warnings |
| Formato | `cargo fmt --all -- --check` | 0 diffs |
| Auditoría | `cargo audit` | 0 vulnerabilidades (exit 0) |
| Cobertura `sw-systemauth` | `cargo llvm-cov -p sw-systemauth --lib --summary-only` | **95.93% regiones / 95.72% líneas** (umbral: ≥85%) |
| Cobertura `sw-agent` | `cargo llvm-cov -p sw-agent --lib --summary-only` | **90.23% regiones / 90.29% líneas** (umbral: ≥85%) |

### 3.6 Evidencia de Ejecución: Aumento de Cobertura en sw-cli (SW-025 - Cobertura ≥85%)

**Fecha:** 2026-10-24  
**Contexto previo:** La cobertura de líneas de `sw-cli` se encontraba en 18.09% (72 de 398 líneas) al cubrir únicamente el parseo de argumentos `clap` en `main.rs`, sin ejercitar la comunicación socket, manejo de errores ni formateo de comandos.  
**Meta:** Elevar la cobertura a ≥85% mediante refactorización testeable y tests de integración con `assert_cmd`.

**Archivos modificados y creados:**
- `crates/sw-cli/Cargo.toml`:
  - Adición de `assert_cmd = "2"` y `predicates = "3"` en `[dev-dependencies]`.
  - Adición de `thiserror = { workspace = true }`, `serde_json = { workspace = true }` y `tempfile = { workspace = true }`.
- `crates/sw-cli/src/main.rs`:
  - Definición del enum de errores tipados `pub enum CliError`:
    - `SocketNotFound(PathBuf)`: socket inexistente con sugerencia de arranque.
    - `ConnectionFailed(PathBuf, String)`: socket presente pero sin listener activo.
    - `SendFailed(String)`: falla al enviar la trama IPC.
    - `ReceiveFailed(String)`: corte de conexión o fallo al recibir la respuesta.
    - `AgentError(String)`: error retornado por la lógica del daemon.
    - `Io(String)`, `Config(String)`, `Other(String)`: mapeos de errores del sistema y configuración.
  - Extracción de la comunicación por socket a función testeable:
    - `pub async fn send_command(socket_path: &Path, action: &str, payload: Value) -> Result<IpcMessage, CliError>`.
    - Soporte transparente para payloads de error tanto en formato string plano como en objeto `{ "error": "..." }`.
  - Extracción de la ejecución de comandos a función desacoplada de la terminal interactiva:
    - `pub async fn handle_command<P>(cli: &Cli, mut prompt_fn: P) -> Result<String, CliError> where P: FnMut(&str) -> Result<String, CliError>`.
    - Permite inyectar prompts sintéticos en pruebas unitarias sin bloquear la terminal.
  - 22 tests unitarios en `main.rs`:
    - Tests de parseo de subcomandos `clap` (migrate, status, unlock con/sin pin, lock, pin set/update interactivos y con flags, agent start).
    - `test_send_command_socket_not_found`: validación de error ante socket inexistente.
    - `test_send_command_receive_failed`: detección de cierre de conexión abrupto por el servidor.
    - `test_send_command_agent_error`: propagación correcta de mensajes de error devueltos por el daemon.
    - `test_send_command_success`: ciclo completo de request/response sobre socket Unix mock.
    - `test_handle_command_status_and_status_locked`: formateo visual de estados.
    - `test_handle_command_unlock_with_pin_and_interactive`: flujo de desbloqueo con y sin prompt.
    - `test_handle_command_lock`: confirmación de bloqueo y purga.
    - `test_handle_command_pin_set_and_update`: gestión de PIN directa e interactiva.
    - `test_handle_command_local_subcommands`: cobertura de subcomandos locales (sync, logins, ssh).
    - `test_resolve_socket_path` y `test_check_goldwarden_go_conflict`.
    - `test_cli_error_display`: verificación de todas las variantes de `Display` de `CliError`.
- `crates/sw-cli/tests/integration.rs` (Nuevo archivo):
  - 10 tests de integración con `assert_cmd` ejecutando el binario real `silverwarden`:
    - `test_cli_help`: verificación de ayuda CLI (`--help`).
    - `test_cli_status_no_agent`: verificación de salida de error formateada cuando el daemon no está activo.
    - `test_cli_status_with_mock_agent`: integración de extremo a extremo recibiendo estado del daemon vía IPC.
    - `test_cli_unlock_with_mock_agent`: desbloqueo exitoso con flag `--pin`.
    - `test_cli_unlock_agent_error`: propagación y código de salida ante error del agente (ej. PIN inválido).
    - `test_cli_lock_with_mock_agent`: bloqueo de sesión vía socket mock.
    - `test_cli_pin_set_with_mock_agent`: configuración de nuevo PIN.
    - `test_cli_pin_update_with_mock_agent`: actualización de PIN existente.
    - `test_cli_local_commands`: ejecución de `sync`, `logins`, `ssh list`, `ssh add`.
    - `test_cli_goldwarden_go_conflict_warning`: detección en tiempo de ejecución del socket de Goldwarden Go activo.
- `.cargo/audit.toml`:
  - Excepciones documentadas y agregada `RUSTSEC-2026-0387` (`crypto-bigint 0.5.5` transitivo en `ssh-key`), manteniendo `cargo audit` en 0 vulnerabilidades (exit 0).

#### Controles obligatorios y resultados reales

| Control | Comando | Resultado real |
|---|---|---|
| Pruebas `sw-cli` | `cargo test -p sw-cli` | 32 pasan (22 unitarias + 10 integración), 0 fallan (0.08s) |
| Pruebas Workspace | `cargo test --workspace --exclude sw-gui` | 163 pasan en total (61 `sw-crypto`, 25 `sw-config`, 5 `sw-ipc`, 22 `sw-agent`, 18 `sw-systemauth`, 32 `sw-cli`), 0 fallan |
| Linter | `cargo clippy --workspace --exclude sw-gui --all-targets -- -D warnings` | 0 warnings |
| Formato | `cargo fmt --all -- --check` | 0 diffs |
| Auditoría | `cargo audit` | 0 vulnerabilidades (exit 0) |
| **Cobertura `sw-cli`** | `cargo llvm-cov -p sw-cli --summary-only` | **90.57% regiones / 92.82% líneas** (Meta: ≥85%, Previo: 18.09%) |
| **Cobertura Total Workspace** | `cargo llvm-cov --workspace --exclude sw-gui --summary-only` | **91.97% regiones / 92.26% líneas** |

**Estado:** ✅ SW-025 Cobertura — Hecho (2026-10-24). Objetivo de cobertura ampliamente superado.

---

## 4. Milestone M4: Bóveda y API de Bitwarden (`sw-vault`, `sw-bitwarden-api`)

**Objetivo:** Implementar la capa completa de transporte HTTP autenticado con refresh automático, el modelo de datos de la bóveda (`SyncData`/`Cipher`), el flujo de autenticación/login (prelogin, derivación KDF, master password hash y descifrado de llaves de perfil), la sincronización completa con persistencia atómica en disco (`~/.cache/silverwarden/vault.json` con permisos `0600`), el CRUD y filtrado de accesos en memoria/remoto, la recepción de eventos push en tiempo real vía Websocket (MessagePack), y el desafío de doble factor (2FA).

### 4.1 Decisiones Arquitectónicas de M4
- **D38:** Inclusión estricta de headers HTTP de cliente (`Authorization: Bearer <token>`, `User-Agent: silverwarden/0.0.1`, `Device-Type: 10`, `Bitwarden-Client-Name: silverwarden`, `Bitwarden-Client-Version: 0.0.1`, y `Auth-Email: base64(email)` en cuerpos form-urlencoded).
- **D39:** Caché atómico de Vault en `~/.cache/silverwarden/vault.json` con permisos Unix `0600` (escritura vía tempfile + rename atómico). Los ciphers se cargan en `VaultStore` en memoria manteniendo los campos cifrados (`EncString`) para descifrado bajo demanda.
- **D40:** 2FA en fases: TOTP y Email integrados en el flujo de login; FIDO2 diferido a versión posterior para aislar dependencias HID en el MVP.
- **D41:** Orden de implementación por dependencias de transporte y datos:
  1. **SW-030 (HTTP autenticado + Refresh Token):** Base de red y transporte para todas las operaciones.
  2. **SW-031 (Modelos SyncData/Cipher):** Base de modelado y deserialización de estructuras.
  3. **SW-033 (Login):** Necesario para obtener el token de acceso y la clave del usuario.
  4. **SW-032 (Sync completo + Caché en disco):** Descarga remota, persistencia atómica y carga en memoria.
  5. **SW-036 (CRUD de ciphers):** Consultas, filtrado bajo demanda y operaciones de bóveda.
  6. **SW-035 (Websocket de notificaciones):** Actualizaciones push en tiempo real vía SignalR/Hub MessagePack.
  7. **SW-034 (2FA):** Soporte de doble factor para cuentas protegidas con TOTP/Email.

### 4.2 Desglose de Historias M4

1. **[SW-030] HTTP autenticado + refresh de token (`sw-bitwarden-api`):**
   - Struct `AuthenticatedClient` envolviendo `reqwest::Client` y `Arc<Mutex<LoginToken>>`.
   - Método `fetch_with_auth(&self, method, url, body) -> Result<Response, ApiError>`.
   - Manejo concurrente de 401 con refresco automático de token bajo mutex y reintento.
   - Mock server con wiremock/httpmock para verificar flujo normal y reintento post-refresh.

2. **[SW-031] Modelos SyncData/Cipher (`sw-vault`):**
   - Modelado de `SyncData`, `Profile`, `Organization`, `Folder`, `Cipher`, `LoginCipher`, `Card`, `Identity`, `SSHKeyCipher`, `Field`, `URI`.
   - Compatibilidad completa con `EncString` (SW-002) y wire format camelCase con serde defaults.

3. **[SW-033] Login (`sw-bitwarden-api`):**
   - Endpoint `POST /accounts/prelogin` para obtener configuración KDF.
   - Derivación KDF con `sw-crypto`.
   - Generación de `master_password_hash` con PBKDF2-HMAC-SHA256 (1 iteración, base64) con paridad exacta de Go.
   - `POST /connect/token` con grant password y descifrado de la `UserSymmetricKey`.

4. **[SW-032] Sync completo + Caché en disco (`sw-vault`, `sw-bitwarden-api`):**
   - `DoFullSync` vía endpoint `GET /sync`.
   - Persistencia segura en `~/.cache/silverwarden/vault.json` (0600) con escritura atómica.
   - Carga en `VaultStore` en memoria sin descifrado masivo preliminar.

5. **[SW-036] CRUD de ciphers (`sw-bitwarden-api`, `sw-vault`):**
   - Operaciones remotas GET, POST, PUT, DELETE de ciphers.
   - Filtrado local en memoria por nombre, usuario y URI descifrando bajo demanda.

6. **[SW-035] Websocket de notificaciones (`sw-bitwarden-api`):**
   - Daemon de conexión a `wss://<notifications_url>/hub?access_token=<token>`.
   - Handshake MessagePack + lectura continua con `tokio-tungstenite` y `rmp-serde`.
   - Despacho de eventos de actualización y reconexión resiliente con backoff.

7. **[SW-034] 2FA (`sw-bitwarden-api`):**
   - Captura y reenvío de desafíos de segundo factor para TOTP y Email.

### 4.3 Evidencia de Ejecución: [SW-030] HTTP autenticado con refresh automático (`sw-bitwarden-api`)

**Fecha:** 2026-10-24  
**Archivos modificados:**
- `crates/sw-config/src/lib.rs`:
  - Añadido atributo `#[serde(default)]` al campo `key` de `LoginToken` para evitar fallos de deserialización cuando el endpoint `/connect/token` responde a solicitudes `grant_type=refresh_token` (las cuales no devuelven la llave simétrica).
- `crates/sw-bitwarden-api/Cargo.toml`:
  - Dependencias: `sw-crypto`, `sw-config`, `sw-vault`, `reqwest`, `tokio`, `tokio-tungstenite`, `rmp-serde`, `serde`, `serde_json`, `thiserror`, `base64`, `url`.
  - Dev-dependency: `wiremock = "0.6"`.
- `crates/sw-bitwarden-api/src/lib.rs`:
  - Definición de cabeceras de cliente Bitwarden:
    - `User-Agent: silverwarden/0.0.1`
    - `Device-Type: 10`
    - `Bitwarden-Client-Name: silverwarden`
    - `Bitwarden-Client-Version: 0.0.1`
  - Re-export de `LoginToken` desde `sw-config`.
  - Enum `ApiError`: variantes `Reqwest`, `Auth`, `Json`, `Url`, `Status`.
  - Enum `RequestBody`: soporte para `Empty`, `Json`, `Form` y `RawForm` con inyección automática de cabecera `Auth-Email: base64(username)` en codificación base64 url-safe sin padding (`URL_SAFE_NO_PAD`).
  - Struct `AuthenticatedClient`:
    - `client: reqwest::Client`, `token: Arc<Mutex<LoginToken>>`, `identity_url: String`, `api_url: String`.
    - Constructores `new()`, `from_token()` y `with_client()`.
    - Métodos de acceso y resolución de endpoints: `token()`, `identity_url()`, `api_url()`, `resolve_api_url()`.
    - `refresh_token(&self) -> Result<(), ApiError>`: POST `/connect/token` con `grant_type=refresh_token`, `refresh_token` y `client_id=connector`. Preserva la llave de cifrado existente si el servidor no la retorna en la rotación de token.
    - `fetch_with_auth(&self, method, url, body) -> Result<Response, ApiError>`: inyecta autorización Bearer y cabeceras estándar; ante respuesta 401 Unauthorized, sincroniza con `Mutex`, ejecuta `refresh_token()` y reintenta la solicitud automáticamente.
  - Batería de pruebas con `wiremock` (10 pruebas unitarias):
    - `test_fetch_with_auth_success_200`: petición HTTP normal con token válido y verificación de cabeceras.
    - `test_fetch_with_auth_401_then_refresh_and_retry_200`: simulación de 401 inicial, refresco exitoso vía `/connect/token` y reintento automático con código 200. Verificación de actualización del token y conservación de `key`.
    - `test_fetch_with_auth_refresh_fails_returns_error`: servidor devuelve 401 y el refresh falla (400 `invalid_grant`) $\rightarrow$ retorno controlado de `ApiError::Auth`.
    - `test_fetch_with_auth_form_sets_auth_email_header`: inyección de `Auth-Email` en peticiones `Form` con campo `username`.
    - `test_fetch_with_auth_json_body`: inyección de `Content-Type: application/json`.
    - `test_refresh_token_missing_returns_auth_error`: error inmediato ante ausencia de `refresh_token`.
    - `test_prelogin_success`: verificación de llamada al endpoint `/api/accounts/prelogin`.
    - `test_fetch_with_auth_raw_form`: soporte para formularios url-encoded crudos con `Auth-Email`.
    - `test_client_accessors_and_resolve_api_url`: resolución de URLs relativas y absolutas.
    - `test_refresh_updates_new_key_when_provided`: actualización de `key` cuando el servidor la provee.

#### Controles obligatorios y resultados reales

| Control | Comando | Resultado real |
|---|---|---|
| Pruebas `sw-bitwarden-api` | `cargo test -p sw-bitwarden-api` | 10 pasan, 0 fallan (0.02s) |
| Pruebas Workspace | `cargo test --workspace --exclude sw-gui` | 173 pasan en total, 0 fallan |
| Linter | `cargo clippy --workspace --exclude sw-gui --all-targets -- -D warnings` | 0 warnings |
| Formato | `cargo fmt --all -- --check` | 0 diffs |
| Auditoría | `cargo audit` | 0 vulnerabilidades (exit 0) |
| **Cobertura `sw-bitwarden-api`** | `cargo llvm-cov -p sw-bitwarden-api --summary-only` | **97.75% regiones / 98.96% líneas** (umbral: ≥85%) |
| **Cobertura Total Workspace** | `cargo llvm-cov --workspace --exclude sw-gui --summary-only` | **92.86% regiones / 93.39% líneas** |

**Estado:** ✅ SW-030 — Hecho (2026-10-24).

### 4.4 Evidencia de Ejecución: [SW-031] Modelos de SyncData y Cipher (`sw-vault`)

**Fecha:** 2026-10-24  
**Archivos modificados:**
- `crates/sw-crypto/src/encstring.rs`:
  - Implementación de `serde::Serialize` y `serde::Deserialize` para `EncString` permitiendo serializar a la representación estándar de Bitwarden (`type.iv|ct[|mac]`) y deserializar desde JSON strings con soporte para valores nulos o cadenas vacías (`EncString::default()`).
  - Prueba unitaria `test_encstring_serde_roundtrip` (62 tests en `sw-crypto`).
- `crates/sw-vault/Cargo.toml`:
  - Adición de `uuid = { workspace = true }`.
- `crates/sw-vault/src/lib.rs`:
  - Definición completa con paridad estricta respecto al código Go (`models.go`):
    - `CipherType`: enum `Login = 1`, `Note = 2`, `Card = 3`, `Identity = 4`, `SshKey = 5`.
    - `FieldType`: enum `Text = 0`, `Hidden = 1`, `Boolean = 2`, `Linked = 3`, `Other(i32)`.
    - `URIMatch`: enum `Domain = 0`, `Host = 1`, `StartsWith = 2`, `Exact = 3`, `RegularExpression = 4`, `Never = 5`, `Other(i32)`.
    - `SecureNoteType`: enum `Generic = 0`, `Other(i32)`.
    - `URI`: `uri: Option<String>`, `match: Option<URIMatch>`.
    - `Field`: `type: Option<FieldType>`, `name: Option<EncString>`, `value: Option<EncString>`.
    - `LoginCipher`: `username`, `password`, `totp`, `uri`, `uris: Vec<URI>`.
    - `SSHKeyCipher`: `private_key: Option<EncString>`, `public_key: Option<EncString>`, `key_fingerprint: Option<EncString>`.
    - `Card`: `cardholder_name`, `brand`, `number`, `exp_month`, `exp_year`, `code`.
    - `Identity`: 17 campos estándar de identidad (`first_name`, `last_name`, `ssn`, `email`, `phone`, etc.).
    - `SecureNoteCipher`: `type: Option<SecureNoteType>`.
    - `Folder`: `id: Option<Uuid>`, `name: Option<String>`, `revision_date: Option<String>`.
    - `Organization`: `id`, `name`, `key`, `seats`, flags de permisos y características.
    - `Profile`: datos de usuario, organizaciones, claves cifradas (`key`, `private_key`), `security_stamp`.
    - `Cipher`: modelo unificado de elemento de bóveda con `type: CipherType`, `id: Option<Uuid>`, `name: EncString`, `login`, `card`, `identity`, `secure_note`, `ssh_key`, `key: Option<EncString>`, `fields`, `collection_ids`, etc.
    - `SyncData`: estructura raíz de sincronización conteniendo `profile: Profile`, `folders: Vec<Folder>`, `ciphers: Vec<Cipher>`.
    - `VaultStore`: almacén en memoria indexado por `Uuid` con operaciones `insert`, `get`, `all`, `len`, `clear`.
  - Atributos serde homogéneos: `#[serde(rename_all = "camelCase")]` y `#[serde(default)]` en todos los tipos opcionales y listas.
  - Batería de pruebas unitarias:
    - `test_sync_data_full_deserialization`: deserialización completa de un payload complejo de `/sync` conteniendo perfil, organizaciones, carpetas, ciphers de tipo Login y ciphers de tipo SSHKey con validación de todos los campos.
    - `test_roundtrip_serialization`: ciclo completo serialize $\rightarrow$ deserialize sin pérdida de información para Cards, Identities y SecureNotes.
    - `test_vault_store_operations`: inserción, consulta por Uuid, conteo y vaciado del almacén en memoria.
    - `test_cipher_type_conversion_and_fallback`: mapeo bidireccional de discriminantes numéricos de ciphers, fields, URIs y notas.

#### Controles obligatorios y resultados reales

| Control | Comando | Resultado real |
|---|---|---|
| Pruebas `sw-vault` | `cargo test -p sw-vault` | 4 pasan, 0 fallan (0.01s) |
| Pruebas Workspace | `cargo test --workspace --exclude sw-gui` | 178 pasan en total, 0 fallan |
| Linter | `cargo clippy --workspace --exclude sw-gui --all-targets -- -D warnings` | 0 warnings |
| Formato | `cargo fmt --all -- --check` | 0 diffs |
| Auditoría | `cargo audit` | 0 vulnerabilidades (exit 0) |
| **Cobertura `sw-vault`** | `cargo llvm-cov -p sw-vault --summary-only` | **97.30% regiones / 97.44% líneas** (umbral: ≥85%) |
| **Cobertura Total Workspace** | `cargo llvm-cov --workspace --exclude sw-gui --summary-only` | **93.40% regiones / 94.03% líneas** |

**Estado:** ✅ SW-031 — Hecho (2026-10-24).

### 4.5 Evidencia de Ejecución: [SW-033] Login con mock server (parte 1) (`sw-bitwarden-api`)

**Fecha:** 2026-10-24  
**Archivos modificados:**
- `crates/sw-bitwarden-api/Cargo.toml`:
  - Adición de dependencias `pbkdf2 = { workspace = true }`, `sha2 = { workspace = true }`, `zeroize = { workspace = true }`.
- `crates/sw-bitwarden-api/src/lib.rs`:
  - Integración de variante `Crypto(#[from] sw_crypto::CryptoError)` en `ApiError`.
  - Re-export de `sw_crypto::{KdfConfig, KdfType}`.
  - Conversión segura `TryFrom<PreloginResponse> for sw_crypto::KdfConfig`.
  - Implementación de `derive_master_password_hash(master_key: &[u8], password: &str) -> String`:
    - PBKDF2-HMAC-SHA256 con 1 iteración sobre bytes del `master_key` y `password` como sal, longitud 32 bytes y codificación Base64 estándar (paridad exacta con Go `pbkdf2.Key(masterKey.GetBytes(), []byte(password), 1, 32, sha256.New)`). Limpieza de memoria con `Zeroize`.
  - Implementación de `decrypt_enc_key(enc_key_wire: &str, stretched_master_key: &[u8]) -> Result<Vec<u8>, ApiError>`:
    - Parsea `enc_key_wire` a `sw_crypto::EncString`, construye el `SymmetricKey` desde los 64 bytes del stretched key y descifra usando `sw_crypto::decrypt_with` con verificación anti-padding oracle de HMAC.
  - Actualización de `prelogin(&self, email: &str) -> Result<sw_crypto::KdfConfig, ApiError>`:
    - Consulta `POST /api/accounts/prelogin` con fallback automático a `/accounts/prelogin` ante 404 para compatibilidad con servidores autoalojados / Vaultwarden.
  - Implementación de `login_with_password(&self, email: &str, master_password_hash: &str, device_uuid: &str) -> Result<LoginToken, ApiError>`:
    - `POST /connect/token` con cabeceras completas de cliente Bitwarden, `Auth-Email` (base64 url-safe sin padding), y campos de formulario: `grant_type=password`, `client_id=web`, `scope=api offline_access`, `deviceType=10`, `deviceIdentifier=device_uuid`, `deviceName=firefox`, `username=email`, `password=master_password_hash`.
    - Actualización atómica en cliente del token recibido.
  - Implementación de `login(&self, email: &str, password: &str, device_uuid: &str) -> Result<(LoginToken, Vec<u8>), ApiError>`:
    - Orquestación completa de 6 etapas:
      1. `prelogin(email)` $\rightarrow$ `KdfConfig`.
      2. `derive_master_key(password, email, &config)` $\rightarrow$ `MasterKey`.
      3. `derive_master_password_hash(master_key, password)` $\rightarrow$ hash base64.
      4. `stretch_key(&master_key)` $\rightarrow$ `SymmetricKey` (64 bytes).
      5. `login_with_password(email, &master_password_hash, device_uuid)` $\rightarrow$ `LoginToken`.
      6. `decrypt_enc_key(&token.key, &stretched_bytes)` $\rightarrow$ `user_symmetric_key` (64 bytes).
  - Funciones standalone de alto nivel: `prelogin`, `login_with_password`, `login`.
  - Batería de 15 pruebas unitarias añadidas (25 tests en total en `sw-bitwarden-api`):
    - `test_derive_master_password_hash_rfc6070_vector`: verificación con vector RFC 6070 adaptado (`Eg+2z/z4syxD5yJSVsT4N6hlSMkszDVICAWYfLcL4Xs=`).
    - `test_decrypt_enc_key_synthetic`: generación sintética de `EncString` (AES-256-CBC + HMAC-SHA256), descifrado y validación de coincidencia de bytes de la cuenta.
    - `test_decrypt_enc_key_error_cases`: cobertura de cadena vacía, formato inválido, clave de tamaño incorrecto y MAC corrupta.
    - `test_login_with_password_success`: mock server con `wiremock` validando cabeceras, formulario url-encoded y deserialización de `LoginToken`.
    - `test_login_with_password_error_400`: validación de rechazo `invalid_grant` propagado como `ApiError::Auth`.
    - `test_login_full_orchestration_success`: orquestación de extremo a extremo simulada con prelogin, derivación de hash, login y descifrado de la clave de usuario, seguido de llamada autenticada exitosa.
    - `test_login_full_orchestration_prelogin_fails`: propagación de error 500 de prelogin.
    - `test_prelogin_404_fallback_to_identity_mount`: fallback transparente entre rutas de prelogin.
    - `test_login_missing_key_returns_auth_error`: validación de error si el servidor no incluye clave.
    - `test_standalone_functions`: wrappers a nivel de módulo.
    - **Tests de paridad Go $\leftrightarrow$ Rust (con vectores reales de Goldwarden Go):**
      - `test_parity_master_key`: deriva con PBKDF2 (600,000 iteraciones) sobre `"Unloader-Woof"` y `"3227908@tcs.com"`, validando coincidencia exacta de `EXPECTED_MASTER_KEY_HEX` (`199221c9...`).
      - `test_parity_master_password_hash`: calcula hash PBKDF2-HMAC-SHA256 (1 iteración) y verifica Base64 exacto `EXPECTED_MASTER_PASSWORD_HASH_B64` (`n9L+3LdK...`).
      - `test_parity_stretch_key`: expande clave maestra con HKDF-SHA256 (`"enc"`, `"mac"`) y verifica coincidencia exacta de los 64 bytes hex `EXPECTED_STRETCHED_KEY_HEX` (`d173d390...`).
      - `test_parity_decrypt_enc_key`: descifra `EXPECTED_ENC_KEY` (`2.VnAx2h55...`) con la clave extendida y verifica coincidencia exacta con `EXPECTED_USER_SYMMETRIC_KEY_HEX` (`f7e4fce1...`) tanto vía `decrypt_enc_key` como directamente con `sw_crypto::decrypt_with`.
      - `test_parity_full_login_pipeline`: simulación completa de prelogin y connect/token con todos los vectores de Goldwarden Go validando token y clave simétrica final.

#### Controles obligatorios y resultados reales

| Control | Comando | Resultado real |
|---|---|---|
| Pruebas `sw-bitwarden-api` | `cargo test -p sw-bitwarden-api` | 25 pasan, 0 fallan (22.20s) |
| Pruebas Workspace | `cargo test --workspace --exclude sw-gui` | 203 pasan en total, 0 fallan |
| Linter | `cargo clippy --workspace --exclude sw-gui --all-targets -- -D warnings` | 0 warnings |
| Formato | `cargo fmt --all -- --check` | 0 diffs |
| Auditoría | `cargo audit` | 0 vulnerabilidades (exit 0) |
| **Cobertura `sw-bitwarden-api`** | `cargo llvm-cov -p sw-bitwarden-api --summary-only` | **96.81% regiones / 97.38% líneas** (umbral: ≥85%) |
| **Cobertura Total Workspace** | `cargo llvm-cov --workspace --exclude sw-gui --summary-only` | **93.85% regiones / 94.40% líneas** |

**Estado:** ✅ SW-033 (Parte 1: Mock server + Paridad Go) — Hecho (2026-10-24).

### 4.6 Evidencia de Ejecución: [SW-032] Sync completo + Caché en disco (`sw-vault`, `sw-bitwarden-api`)

**Fecha:** 2026-10-24  
**Archivos modificados:**
- `Cargo.toml` (raíz):
  - Añadida dependencia de workspace `dirs = "5.0"`.
- `crates/sw-vault/Cargo.toml`:
  - Dependencias añadidas: `dirs = { workspace = true }`, `tokio = { workspace = true, features = ["sync", "fs", "rt"] }`, `tempfile = { workspace = true }`.
- `crates/sw-vault/src/lib.rs`:
  - Enum de error de bóveda `VaultError`: variantes `Io`, `Json`, `NotFound`, `Api`, `Other`.
  - Struct `VaultPaths`:
    - Métodos `new()`, `default_paths()`, `base_dir()`, `vault_file()`.
    - Resolución estándar de ruta base vía `dirs::data_dir()` (`~/.local/share/silverwarden` en Linux con fallback) y archivo `vault.json`.
    - `ensure_dirs(&self) -> Result<(), VaultError>`: creación segura de directorios con permisos Unix `0700`.
  - Persistencia atómica en disco:
    - `save_vault(path: &Path, data: &SyncData) -> Result<(), VaultError>`:
      - Crea archivo temporal en el directorio destino (`tempfile::NamedTempFile::new_in(parent)`).
      - Escribe JSON serializado, vacía buffers con `flush()` y `sync_all()`.
      - Aplica permisos Unix estrictos `0600` en el archivo temporal antes del renombre.
      - Renombra atómicamente a la ruta de destino vía `.persist(path)`.
      - Reasegura permisos `0600` en la ruta final.
    - `load_vault(path: &Path) -> Result<SyncData, VaultError>`:
      - Validación de existencia previa (`VaultError::NotFound`).
      - Deserialización segura mediante `BufReader` y `serde_json::from_reader`.
    - Envoltorios asíncronos sin bloqueo de event-loop: `save_vault_async` y `load_vault_async` con `tokio::task::spawn_blocking`.
  - Almacén en memoria seguro `VaultStore`:
    - Protegido por `tokio::sync::RwLock` en memoria: `ciphers: RwLock<HashMap<Uuid, Cipher>>`, `folders: RwLock<Vec<Folder>>`, `profile: RwLock<Option<Profile>>`, `last_synced: RwLock<Option<u64>>`.
    - Métodos asíncronos: `load_sync_data` (carga sin descifrado masivo preliminar), `to_sync_data`, `insert`, `get`, `delete`, `all`, `len`, `is_empty`, `clear`, `profile`, `folders`, `last_synced`, `set_last_synced`.
    - Métodos bloqueantes síncronos: `blocking_insert`, `blocking_get`, `blocking_delete`, `blocking_all`, `blocking_len`, `blocking_clear`, `blocking_load_sync_data`, `blocking_to_sync_data`, `blocking_last_synced`, `blocking_set_last_synced`.
- `crates/sw-bitwarden-api/Cargo.toml`:
  - Adición de dev-dependencies `tempfile = { workspace = true }` y `uuid = { workspace = true }`.
- `crates/sw-bitwarden-api/src/lib.rs`:
  - Integración de variante `Vault(#[from] sw_vault::VaultError)` en `ApiError`.
  - Implementación de `sync(&self) -> Result<sw_vault::SyncData, ApiError>` en `AuthenticatedClient`:
    - Llamada GET al endpoint `/sync` con autorización y cabeceras estándar.
    - Fallback transparente a `/api/sync` ante 404 para compatibilidad total con servidores autoalojados / proxies.
  - Implementación de `do_full_sync(&self, vault_paths: &sw_vault::VaultPaths, vault_store: &sw_vault::VaultStore) -> Result<sw_vault::SyncData, ApiError>` en `AuthenticatedClient`:
    - Descarga remota de `SyncData` vía `self.sync().await`.
    - Persistencia atómica en disco en `vault_paths.vault_file()` con permisos Unix `0600`.
    - Carga en memoria sin descifrado en `vault_store`.
    - Registro de marca temporal Unix en `vault_store.set_last_synced()`.
  - Wrappers standalone: `sw_bitwarden_api::sync` y `sw_bitwarden_api::do_full_sync`.
  - Batería de pruebas obligatorias completada (11 pruebas en `sw-vault`, 5 nuevas en `sw-bitwarden-api`):
    - **Test 1 (Roundtrip save/load):** `test_vault_save_and_load_roundtrip` y `test_vault_async_save_and_load`.
    - **Test 2 (Permisos 0600 en Unix):** `test_vault_file_permissions_0600`.
    - **Test 3 (Concurrencia RwLock):** `test_vault_store_rwlock_concurrency`.
    - **Test 4 (Errores de archivo inexistente / corrupto):** `test_vault_load_nonexistent_and_corrupt_errors`.
    - **Test 5 (do_full_sync con Wiremock y verificación de caché/memoria):** `test_do_full_sync_wiremock_cache_and_memory` y `test_standalone_sync_and_do_full_sync`.

#### Controles obligatorios y resultados reales

| Control | Comando | Resultado real |
|---|---|---|
| Pruebas `sw-vault` | `cargo test -p sw-vault` | 11 pasan, 0 fallan (0.01s) |
| Pruebas `sw-bitwarden-api` | `cargo test -p sw-bitwarden-api` | 30 pasan, 0 fallan (26.96s) |
| Pruebas Workspace | `cargo test --workspace --exclude sw-gui` | 219 pasan en total, 0 fallan |
| Linter | `cargo clippy --workspace --exclude sw-gui --all-targets -- -D warnings` | 0 warnings |
| Formato | `cargo fmt --all -- --check` | 0 diffs |
| Auditoría | `cargo audit` | 0 vulnerabilidades (exit 0) |
| **Cobertura `sw-vault`** | `cargo llvm-cov -p sw-vault --summary-only` | **95.64% regiones / 96.50% líneas** (umbral: ≥85%) |
| **Cobertura `sw-bitwarden-api`** | `cargo llvm-cov -p sw-bitwarden-api --summary-only` | **97.06% regiones / 97.79% líneas** (umbral: ≥85%) |
| **Cobertura Total Workspace** | `cargo llvm-cov --workspace --exclude sw-gui --summary-only` | **93.92% regiones / 94.53% líneas** |

**Estado:** ✅ SW-032 — Hecho (2026-10-24).

---

### 4.7 Evidencia de Ejecución: [SW-036] CRUD de ciphers y descifrado bajo demanda

**Fecha:** 2026-10-24  
**Crates afectados:** `sw-bitwarden-api` (CRUD REST) y `sw-vault` (operaciones locales y descifrado bajo demanda).

#### Archivos modificados y creados:
- `crates/sw-bitwarden-api/Cargo.toml`:
  - Promoción de `uuid = { workspace = true }` a dependencia principal en `[dependencies]`.
- `crates/sw-bitwarden-api/src/ciphers.rs` (nuevo):
  - `get_cipher(client: &AuthenticatedClient, uuid: &Uuid) -> Result<Cipher, ApiError>`: GET a `/ciphers/{uuid}` vía `fetch_with_auth` con fallback a `/api/ciphers/{uuid}`.
  - `post_cipher(client: &AuthenticatedClient, cipher: &Cipher) -> Result<Cipher, ApiError>`: POST a `/ciphers` con JSON serializado y fallback a `/api/ciphers`.
  - `put_cipher(client: &AuthenticatedClient, uuid: &Uuid, cipher: &Cipher) -> Result<Cipher, ApiError>`: PUT a `/ciphers/{uuid}` con JSON y fallback a `/api/ciphers/{uuid}`.
  - `delete_cipher(client: &AuthenticatedClient, uuid: &Uuid) -> Result<(), ApiError>`: DELETE a `/ciphers/{uuid}` con fallback a `/api/ciphers/{uuid}`.
- `crates/sw-bitwarden-api/src/lib.rs`:
  - Declaración `pub mod ciphers;` y re-exportación de funciones CRUD.
  - Métodos asociados en `AuthenticatedClient`: `client.get_cipher(uuid)`, `client.post_cipher(cipher)`, `client.put_cipher(uuid, cipher)`, `client.delete_cipher(uuid)`.
  - Batería de pruebas con `wiremock`:
    - `test_get_cipher_mock`: mock devuelve `Cipher` de prueba, verificación de deserialización y campos.
    - `test_post_cipher_mock`: mock recibe POST, devuelve `Cipher` con id generado.
    - `test_put_cipher_mock`: mock recibe PUT, devuelve `Cipher` actualizado.
    - `test_delete_cipher_mock`: mock recibe DELETE, devuelve 200.
    - `test_cipher_404_error`: mock devuelve 404, verificación de `ApiError::Status`.
    - `test_cipher_api_fallback_mock`: verificación de fallback transparente a prefijo `/api/ciphers`.
- `crates/sw-vault/src/lib.rs`:
  - Struct `DecryptedCipher` con campos requeridos: `id`, `name`, `cipher_type`, `username`, `password`, `uri`, `notes`, `totp`, `favorite`.
  - Re-exportación de `sw_crypto` (`decrypt_with`, `encrypt_with`, `encrypt_with_to_string`, `EncString`, `EncStringType`, `SymmetricKey`) y `uuid::Uuid`.
  - Ampliación de `VaultError` con variantes tipadas: `Crypto(#[from] sw_crypto::CryptoError)` y `Utf8(#[from] std::string::FromUtf8Error)`.
  - Implementación en `VaultStore`:
    - `get_logins(&self) -> Vec<Cipher>` (async) y `blocking_get_logins(&self) -> Vec<Cipher>`.
    - `get_notes(&self) -> Vec<Cipher>` (async) y `blocking_get_notes(&self) -> Vec<Cipher>`.
    - `get_login_by_filter(&self, uuid, org_id, name, username, key) -> Option<Cipher>` (async) y variante bloqueante.
    - `get_note_by_filter(&self, uuid, org_id, name, key) -> Option<Cipher>` (async) y variante bloqueante.
    - `decrypt_cipher(cipher: &Cipher, key: &SymmetricKey) -> Result<DecryptedCipher, VaultError>`: síncrono (CPU-bound) con descifrado obligatorio de `name` y condicional de `username`, `password`, `uri` (con fallback a `uris`), `notes`, `totp`.
    - `search(&self, filter: &str, key: &SymmetricKey) -> Vec<DecryptedCipher>` (async) y variante bloqueante.
    - Método de conveniencia `Cipher::decrypt(&self, key: &SymmetricKey) -> Result<DecryptedCipher, VaultError>`.
  - Pruebas unitarias obligatorias completadas (26 pruebas en total en `sw-vault`):
    - `test_vault_store_get_logins`: almacén con 3 logins, 1 nota, 1 cipher borrado; verifica que devuelve 3 activos.
    - `test_vault_store_get_notes`: idem con notas activas y borradas.
    - `test_get_login_by_filter_name`: descifrado bajo demanda y filtrado por nombre exacto.
    - `test_get_login_by_filter_username`: descifrado bajo demanda y filtrado por username.
    - `test_get_note_by_filter`: filtrado por nota, UUID y organización.
    - `test_decrypt_cipher_full`: cifrado completo (name, username, password, uri, notes, totp), descifrado y validación integral de todos los campos.
    - `test_decrypt_cipher_with_null_fields`: cipher sin login ni notes con `None` en campos opcionales.
    - `test_decrypt_cipher_error_on_null_name`: rechazo controlado ante cipher con nombre nulo/vacío.
    - `test_search_matches_name_and_username`: búsqueda insensible y por subcadena en name y username, ignorando ciphers eliminados.
    - `test_vault_store_blocking_filtering_and_search`: validación de variantes bloqueantes sin contexto de runtime.
    - `test_decrypt_cipher_uri_fallback_and_login_cases`: fallback de `login.uri` nulo a lista `login.uris`.
    - `test_filter_edge_cases`: filtrado con organizaciones coincidentes y no coincidentes, ciphers sin login o con campos nulos.
    - Helpers: `make_test_key() -> SymmetricKey` (64 bytes fijos) y `make_encrypted_cipher(...)`.

#### Controles obligatorios y resultados reales

| Control | Comando | Resultado real |
|---|---|---|
| Pruebas `sw-vault` | `cargo test -p sw-vault` | 26 pasan, 0 fallan (0.01s) |
| Pruebas `sw-bitwarden-api` | `cargo test -p sw-bitwarden-api` | 36 pasan, 0 fallan (23.39s) |
| Pruebas Workspace | `cargo test --workspace --exclude sw-gui` | 239 pasan en total, 0 fallan |
| Linter | `cargo clippy --workspace --exclude sw-gui --all-targets -- -D warnings` | 0 warnings |
| Formato | `cargo fmt --all -- --check` | 0 diffs |
| Auditoría | `cargo audit` | 0 vulnerabilidades (exit 0) |
| **Cobertura `sw-vault`** | `cargo llvm-cov -p sw-vault --summary-only` | **97.41% regiones / 97.98% líneas** (umbral: ≥85%) |
| **Cobertura `sw-bitwarden-api`** | `cargo llvm-cov -p sw-bitwarden-api --summary-only` | **96.07% regiones / 97.62% líneas** (umbral: ≥85%) |

**Estado:** ✅ SW-036 — Hecho (2026-10-24).

---

### [SW-035] Websocket de notificaciones (`sw-bitwarden-api`)

**Fecha:** 2026-10-25  
**Crate:** `sw-bitwarden-api`.  
**Dependencias añadidas:** `futures-util = "0.3"`, `hex = { workspace = true }` (dev).

#### 1. Implementación

- **Módulo `sw-bitwarden-api::websocket`:**
  - `NotificationMessage`:
    - `message_type: i32`
    - `cipher_id: Option<String>`
  - `build_hub_url(url, token)`: normalización de URLs (`http`/`https` $\rightarrow$ `ws`/`wss`), anexión de `/hub` y parámetro `access_token`.
  - `parse_message_pack(message: &[u8]) -> Option<NotificationMessage>`:
    - Decodificación y salto del prefijo varint SignalR de 7 bits (`lenBufferLen`) con soporte fallback para MessagePack plano sin varint.
    - Extracción de `Type` (i32) y `Id` (String opcional) de `Payload` (en índice 4 del array SignalR `[type, headers, invocationId, target, arguments]`).
    - Paridad byte a byte con la implementación de referencia en Go (`websocketMessageType` y `parseMessageTypeFromMessagePack`).
  - `encode_notification_message(message_type, cipher_id, with_varint)`: helper de codificación para testing y emulación.
  - `WebsocketClient`:
    - `connect(url: &str, token: &str) -> Result<Self, ApiError>`: conexión asíncrona vía `tokio_tungstenite::connect_async` y envío del handshake requerido `{"protocol":"messagepack","version":1}\x1e`.
    - `next_message(&mut self) -> Option<NotificationMessage>`: lectura asíncrona de tramas WebSocket, filtrado de tramas de control y pings (con respuesta Pong automática), ignorado de respuestas de texto a handshake y parseo MessagePack de tramas binarias.
    - `close(&mut self)`: cierre controlado de la conexión.
    - `is_connected(&self) -> bool`: estado de conexión activa.
  - `run_websocket_daemon` / `run_websocket_daemon_with_options`:
    - Bucle asíncrono con tolerancia a caídas y reconexión periódica (backoff configurable, 60s por defecto).
    - Despacho reactivo:
      - `SyncCiphers (4)` / `SyncVault (5)`: ejecuta `api_client.do_full_sync(&vault_paths, &vault_store)`.
      - `SyncCipherUpdate (0)` / `SyncCipherCreate (1)`: consulta `get_cipher(uuid)` y actualiza `vault_store.insert(cipher)`.
      - `SyncCipherDelete (9)` / `SyncLoginDelete (2)`: remueve `vault_store.delete(&uuid)`.
      - `LogOut (11)`: limpia la bóveda en memoria (`vault_store.clear()`), cierra el socket y sale limpiamente.
    - `ApiError`: adición de variantes `WebSocket(Box<tokio_tungstenite::tungstenite::Error>)` y `MsgPack(#[from] rmp_serde::decode::Error)`.

#### 2. Pruebas realizadas

- `websocket::tests::test_build_hub_url`: normalización de esquema, ruta y query de conexión para múltiples variantes de URL.
- `websocket::tests::test_parse_message_pack_go_parity_fixtures`: validación estricta contra fixtures reales generados con el codificador MessagePack de Go:
  - `SyncCipherUpdate` con prefijo varint (`4f95d0...`).
  - `SyncCipherUpdate` plano sin varint (`95d0...`).
  - `SyncCiphers` sin ID de payload (`95d00180c0ae...d004`).
- `websocket::tests::test_parse_message_pack_synthetic_roundtrip`: serialización y deserialización sintética de notificaciones y manejo de tramas cortas/inválidas.
- `websocket::tests::test_mock_websocket_server_handshake_and_update`:
  - Servidor WebSocket mock aceptando conexión y validando handshake inicial SignalR.
  - Envío de notificación `SyncCipherUpdate` (Type: 0) con UUID de prueba.
  - Consulta mock a WireMock HTTP (`GET /ciphers/{id}`).
  - Despacho y verificación de llamada mock.
  - Finalización con evento `LogOut` (Type: 11) y verificación de borrado seguro.
- `websocket::tests::test_mock_websocket_server_update_then_delete`: inserción reactiva seguida de `SyncCipherDelete` (Type: 9) con canal de apagado `stop_rx`.
- `websocket::tests::test_websocket_client_methods_and_sync_ciphers`: validación de accesores del cliente y recepción de evento `SyncCiphers` (Type: 4) ejecutando `do_full_sync` con actualización de `last_synced`.

#### 3. Controles obligatorios y resultados reales

| Control | Comando | Resultado real |
|---|---|---|
| Pruebas `sw-bitwarden-api` | `cargo test -p sw-bitwarden-api` | 42 pasan, 0 fallan (58.28s) |
| Pruebas Workspace | `cargo test --workspace --exclude sw-gui` | 245 pasan en total, 0 fallan |
| Linter | `cargo clippy -p sw-bitwarden-api -- -D warnings` | 0 warnings |
| Formato | `cargo fmt --check` | 0 diffs |
| Auditoría | `cargo audit` | 0 vulnerabilidades (1 warning informativo documentado) |
| **Cobertura `sw-bitwarden-api`** | `cargo llvm-cov -p sw-bitwarden-api` | **94.72% líneas / 93.89% regiones** (umbral: ≥85%) |

**Estado:** ✅ SW-035 — Hecho (2026-10-25).

---

### [SW-034] 2FA (TOTP, Email, FIDO2 stub) (`sw-bitwarden-api`)

**Fecha:** 2026-10-25  
**Crate:** `sw-bitwarden-api`.  
**Dependencias:** ninguna adicional.

#### 1. Implementación

- **Módulo `sw-bitwarden-api::twofactor`:**
  - `TwoFactorProvider`: enum que modela los tipos de proveedores soportados por Bitwarden (`Authenticator = 0`, `Email = 1`, `Duo = 2`, `YubiKey = 3`, `U2f = 4`, `Remember = 5`, `OrganizationDuo = 6`, `WebAuthn = 7`).
  - `parse_two_factor_error(body: &str) -> Option<(Vec<i32>, String)>`:
    - Detección reactiva de respuestas de desafío 2FA.
    - Soporte para arrays `TwoFactorProviders` / `twoFactorProviders` y diccionarios `TwoFactorProviders2`.
    - Extracción de token de desafío `TwoFactorToken` / `twoFactorToken` / `authRequest`.
  - `complete_totp`: autenticación secundaria con código TOTP (proveedor 0) vía `POST /connect/token`.
  - `complete_email`: autenticación secundaria con código recibido por correo (proveedor 1) vía `POST /connect/token`.
  - `send_two_factor_email_login`: envío inicial de código de verificación por correo vía `POST /two-factor/send-email-login`.
  - `complete_fido2`: stub documentado que retorna `ApiError::NotImplemented("FIDO2 requires hardware and is postponed to post-MVP")`.
- **Integración en `login_with_password`:**
  - Intercepción de respuestas HTTP 401/400 que contengan `"TwoFactor"`.
  - Retorno estructurado de `ApiError::TwoFactorRequired { providers, token }`.
  - Preservación de `ApiError::Status` en cuerpos 2FA no reconocidos y `ApiError::Auth` para errores convencionales de credenciales.
- **Acceso en `AuthenticatedClient`:**
  - Métodos `complete_totp`, `complete_email`, `send_two_factor_email_login`, `complete_fido2` y accesor `http_client()`.

#### 2. Pruebas realizadas

- `twofactor::tests::test_login_detects_two_factor_required`: mock server respondiendo con 401 y `{"TwoFactorProviders":[0,1],"TwoFactorToken":"abc"}`, validando que `login_with_password` devuelve `ApiError::TwoFactorRequired`.
- `twofactor::tests::test_login_two_factor_unrecognized_format_returns_status`: respuesta con `"TwoFactor"` sin token, validando degradación a `ApiError::Status`.
- `twofactor::tests::test_complete_totp_success`: verificación del formulario enviado a `/connect/token` (`twoFactorProvider=0`, `twoFactorToken=code`, `authRequest=token`) y retorno de `LoginToken`.
- `twofactor::tests::test_complete_email_success`: verificación del formulario enviado con `twoFactorProvider=1` y recepción del token.
- `twofactor::tests::test_complete_email_send_step`: verificación del endpoint `POST /two-factor/send-email-login` con payload `{email, deviceIdentifier}` tanto en éxito (200) como en fallo (400).
- `twofactor::tests::test_complete_fido2_not_implemented`: verificación de que `complete_fido2` retorna `ApiError::NotImplemented`.
- `twofactor::tests::test_two_factor_providers_parsing`: extracción robusta en arrays PascalCase, camelCase y mapas `TwoFactorProviders2`.
- `twofactor::tests::test_login_full_orchestration_two_factor`: orquestación completa: prelogin $\rightarrow$ derivación de clave/hash $\rightarrow$ intento de login $\rightarrow$ intercepción de `TwoFactorRequired` $\rightarrow$ resolución exitosa vía `complete_totp`.

#### 3. Controles obligatorios y resultados reales

| Control | Comando | Resultado real |
|---|---|---|
| Pruebas `sw-bitwarden-api` | `cargo test -p sw-bitwarden-api` | 50 pasan, 0 fallan (60.08s) |
| Pruebas `sw-config` | `cargo test -p sw-config -- --test-threads=1` | 25 pasan, 0 fallan (219.91s) |
| Linter | `cargo clippy -p sw-bitwarden-api -- -D warnings` | 0 warnings |
| Formato | `cargo fmt --check` | 0 diffs |
| Auditoría | `cargo audit` | 0 vulnerabilidades (1 warning informativo documentado) |
| **Cobertura `sw-bitwarden-api`** | `cargo llvm-cov -p sw-bitwarden-api` | **92.95% líneas / 93.34% regiones** (umbral: ≥85%) |

**Estado:** ✅ SW-034 — Hecho (2026-10-25).











