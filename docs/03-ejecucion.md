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

**Commit:** Implementación y verificación de interoperabilidad (2026-10-13).

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







