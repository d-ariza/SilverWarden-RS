# Trazabilidad de Decisiones de Diseño

**Proyecto:** silverWarden-rs
**Fecha:** 2026-10-26
**Propósito:** Registrar cada decisión de diseño significativa, con su contexto, alternativas consideradas, y evidencia que la respalda. Esto permite entender el "por qué" de cada decisión dentro de 3 meses (o 3 años).

---

## Formato

Cada decisión se registra con:
- **ID:** D-NNN (secuencial).
- **Fecha:** cuándo se tomó.
- **Contexto:** por qué surgió la decisión.
- **Decisión:** qué se decidió.
- **Alternativas:** qué se descartó y por qué.
- **Evidencia:** código, tests, documentos que la respaldan.
- **Estado:** Vigente / Reemplazada por D-NNN / Pendiente.

---

## D-1 — RustCrypto como stack criptográfico

- **Fecha:** 2026-10-12
- **Contexto:** reescritura de un gestor de contraseñas compatible con Bitwarden. Se necesita AES-CBC-256+HMAC, RSA-OAEP-SHA1 legacy, ChaCha20-Poly1305, Argon2i, SHA3-256.
- **Decisión:** usar RustCrypto (`aes`, `cbc`, `hmac`, `sha2`, `sha3`, `hkdf`, `argon2`, `rsa`, `chacha20poly1305`).
- **Alternativas:** `ring` (no soporta RSA-OAEP-SHA1), `sodiumoxide` (no soporta AES-CBC).
- **Evidencia:** paridad Go↔Rust verificada en KDF, stretch, cipher, RSA (ver `03-ejecucion.md`).
- **Estado:** Vigente.

## D-2 — LockedBuffer propio

- **Fecha:** 2026-10-12
- **Contexto:** los secretos (claves, PINs, tokens) deben protegerse en memoria.
- **Decisión:** trait `LockedBuffer` con `MemLockedBuffer` (mlock + MADV_DONTDUMP + zeroize) y `MemoryBuffer` (para tests).
- **Alternativas:** crate `secrets` (menos control), `memsec` (más dependencias).
- **Evidencia:** `sw-crypto/src/mem.rs`, tests de wipe y mlock.
- **Estado:** Vigente.

## D-20 — Validación completa de padding PKCS#7

- **Fecha:** 2026-10-13
- **Contexto:** Go solo leía el último byte del padding. Eso es un bug de seguridad.
- **Decisión:** validar que **todos** los bytes de padding son iguales a `n`.
- **Alternativas:** replicar el bug de Go (rechazada, es un bug).
- **Evidencia:** `sw-crypto/src/cipher.rs`, test `test_pkcs7_unpad_invalid_padding`.
- **Estado:** Vigente.

## D-30 — Argon2i en config (no Argon2id)

- **Fecha:** 2026-10-18
- **Contexto:** Goldwarden Go usa `argon2.Key` (variante i) para cifrar la config con el PIN.
- **Decisión:** usar `Algorithm::Argon2i` con `t=2, m=2048 KiB, p=8` para paridad exacta.
- **Alternativas:** Argon2id (rompe paridad con Go), PBKDF2 (no es lo que usa Go).
- **Evidencia:** `sw-config/src/lib.rs`, paridad con `goldwarden.json` real.
- **Estado:** Vigente.

## D-31 — Formato Tink para ChaCha20-Poly1305 en config

- **Fecha:** 2026-10-18
- **Contexto:** Goldwarden Go usa `tink-crypto` para cifrar los campos del config. Tink añade una cabecera de 5 bytes al ciphertext.
- **Decisión:** replicar el wire format de Tink: `[0x00, 0x00, 0x00, 0x00, 0x00] || nonce || ct || tag`.
- **Alternativas:** usar RustCrypto directo (rompe paridad con Go).
- **Evidencia:** `sw-config/src/lib.rs`, test con `goldwarden.json` real.
- **Estado:** Vigente.

## D-36 — Sesiones SSH endurecidas

- **Fecha:** 2026-10-20
- **Contexto:** Go validaba sesiones SSH solo por tipo, sin verificar PID. Eso es laxo.
- **Decisión:** match exacto de PID, PPID y grand-PPID para `AccessVault` y `Pin`. Para `SSHKey`, match por tipo solo si el proceso es `ssh`, `ssh-keygen` o `git`.
- **Alternativas:** replicar la laxitud de Go (rechazada, es un riesgo).
- **Evidencia:** `sw-systemauth/src/lib.rs`, test `test_session_hierarchy`.
- **Estado:** Vigente.

## D-42 — GUI como cliente IPC del agente

- **Fecha:** 2026-10-24
- **Contexto:** la GUI Tauri necesita acceder al vault sin duplicar la lógica de seguridad.
- **Decisión:** la GUI es un cliente IPC del agente, igual que el CLI. El agente es el único dueño del estado (vault, clave, sesiones).
- **Alternativas:** GUI con estado propio (rechazada, duplica la lógica), GUI que ejecuta el CLI como subproceso (rechazada, lenta y frágil).
- **Evidencia:** `01-analisis.md` §4.4, `02-plan.md` D42.
- **Estado:** Vigente.

## D-43 — Agente obligatorio

- **Fecha:** 2026-10-24
- **Contexto:** la GUI necesita el agente para funcionar.
- **Decisión:** si el agente no está corriendo, la GUI muestra un error claro ("Ejecuta `silverwarden agent start`"). No hay fallback a acceso directo.
- **Alternativas:** GUI que arranca el agente automáticamente (rechazada, complica el ciclo de vida).
- **Evidencia:** `01-analisis.md` §4.4.
- **Estado:** Vigente.

## D-M5-1 — `russh 0.65` para el agente SSH

- **Fecha:** 2026-10-26
- **Contexto:** se necesita parsear claves OpenSSH, firmar, y manejar el protocolo SSH agent. `russh` está en deps (para el cliente SSH de M5).
- **Decisión:** usar `russh 0.65.0` (corrige CVE-2026-111061 de versiones <0.64.1).
- **Alternativas:** `ssh-agent-lib` (menos mantenida), implementación manual del protocolo (más trabajo).
- **Evidencia:** `Cargo.lock` con `russh v0.65.0`, tests con `ssh-add -L` y `ssh-keygen -Y sign`.
- **Estado:** Vigente.

## D-M5-2 — Framing manual del protocolo SSH agent

- **Fecha:** 2026-10-26
- **Contexto:** el `AgentServer` de `russh` (`russh::keys::agent::server::serve`) mantiene un `KeyStore` interno y **no soporta un backend externo**. Nuestro modelo es que las claves viven en el vault cifrado, no en memoria del agente.
- **Decisión:** implementar el framing del protocolo SSH agent a mano (`[u32 len][u8 msg_type][payload]`), usando los tipos de `russh` (`PrivateKey`, `PublicKey`, `sign_with_hash_alg`) para parsear y firmar.
- **Alternativas:** usar `russh::keys::agent::server::serve` (rechazada, no soporta backend externo).
- **Evidencia:** `sw-ssh-agent/src/lib.rs`, tests con `ssh-add -L`, `ssh-keygen -Y sign`, `git commit -S`.
- **Estado:** Vigente.

## D-M5-3 — Tipo `SSHKey` (5) para claves SSH

- **Fecha:** 2026-10-26
- **Contexto:** Bitwarden oficial migró de `SecureNote` + campos custom a `SSHKey` (tipo 5) en 2024. Vaultwarden lo soporta.
- **Decisión:** usar `CipherType::SshKey = 5` para las claves SSH. Mantener compatibilidad con `SecureNote` + `custom-type: ssh-key` para migración desde Goldwarden Go.
- **Alternativas:** solo `SecureNote` (rechazada, no es el estándar actual).
- **Evidencia:** `sw-vault/src/lib.rs`, `sw-ssh-agent` lee ambos formatos.
- **Estado:** Vigente.

## D-M5-4 — Bypass de aprobación en tests, no en runtime

- **Fecha:** 2026-10-26
- **Contexto:** los tests de `sw-ssh-agent` necesitan saltarse la aprobación por pinentry. Se implementó un bypass con variables de entorno (`SILVERWARDEN_SYSTEM_AUTH_DISABLED`), lo cual es un riesgo de seguridad en producción.
- **Decisión:** mover el bypass a `#[cfg(test)]` o a un feature flag de compilación. Nunca a una variable de entorno en runtime.
- **Alternativas:** mantener el bypass por variable de entorno (rechazada, riesgo de seguridad).
- **Evidencia:** Solucionado y refactorizado en el commit `2aa6e36`, restringiendo el bypass estrictamente a entornos de compilación de pruebas (`#[cfg(test)]`).
- **Estado:** Vigente.

## D47 — Configuración guiada (`silverwarden config setup`)

- **Fecha:** 2026-10-30
- **Contexto:** Los usuarios requieren conectarse a servidores diversos (Bitwarden oficial, Vaultwarden local o propio, o configuración manual de endpoints). Además, los servidores locales suelen usar certificados autofirmados que `reqwest` rechaza por defecto.
- **Decisión:** Implementar el subcomando interactivo `silverwarden config setup` que consulta el tipo de servidor (1: Bitwarden Oficial, 2: Vaultwarden / Autoalojado, 3: Manual) y si se deben aceptar certificados autofirmados (`danger_accept_invalid_certs`). Deduplica automáticamente rutas base para derivar `/identity`, `/api` y `/notifications`.
- **Alternativas:** Configuración manual mediante flags o edición directa de JSON (propensa a errores de formato o duplicación de rutas).
- **Evidencia:** `crates/sw-cli/src/main.rs`, tests unitarios y de integración con Docker.
- **Estado:** Vigente.

## D48 — Inclusión de `encryptedFor` en POST /ciphers

- **Fecha:** 2026-10-30
- **Contexto:** Vaultwarden 1.37.4+ rechaza la creación de ciphers con HTTP 422 Unprocessable Entity si falta el UUID del perfil de usuario propietario.
- **Decisión:** Añadir el campo `encrypted_for: Option<Uuid>` (serializado como `encryptedFor` en camelCase) a `Cipher` en `sw-vault`. El agente `sw-agent` obtiene el `profile.id` sincronizado previamente y lo inyecta al crear ciphers. Si la bóveda no está sincronizada, el CLI devuelve un mensaje claro pidiendo ejecutar `silverwarden sync` primero.
- **Alternativas:** Omitir `encryptedFor` y requerir parches en el servidor (incompatible con instancias existentes).
- **Evidencia:** `crates/sw-vault/src/lib.rs`, `crates/sw-agent/src/lib.rs`, validación exitosa en servidor real.
- **Estado:** Vigente.

## D49 — Cabecera `Bitwarden-Client-Version` moderna (>= 2024.12.0)

- **Fecha:** 2026-10-31
- **Contexto:** Vaultwarden (en su endpoint `GET /sync`) filtra y omite los ciphers de tipo 5 (`CipherType::SshKey`) si la cabecera `Bitwarden-Client-Version` enviada por el cliente no cumple la restricción semver `>= 2024.12.0`. Nuestro cliente enviaba `0.0.1`, haciendo que Vaultwarden omitiera las claves SSH descargadas.
- **Decisión:** Actualizar `BITWARDEN_CLIENT_VERSION` en `crates/sw-bitwarden-api/src/lib.rs` a `"2024.12.0"`.
- **Alternativas:** Mantener `0.0.1` (provoca sincronización incompleta de ítems tipo 5 en Vaultwarden).
- **Evidencia:** `crates/sw-bitwarden-api/src/lib.rs`, test `test_sync_sends_modern_client_version_header`, y verificación en Vaultwarden local donde se sincronizan los 8 ciphers incluyendo las 2 claves SSH.
- **Estado:** Vigente.

## D50 — Aislamiento de almacenamiento en WebSocket Daemon vía inyección de `VaultPaths`

- **Fecha:** 2026-10-31
- **Contexto:** Al recibir notificaciones push `SyncCiphers` / `SyncVault`, el daemon de WebSocket invocaba `do_full_sync` utilizando `VaultPaths::default_paths()`. En entornos de pruebas esto escribía directamente en `~/.local/share/silverwarden/vault.json` del usuario host, violando el principio de aislamiento de tests.
- **Decisión:** Exigir `vault_paths: VaultPaths` como parámetro explícito en `run_websocket_daemon` y `run_websocket_daemon_with_options`. Los tests inyectan un `VaultPaths::new(&temp_dir.path().join("cache"))`, mientras que en runtime de producción se provee la ruta estándar del sistema.
- **Alternativas:** Modificar variables globales de directorio de datos o asumir que el test corre en contenedor efímero (frágil y riesgoso para el entorno del desarrollador).
- **Evidencia:** `crates/sw-bitwarden-api/src/websocket.rs`, test `test_websocket_sync_writes_to_injected_vault_path` que verifica que la escritura ocurre dentro del `TempDir` y que el archivo real del host permanece intacto.
- **Estado:** Vigente.

## D51 — Aceptación y medición dual de la cobertura (estándar y producción pura)

- **Fecha:** 2026-11-01
- **Contexto:** La cobertura inicial reportada para `sw-cli` fue **85.19%** según `cargo llvm-cov -p sw-cli --summary-only`, pero incluía líneas del módulo `mod tests` (en el mismo archivo `main.rs`). Surgió la duda de si la cobertura de producción pura estaba por debajo del umbral del 85%, mientras que en `sw-agent` la producción pura se encontraba en 78.97%.
- **Decisión:** Mantener la métrica estándar para trazabilidad del workspace y medir formalmente la cobertura de producción pura en los crates donde tests y producción conviven en el mismo archivo. Se implementó una suite exhaustiva en `sw-agent` y `sw-cli` para llevar la producción pura a ≥90% en ambos crates núcleo.
- **Alternativas:**
  - (a) Bloquear milestones sin medir producción pura o confiar ciegamente en el artefacto del denominador. Rechazada: oculta gaps reales en módulos críticos como el daemon.
  - (b) Mover todos los tests a directorios externos antes de tiempo. Pospuesta: requiere refactorizaciones estructurales de paths y visibilidad interna innecesarias para la fase actual.
- **Evidencia:** 
  - `sw-cli`: 85.78% total archivo / **95.97% producción pura** (786/819 líneas evaluables).
  - `sw-agent`: 97.16% total archivo / **92.46% producción pura** (932/1008 líneas evaluables).
  - Workspace total: **92.90% líneas / 92.81% regiones** (404 tests pasando, 0 fallos). Ver `docs/04-validacion.md` §9.8.
- **Estado:** Vigente (Verificado y cerrado).

## D52 — Ubicación canónica de las lecciones aprendidas

- **Fecha:** 2026-11-01
- **Contexto:** El commit `969fa84` ("docs: plan de M6") movió por error la sección `## 8. Lecciones de M5 (SSH Agent)` de `docs/lecciones-aprendidas.md` a `docs/deuda-tecnica.md`. Las lecciones aprendidas (patrones de diseño, metodología, seguridad) no son deuda técnica: son documentación de conocimiento que debe residir en `lecciones-aprendidas.md`.
- **Decisión:** Las lecciones aprendidas de cada milestone van en `docs/lecciones-aprendidas.md`, bajo `## N. Lecciones de MX`. `docs/deuda-tecnica.md` es exclusivamente para deudas técnicas (`DT-NNN`), no para lecciones. Se revierte el movimiento de `969fa84` en el cierre de M5.
- **Alternativas:**
  - (a) Dejar la sección 8 en `deuda-tecnica.md` y añadir 8.7 allí. Rechazada: perpetúa el error de organización y mezcla conceptos (deuda vs. conocimiento).
  - (b) Duplicar la sección 8 en ambos documentos. Rechazada: viola el principio DRY y crea dos fuentes de verdad que se desincronizan.
- **Evidencia:** `docs/lecciones-aprendidas.md` (sección 8 completa 8.1-8.8), `docs/deuda-tecnica.md` (sin sección 8, solo DT-18), commits `969fa84` (movimiento erróneo) y el commit de cierre de M5 (reversión). `grep -c "## 8. Lecciones de M5" docs/lecciones-aprendidas.md` → 1; `grep -c "## 8. Lecciones de M5" docs/deuda-tecnica.md` → 0.
- **Estado:** Vigente.


