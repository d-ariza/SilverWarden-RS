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

## D-M6-1 — PinCache cachea los 32 bytes de la `config_key` en `LockedBuffer`

- **Fecha:** 2026-11-01
- **Contexto:** La derivación de clave con Argon2i (`t=2, m=2048 MiB, p=8`) consume ~2-5 segundos de CPU y 2 GiB de RAM en cada desbloqueo del vault. Repetir esta operación continuamente degrada severamente la experiencia de usuario.
- **Decisión:** El PinCache cachea los 32 bytes de la `config_key` en `LockedBuffer` (`MemLockedBuffer` con `mlock` + `MADV_DONTDUMP` + `Zeroize`). NO cachea la `user_symmetric_key` ni el PIN. La `config_key` es de 32 bytes (Argon2i); no se construye una `SymmetricKey` de 64 bytes con MAC redundante. En cada desbloqueo con caché válido, la `user_symmetric_key` se descifra desde `encrypted_user_symmetric_key` con la `config_key` en microsegundos vía AES-CBC-256.
- **Alternativas:**
  - (a) Construir `SymmetricKey::from_parts(key, key)` duplicando 32 bytes a 64 bytes con MAC redundante. Rechazada: fallo de diseño, la `config_key` mide exactamente 32 bytes.
  - (b) Cachear el PIN del usuario en memoria. Rechazada por seguridad: el PIN es el secreto maestro raíz del usuario y nunca debe persistir en memoria.
  - (c) Cachear la `user_symmetric_key` en el PinCache. Rechazada: la `user_symmetric_key` solo debe residir en el gestor de bóveda activo; la separación criptográfica mantiene el menor radio de impacto.
- **Evidencia:** `crates/sw-agent/src/lib.rs` (`struct PinCache` con `Option<MemLockedBuffer>`, `Unlock` handler con branch `from_cache: true`), tests `test_pin_cache_store_and_get`, `test_unlock_uses_pin_cache_when_valid`, `test_unlock_cache_hit_decrypts_token_and_symmetric_key`.
- **Estado:** Vigente.

## D-M6-2 — TTL deslizante (sliding window) de 15 minutos configurable

- **Fecha:** 2026-11-01
- **Contexto:** Se requiere un balance entre usabilidad y seguridad de sesión. Una sesión demasiado corta obliga al usuario a esperar 2-5s constantemente; una sesión estática infinita expone la clave si el equipo queda desatendido.
- **Decisión:** Establecer un TTL por defecto de 900 segundos (15 minutos), configurable mediante `RuntimeConfig.pin_cache_ttl_secs`. El TTL es deslizante (*sliding*): cada lectura exitosa (`PinCache::get`) reinicia la ventana de expiración a `now + ttl`.
- **Alternativas:**
  - (a) TTL fijo absoluto (ignora actividad del usuario). Rechazada: bloquea operaciones legítimas en medio del flujo de trabajo activo.
  - (b) TTL no configurable codificado en constantes. Rechazada: impide a usuarios avanzados o entornos de alta seguridad ajustar su ventana de exposición.
- **Evidencia:** `crates/sw-config/src/lib.rs` (`RuntimeConfig.pin_cache_ttl_secs`), `crates/sw-agent/src/lib.rs` (`PinCache::get`), test `test_pin_cache_ttl_resets_on_get`, `test_pin_cache_expires_after_ttl`.
- **Estado:** Vigente.

## D-M6-3 — Empleo de `tokio::time::Instant` y tests con TTLs cortos

- **Fecha:** 2026-11-01
- **Contexto:** Se intentó usar `tokio::time::pause()` para tests deterministas, pero `pause()` no afecta a `Instant::now()` sin la feature `test-util`.
- **Decisión:** Los tests de TTL usan `tokio::time::sleep` real con TTLs cortos (50-70ms). Si en M6+ se necesita determinismo total, migrar a un `Clock` trait inyectable. `PinCache` mantiene `tokio::time::Instant` para integración con el runtime asíncrono.
- **Alternativas:**
  - (a) Forzar dependencia `tokio/test-util` en producción. Rechazada para no inflar dependencias de release.
  - (b) Usar `std::time::Instant`. Rechazada: bloquea la integración asíncrona fluida con Tokio time y timers futuros.
- **Evidencia:** `crates/sw-agent/src/lib.rs` (`PinCache.expires_at: Option<tokio::time::Instant>`), tests `test_pin_cache_expires_after_ttl` y `test_pin_cache_ttl_resets_on_get`. Registrado en `docs/deuda-tecnica.md` (DT-20).
- **Estado:** Vigente.

## D-M6-4 — Limpieza estricta (Zeroize) del PinCache en Lock y PinUpdate

- **Fecha:** 2026-11-01
- **Contexto:** Cuando el usuario bloquea explícitamente el vault o modifica su PIN maestro, mantener la `config_key` anterior en memoria vulneraría las expectativas de seguridad y el aislamiento de sesiones.
- **Decisión:** Ejecutar `state.pin_cache.clear()` (que libera y zeroiza la memoria bloqueada de `SymmetricKey`) de forma inmediata al procesar la acción IPC `Lock` y al cambiar el PIN con `PinUpdate`. Tras `PinUpdate`, se cachea exclusivamente la clave derivada del nuevo PIN.
- **Alternativas:**
  - (a) Mantener el caché tras `Lock` permitiendo desbloqueos rápidos subsecuentes. Rechazada tajantemente: `Lock` es una orden explícita de clausura que debe purgar todos los secretos de memoria.
- **Evidencia:** `crates/sw-agent/src/lib.rs` (handlers de `Lock` y `PinUpdate`), tests `test_lock_clears_pin_cache`, `test_pin_update_clears_and_stores_new`.
- **Estado:** Vigente.

## D-M6-5 — Backend D-Bus Notifications (`org.freedesktop.Notifications`) y Notifier async

- **Fecha:** 2026-11-01
- **Contexto:** Se requiere notificar al usuario en el escritorio Linux sobre eventos clave de seguridad. Se cuenta con `zbus 5.0` en dependencias del workspace.
- **Decisión:** Implementar `DbusNotifier` en `sw-notify` conectándose al bus de sesión vía `org.freedesktop.Notifications`. El trait `Notifier` se evoluciona a `#[async_trait] pub trait Notifier: Send + Sync + std::fmt::Debug { async fn notify(&self, title: &str, body: &str) -> Result<(), NotifyError>; }` usando `async-trait 0.1` (estándar, mantenido, sin CVEs). El backend alternativo XDG Portal (`org.freedesktop.portal.Notification`) se pospone a post-MVP (DT-21) para evitar dependencias pesadas como `ashpd`.
- **Alternativas:**
  - (a) Mantener `Notifier` síncrono usando `zbus::blocking`. Rechazada: bloquea threads del runtime tokio de forma innecesaria en operaciones asíncronas.
  - (b) Implementar XDG Portal inmediatamente con `ashpd`. Rechazada: introduce dependencias pesadas y complejidad innecesaria para el MVP.
- **Evidencia:** `crates/sw-notify/src/lib.rs` (`DbusNotifier`, `Notifier`), `Cargo.toml`.
- **Estado:** Vigente.

## D-M6-6 — Inyección de dependencias `Arc<dyn Notifier>` en AgentState y VaultAgentServer

- **Fecha:** 2026-11-01
- **Contexto:** Los tests unitarios y de integración deben ejecutarse sin depender de la presencia de un daemon D-Bus activo en el entorno (especialmente en CI o entornos headless).
- **Decisión:** Inyectar `notifier: Arc<dyn Notifier>` en `AgentState` e inyectar `notifier: Option<Arc<dyn Notifier>>` en `VaultAgentServer`. Se implementa `MockNotifier` en `sw-notify` con contador de notificaciones en memoria protegida por `Mutex`, permitiendo simular éxito y fallos programados.
- **Alternativas:**
  - (a) Instanciar `DbusNotifier` directamente hardcodeado en los handlers. Rechazada: imposibilita pruebas unitarias fiables y rompe CI sin D-Bus.
- **Evidencia:** `crates/sw-agent/src/lib.rs` (`AgentState::with_notifier`), `crates/sw-ssh-agent/src/lib.rs` (`VaultAgentServer::with_notifier`).
- **Estado:** Vigente.

## D-M6-7 — Notificación restringida a firma SSH exitosa y bloqueo de vault con fallback silencioso

- **Fecha:** 2026-11-01
- **Contexto:** Evitar saturar al usuario con notificaciones continuas (alerta por PIN erróneo, sync periódico, etc.) en esta fase.
- **Decisión:** Notificar exclusivamente dos eventos en SW-053: (1) firma SSH completada con éxito indicando el nombre de la clave utilizada (`"Firma SSH con clave '{}'"`), y (2) bloqueo de la bóveda (`"Bóveda bloqueada"`). Ambos llamados implementan fallback silencioso: si el envío a D-Bus falla (ej. daemon caído o sin sesión), se ignora el error sin interrumpir ni fallar la operación principal (firma SSH o Lock).
- **Alternativas:**
  - (a) Interrumpir la firma SSH si falla la notificación. Rechazada: una falla en el bus de notificaciones no debe bloquear la capacidad operativa del usuario.
- **Evidencia:** `crates/sw-agent/src/lib.rs` (`Lock`), `crates/sw-ssh-agent/src/lib.rs` (`sign_with_key_context`), tests `test_lock_succeeds_even_if_notifier_fails` y `test_sign_succeeds_even_if_notifier_fails`.
- **Estado:** Vigente.

## D-M6-8 — Pruebas unitarias con Mock y pruebas de integración D-Bus real aisladas en tests/

- **Fecha:** 2026-11-01
- **Contexto:** Las pruebas que interactúan con un daemon D-Bus real (`test_dbus_notifier_smoke` y `test_dbus_notifier_returns_error_without_session`) no pueden garantizarse en CI y deben marcarse con `#[ignore]`. Si residen dentro de `src/lib.rs`, distorsionan el denominador de cobertura de `cargo llvm-cov`.
- **Decisión:** Alojar los tests unitarios con `MockNotifier` y casos de error de dirección en `crates/sw-notify/src/lib.rs`, y aislar los tests con D-Bus real / manuales en `crates/sw-notify/tests/manual_dbus.rs` con `#[ignore]`.
- **Alternativas:**
  - (a) Dejar los tests `#[ignore]` dentro de `src/lib.rs`. Rechazada: genera un artefacto del denominador bajando la cobertura de líneas de producción del crate artificialmente.
- **Evidencia:** `crates/sw-notify/tests/manual_dbus.rs`, cobertura `sw-notify` del 94.68% de líneas.
- **Estado:** Vigente.

## D-M6-9 — Lock automático por inactividad, suspensión del sistema y bloqueo de pantalla

- **Fecha:** 2026-11-01
- **Contexto:** El agente debe proteger el vault de accesos no autorizados cuando el usuario se aleja o suspende su equipo, replicando la paridad con Goldwarden Go.
- **Decisión:** Implementar bloqueo automático ante 3 eventos: (1) inactividad por exceder el TTL configurado sin peticiones IPC, (2) suspensión del sistema señalada por `PrepareForSleep(start=true)` de `systemd-logind`, y (3) bloqueo de pantalla señalado por `Lock` de `systemd-logind`. Cada evento limpia `PinCache`, ejecuta `sessions.wipe()`, bloquea `vault_agent`, y emite la notificación de escritorio correspondiente.
- **Alternativas:**
  - (a) Delegar el bloqueo exclusivamente al usuario o CLI. Rechazada: infringe la especificación de seguridad de Goldwarden ante suspensión y desatención física.
- **Evidencia:** `crates/sw-agent/src/lib.rs` (`handle_logind_event`, `spawn_idle_monitor`), tests `test_idle_monitor_locks_after_ttl`, `test_logind_prepare_for_sleep_locks`, `test_logind_lock_signal_locks`.
- **Estado:** Vigente.

## D-M6-10 — TTL default de 600 segundos (10 min) configurable en RuntimeConfig

- **Fecha:** 2026-11-01
- **Contexto:** Se requiere un intervalo de tiempo de inactividad razonable y configurable para el bloqueo de la bóveda.
- **Decisión:** Establecer un TTL default de 600 segundos (10 minutos) en `RuntimeConfig.idle_ttl_secs`, configurable vía `silverwarden.json` con soporte de aliases `idle_ttl_secs` y `idleTtlSecs`. Es más estricto que el TTL de `PinCache` (900s) debido a que la bóveda abierta expone credenciales y secretos completos.
- **Alternativas:**
  - (a) Usar el mismo TTL de PinCache (15 min). Rechazada: 10 minutos proporciona mayor seguridad contra accesos no autorizados en terminales desatendidas.
- **Evidencia:** `crates/sw-config/src/lib.rs` (`DEFAULT_IDLE_TTL_SECS = 600`), test `test_runtime_config_idle_ttl_secs_default_and_roundtrip`.
- **Estado:** Vigente.

## D-M6-11 — Contador de inactividad basado en `tokio::time::Instant` y `touch_activity`

- **Fecha:** 2026-11-01
- **Contexto:** Cada petición IPC al demonio debe actualizar el temporizador de inactividad sin causar contención de locks en el estado global.
- **Decisión:** Proteger el timestamp `last_activity` con un `Arc<tokio::sync::RwLock<tokio::time::Instant>>` independiente dentro de `AgentState`. En `handle_message`, invocar `state.touch_activity().await` adquiriendo y liberando de inmediato el lock de actividad antes de procesar el mensaje con el registro de acciones.
- **Alternativas:**
  - (a) Mantener el timestamp dentro del lock `write().await` global durante toda la ejecución de los handlers. Rechazada: introduciría contención innecesaria en operaciones de larga duración.
- **Evidencia:** `crates/sw-agent/src/lib.rs` (`touch_activity`, `handle_message`), test `test_last_activity_updates_on_ipc`.
- **Estado:** Vigente.

## D-M6-12 — Monitoreo de `systemd-logind` en bus de sistema con fallback silencioso

- **Fecha:** 2026-11-01
- **Contexto:** Los eventos de suspensión (`PrepareForSleep`) y bloqueo (`Lock`) provienen de `org.freedesktop.login1` en el bus de sistema D-Bus (`zbus::Connection::system()`). En entornos de desarrollo, contenedores o sistemas no-systemd, el bus de sistema o logind pueden no estar disponibles.
- **Decisión:** Ejecutar `spawn_logind_monitor` en un task en segundo plano que intente conectarse a `org.freedesktop.login1`. Si la conexión o las suscripciones fallan, emitir un warning vía `tracing::warn!` y finalizar la tarea limpiamente sin abortar el demonio del agente.
- **Alternativas:**
  - (a) Abortar el arranque del daemon si `systemd-logind` no responde. Rechazada: impediría usar el agente en entornos WSL, contenedores Docker o entornos no-systemd.
- **Evidencia:** `crates/sw-agent/src/lib.rs` (`spawn_logind_monitor`), test `test_spawn_logind_monitor_shutdown`, `crates/sw-agent/tests/manual_logind.rs`.
- **Estado:** Vigente.





## D-M6-13 — Biometría Polkit como desbloqueo alternativo condicionado al PinCache

- **Fecha:** 2026-11-01
- **Contexto:** Se requiere permitir el desbloqueo rápido del vault mediante huella dactilar o autenticación biométrica en Linux sin comprometer la seguridad criptográfica.
- **Decisión:** Implementar la biometría como un método alternativo de desbloqueo (Opción A). La biometría no reemplaza al PIN maestro ni puede derivar la `config_key` por sí misma; únicamente complementa el flujo cuando el `PinCache` en memoria bloqueada está vigente y el usuario ha activado explícitamente `biometrics_enabled = true`.
- **Alternativas:**
  - (a) Reemplazar el PIN por biometría almacenando la clave en el keyring del sistema. Rechazada: el PIN sigue siendo obligatorio como secreto raíz; el keyring expone la clave a procesos con privilegios de usuario.
- **Evidencia:** `crates/sw-agent/src/lib.rs` (handler `Unlock`), tests `test_unlock_with_biometrics_success`, `test_unlock_with_biometrics_denied`, `test_unlock_with_biometrics_disabled`.
- **Estado:** Vigente.

## D-M6-14 — Trait `Biometrics` con paso de `CallingContext` y configuración opt-in

- **Fecha:** 2026-11-01
- **Contexto:** Polkit requiere identificar el sujeto exacto a autorizar (`unix-process` con PID y start-time), el cual corresponde al proceso cliente que invocó al agente (no al agente mismo). Además, la biometría debe ser opt-in.
- **Decisión:** Definir el trait `Biometrics` en `sw-systemauth` con la firma `async fn authenticate(&self, reason: &str, ctx: &CallingContext) -> Result<bool, BiometricsError>`. Proveer la implementación real `PolkitBiometrics` (usando `zbus 5.x` sobre `org.freedesktop.PolicyKit1.Authority.CheckAuthorization`) y `MockBiometrics` para pruebas. El parámetro `biometrics_enabled: bool` en `RuntimeConfig` tiene valor por defecto `false`.
- **Alternativas:**
  - (a) Autorizar el proceso del agente SilverWarden en Polkit. Rechazada: Polkit debe solicitar consentimiento al usuario identificando la aplicación cliente llamante.
- **Evidencia:** `crates/sw-systemauth/src/biometrics.rs`, `crates/sw-config/src/lib.rs` (`biometrics_enabled`).
- **Estado:** Vigente.

## D-M6-15 — Pruebas unitarias en memoria con `MockBiometrics` y prueba Polkit real aislada con `#[ignore]`

- **Fecha:** 2026-11-01
- **Contexto:** Polkit requiere interacción de usuario o políticas del sistema en `/usr/share/polkit-1/actions/`, las cuales fallan en entornos CI headless o no interactivos.
- **Decisión:** Cubrir unitariamente al 100% las ramas de éxito, rechazo y desactivación de biometría en `sw-agent` y `sw-systemauth` usando `MockBiometrics`. Aislar la prueba de humo contra el servicio Polkit real en `crates/sw-agent/tests/manual_polkit.rs` marcada con `#[ignore]`.
- **Alternativas:**
  - (a) Ejecutar la prueba Polkit real en el suite de CI. Rechazada: produciría fallos espurios en runners automatizados sin entorno de sesión gráfico o de autorización activa.
- **Evidencia:** `crates/sw-agent/src/lib.rs` (tests 1 a 5 de biometría), `crates/sw-agent/tests/manual_polkit.rs`.
- **Estado:** Vigente.

## D-M6-16 — Instalación de systemd user unit y Polkit policy en directorios de usuario sin root

- **Fecha:** 2026-11-01
- **Contexto:** El daemon de SilverWarden corre como agente del usuario. La instalación de servicios y políticas debe poder realizarse de forma autónoma sin privilegios de root (`sudo`).
- **Decisión:** Instalar la unidad systemd en `~/.config/systemd/user/silverwarden.service` (con permisos `0600` y directorio `0700`) y la política de Polkit en `~/.local/share/polkit-1/actions/org.silverwarden.unlock.policy` (permisos `0600` y directorio `0700`). Polkit soporta la lectura de acciones locales de usuario en dicho path para sesiones de escritorio modernas.
- **Alternativas:**
  - (a) Requerir instalación en `/etc/systemd/system/` y `/usr/share/polkit-1/actions/` con root. Rechazada: violaría el principio de menor privilegio y dificultaría instalaciones portables o sin sudo.
- **Evidencia:** `crates/sw-cli/src/systemd.rs`, `crates/sw-cli/src/main.rs` (`Commands::SetupSystemd`).
- **Estado:** Vigente.

## D-M6-17 — Comando `silverwarden setup-systemd` con flags `--dry-run` y `--no-enable`

- **Fecha:** 2026-11-01
- **Contexto:** Los usuarios y empaquetadores requieren flexibilidad al configurar el servicio de usuario de systemd: algunos desean inspeccionar los archivos antes de escribir, otros empaquetan sin habilitar inmediatamente el servicio, y otros desean el flujo completo en un solo comando.
- **Decisión:** Implementar el subcomando `silverwarden setup-systemd` con soporte para:
  - `--dry-run`: renderiza e imprime el contenido de la unidad systemd y la política Polkit con sus rutas destino sin escribir en disco.
  - `--no-enable`: escribe los archivos con permisos estrictos pero omite la invocación a `systemctl --user daemon-reload` y `enable --now`.
  - Modo por defecto: instala archivos, valida sintaxis con `systemd-analyze verify`, ejecuta `systemctl --user daemon-reload` y arranca con `systemctl --user enable --now silverwarden.service`.
- **Alternativas:**
  - (a) Proveer solo scripts bash externos fuera del binario CLI. Rechazada: el binario es auto-contenido y conoce su ruta absoluta de ejecución.
- **Evidencia:** `crates/sw-cli/src/main.rs`, tests `test_setup_systemd_dry_run_does_not_write`, `test_setup_systemd_no_enable_writes_files`, `test_setup_systemd_with_enable`.
- **Estado:** Vigente.

## D-M6-18 — Fallback no bloqueante en validación y gestión de systemctl / systemd-analyze

- **Fecha:** 2026-11-01
- **Contexto:** En contenedores, sesiones SSH sin socket de bus de usuario de systemd, o entornos sin systemd (ej. WSL sin soporte nativo o Alpine Linux), las llamadas a `systemd-analyze verify` o `systemctl --user` pueden fallar o no existir.
- **Decisión:** Tratar la validación de sintaxis con `systemd-analyze verify` y las operaciones de `systemctl` como pasos auxiliares no fatales. Si las herramientas no están presentes o fallan, capturar el error/warning e incluirlo en el reporte de salida del CLI sin retornar error `Err(CliError)`.
- **Alternativas:**
  - (a) Abortar la instalación con error si `systemctl` falla. Rechazada: impediría la preparación de configuraciones en chroot o entornos de aprovisionamiento previo al inicio de sesión.
- **Evidencia:** `crates/sw-cli/src/main.rs` (`Commands::SetupSystemd`), tests `test_setup_systemd_missing_systemctl_and_systemd_analyze`, `test_setup_systemd_mock_binaries_warning_and_failure`.
- **Estado:** Vigente.
