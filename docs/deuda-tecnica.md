# Deuda Técnica Conocida

**Proyecto:** silverWarden-rs
**Fecha:** 2026-10-27
**Propósito:** Registrar la deuda técnica conocida, con su impacto, el motivo por el que se pospuso, y cuándo se retomará.

---

## Items Abiertos

### DT-2 — FIDO2 como stub (SW-034)
- **Descripción:** `complete_fido2` devuelve `ApiError::NotImplemented`.
- **Impacto:** Medio. Algunos usuarios usan llaves FIDO2 físicas.
- **Motivo:** Requiere hardware y la crate `ctap-hid-fido2` no está madura. Se pospuso a post-MVP.
- **Retoma:** Post-MVP (si hay demanda).
- **Estado:** Abierta.

### DT-5 — GUI Tauri (M7)
- **Descripción:** La GUI Tauri no está implementada. El proyecto solo tiene CLI.
- **Impacto:** Alto. La visión de "KeePassXC + Vaultwarden" no se cumple sin GUI.
- **Motivo:** M7 está planificado para después de M6.
- **Retoma:** M7.
- **Estado:** Abierta.

### DT-7 — `tokio 1.53.2` con warning de `AsyncFd::new`
- **Descripción:** `cargo audit` reporta `RUSTSEC-2026-0386` (unsound) en `tokio 1.53.2`.
- **Impacto:** Bajo. No usamos `AsyncFd::new` en el MVP.
- **Motivo:** No hay versión parcheada aún.
- **Retoma:** Cuando tokio publique un parche.
- **Estado:** Abierta.

### DT-12 — Comando `silverwarden ssh import/add` en el CLI
- **Descripción:** El agente tiene la lógica IPC implementada (`ImportSSHKey`, `NewSSHKey`), pero el CLI (`sw-cli`) no expone el subcomando para que el usuario pueda importar claves SSH directamente desde la terminal (actualmente solo se puede vía IPC/GUI o `ssh-add`).
- **Impacto:** Bajo (usabilidad de terminal; viable vía `ssh-add` estándar).
- **Motivo:** Prioridad enfocada en paridad del daemon SSH y soporte para GUI en M5.
- **Retoma:** M7 o post-MVP.
- **Estado:** Abierta.

### DT-13 — Normalizar las claves SSH en Vaultwarden
- **Descripción:** En Vaultwarden local funcionó con claves de tipo `SSHKey` (tipo 5), pero en instancias como Disroot se guardaron históricamente como `SecureNote`. Además, Vaultwarden filtra los ciphers tipo 5 si el cliente no reporta `Bitwarden-Client-Version >= 2024.12.0`.
- **Impacto:** Bajo. Mitigado y resuelto con D-M5-3 (soporte dual de tipo 5 y SecureNote) y D49 (`BITWARDEN_CLIENT_VERSION = "2024.12.0"`).
- **Motivo:** Asegurar interoperabilidad tanto con vaults legados como con implementaciones modernas de Vaultwarden.
- **Retoma:** M6/M7.
- **Estado:** Mitigada / Resuelta para Tipo 5 en Vaultwarden moderno (D49).

### DT-14 — Comandos CLI para Notas, Tarjetas e Identidades
- **Descripción:** El agente tiene el modelo (`sw-vault`) y la API (`sw-bitwarden-api`), pero el CLI no tiene subcomandos para crear/leer/borrar estos tipos.
- **Impacto:** Medio (funcionalidades completas de bóveda desde terminal).
- **Motivo:** Se priorizó el flujo crítico de Logins y Claves SSH.
- **Retoma:** M7 (GUI) o post-MVP. Evidencia: `docs/api-fixtures.md`.
- **Estado:** Abierta.

### DT-15 — Validación de contraseñas contra Pwned Passwords
- **Descripción:** La web de Bitwarden valida que las contraseñas no estén filtradas. silverWarden aún no lo hace.
- **Impacto:** Bajo (seguridad preventiva opcional).
- **Motivo:** No bloqueante para el funcionamiento del MVP.
- **Retoma:** Post-MVP. Endpoint documentado en `docs/api-fixtures.md`.
- **Estado:** Abierta.

### DT-16 — Gestión de claves SSH legacy (SecureNote vs SSHKey)
- **Descripción:** El servidor local usa `SSHKey` (tipo 5), pero Disroot usa `SecureNote`. El agente Rust maneja ambos, pero hay que verificar si Vaultwarden requiere el flag `EXPERIMENTAL_CLIENT_FEATURE_FLAGS=ssh-key-vault-item` para exponerlos correctamente a los clientes modernos.
- **Impacto:** Medio (interoperabilidad entre distintos backends y clientes).
- **Motivo:** Bitwarden oficial y Vaultwarden evolucionaron en el soporte nativo de tipo 5.
- **Retoma:** M6/M7.
- **Estado:** Abierta.

### DT-19 — El CLI no consulta `Status` antes de `Unlock` para omitir el prompt de PIN
- **Descripción:** En SW-050 se implementó el PinCache en `sw-agent` y el atajo de cache hit cuando no se envía PIN en el payload de `Unlock`. Sin embargo, `sw-cli` (`silverwarden unlock`) aún solicita interactivamente el PIN por terminal antes de enviar la petición IPC, en lugar de consultar primero la acción `Status` del agente para verificar si `pin_cached: true` y omitir el prompt.
- **Impacto:** Bajo (usabilidad en terminal). El atajo está disponible para clientes IPC (como la futura GUI M7 o llamadas de automatización), pero el CLI aún pide el PIN antes de despachar.
- **Motivo:** Fuera del alcance estricto de SW-050 (enfocado en el subsistema de agente `sw-agent`).
- **Retoma:** M6 (refactorización de comandos de sesión en CLI) o M7.
- **Estado:** Abierta.

### DT-20 — PinCache usa sleep real en tests de TTL (no determinista)
- **Descripción:** En `sw-agent`, los tests de TTL de `PinCache` (`test_pin_cache_expires_after_ttl` y `test_pin_cache_ttl_resets_on_get`) utilizan `tokio::time::sleep` real con duraciones cortas (50-70ms) en lugar de avance virtual del reloj (`tokio::time::pause()` y `advance()`), debido a que `Instant::now()` no es interceptado sin habilitar la feature `test-util` de tokio.
- **Impacto:** Bajo (las pruebas demoran ~200ms en total y pasan de forma consistente en CI local).
- **Motivo:** Evitar añadir dependencias adicionales o feature flags de prueba en crates de producción.
- **Retoma:** M6+ (si se requiere determinismo temporal absoluto, introducir una abstracción `Clock` inyectable).
- **Estado:** Abierta.

### DT-21 — Backend XDG Desktop Portal para notificaciones (pospuesto a post-MVP)
- **Descripción:** En SW-053 se implementó el backend D-Bus estándar (`org.freedesktop.Notifications`). Para compatibilidad con entornos confinados (Flatpak, Snap) donde el acceso al bus de notificaciones directo puede estar restringido por políticas sandbox, se debe añadir el backend de XDG Desktop Portal (`org.freedesktop.portal.Notification`).
- **Impacto:** Bajo para MVP CLI/Daemon local (la inmensa mayoría de distribuciones Linux exponen `org.freedesktop.Notifications` en la sesión de usuario).
- **Motivo:** Evitar dependencias adicionales pesadas (como `ashpd`) o complejidad de IPC en la fase M6.
- **Retoma:** M10 (Portabilidad y Empaquetado).
- **Estado:** Abierta.

### DT-22 — Integración de systemd-logind probada manualmente o ignorada en CI
- **Descripción:** La suscripción a señales D-Bus de `systemd-logind` (`PrepareForSleep`, `Lock`) se prueba unitariamente a nivel de lógica en `handle_logind_event` y con `spawn_idle_monitor`, pero la prueba de integración contra el bus de sistema D-Bus real (`tests/manual_logind.rs`) está marcada con `#[ignore]` para evitar fallos en entornos CI headless o contenedores donde no corre `systemd-logind`.
- **Impacto:** Bajo. La lógica de bloqueo, limpieza de caché y notificaciones está cubierta al 100% en tests unitarios.
- **Motivo:** Ausencia del bus de sistema de `systemd-logind` en runners CI estándar.
- **Retoma:** M10 (CI e2e con contenedor o VM con bus de sistema activo).
- **Estado:** Abierta.

### DT-24 — Tests manuales D-Bus (`manual_polkit.rs` y `manual_logind.rs`) requieren bus real (no CI)
- **Descripción:** Los tests de integración con servicios del sistema (`manual_polkit.rs` para Polkit y `manual_logind.rs` para systemd-logind) requieren un bus D-Bus de sistema y de sesión activo y permisos de interacción. En entornos CI headless o contenedores estándar, estas pruebas deben mantenerse marcadas con `#[ignore]`.
- **Impacto:** Bajo. La lógica funcional está 100% cubierta con mocks unitarios en memoria.
- **Motivo:** Aislamiento de infraestructura en entornos de integración continua automatizados.
- **Retoma:** M10 (Infraestructura de CI con VM o bus simulado).
- **Estado:** Abierta.

### DT-25 — Manejo de 2FA en Vaultwarden (TOTP) verificado, Email pendiente
- **Descripción:** El flujo de 2FA con TOTP ha sido verificado contra Disroot. El flujo de 2FA con Email (provider 1) está implementado pero no se ha probado end-to-end contra Disroot.
- **Impacto:** Bajo. TOTP cubre el caso de uso principal.
- **Motivo:** El usuario tiene configurado TOTP como método principal.
- **Retoma:** M7 o cuando se requiera.
- **Estado:** Abierta.

### DT-26 — Listado unificado y paginado por tipo en el CLI
- **Descripción:** El comando `logins list` solo muestra logins, ocultando notas, tarjetas y claves SSH. Para usuarios con bóvedas grandes (ej. Disroot con 274 logins), la salida puede inundar la terminal sin paginación.
- **Impacto:** Medio (UX).
- **Motivo:** Prioridad en el MVP para gestión de logins. El resto de tipos se accede vía SSH agent o API.
- **Retoma:** M7 (junto con la GUI). Implementar `silverwarden list --type <logins|notes|cards|identities|ssh-keys>` con paginación (`--limit`, `--page`).
- **Estado:** Abierta.

### DT-33 — `impl From<String> for AgentError` con `contains()` (antipatrón P4)
- **Descripción:** La conversión `From<String>` para `AgentError` inspecciona subcadenas con `.contains()` para deducir variantes de error tipadas (`InvalidPin`, `Locked`), violando el principio P4 (errores como datos, no strings).
- **Impacto:** Bajo/Medio (fragilidad en la taxonomía de errores del daemon).
- **Motivo:** Facilita la transición gradual mientras los handlers aún retornan strings en ciertas rutas internas.
- **Retoma:** Fase 3.1.4 del plan de cierre arquitectónico (contrato completamente tipado en handlers).
- **Estado:** Abierta.

### DT-34 — `dispatch_request` construye `serde_json::json!` para pasar a handlers
- **Descripción:** `AgentDaemon::dispatch_request` desempaqueta variantes del enum tipado `Request` y reconstruye objetos `serde_json::Value` sueltos (`json!({...})`) para invocarlos en los handlers del registry, en lugar de pasar directamente los structs tipados.
- **Impacto:** Medio (degradación temporal de tipado en la frontera interna de la aplicación).
- **Motivo:** Permitir el desacoplamiento progresivo sin reescribir simultáneamente las 19 funciones de manejo.
- **Retoma:** Fase 3.1.4 del plan de cierre arquitectónico.
- **Estado:** Abierta.

### DT-35 — `tokio::runtime::Handle::try_current()` en constructor síncrono de `AgentDaemon`
- **Descripción:** `AgentDaemon::new()` es una función síncrona que intenta obtener el runtime asíncrono actual mediante `tokio::runtime::Handle::try_current()` para tareas en background, en lugar de recibir explícitamente el handle o estructurarse como un constructor asíncrono o inyectado.
- **Impacto:** Bajo (puede fallar si se instancia fuera de un runtime activo de Tokio).
- **Motivo:** Conveniencia para entrypoints existentes en el CLI y daemon.
- **Retoma:** Fase 1.3 del plan de cierre arquitectónico.
- **Estado:** Abierta.

### DT-36 — `impl Clone for AsymmetricKey` con `expect` en ruta de producción
- **Descripción:** La implementación manual de `Clone` para `AsymmetricKey` usa `expect("AsymmetricKey clone must succeed")` como fallback cuando `try_clone()` falla. Esto puede panickar en producción si `mlock` no está disponible (contenedores, entornos restringidos) y el re-parseo también falla.
- **Impacto:** Bajo (el camino feliz funciona y hay fallback), pero viola P9 ("Cero `unwrap()` en rutas de producción").
- **Motivo:** Compatibilidad con código existente que espera `Clone` (por ejemplo, `Keyring` o `VaultStore` clonan claves).
- **Retoma:** Tarea de refactor de `AsymmetricKey` (post-M7), sustituyendo `impl Clone` por `try_clone() -> Result` y propagando el error a los consumidores.
- **Estado:** Abierta.

### DT-37 — `impl Clone for SymmetricKey` con `expect` en ruta de producción
- **Descripción:** La implementación manual de `Clone` para `SymmetricKey` usa `expect("SymmetricKey clone must succeed")` como fallback cuando `try_clone()` falla. Esto puede panickar en producción si `mlock` no está disponible (contenedores, entornos restringidos) y el re-parseo también falla.
- **Impacto:** Bajo (el camino feliz funciona y hay fallback), pero viola P9 ("Cero `unwrap()` en rutas de producción").
- **Motivo:** Compatibilidad con código existente que espera `Clone` (por ejemplo, `Keyring`, `VaultStore` o `sw-agent` clonan claves simétricas).
- **Retoma:** Tarea de refactor de `SymmetricKey` (post-M7), sustituyendo `impl Clone` por `try_clone() -> Result` y propagando el error a los consumidores.
- **Estado:** Abierta.

### DT-38 — Lógica duplicada de resolución de `cipher.key` en `sw-vault`
- **Descripción:** La lógica para descifrar `cipher.key` (clave de organización) y usarla para descifrar los campos del cipher está duplicada 3 veces en `sw-vault/src/lib.rs` (en `get_login_by_filter`, `search`, y `decrypt_cipher`). Viola DRY y P6 (una sola razón de cambio).
- **Impacto:** Bajo (funciona, pero es frágil ante cambios futuros).
- **Motivo:** Implementación incremental para resolver el bug de las Organizaciones (los 274 logins de Disroot) sin refactorizar los 3 sitios a la vez.
- **Retoma:** Fase 3.1.4 del plan de cierre (handlers tipados) o tarea de refactor de `sw-vault` (post-M7). Extraer `fn resolve_cipher_key(cipher: &Cipher, user_key: &SymmetricKey) -> Option<SymmetricKey>`.
- **Estado:** Abierta.

### DT-39 — Tests de `sw-cli` dependen de `$HOME` y usan `ENV_MUTEX` global
- **Descripción:** Varios tests de `sw-cli` (`test_resolve_socket_path`, `test_check_goldwarden_go_conflict`, `test_setup_systemd_missing_home`, etc.) leen o modifican `$HOME` y se serializan con un `ENV_MUTEX` global. Esto viola P8 ("Nunca escribe en `$HOME`... Nunca depende del entorno") y es frágil: si un test futuro toca `$HOME` sin el lock, la condición de carrera vuelve (ver el fallo de `test_resolve_socket_path` en la sesión de commits del plan de cierre).
- **Impacto:** Medio (tests frágiles, no deterministas).
- **Motivo:** El refactor para inyectar `$HOME` como parámetro (como el `Clock`) es grande y afecta a muchos tests.
- **Retoma:** Tarea de refactor de tests de `sw-cli` (post-M7). Extraer `$HOME` a un parámetro inyectable (`HomeDir` trait o similar) y eliminar el `ENV_MUTEX`.
- **Estado:** Abierta.

---

## Items Cerrados (Histórico)

### DT-27 — Correcciones de sintaxis en scripts de smoke test
- **Descripción:** El script original del smoke test usaba `--name` para `logins delete` (debería ser posicional) y `ssh-keygen -Y sign` apuntaba incorrectamente al archivo de texto en lugar de la clave.
- **Impacto:** Bajo (documentación).
- **Motivo:** Errores de redacción en el documento de pruebas, no en el código del CLI.
- **Retoma:** Inmediato (corregido en la Acción 2 de esta tarea).
- **Estado:** Cerrada.

### DT-8 — `sw-notify` como stub
- **Descripción:** El crate `sw-notify` no tenía implementación real.
- **Resolución:** En SW-053 se implementó el backend D-Bus Notifications (`org.freedesktop.Notifications`) con fallback silencioso e inyección en `sw-agent`.
- **Estado:** Cerrada (SW-053).

### DT-9 — Lock por inactividad no implementado
- **Descripción:** El agente no bloqueaba el vault automáticamente por inactividad ni al suspender o bloquear pantalla.
- **Resolución:** En SW-052 se implementó el contador de inactividad configurable (`RuntimeConfig.idle_ttl_secs`), el monitoreo de señales `PrepareForSleep` y `Lock` de `systemd-logind`, y el bloqueo con limpieza de sesiones y PinCache.
- **Estado:** Cerrada (SW-052).

### DT-10 — Biometría (polkit) no implementada
- **Descripción:** El agente no contaba con desbloqueo biométrico.
- **Resolución:** En SW-051 se implementó el trait `Biometrics`, el backend `PolkitBiometrics` con paso de `CallingContext` (PID + start-time), y el desbloqueo alternativo condicionado al `PinCache`.
- **Estado:** Cerrada (SW-051).

### DT-11 — Setup systemd no implementado
- **Descripción:** El agente no arrancaba automáticamente al login del usuario y requería configuración manual.
- **Resolución:** En SW-054 se añadió la plantilla `silverwarden.service` para `systemd --user`, la política Polkit `org.silverwarden.unlock.policy`, y el subcomando `silverwarden setup-systemd` con flags `--dry-run` y `--no-enable`.
- **Estado:** Cerrada (SW-054).

### DT-23 — Política de acción Polkit `org.silverwarden.unlock` no instalada en el sistema
- **Descripción:** En SW-051 se utilizaba el action ID placeholder `org.freedesktop.policykit.exec`.
- **Resolución:** En SW-054 se añadió la plantilla canónica `POLKIT_POLICY_TEMPLATE`, se actualizó `sw-systemauth` para usar `"org.silverwarden.unlock"`, y se implementó `silverwarden setup-systemd` para instalar el archivo de política en `~/.local/share/polkit-1/actions/org.silverwarden.unlock.policy`.
- **Estado:** Cerrada (SW-054).

### DT-1 — Bypass de aprobación por variable de entorno (SW-043)
- **Estado:** Cerrada (commit `2aa6e36`). Movido a `#[cfg(test)]`.

### DT-3 — Add/Remove del protocolo SSH agent (SW-044)
- **Estado:** Cerrada (commit `5be5e24`). Implementado `ADD_IDENTITY`, `ADD_ID_CONSTRAINED`, `REMOVE_IDENTITY`, `REMOVE_ALL_IDENTITIES`.

### DT-4 — Acciones IPC para la GUI (SW-045)
- **Estado:** Cerrada (commit `859179e`). Implementado `ListSSHKeys`, `ImportSSHKey`, `NewSSHKey`, `DeleteSSHKey`.

### DT-6 — Cobertura de `sw-ssh-agent` (87.48%)
- **Estado:** Cerrada (commits `bcf8252` y `5be5e24`). Cobertura ahora 94.49% (SW-046).

### DT-18 — Cobertura de producción pura en `sw-cli` y `sw-agent`
- **Descripción:** La cobertura inicial reportada incluía líneas de `mod tests` en el denominador, dejando dudas sobre el porcentaje real de código de producción.
- **Resolución:** Medición exhaustiva línea a línea y ampliación de tests. En `sw-cli`, las líneas de producción 1-1259 alcanzaron un **95.97%** (786/819 evaluables). En `sw-agent`, las líneas de producción 1-1383 alcanzaron un **92.46%** (932/1008 evaluables). Ambas superan holgadamente el umbral de calidad ≥90%. A futuro en refactorizaciones mayores se evaluará separar módulos de tests a archivos externos para facilitar la exclusión automática de herramientas.
- **Estado:** Cerrada (validado empíricamente, ver `docs/04-validacion.md` §9.8 y decisión D51).

