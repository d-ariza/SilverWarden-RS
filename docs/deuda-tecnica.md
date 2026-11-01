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

### DT-8 — `sw-notify` como stub
- **Descripción:** El crate `sw-notify` no tiene implementación real. Las notificaciones del agente SSH (firma exitosa) no se muestran al usuario.
- **Impacto:** Bajo (funcionalidad, no seguridad).
- **Motivo:** Se pospuso a M6 (SW-053).
- **Retoma:** M6.
- **Estado:** Abierta.

### DT-9 — Lock por inactividad no implementado
- **Descripción:** El agente no bloquea el vault automáticamente si el sistema está inactivo.
- **Impacto:** Medio. Un usuario que deja la sesión abierta podría tener el vault expuesto.
- **Motivo:** Se pospuso a M6 (SW-052).
- **Retoma:** M6.
- **Estado:** Abierta.

### DT-10 — Biometría (polkit) no implementada
- **Descripción:** El agente no usa biometría para desbloquear el vault.
- **Impacto:** Medio. La experiencia de usuario es peor (hay que escribir el PIN siempre).
- **Motivo:** Se pospuso a M6 (SW-051).
- **Retoma:** M6.
- **Estado:** Abierta.

### DT-11 — Setup systemd no implementado
- **Descripción:** El agente no se arranca automáticamente al login del usuario.
- **Impacto:** Bajo (usabilidad).
- **Motivo:** Se pospuso a M6 (SW-054).
- **Retoma:** M6.
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

---

## Items Cerrados (Histórico)

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

