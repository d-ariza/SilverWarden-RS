# Deuda Técnica Conocida

**Proyecto:** silverWarden-rs
**Fecha:** 2026-10-27
**Última auditoría:** 2026-11-13
**Propósito:** Registrar la deuda técnica conocida, con su impacto, el motivo por el que se pospuso, y cuándo se retomará.

---

## Auditoría 2026-11-13

Verificación contra el código real, no contra la memoria del documento. Cada fila
tiene la evidencia que la respalda.

| DT | Estado verificado | Evidencia | Disposición |
|---|---|---|---|
| DT-2 | Abierta | `sw-bitwarden-api/src/twofactor.rs:164` devuelve `NotImplemented` | Fuera de alcance (post-MVP) |
| DT-5 | **Parcial** | GUI con 4 rutas (`login`, `setup`, `vault`, inicio); comandos Tauri tipados (`get_agent_status`, `list_logins`, `get_login`, `sync_vault`, `list_ssh_keys`, `pin_set`, `pin_update`, `get_config`, `set_config`) y DTOs `ts-rs` listos (§3.1–§3.3) | Fase 3 (§3.4–§3.6 para gateway, FSM y vistas) |
| DT-7 | **Cerrada** | `tokio 1.54.1`; `cargo audit` sin RUSTSEC-2026-0386 | Cerrada el 2026-11-14 (`cargo update`) |
| DT-12 | **Cerrada** | `sw-cli/src/commands/ssh.rs` despacha `ListSshKeys`, `ImportSshKey` y `NewSshKey` por IPC | Cerrada el 2026-11-14 |
| DT-13 | **Cerrada** | Soporte dual `SSHKey`/`SecureNote` + `BITWARDEN_CLIENT_VERSION = "2024.12.0"` (D-M5-3, D49) | Resuelta para Tipo 5 y legacy |
| DT-14 | Abierta | `Commands` no tiene notas/tarjetas/identidades | Fuera de alcance |
| DT-15 | Abierta | `rg "pwned\|HIBP"` → 0 resultados | Fuera de alcance |
| DT-16 | Mitigada | `SSHKeyCipher` y `SecureNoteCipher` conviven en `sw-vault` | Se mantiene |
| DT-19 | **Cerrada** | `sw-cli/src/commands/unlock.rs` consulta `Status` (`pin_cached`) antes de pedir PIN | Cerrada el 2026-11-14 |
| DT-20 | **Cerrada** | Tests de TTL usan `FakeClock` + `advance` (`sw-agent/src/tests.rs:2594`) | Cerrada por 1.1.4 |
| DT-21 | Abierta | `rg "portal.Notification\|ashpd"` → 0 resultados | Fuera de alcance |
| DT-22 | Abierta (diseño) | `sw-agent/tests/manual_logind.rs` con `#[ignore]` | Fuera de alcance (CI) |
| DT-24 | Abierta (diseño) | `manual_polkit.rs`, `manual_logind.rs`, `manual_dbus.rs` ignorados | Fuera de alcance (CI) |
| DT-25 | Abierta | `TwoFactorProvider::Email` existe; sin E2E | Fuera de alcance |
| DT-26 | Abierta | No hay `list --type` ni paginación | Fuera de alcance |
| DT-33 | **Cerrada** | Eliminados `From<String>` / `From<&str>` para `AgentError`; `rg "From<String> for AgentError\|From<&str> for AgentError" crates/sw-agent` → `0` | Cerrada el 2026-11-14 (Fase 3.1.4) |
| DT-34 | **Cerrada** | Eliminado todo `serde_json::json!` en `handlers/` y `dispatch_request`; `rg "serde_json::json!" crates/sw-agent/src/handlers crates/sw-agent/src/lib.rs` → `0` | Cerrada el 2026-11-14 (Fase 3.1.4) |
| DT-35 | **Cerrada** | `AgentDaemon::with_vault_agent` usa `VaultStore::try_load_sync_data`; `rg "try_current"` → 0 | Cerrada el 2026-11-14 |
| DT-36 | Abierta | `sw-crypto/src/asymmetric.rs:69` usa `expect` | Post-M7 |
| DT-37 | Abierta | `sw-crypto/src/keyhierarchy.rs:95` usa `expect` | Post-M7 |
| DT-38 | **Cerrada** | `VaultStore::resolve_cipher_key` en `crates/sw-vault/src/decrypt.rs` (**1** ocurrencia en producción) | Cerrada en Fase 2 (post-2.2.2) |
| DT-39 | Abierta | 13 usos de `HOME` + `ENV_MUTEX`/`ASYNC_ENV_MUTEX` en `sw-cli/src/tests.rs` | Post-M7 |
| DT-40 | **Cerrada** | `rustix 1.1.6`; `cargo audit` sin RUSTSEC-2026-0486 | Cerrada el 2026-11-14 (`cargo update`) |
| DT-41 | **Cerrada** | `async-executor 1.14.1` (sin versión *yanked*) | Cerrada el 2026-11-14 (`cargo update`) |
| DT-42 | **Cerrada** | 11 dependencias declaradas sin uso (2 de workspace + 9 de crate) | Eliminadas el 2026-11-14 |

**Lectura de conjunto:**

- **13 fichas** en "Items Abiertos": 1 mitigada (`DT-16`), 1 parcial (`DT-5`) y 11 abiertas (`DT-2`, `DT-14`, `DT-15`, `DT-21`, `DT-22`, `DT-24`, `DT-25`, `DT-26`, `DT-36`, `DT-37`, `DT-39`).
- **23 fichas** en "Items Cerrados (Histórico)": 12 previas + 9 cerradas tras Fase 2 (`DT-7`, `DT-12`, `DT-13`, `DT-19`, `DT-35`, `DT-38`, `DT-40`, `DT-41`, `DT-42`) + 2 cerradas en Fase 3.1.4 (`DT-33`, `DT-34`).
- **DT-20 ya se cerró** con el puerto `Clock` de 1.1.4; su ficha vive ahora en el histórico.
- **DT-33 y DT-34 cerradas (Fase 3.1.4)**: se eliminaron `From<String>`/`From<&str>` para `AgentError` y las llamadas `serde_json::json!` en `crates/sw-agent/src/handlers/` y `dispatch_request` usando DTOs tipados de `sw-ipc::dto`.
- **DT-35 y DT-38 cerradas**: `VaultStore::try_load_sync_data` eliminó el último `try_current()` en `AgentDaemon::with_vault_agent`, y `VaultStore::resolve_cipher_key` consolidó las 5 copias de `cipher.key`.
- **DT-7, DT-40 y DT-41 cerradas**: `tokio 1.54.1`, `rustix 1.1.6` y `async-executor 1.14.1` actualizados; `cargo audit` reporta 0 vulnerabilidades y 0 avisos sobre 468 dependencias.
- **DT-12 cerrada**: `sw-cli/src/commands/ssh.rs` despacha `Request::ListSshKeys`, `Request::ImportSshKey` y `Request::NewSshKey` por IPC al agente.

---

## Items Abiertos

### DT-2 — FIDO2 como stub (SW-034)
- **Descripción:** `complete_fido2` devuelve `ApiError::NotImplemented`.
- **Impacto:** Medio. Algunos usuarios usan llaves FIDO2 físicas.
- **Motivo:** Requiere hardware y la crate `ctap-hid-fido2` no está madura. Se pospuso a post-MVP.
- **Retoma:** Post-MVP (si hay demanda).
- **Estado:** Abierta.

### DT-5 — GUI Tauri (M7)
- **Descripción:** La GUI Tauri existe parcialmente: `crates/sw-gui` tiene 4 rutas (`/`, `login`, `setup`, `vault`). En Fase 3a (§3.1–§3.3) se tipó el contrato IPC (`sw-ipc::dto`), se generaron los tipos TypeScript con `ts-rs` (`crates/sw-gui/src/lib/types/generated/`) y se tiparon/añadieron todos los comandos Tauri (`get_agent_status`, `list_logins`, `get_login`, `sync_vault`, `list_ssh_keys`, `pin_set`, `pin_update`, `get_config`, `set_config`). Quedan pendientes el gateway TypeScript, la FSM en Svelte y las vistas nuevas.
- **Impacto:** Medio. La visión de "KeePassXC + Vaultwarden" ya es demostrable; falta paridad con el CLI.
- **Motivo:** M7 se ejecutó a medias; el resto está planificado en la fase 3 del plan de cierre.
- **Retoma:** Fase 3 del plan de cierre (`docs/05-plan-cierre.md` §3.4–§3.6).
- **Estado:** Parcial (backend IPC + `ts-rs` + comandos Tauri completados en §3.1–§3.3; UI pendiente en §3.4–§3.6).

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

### DT-39 — Tests de `sw-cli` dependen de `$HOME` y usan `ENV_MUTEX` global
- **Descripción:** Varios tests de `sw-cli` (`test_resolve_socket_path`, `test_check_goldwarden_go_conflict`, `test_setup_systemd_missing_home`, etc.) leen o modifican `$HOME` y se serializan con un `ENV_MUTEX` global. Esto viola P8 ("Nunca escribe en `$HOME`... Nunca depende del entorno") y es frágil: si un test futuro toca `$HOME` sin el lock, la condición de carrera vuelve (ver el fallo de `test_resolve_socket_path` en la sesión de commits del plan de cierre).
- **Impacto:** Medio (tests frágiles, no deterministas).
- **Motivo:** El refactor para inyectar `$HOME` como parámetro (como el `Clock`) es grande y afecta a muchos tests.
- **Retoma:** Tarea de refactor de tests de `sw-cli` (post-M7). Extraer `$HOME` a un parámetro inyectable (`HomeDir` trait o similar) y eliminar el `ENV_MUTEX`.
- **Estado:** Abierta.

---

## Items Cerrados (Histórico)

### DT-33 — `impl From<String> for AgentError` con `contains()` (antipatrón P4)
- **Descripción:** Las conversiones `From<String>` y `From<&str>` para `AgentError` en `crates/sw-agent/src/lib.rs` inspeccionaban subcadenas con `.contains()` para inferir `InvalidPin` o `Locked`.
- **Resolución:** Eliminados `impl From<String> for AgentError` e `impl From<&str> for AgentError` en `crates/sw-agent/src/lib.rs` el 2026-11-14 (Fase 3.1.4); los errores ahora se construyen y propagan directamente como variantes tipadas de `AgentError`.
- **Evidencia:** `rg -c "From<String> for AgentError|From<&str> for AgentError" crates/sw-agent` → `0`.
- **Estado:** Cerrada en el árbol de trabajo (Fase 3.1.4, 2026-11-14).

### DT-34 — `dispatch_request` construye `serde_json::json!` para pasar a handlers
- **Descripción:** `AgentDaemon::dispatch_request` desempaquetaba variantes tipadas de `Request` y reconstruía `serde_json::json!({...})` para invocar los handlers por texto, devolviendo `serde_json::Value`.
- **Resolución:** En Fase 3.1.4 (2026-11-14), los handlers devuelven DTOs tipados de `sw-ipc::dto` (`AgentStatus`, `Vec<LoginSummary>`, `LoginDetail`, `SyncResult`, `Vec<SshKeySummary>`, `ConfigView`, `PinChangeResult`, `OperationAck`) y `dispatch_request` invoca directamente los entrypoints tipados sin usar `serde_json::json!`.
- **Evidencia:** `rg -c "serde_json::json!" crates/sw-agent/src/handlers crates/sw-agent/src/lib.rs` → `0`.
- **Estado:** Cerrada en el árbol de trabajo (Fase 3.1.4, 2026-11-14).

### DT-7 — `tokio 1.53.2` con warning de `AsyncFd::new` (`RUSTSEC-2026-0386`)
- **Descripción:** `cargo audit` reportaba `RUSTSEC-2026-0386` (unsound) en `tokio 1.53.2`.
- **Resolución:** Actualizado a `tokio 1.54.1` en `Cargo.lock` el 2026-11-14 (`cargo update -p tokio -p rustix@1.1.5 -p async-executor`).
- **Evidencia:** `cargo audit` (1509 advisories, 468 dependencias) → `0` vulnerabilidades, `0` avisos.
- **Estado:** Cerrada en el árbol de trabajo (2026-11-14).

### DT-12 — Comando `silverwarden ssh list/add` en el CLI
- **Descripción:** `crates/sw-cli/src/commands/ssh.rs` era un stub que imprimía texto sin conectar al agente por IPC.
- **Resolución:** Conectado a `AgentClient` el 2026-11-14: `ssh list` envía `Request::ListSshKeys`, `ssh add <ruta-pem>` lee el archivo y envía `Request::ImportSshKey`, y `ssh add <nombre>` envía `Request::NewSshKey` (`Ed25519`), validando cadenas vacías localmente antes de resolver el socket.
- **Evidencia:** `crates/sw-cli/src/commands/ssh.rs`; `test_handle_command_local_subcommands` y `test_ssh_subcommands` en `crates/sw-cli/src/tests.rs` + `test_cli_local_commands` en `crates/sw-cli/tests/integration.rs` usando sockets mock en `tempdir`.
- **Estado:** Cerrada en el árbol de trabajo (2026-11-14).

### DT-13 — Normalizar las claves SSH en Vaultwarden
- **Descripción:** En Vaultwarden local funcionó con claves de tipo `SSHKey` (tipo 5), pero en Disroot se guardaron históricamente como `SecureNote`. Además, Vaultwarden filtra los ciphers tipo 5 si el cliente no reporta `Bitwarden-Client-Version >= 2024.12.0`.
- **Resolución:** Resuelta mediante el soporte dual de `SSHKey` (tipo 5) y `SecureNote` (`D-M5-3`) junto con `BITWARDEN_CLIENT_VERSION = "2024.12.0"` (`D49`).
- **Estado:** Cerrada (validada por D-M5-3 y D49).

### DT-19 — El CLI consulta `Status` antes de `Unlock` para omitir el prompt de PIN
- **Descripción:** `crates/sw-cli/src/commands/unlock.rs` pedía el PIN interactivamente cuando no se pasaba `--pin`, sin consultar primero el estado del caché del agente.
- **Resolución:** Cuando `pin` es `None`, `commands/unlock.rs` consulta `Request::Status` y verifica `pin_cached`: si es `true`, envía `Request::Unlock { pin: None }` sin invocar el prompt; si es `false`, solicita el PIN interactivo y usa `call_ok` para propagar errores del agente.
- **Evidencia:** `crates/sw-cli/src/commands/unlock.rs`; `test_handle_command_unlock_with_pin_and_interactive` (`sw-cli/src/tests.rs`) + `test_cli_unlock_with_mock_agent` y `test_cli_unlock_agent_error` (`sw-cli/tests/integration.rs`).
- **Estado:** Cerrada en el árbol de trabajo (2026-11-14).

### DT-35 — `tokio::runtime::Handle::try_current()` en constructor síncrono de `AgentDaemon`
- **Descripción:** `AgentDaemon::with_vault_agent` en `crates/sw-agent/src/lib.rs` usaba `tokio::runtime::Handle::try_current()` para lanzar `load_sync_data` en segundo plano si encontraba `vault.json`.
- **Resolución:** Extraído el helper compartido `VaultStore::apply_sync_data` y añadido `VaultStore::try_load_sync_data(&self, SyncData) -> bool` en `crates/sw-vault/src/store.rs` usando `try_write()` no bloqueante; `AgentDaemon::with_vault_agent` carga `vault.json` de forma síncrona y determinista sin consultar el runtime de Tokio.
- **Evidencia:** `rg -n "try_current" crates --glob '!target'` → `0` coincidencias; tests de `sw-vault` (`41 passed`, incluyendo `try_load_sync_data` fuera de runtime y bajo contención) y `sw-agent` (`77 passed`, `+2` manuales ignorados); `./scripts/check-file-size.sh` (`crates/sw-agent/src/lib.rs` en `761` líneas, `0` violaciones).
- **Estado:** Cerrada en el árbol de trabajo (2026-11-14).

### DT-40 — `rustix 1.1.5` con `RUSTSEC-2026-0486`
- **Descripción:** `cargo audit` reportaba `RUSTSEC-2026-0486` (unsound en `xattr` con buffer vacío) en `rustix 1.1.5`.
- **Resolución:** Actualizado a `rustix 1.1.6` en `Cargo.lock` el 2026-11-14 (`cargo update -p tokio -p rustix@1.1.5 -p async-executor`).
- **Evidencia:** `cargo audit` → `0` vulnerabilidades, `0` avisos.
- **Estado:** Cerrada en el árbol de trabajo (2026-11-14).

### DT-41 — `async-executor 1.14.0` yanked
- **Descripción:** `cargo audit` marcaba `async-executor 1.14.0` como *yanked* en crates.io.
- **Resolución:** Actualizado a `async-executor 1.14.1` en `Cargo.lock` el 2026-11-14 (`cargo update -p tokio -p rustix@1.1.5 -p async-executor`).
- **Evidencia:** `cargo audit` → `0` vulnerabilidades, `0` avisos (`cargo test --workspace --exclude sw-gui` → `508 passed, 0 failed, 5 ignored`; `cargo clippy --workspace --exclude sw-gui --all-targets -- -D warnings` → exit `0`; `cargo check --manifest-path crates/sw-gui/src-tauri/Cargo.toml` → exit `0`; `cargo fmt --all -- --check` → exit `0`).
- **Estado:** Cerrada en el árbol de trabajo (2026-11-14).

### DT-38 — Lógica duplicada de resolución de `cipher.key` en `sw-vault`
- **Descripción:** La lógica para descifrar `cipher.key` (clave de organización) y usarla para descifrar campos del cipher estuvo duplicada **5 veces** en producción (originalmente en `sw-vault/src/lib.rs`, trasladada sin cambios de comportamiento a `crates/sw-vault/src/decrypt.rs` durante el split `2.2.2`).
- **Resolución:** Consolidada el 2026-11-14 en `VaultStore::resolve_cipher_key(cipher: &Cipher, user_key: &SymmetricKey) -> Option<SymmetricKey>` dentro de `crates/sw-vault/src/decrypt.rs`, sustituyendo los 5 sitios duplicados (`filter_logins`, `filter_notes`, `decrypt_cipher`, `extract_ssh_key_ciphers`, `extract_legacy_ssh_notes`).
- **Evidencia:** `rg -n "cipher\.key" crates/sw-vault/src --glob '!tests.rs'` → **1 sola ocurrencia** (`decrypt.rs:13`); `crates/sw-vault/src/decrypt.rs` baja a `402` líneas; `./scripts/check-file-size.sh` → OK (`violaciones: 0`); `cargo test -p sw-vault -p sw-agent -p sw-vault-agent` → `41 passed` (`sw-vault`, incluidos 11 `caracterizacion_*`), `77 passed` (`sw-agent`, +2 manuales ignorados) y `23 passed` (`sw-vault-agent`); `cargo clippy -p sw-vault --all-targets -- -D warnings` y `cargo fmt --all -- --check` → exit `0`.
- **Estado:** Cerrada en el árbol de trabajo (Fase 2, 2026-11-14).

### DT-42 — Dependencias declaradas sin uso (11)
- **Descripción:** `cargo check --workspace --all-targets` reportaba 11 dependencias declaradas y no usadas:
  - workspace: `sw-autotype`, `sw-browserbiometrics`, `anyhow`, `ssh-key`;
  - `sw-autotype`: `tracing`;
  - `sw-browserbiometrics`: `serde`, `serde_json`, `tokio`;
  - `sw-cli`: `anyhow`;
  - `sw-config`: `sw-crypto`;
  - `sw-crypto`: `chacha20poly1305`, `sha3`;
  - `sw-ssh-agent`: `ssh-key`.
- **Resolución:** eliminadas de los `Cargo.toml` correspondientes el 2026-11-14. `ssh-key` se sigue usando a través de `russh::keys::ssh_key`, no como dependencia directa.
- **Evidencia:** `cargo check --workspace --all-targets` → 0 warnings; `cargo clippy --workspace --all-targets -- -D warnings` → 0 warnings; `cargo test --workspace` → 489 passed, 0 failed.
- **Estado:** Cerrada en el árbol de trabajo (pendiente de commit).

### DT-20 — PinCache usaba sleep real en tests de TTL (no determinista)
- **Descripción:** En `sw-agent`, los tests de TTL de `PinCache` usaban `tokio::time::sleep` real (50-70 ms) en lugar de avance virtual del reloj.
- **Resolución:** El puerto `Clock` (fase 1.1.1–1.1.4) permite inyectar `FakeClock` y avanzar el tiempo sin dormir. Los tests de TTL son deterministas (`sw-agent/src/tests.rs:2594`).
- **Estado:** Cerrada (1.1.4, `FakeClock`).

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

