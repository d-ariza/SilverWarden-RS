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

### DT-18 — Cobertura de producción pura en `sw-cli` no medida

- **Descripción:** La cobertura de `sw-cli` reportada por `cargo llvm-cov -p sw-cli --summary-only` es **85.19% de líneas**, pero incluye las líneas del módulo `mod tests` (que viven en `main.rs`) en el denominador. Al añadir 1815 líneas de tests en el commit `0eefb93`, el porcentaje subió parcialmente por artefacto del denominador. La cobertura de "producción pura" (excluyendo tests) **no se ha medido** y se estima inferior al 85%.
- **Impacto:** Medio (metodológico). El gate del proyecto se cumple según la métrica estándar, pero la métrica es vulnerable a gaming.
- **Motivo:** Los tests viven en `main.rs` por simplicidad. `cargo llvm-cov --ignore-filename-regex` no permite excluir módulos dentro de un archivo (el regex se aplica al nombre de archivo, no al contenido).
- **Retoma:** M6. Opciones a evaluar: (a) mover tests a `tests/` (integración) y `src/tests.rs` (unitarios con `#[path]`) y usar `--ignore-filename-regex`; (b) usar `#[cfg_attr(coverage, coverage(off))]` en `mod tests` (requiere feature `coverage`); (c) adoptar `tarpaulin --ignore-tests`. Validar que la cobertura de producción pura ≥85% antes de cerrar M6.
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

