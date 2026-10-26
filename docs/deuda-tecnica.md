# Deuda Técnica Conocida

**Proyecto:** silverWarden-rs
**Fecha:** 2026-10-26
**Propósito:** Registrar la deuda técnica conocida, con su impacto, el motivo por el que se pospuso, y cuándo se retomará. Esto evita que la deuda se olvide y se convierta en un problema mayor.

---

## Formato

Cada item de deuda se registra con:
- **ID:** DT-NNN (secuencial).
- **Descripción:** qué falta o qué está mal.
- **Impacto:** qué riesgo implica.
- **Motivo:** por qué se pospuso.
- **Retoma:** cuándo se retomará (milestone, post-MVP, v2).
- **Estado:** Abierta / En progreso / Cerrada.

---

## DT-1 — Bypass de aprobación por variable de entorno (SW-043)

- **Descripción:** `DefaultApprovalProvider` en `sw-ssh-agent` tiene un bypass mediante `SILVERWARDEN_SYSTEM_AUTH_DISABLED` y `GOLDWARDEN_SYSTEM_AUTH_DISABLED`. Si alguien deja esa variable activa en producción, el agente firma sin pedir aprobación.
- **Impacto:** Alto (riesgo de seguridad).
- **Motivo:** se implementó para los tests, pero no se aisló a `#[cfg(test)]`.
- **Retoma:** inmediato (antes de cerrar M5).
- **Estado:** Abierta.

## DT-2 — FIDO2 como stub (SW-034)

- **Descripción:** `complete_fido2` devuelve `ApiError::NotImplemented`. El flujo de FIDO2 no está implementado.
- **Impacto:** Medio (algunos usuarios usan llaves FIDO2).
- **Motivo:** requiere hardware y la crate `ctap-hid-fido2` no está madura. Se pospuso a post-MVP.
- **Retoma:** post-MVP (si hay demanda).
- **Estado:** Abierta.

## DT-3 — Add/Remove del protocolo SSH agent (SW-044)

- **Descripción:** `handle_connection` soportaba solo List y Sign, rechazando `SSH2_AGENTC_ADD_IDENTITY` (17), `SSH2_AGENTC_ADD_ID_CONSTRAINED` (25), `SSH2_AGENTC_REMOVE_IDENTITY` (18), y `SSH2_AGENTC_REMOVE_ALL_IDENTITIES` (19).
- **Impacto:** Medio (no se podía usar `ssh-add` para añadir/borrar claves).
- **Motivo:** pendiente de SW-044.
- **Resolución:** Implementado en SW-044 con parsing OpenSSH KeypairData, aprobación pinentry, sincronización Bitwarden (`POST /ciphers` y `DELETE /ciphers/{uuid}`) y suite de tests con `ssh-add` real.
- **Estado:** Cerrada (2026-10-26).

## DT-4 — Acciones IPC para la GUI (SW-045)

- **Descripción:** el agente no expone `ListSSHKeys`, `ImportSSHKey`, `NewSSHKey`, `DeleteSSHKey`. La GUI no puede gestionar claves SSH.
- **Impacto:** Medio (la GUI no puede funcionar como gestor de claves).
- **Motivo:** pendiente de SW-045.
- **Retoma:** SW-045 (M5).
- **Estado:** Abierta.

## DT-5 — GUI Tauri (M7)

- **Descripción:** la GUI Tauri no está implementada. El proyecto solo tiene CLI.
- **Impacto:** Alto (la visión de "KeePassXC + Vaultwarden" no se cumple sin GUI).
- **Motivo:** M7 está planificado para después de M5.
- **Retoma:** M7 (post-M5).
- **Estado:** Abierta.

## DT-6 — Cobertura de `sw-ssh-agent`

- **Descripción:** la cobertura de `sw-ssh-agent` estaba en 87.48% líneas.
- **Impacto:** Bajo.
- **Resolución:** Tras la implementación de SW-044 y su batería de 28 pruebas unitarias y de integración E2E, la cobertura alcanzó **89.92% líneas / 90.28% regiones** (superando el umbral mínimo del 85%).
- **Estado:** Cerrada (2026-10-26).

## DT-7 — `tokio 1.53.2` con warning de `AsyncFd::new`

- **Descripción:** `cargo audit` reporta `RUSTSEC-2026-0386` (unsound) en `tokio 1.53.2`.
- **Impacto:** Bajo (no usamos `AsyncFd::new` en el MVP).
- **Motivo:** no hay versión parcheada aún.
- **Retoma:** cuando tokio publique un parche.
- **Estado:** Abierta.
