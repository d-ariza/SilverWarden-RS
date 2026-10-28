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

---

## 8. Lecciones de M5 (SSH Agent)

### 8.1. El framing manual del protocolo SSH agent es viable (pero tiene límites)
**Problema:** `russh::keys::agent::server::serve` mantiene un `KeyStore` interno que no soporta un backend externo (nuestro vault cifrado). Tuvimos que implementar el framing manual.
**Lección:** Para `List` y `Sign` básicos, el framing manual es aceptable y funciona (`ssh-add -L`, `ssh-keygen -Y sign`, `git commit -S` pasan). Para `Add`/`Remove` y constraints, hay que parsear más tipos (Ed25519, RSA, ECDSA) y constraints (lifetime, confirm). Es más trabajo, pero viable.
**Generalización:** Cuando una crate no soporta tu modelo de datos, implementar la capa de protocolo a mano es válido si usas los tipos de la crate (`PrivateKey`, `PublicKey`, `sign_with_hash_alg`) para no reinventar la criptografía.

### 8.2. Los tests que generan claves RSA son lentos en debug
**Problema:** Generar claves RSA-2048 en modo debug tarda ~35-40s por clave. Eso hacía que los tests de `sw-agent` tardaran 88s.
**Solución:** Usar fixtures precargados (`TEST_RSA_PEM`) en tests, no generar claves en cada iteración.
**Generalización:** En tests, usa fixtures para operaciones criptográficas costosas (RSA, Argon2 con memoria alta). Los tests deben correr en segundos, no en minutos.

### 8.3. Nunca escribas en `$HOME` en tests
**Problema:** Los tests de `sw-agent` escribieron en `~/.config/goldwarden/goldwarden.json` real, corrompiendo la configuración del usuario.
**Solución:** Inyectar un `TempDir` como `ConfigDirectory` en tests. Nunca usar `std::env::set_var("HOME", ...)` (es inseguro en tests paralelos).
**Generalización:** Cualquier test que toque el sistema de archivos debe usar un directorio temporal aislado. Añade un test de regresión que verifique que el archivo real no se toca.

### 8.4. El bypass de seguridad solo en `#[cfg(test)]`
**Problema:** El `DefaultApprovalProvider` tenía un bypass por variable de entorno (`SILVERWARDEN_SYSTEM_AUTH_DISABLED`). Si alguien la dejaba activa en producción, el agente firmaba sin aprobación.
**Solución:** Mover el bypass a `#[cfg(test)]` y usar un método `with_bypass()` solo disponible en tests.
**Generalización:** Nunca dejes un bypass de seguridad accesible en runtime. Si necesitas un bypass para tests, aíslalo con `#[cfg(test)]` o un feature flag de compilación.

### 8.5. Documentar la interoperabilidad con el sistema de referencia
**Problema:** No teníamos una matriz clara de qué features soporta silverWarden vs Goldwarden Go vs OpenSSH.
**Solución:** Crear `docs/interop-ssh-agent.md` con una tabla comparativa y documentar las limitaciones conocidas (passphrase, DSA, hardware keys).
**Generalización:** Si estás reescribiendo un sistema, documenta la matriz de interop. Ayuda a decidir qué priorizar y a detectar gaps.

### 8.6. La deuda técnica debe revisarse al cerrar cada milestone
**Problema:** Algunas deudas (DT-1, DT-3, DT-4, DT-6) se resolvieron durante M5, pero no se actualizó el documento hasta el final.
**Solución:** Al cerrar cada milestone, revisar `deuda-tecnica.md` y marcar como "Cerrada" lo que se haya resuelto.
**Generalización:** La deuda técnica es un documento vivo. Si no se revisa, se olvida y se convierte en un problema mayor.
