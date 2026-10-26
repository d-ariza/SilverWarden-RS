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
- **Evidencia:** pendiente de implementar (ver `deuda-tecnica.md`).
- **Estado:** Pendiente.
