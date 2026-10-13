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
| M1 | [SW-003] KDF Bitwarden | Pendiente | Por implementar |
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

### [SW-001] Memoria segura bloqueada & [SW-002] EncString

**Comando ejecutado:**
```bash
cargo test -p sw-crypto
```

**Salida real obtenida:**
```text
   Compiling sw-crypto v0.1.0 (/home/hermes/Proyectos/SilverWarden-Rs/crates/sw-crypto)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 13.59s
     Running unittests src/lib.rs (target/debug/deps/sw_crypto-b1e6b98d9ab6421f)

running 7 tests
test encstring::tests::test_invalid_formats ... ok
test encstring::tests::test_is_null ... ok
test encstring::tests::test_roundtrip_type_2 ... ok
test encstring::tests::test_roundtrip_type_0 ... ok
test mem::tests::test_empty_buffers ... ok
test mem::tests::test_mem_locked_buffer_lifecycle ... ok
test mem::tests::test_memory_buffer_wipe ... ok

test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

**Criterios de aceptación verificados:**
- [x] Trait `LockedBuffer` y las dos implementaciones (`MemLockedBuffer` y `MemoryBuffer`) compilan en Linux con `rustix`.
- [x] `wipe()` pisa los bytes a ceros (verificado en `test_memory_buffer_wipe` y `test_mem_locked_buffer_lifecycle`).
- [x] Desbloqueo y `zeroize` al dropear el buffer.
- [x] Roundtrip serialize→parse de `EncString` tipos 0 y 2.
- [x] Rechazo de tipos inválidos y partes faltantes con errores tipados `CryptoError`.
- [x] `is_null()` verificado equivalente a Go.

