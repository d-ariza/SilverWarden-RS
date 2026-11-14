# Plan de Cierre Arquitectónico y Buenas Prácticas

**Versión:** 3.1  
**Fecha:** 2026-11-07  
**Ámbito:** SilverWarden-Rs (workspace Rust + Tauri/Svelte)  
**Referencia externa:** `../continuidad/04-buenas-practicas.md` (v1.1), fuera de este repo. Si se quiere una referencia interna, copiarla a `docs/04-buenas-practicas.md`.  
**Estado:** Activo / En ejecución  
**Alcance:** deuda arquitectónica y gates de calidad. No cierra deuda funcional (ver §9).

**Cambios v3.1 respecto a v3.0:**

- Se corrige el “Estado inicial”: `shared_vault_agent()` sigue existiendo y el contrato IPC sigue teniendo `serde_json::Value`.
- La Fase 2 mide **líneas de producción**, no líneas totales.
- Se añade la composición única de `VaultAgentServer` y la corrección de la inversión `sw-agent → sw-ssh-agent`.
- Se añade el eslabón que faltaba en el frontend: DTOs Rust → comandos Tauri tipados → `ts-rs` → gateway.
- Se añaden `cargo audit`, jobs de CI, Vitest, CSP y DoD por tarea.
- Se sustituye “Cero Deuda Técnica” por “Cierre de deuda arquitectónica” y se añade la tabla de DTs.

---

## 0. Cómo se lee este plan

Cada tarea es un checkbox. Ninguna tarea se cierra sin **salida real** de los comandos de verificación.

Los identificadores `X.Y` son de tarea; el número de sección del documento es independiente y se mantiene para trazabilidad con la v3.0.

Formato de tarea:

```text
- [ ] X.Y.Z — Título
  - Objetivo: qué se consigue.
  - Pasos: qué se hace, en orden.
  - Verificación: comando y resultado esperado.
  - DoD: criterio de aceptación.
```

Reglas:

- **Una tarea, un commit lógico.**
- **No se avanza de fase con tareas abiertas de la fase anterior**, salvo las marcadas como opcionales.
- **La evidencia va en el PR**: salida de los comandos, no un resumen.
- **Si un comando no se puede ejecutar en local, se ejecuta en CI y se enlaza el job.**

---

## 1. Decisiones fundacionales

1. **Sin excepciones heredadas:** todo archivo de **producción** que supere 800 líneas se divide. La alarma son 500 líneas.
2. **`AgentState` ≤ 6 campos por struct:** se compone de `SecurityContext`, `SessionContext` y `DaemonServices`.
3. **Un solo `VaultAgentServer` por proceso:** el daemon y el SSH agent comparten la misma instancia. Se elimina el singleton.
4. **Contrato IPC tipado de verdad:** `Request` y `Response` no transportan `serde_json::Value` en la frontera.
5. **El frontend no adivina respuestas:** DTOs Rust → comandos Tauri tipados → `ts-rs` → gateway.
6. **Determinismo:** `Clock` inyectable para el tiempo; `Notify`/`oneshot` para sincronización de IPC. Nada de `sleep` como mecanismo de sincronización.
7. **Los gates viven en CI**, no solo en la máquina del desarrollador.
8. **Cada decisión relevante deja un ADR.**

---

## 2. Estado inicial verificado

### 2.1. Lo que ya está hecho

- [x] `IpcRequest` e `IpcResponse` eliminados; `Request` y `Response` viven en `sw-ipc`.
- [x] `sw-client` existe y lo usan `sw-cli` y `sw-gui/src-tauri`.
- [x] `sw-agent/src/lib.rs` en ~750 líneas, con `handlers/` y `state/`.
- [x] `sw-cli/src/main.rs` en ~570 líneas, con `commands/`.
- [x] `AgentError` y `ClientError` con códigos estables (`locked`, `invalid_pin`, etc.).
- [x] `AgentState` tiene 13 campos y está localizado en `sw-agent/src/state/state.rs`.
- [x] No existen `ts-rs`, `Clock`, `FakeClock`, `scripts/` ni `docs/adr/`; las tareas de este plan son reales.

### 2.2. Lo que el plan v3.0 daba por cerrado y no lo está

| Claim v3.0                                       | Estado real                                                 | Evidencia                                                                                             |
| ------------------------------------------------ | ----------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| “Eliminado el singleton `shared_vault_agent()`”  | ❌ Sigue existiendo y se usa                                | `crates/sw-ssh-agent/src/lib.rs:981-996`, `crates/sw-cli/src/commands/agent.rs:23`                    |
| “`VaultAgentServer` inyectado por constructor”   | ❌ El daemon crea otra instancia distinta                   | `crates/sw-agent/src/lib.rs:317-320` frente a `crates/sw-ssh-agent/src/lib.rs:989`                    |
| “Eliminada la dependencia `sw-cli` → `sw-agent`” | ❌ `sw-cli` sigue dependiendo                               | `crates/sw-cli/Cargo.toml`, `crates/sw-cli/src/main.rs:259`, `crates/sw-cli/src/commands/agent.rs:15` |
| “Contrato IPC tipado”                            | ⚠️ Parcial: quedan `Value` en la frontera                   | `crates/sw-ipc/src/lib.rs:34,36,98`                                                                   |
| “`sw-client` es la fachada única”                | ⚠️ Cierto para framing; la GUI sigue construyendo el socket | `crates/sw-gui/src-tauri/src/lib.rs:83-86`                                                            |
| “Guía en `docs/04-buenas-practicas.md`”          | ❌ Ese archivo no existe                                    | La guía está en `../continuidad/04-buenas-practicas.md`                                               |

### 2.3. El bug que el plan no ve: dos vaults en el mismo proceso

`sw-cli agent start` arranca:

1. el daemon con `AgentDaemon::new()`, que crea `VaultAgentServer::default()`;
2. el servidor SSH con `SshAgentServer::for_shared_agent()`, que usa el singleton global.

Son **dos `VaultStore` distintos**. El daemon desbloquea el suyo (`crates/sw-agent/src/handlers/session.rs:74`); el SSH agent usa el otro, que nunca se desbloquea. No es solo deuda de P3: es un bug funcional y no tiene test.

---

## 3. Fase 1 — Arquitectura limpia del agente

**Objetivo de fase:** cumplir P2, P3, P6 y P8 en `sw-agent`, `sw-cli`, `sw-client` y `sw-ssh-agent`.

### 1.1. Puerto `Clock` y determinismo

- [x] **1.1.1 — Crear el puerto `Clock`**
  - Objetivo: aislar el tiempo real detrás de una interfaz.
  - Pasos:
    - Crear `crates/sw-agent/src/ports/clock.rs`.
    - Definir `pub trait Clock: Send + Sync { fn now(&self) -> std::time::Instant; }`.
    - Implementar `SystemClock`.
    - Implementar `FakeClock` con `advance(Duration)` e interior mutabilidad (`Mutex`/`RwLock`).
  - Verificación: `cargo test -p sw-agent` compila y los tests de `Clock` pasan.
  - DoD: no se usa `tokio::time::Instant` en el puerto; el trait no depende de Tokio.

- [x] **1.1.2 — Inyectar `Clock` en `PinCache`**
  - Objetivo: que el TTL sea determinista.
  - Pasos:
    - Añadir `clock: Arc<dyn Clock>` a `PinCache`.
    - Sustituir `tokio::time::Instant::now()` por `self.clock.now()`.
    - Actualizar `PinCache::new` y todos sus usos.
  - Verificación: `cargo test -p sw-agent pin_cache`.
  - DoD: `PinCache` no llama a `Instant::now()` directamente.

- [x] **1.1.3 — Inyectar `Clock` en el idle monitor**
  - Objetivo: que `spawn_idle_monitor` no dependa del reloj real.
  - Pasos:
    - Pasar `Arc<dyn Clock>` a `spawn_idle_monitor`.
    - Sustituir el cálculo de `last_activity.elapsed()` por `clock.now() - last_activity`.
    - Mantener el intervalo de comprobación, pero inyectable o configurable en tests.
  - Verificación: `cargo test -p sw-agent idle_monitor`.
  - DoD: los tests de idle monitor no usan `sleep` para avanzar el tiempo.

- [x] **1.1.4 — Reemplazar los `sleep` de `PinCache`**
  - Objetivo: eliminar los 4 `sleep` de TTL.
  - Pasos:
    - Localizar los tests en `crates/sw-agent/src/tests.rs` (líneas ~2581-2611).
    - Sustituir `tokio::time::sleep(...)` por `fake_clock.advance(...)`.
  - Verificación: `grep -n "sleep" crates/sw-agent/src/tests.rs` no muestra líneas en los tests de `PinCache`.
  - DoD: los tests de TTL pasan 50 veces seguidas sin fallos.

- [x] **1.1.5 — Sustituir los `sleep` de sincronización de IPC**
  - **Estado real (2026-11-13):** completado (incluyendo `1.1.5b`). Sustituidos los 9 `tokio::time::sleep` de `crates/sw-cli/src/tests.rs` y el de `crates/sw-agent/src/tests.rs` por el helper `wait_until(desc, timeout, cond)`.
  - Objetivo: que los tests no esperen a que “arranque algo”.
  - Pasos:
    - Identificar los `sleep` que esperan a que el servidor/cliente esté listo (14 en `sw-agent`, 8 en `sw-cli`).
    - Sustituirlos por `tokio::sync::Notify`, `oneshot` o un helper `wait_until(predicado, timeout)`.
    - No usar `Clock` para esto: no es tiempo de negocio, es sincronización.
  - Verificación: `grep -rn "tokio::time::sleep" crates/sw-agent/src/tests.rs crates/sw-cli/src/tests.rs` solo muestra casos justificados y documentados.
  - DoD: la suite no depende de esperas fijas; no hay `sleep` como mecanismo de sincronización.

- [x] **1.1.6 — Verificación de fase**
  - `cargo test -p sw-agent`
  - `cargo test -p sw-cli`
  - `cargo clippy -p sw-agent -p sw-cli --all-targets -- -D warnings`
  - Ejecutar la suite 50 veces: `for i in $(seq 1 50); do cargo test -p sw-agent --quiet || break; done`
  - DoD: 50/50 en verde y sin pausas de tiempo real en los tests de TTL.
  - **Evidencia (2026-11-13):** `50/50` ejecuciones de `cargo test -p sw-agent --quiet` en verde (77 passed, 0 failed en cada iteración); `cargo test -p sw-cli` en verde (122 unitarios + 10 integración, 0 failed); `cargo clippy -p sw-agent -p sw-cli --all-targets -- -D warnings` sin warnings; `rg -n "std::thread::sleep|tokio::time::sleep" crates/sw-agent/src crates/sw-cli/src` muestra únicamente los 2 sondeos internos de `wait_until` (`crates/sw-agent/src/tests.rs:14`, `crates/sw-cli/src/tests.rs:1186`) y el test unitario del reloj real `SystemClock` (`crates/sw-agent/src/ports/clock.rs:70`, `test_system_clock_advances`), sin ningún sleep de TTL.

### 1.2. Subdivisión de `AgentState`

- [x] **1.2.1 — Definir `SecurityContext`**
  - Campos: `biometrics`, `pin_cache`, `keyring`, `notifier`, `clock`, `last_activity`.
  - Límite: 6 campos.
  - Verificación: `cargo check -p sw-agent`.

- [x] **1.2.2 — Definir `SessionContext`**
  - Campos: `sessions`, `is_locked`, `has_pin`.
  - Límite: 3 campos.
  - Verificación: `cargo check -p sw-agent`.

- [x] **1.2.3 — Definir `DaemonServices`**
  - Campos: `vault_agent`, `api_client`, `shutdown_sender`, `config`, `config_directory`.
  - Límite: 5 campos.
  - Verificación: `cargo check -p sw-agent`.

- [x] **1.2.4 — Componer `AgentState`**
  - `AgentState { security: SecurityContext, session: SessionContext, services: DaemonServices }`.
  - Total: 3 campos.
  - Verificación: `grep -A 6 "pub struct AgentState" crates/sw-agent/src/state/state.rs`.

- [x] **1.2.5 — Actualizar handlers**
  - Objetivo: que los handlers sigan recibiendo `&mut AgentState` compuesto.
  - Pasos:
    - No intentar “un sub-contexto por handler”: `handle_unlock`, `handle_sync` y `handle_list_logins` necesitan 2-3 contextos.
    - Acceder a `state.security`, `state.session` y `state.services` desde el handler.
    - Mantener la firma `&mut AgentState` para no duplicar variantes.
  - Verificación: `cargo test -p sw-agent` y `cargo clippy -p sw-agent -- -D warnings`.
  - DoD: cada sub-struct tiene ≤6 campos; `AgentState` tiene 3.

- [x] **1.2.6 — Actualizar constructores y métodos**
  - `AgentState::new`, `load_or_default_with`, `with_vault_agent`, `with_config_directory`, `vault_path`, `touch_activity`.
  - Verificación: `cargo test -p sw-agent` en verde.

- [x] **1.2.7 — Test de composición**
  - Un test que construya `AgentState` con `FakeClock` y verifique que los tres contextos se actualizan correctamente.
  - Verificación: `cargo test -p sw-agent agent_state`.

### 1.3. Composición única de `VaultAgentServer`

- [x] **1.3.1 — Eliminar el singleton**
  - Borrar `static SHARED_VAULT_AGENT` y `pub fn shared_vault_agent()` de `crates/sw-ssh-agent/src/lib.rs`.
  - Verificación: `grep -rn "shared_vault_agent" crates/` vacío.

- [x] **1.3.2 — Eliminar `for_shared_agent`**
  - Borrar `SshAgentServer::for_shared_agent`.
  - Verificación: `grep -rn "for_shared_agent" crates/` vacío.

- [x] **1.3.3 — Crear la composición en `sw-cli`**
  - En `crates/sw-cli/src/commands/agent.rs`:
    - Crear un solo `let vault_agent = Arc::new(VaultAgentServer::default());`.
    - Construir `let daemon = AgentDaemon::with_vault_agent(AgentState::load_or_default_with(vault_agent.clone()), vault_agent.clone());`.
    - Arrancar el daemon con `sw_agent::run_agent_daemon_with_shutdown(&agent_sock, daemon, shutdown_future)`.
    - Construir `SshAgentServer::new(ssh_sock, (*vault_agent).clone())`.
  - Verificación: el código compila y ambos servidores comparten la misma instancia.

- [x] **1.3.4 — `AgentDaemon::new()` deja de crear su propio agente**
  - Opción A: eliminar `AgentDaemon::new()` y usar siempre `with_vault_agent`.
  - Opción B: mantener `new()` solo para tests y documentarlo.
  - Verificación: `grep -rn "VaultAgentServer::default()" crates/sw-agent/src/lib.rs` no aparece en producción.

- [x] **1.3.5 — Test de integración del vault compartido**
  - Arrancar daemon y SSH agent con la misma instancia.
  - Desbloquear por el daemon.
  - Pedir `ListSshKeys` por el socket SSH y comprobar que devuelve las claves.
  - Verificación: `cargo test -p sw-cli shared_vault`.
  - DoD: el test falla si se vuelven a crear dos instancias.

### 1.4. Dirección de dependencias

- [x] **1.4.1 — Mover `VaultAgentServer` a un crate neutral**
  - Opción recomendada: crear `crates/sw-vault-agent` con `VaultAgentServer`, `ApprovalProvider` y la lógica de sesión. Ese crate depende de `sw-vault`, `sw-crypto`, `sw-systemauth`, `sw-bitwarden-api`, `sw-notify` y `russh`.
  - `sw-agent` y `sw-ssh-agent` dependen de `sw-vault-agent`.
  - Alternativa: mantenerlo en `sw-ssh-agent` y documentar la excepción con ADR-0007.
  - Verificación: `cargo tree -p sw-agent | grep sw-ssh-agent` vacío.
  - DoD: el núcleo no depende del adaptador SSH.

- [x] **1.4.2 — Ajustar dependencias**
  - `sw-agent` puede mantener `sw-ssh-agent` solo como `dev-dependency` si los tests usan `generate_test_ed25519`.
  - `sw-ssh-agent` depende de `sw-vault-agent`.
  - Verificación: `cargo tree -p sw-agent --edges normal | grep sw-ssh-agent` vacío.

- [x] **1.4.3 — Verificación de fase**
  - `cargo tree -p sw-agent`
  - `cargo tree -p sw-ssh-agent`
  - `cargo test --workspace`
  - DoD: no hay ciclos ni dependencias del núcleo hacia adaptadores.

### 1.5. Centralización de rutas

- [x] **1.5.1 — Crear el módulo de rutas**
  - Opción recomendada: `crates/sw-config/src/paths.rs` con `default_socket_path()` y `default_ssh_agent_socket_path()`.
  - Opción alternativa: `crates/sw-paths`.
  - No ponerlo en `sw-client`: `sw-agent` (servidor) no debe depender de `sw-client` (cliente).
  - Verificación: `cargo check -p sw-config`.

- [x] **1.5.2 — Usar la función en todos los consumidores**
  - `sw-agent/src/lib.rs` deja de definir `default_socket_path`.
  - `sw-cli/src/main.rs` importa desde `sw-config`.
  - `sw-gui/src-tauri/src/lib.rs` deja de hardcodear `~/.silverwarden.sock`.
  - Verificación: `grep -rn "silverwarden.sock" crates/` solo aparece en `sw-config` y tests.

- [x] **1.5.3 — Corregir la verificación de la dependencia**
  - No afirmar que mover la ruta elimina `sw-cli → sw-agent`: `sw-cli` sigue usando `sw_agent::run_agent`.
  - Si se quiere eliminar esa dependencia, separar el binario del daemon (ver 1.5.4).
  - Verificación: `cargo tree -p sw-cli | grep sw-agent` documenta la dependencia real.
  - **Evidencia (2026-11-13):** `cargo tree -p sw-cli | rg sw-agent` →
    `├── sw-agent v0.1.0 (/home/hermes/Proyectos/SilverWarden-RS/SilverWarden-Rs/crates/sw-agent)`.
    Documentada como dependencia esperada en `scripts/check-deps.sh` y corregida la afirmación previa en ADR-0008 §1.

- [x] **1.5.4 — Decidir el arranque del daemon**
  - Opción A: `sw-cli agent start` sigue siendo el entrypoint y `sw-cli` depende de `sw-agent` (aceptado y documentado).
  - Opción B: `sw-agent` se convierte en binario real (`src/main.rs` sirve el socket) y `sw-cli` lo executa.
  - Verificación: `cargo run -p sw-agent` no termina inmediatamente (si se elige B).
  - DoD: la decisión queda en ADR-0008.
  - **Evidencia (2026-11-13):** Opción A aceptada en
    `docs/adr/adr-0008-daemon-entrypoint-and-paths.md`. `sw-cli agent start`
    compone `VaultAgentServer`, lanza `run_agent` + `SshAgentServer`, espera
    `Ctrl+C` y limpia los sockets. `sw-agent/src/main.rs` queda como utilidad de
    desarrollo, no como entrypoint.

---

## 4. Fase 2 — Modularización de monolitos

**Objetivo de fase:** cumplir P6 midiendo **líneas de producción**, no líneas totales.

### 2.1. Criterio de medición

- [x] **2.1.1 — Corregir `scripts/check-file-size.sh`**
  - Contar solo código fuera de `#[cfg(test)]`.
  - Excluir `tests.rs`, `tests/`, `target/` y `fuzz/`.
  - Fallar con código 1 si un archivo de producción supera 800 líneas.
  - Avisar (sin fallar) entre 500 y 800.
  - Verificación: el script falla con un archivo de prueba de 801 líneas y pasa con el repo actual.
  - **Estado real (2026-11-14):** `scripts/check-file-size.sh` creado con `--self-test`.
    El repo **no pasa todavía**: detecta 2 violaciones reales
    (`sw-vault/src/lib.rs` 1.376 y `sw-bitwarden-api/src/lib.rs` 1.005), que son
    exactamente 2.2.2 y 2.2.3. El self-test sí pasa (600 → WARN, 801 → exit 1,
    tests excluidos).
  - **Evidencia:** `./scripts/check-file-size.sh --self-test` → `SELF-TEST OK`;
    `./scripts/check-file-size.sh` → `Archivos medidos: 57 · violaciones: 2 · avisos: 7`.

- [x] **2.1.2 — Mover tests inline a archivos separados**
  - Hay 18 archivos con `mod tests { ... }` inline (22 archivos con `#[cfg(test)]` auxiliares).
  - Moverlos a `tests.rs` o `tests/` como parte del split de cada archivo.
  - Verificación: `grep -rn "#\[cfg(test)\]" crates --include="*.rs"` solo aparece en `tests.rs`/`tests/` y en módulos pequeños justificados.
  - DoD: el gate de tamaño y el de cobertura son medibles sin heurísticas.
  - **Estado real (2026-11-14):** movidos los 3 bloques grandes:
    - `sw-vault/src/lib.rs` (1.390 líneas de test) → `sw-vault/src/tests.rs`;
    - `sw-bitwarden-api/src/lib.rs` (1.644) → `sw-bitwarden-api/src/tests.rs`;
    - `sw-bitwarden-api/src/websocket.rs` (681) → `sw-bitwarden-api/src/websocket_tests.rs`
      (declarado con `#[path = "websocket_tests.rs"]` porque `websocket` es un módulo de archivo).
  - **Evidencia:** `rg -n "mod tests \{"` en los 3 archivos → 0;
    `cargo test -p sw-vault -p sw-bitwarden-api` → 30 + 64 passed, 0 failed;
    `./scripts/check-file-size.sh` → `sw-vault` 1.375 y `sw-bitwarden-api` 1.004
    (ahora se mide solo producción, sin el bloque de tests).

- [x] **2.1.3 — Corregir `scripts/coverage-production.py`**
  - Ejecutar `cargo llvm-cov` con `--ignore-filename-regex` para `tests?\.rs$` y `tests/`.
  - Excluir también `#[cfg(test)]` inline: moverlos a archivos separados. Si se usa nightly, `#[coverage(off)]` es una alternativa.
  - Comprobar cobertura de producción ≥90%.
  - Verificación: el script informa del porcentaje y falla por debajo de 90.
  - **Estado real (2026-11-14):** `scripts/coverage-production.py` creado, con
    `--threshold` y `--reuse`. Ignora `tests.rs`, `*_tests.rs`, `tests/` y `fuzz/`,
    y descarta rutas de otro checkout (21 entradas de
    `/home/hermes/Proyectos/SilverWarden-RS/crates/...`, que no existen).
  - **Cobertura medida: 88.08 %**, por debajo del objetivo de 90 %. El gate
    funciona y falla; la brecha se cierra en 4.2.2 subiendo tests, no bajando el
    umbral.
  - **Evidencia:** `python3 scripts/coverage-production.py --threshold 101` → exit 1;
    `python3 scripts/coverage-production.py` → `cobertura producción: 88.08%` y exit 1.

**Medición actual** (producción = líneas antes de `mod tests`; auditada 2026-11-13):

| Archivo                             | Total | Producción | Veredicto P6          |
| ----------------------------------- | ----: | ---------: | --------------------- |
| `sw-vault/src/lib.rs`               | 1.377 |  **1.375** | Viola                 |
| `sw-bitwarden-api/src/lib.rs`       | 1.006 |  **1.004** | Viola                 |
| `sw-agent/src/lib.rs`               |   768 |        766 | Alarma                |
| `sw-config/src/lib.rs`              | 1.713 |        701 | Alarma                |
| `sw-vault-agent/src/agent.rs`       |   662 |        662 | Alarma                |
| `sw-ssh-agent/src/lib.rs`           | 2.166 |        637 | Correcto (aviso >500) |
| `sw-cli/src/main.rs`                |   556 |        554 | Alarma                |
| `sw-bitwarden-api/src/websocket.rs` |   533 |        532 | Alarma                |
| `sw-agent/src/handlers/session.rs`  |   522 |        522 | Alarma                |
| `sw-systemauth/src/lib.rs`          |   869 |        406 | Correcto              |

> Medición 2026-11-14 tras 2.1.2, con `./scripts/check-file-size.sh`.
> `sw-vault` y `sw-bitwarden-api` ya no incluyen tests inline: viven en
> `tests.rs`, por eso el total baja a ~1.377 / ~1.006.

### 2.2. Splits obligatorios (violan P6)

- [x] **2.2.1 — `sw-ssh-agent/src/lib.rs` (cerrada por 1.4)**
  - **Estado real (2026-11-13):** 638 líneas de producción; `VaultAgentServer` vive en `sw-vault-agent`. No requiere split adicional.
  - Verificación: `awk '/^(pub )?mod tests/{print NR-1; exit}' crates/sw-ssh-agent/src/lib.rs` → 638; `cargo test -p sw-ssh-agent`.

- [ ] **2.2.2 — `sw-vault/src/lib.rs` (1.375 líneas de producción)**
  - Extraer `store.rs` (store y concurrencia).
  - Extraer `models.rs` (modelos y tipos de ciphers).
  - Extraer `decrypt.rs` (descifrado y resolución de claves).
  - Extraer `storage.rs` (persistencia y permisos `0600`).
  - Dejar `lib.rs` < 300 líneas.
  - Verificación: `cargo test -p sw-vault`, `cargo clippy -p sw-vault -- -D warnings`, `wc -l` producción ≤800.

- [ ] **2.2.3 — `sw-bitwarden-api/src/lib.rs` (1.004 líneas de producción)**
  - Extraer `client.rs` (cliente HTTP autenticado).
  - Extraer `sync.rs` (sincronización de vault).
  - Extraer `auth.rs` (autenticación y 2FA).
  - Dejar `lib.rs` < 300 líneas.
  - Verificación: `cargo test -p sw-bitwarden-api`, `cargo clippy -p sw-bitwarden-api -- -D warnings`, `wc -l` producción ≤800.

- [x] **2.2.4 — Tests de caracterización antes de cada split**
  - Antes de mover código, capturar el comportamiento actual: tests existentes, snapshots de respuestas o fixtures.
  - Refactorizar sin cambiar la salida.
  - Verificación: los tests de caracterización pasan antes y después.
  - DoD: ningún split cambia comportamiento observable.
  - **Estado real (2026-11-14):** añadidos **19 tests** con prefijo `caracterizacion_`:
    - `sw-vault/src/tests.rs` (11): enums numéricos, claves JSON de `URI`, `Field`,
      `LoginCipher`, `SSHKeyCipher`, `Card`, `Identity`, `SecureNoteCipher`,
      `Folder`, `Organization`, `Profile`, `Cipher`, `SyncData`,
      `DecryptedCipher` y `VaultSshKey`; `null` → vec vacío; tipos numéricos; `Display` de errores.
    - `sw-bitwarden-api/src/tests.rs` (8): `Display` de `ApiError`, JSON y
      defaults de `PreloginResponse`, parseo de 2FA, mapeo de `TwoFactorProvider`,
      constantes de cliente, `RequestBody` y `decrypt_enc_key("")`.
  - **Evidencia (antes del split):**
    - `cargo test -p sw-vault caracterizacion` → 11 passed, 0 failed.
    - `cargo test -p sw-bitwarden-api caracterizacion` → 8 passed, 0 failed.
    - `cargo test --workspace` → 508 passed, 0 failed.
    - `cargo fmt --all -- --check` y `cargo clippy -p sw-vault -p sw-bitwarden-api --all-targets -- -D warnings` → limpios.

### 2.3. Limpieza opcional de zona de alarma

- [ ] **2.3.1 — `sw-config/src/lib.rs` (695 líneas de producción)**
  - Opcional: extraer `model.rs`, `paths.rs`, `migration.rs`, `defaults.rs`.
  - No es un incumplimiento de P6; es zona de alarma.
  - Verificación: `cargo test -p sw-config`.

- [ ] **2.3.2 — `sw-bitwarden-api/src/websocket.rs` (530 líneas de producción)**
  - Opcional: extraer `protocol.rs`, `connection.rs`, `dispatcher.rs`.
  - No es un incumplimiento de P6.
  - Verificación: `cargo test -p sw-bitwarden-api`.

- [ ] **2.3.3 — `sw-systemauth/src/lib.rs` (405 líneas de producción)**
  - Opcional por cohesión: extraer `process.rs` y `pam.rs`.
  - No es un incumplimiento de P6.
  - Verificación: `cargo test -p sw-systemauth`.

- [ ] **2.3.4 — No bloquear el cierre por 2.3.x**
  - Estas tareas pueden quedar fuera de la v1.0 del plan.
  - DoD: el plan distingue “obligatorio” de “mejora”.

### 2.4. Verificación de fase

- [ ] **2.4.1 — Ejecutar los gates**
  - `./scripts/check-file-size.sh`
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo fmt --all -- --check`
  - DoD: 3 splits obligatorios cerrados; 0 archivos de producción >800.

---

## 5. Fase 3 — Frontend tipado y moderno

**Objetivo de fase:** cumplir §5.1, §5.2, §5.3, §5.4, §5.5, §5.6, §5.7 y §5.8 de la guía.

### 3.1. Contrato IPC tipado

- [ ] **3.1.1 — Definir DTOs en `sw-ipc`**
  - `AgentStatus { locked, has_pin, logged_in, pin_cached, pin_cached_remaining_secs, version }`.
  - `LoginSummary { id, name, username }`.
  - `LoginDetail { id, name, username, password, totp }`.
  - `SyncResult { total, logins, ssh_keys, notes, cards, identities }`.
  - `SshKeySummary { id, name, key_type }`.
  - `ConfigView { api_url, identity_url, notifications_url, danger_accept_invalid_certs }`.
  - `PinChangeResult { updated }`.
  - Verificación: `cargo check -p sw-ipc`.

- [ ] **3.1.2 — Tipar `Response` por operación**
  - Eliminar `Response::Ok(serde_json::Value)`.
  - Opción A: `Response::Status(AgentStatus)`, `Response::Logins(Vec<LoginSummary>)`, etc.
  - Opción B: `Response<T>` genérico con `T` por operación.
  - Verificación: `grep -n "serde_json::Value" crates/sw-ipc/src/lib.rs` vacío en la frontera.

- [ ] **3.1.3 — Tipar `Request`**
  - Sustituir `SyncData(serde_json::Value)` y `ReloadVault(serde_json::Value)` por `SyncData(SyncPayload)` y `ReloadVault(SyncPayload)`.
  - Verificación: `cargo test -p sw-ipc`.

- [ ] **3.1.4 — Handlers devuelven DTOs**
  - `handle_list_logins` devuelve `Vec<LoginSummary>`.
  - `handle_get_login` devuelve `LoginDetail`.
  - `handle_sync` devuelve `SyncResult`.
  - `handle_status` devuelve `AgentStatus`.
  - Actualizar `sw-client::call_ok`/`send_ok` para devolver el DTO correspondiente; no `serde_json::Value`.
  - Verificación: `grep -rn "serde_json::json!" crates/sw-agent/src/handlers` no se usa para construir respuestas de contrato.

- [ ] **3.1.5 — Tests de contrato**
  - Serialización/deserialización de cada DTO.
  - Test de compatibilidad con el formato JSON actual.
  - Verificación: `cargo test -p sw-ipc -p sw-agent`.

### 3.2. Generación de TypeScript con `ts-rs`

- [ ] **3.2.1 — Añadir `ts-rs` de forma opcional**
  - `[dependencies] ts-rs = { version = "...", optional = true }`.
  - Feature `ts` que active la dependencia.
  - Evitar que `ts-rs` entre en el build de producción.
  - Verificación: `cargo tree -p sw-ipc --no-default-features | grep ts-rs` vacío; con `--features ts` aparece.

- [ ] **3.2.2 — Derivar `TS` en los DTOs**
  - `#[cfg_attr(feature = "ts", derive(TS))]`.
  - `#[cfg_attr(feature = "ts", ts(export, export_to = "..."))]`.
  - Verificación: `cargo test -p sw-ipc --features ts`.

- [ ] **3.2.3 — Test de exportación**
  - Test que genere los `.ts` en `crates/sw-gui/src/lib/types/generated/`.
  - Verificación: los archivos se crean y no contienen `any`.

- [ ] **3.2.4 — Gate de tipos generados**
  - `git diff --exit-code crates/sw-gui/src/lib/types/generated/` tras el test.
  - Verificación: si los tipos cambian y no se commitean, el gate falla.

### 3.3. Comandos Tauri tipados

- [ ] **3.3.1 — Tipar `get_agent_status`**
  - Devolver `Result<AgentStatus, String>`.
  - Eliminar `payload["locked"].as_bool().unwrap_or(true)` y los fallbacks.
  - Verificación: `grep -n "as_bool().unwrap_or" crates/sw-gui/src-tauri/src/lib.rs` vacío.

- [ ] **3.3.2 — Tipar el resto de comandos**
  - `list_logins -> Result<Vec<LoginSummary>, String>`.
  - `sync_vault -> Result<SyncResult, String>`.
  - `get_login -> Result<LoginDetail, String>`.
  - Verificación: `cargo check --manifest-path crates/sw-gui/src-tauri/Cargo.toml`.

- [ ] **3.3.3 — Añadir comandos que faltan**
  - `list_ssh_keys`.
  - `pin_set`.
  - `pin_update`.
  - `get_config`.
  - `set_config`.
  - `save_settings` / `load_settings` si se mantienen.
  - Verificación: `grep -n "#\[tauri::command\]" crates/sw-gui/src-tauri/src/lib.rs` lista todos.

- [ ] **3.3.4 — Usar la ruta centralizada**
  - `get_agent_client` usa `sw_config::default_socket_path()`.
  - Verificación: `grep -n "silverwarden.sock" crates/sw-gui/src-tauri/src/lib.rs` vacío.

### 3.4. Gateway tipado

- [ ] **3.4.1 — Crear `src/lib/api/agent.ts`**
  - Métodos: `getStatus`, `unlock`, `lock`, `sync`, `listLogins`, `getLogin`, `listSshKeys`, `pinSet`, `pinUpdate`, `getConfig`, `setConfig`, `copyToClipboard`, `setMenuState`, `saveSettings`, `loadSettings`.
  - Tipos importados desde `types/generated`.
  - Verificación: `pnpm --dir crates/sw-gui check`.

- [ ] **3.4.2 — Refactorizar consumidores**
  - `routes/vault/+page.svelte`.
  - `routes/login/+page.svelte`.
  - `lib/state/vault.svelte.ts`.
  - `lib/design/theme.svelte.ts`.
  - Verificación: `grep -rn "invoke(" crates/sw-gui/src/` solo devuelve `src/lib/api/agent.ts`.

- [ ] **3.4.3 — Eliminar interfaces duplicadas**
  - `LoginItem` y `LoginDetail` dejan de estar definidos en dos sitios.
  - Verificación: `grep -rn "interface LoginItem" crates/sw-gui/src/` devuelve una sola definición (o ninguna, si viene de generated).

### 3.5. Máquina de estados finita

- [ ] **3.5.1 — Modelar la unión discriminada**
  - Estados: `disconnected`, `needs_setup`, `logged_out`, `locked`, `unlocking`, `unlocked`, `syncing`, `error`.
  - `unlocked` y `syncing` llevan `logins: LoginSummary[]`.
  - `error` lleva `message: string`.
  - Verificación: `pnpm --dir crates/sw-gui check`.

- [ ] **3.5.2 — Eliminar los booleanos**
  - Borrar `isLoading`, `isSyncing`, `isLocking`, `error`.
  - Verificación: `grep -n "isLoading\|isSyncing\|isLocking" crates/sw-gui/src/lib/state/vault.svelte.ts` vacío.

- [ ] **3.5.3 — Definir transiciones y guards**
  - `disconnected → locked` al conectar.
  - `locked → unlocking → unlocked` al desbloquear.
  - `unlocked → syncing → unlocked` al sincronizar.
  - `cualquiera → error` con mensaje.
  - `cualquiera → disconnected` al perder el socket.
  - Verificación: tabla de transiciones documentada en el código.

- [ ] **3.5.4 — Tests de transiciones con Vitest**
  - Un test por transición válida y por transición inválida.
  - Verificación: `pnpm --dir crates/sw-gui test`.

- [ ] **3.5.5 — Adaptar la UI**
  - Las vistas reaccionan a `vaultState.status.state`.
  - Verificación: `pnpm --dir crates/sw-gui build`.

### 3.6. Vistas de SSH y configuración

- [ ] **3.6.1 — Vista/tab de claves SSH**
  - Lista `SshKeySummary`.
  - Acciones: importar, crear, borrar (si el backend lo soporta).
  - Verificación: `pnpm --dir crates/sw-gui check`.

- [ ] **3.6.2 — Vista de configuración**
  - URL de API, URL de identidad, preferencias y cambio de PIN.
  - Usa `getConfig`/`setConfig`/`pinUpdate`.
  - Verificación: `pnpm --dir crates/sw-gui check`.

- [ ] **3.6.3 — Cinco estados de UI en cada vista**
  - Carga (skeleton), vacío, error, éxito, sin conexión.
  - Verificación: revisión manual + checklist en el PR.

### 3.7. Calidad de frontend

- [ ] **3.7.1 — Añadir Vitest**
  - `vitest` y `@testing-library/svelte` en `devDependencies`.
  - Script `test` en `package.json`.
  - Verificación: `pnpm --dir crates/sw-gui test` ejecuta al menos los tests de FSM.

- [ ] **3.7.2 — CSP estricta**
  - `tauri.conf.json`: `"csp": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"` (ajustar a lo que necesite Svelte).
  - Verificación: la app arranca y no hay violaciones de CSP en consola.

- [ ] **3.7.3 — Accesibilidad**
  - Contraste ≥4.5:1.
  - Foco visible.
  - `aria-label` en botones con solo icono.
  - Navegación por teclado.
  - Texto mínimo `0.875rem`.
  - Verificación: checklist manual + `svelte-check`.

- [ ] **3.7.4 — Design tokens**
  - Cero colores/tamaños/márgenes hardcodeados.
  - Todo por variables CSS.
  - Temas claro y oscuro validados.
  - Verificación: `grep -rn "#[0-9a-fA-F]\{3,6\}" crates/sw-gui/src/` solo en tokens.

- [ ] **3.7.5 — Smoke E2E de arranque**
  - Un test que abra la app y compruebe que la vista principal renderiza.
  - Verificación: el test pasa en CI.

---

## 6. Fase 4 — Tooling, gates y CI

**Objetivo de fase:** que ninguna violación vuelva a entrar (P10 y §8.1).

### 4.1. Scripts

- [ ] **4.1.1 — `scripts/check-file-size.sh`**
  - Mide líneas de producción.
  - Falla >800; avisa 500-800.
  - Verificación: caso de prueba con 801 líneas falla.

- [ ] **4.1.2 — `scripts/coverage-production.py`**
  - `cargo llvm-cov`.
  - Excluye tests y `#[cfg(test)]`.
  - Falla <90%.
  - Verificación: ejecución local con el repo actual.

- [ ] **4.1.3 — `scripts/check-generated-types.sh`**
  - Ejecuta `cargo test -p sw-ipc --features ts`.
  - Comprueba `git diff --exit-code` sobre `sw-gui/src/lib/types/generated/`.
  - Verificación: tipos desactualizados fallan.

### 4.2. CI

- [ ] **4.2.1 — Job `backend`**
  - `cargo fmt --all -- --check`.
  - `cargo clippy --workspace --all-targets -- -D warnings`.
  - `cargo test --workspace`.
  - Verificación: el job está en verde en un PR limpio.

- [ ] **4.2.2 — Job `coverage`**
  - Instalar `cargo-llvm-cov` y `llvm-tools-preview`.
  - `python3 ./scripts/coverage-production.py`.
  - Verificación: el job publica el porcentaje y falla por debajo de 90.

- [ ] **4.2.3 — Job `audit`**
  - Instalar `cargo-audit`.
  - `cargo audit` con `.cargo/audit.toml`.
  - Documentar las excepciones vigentes (RUSTSEC-2023-0071, RUSTSEC-2024-0370, RUSTSEC-2024-0429, RUSTSEC-2026-0370/0371/0372, RUSTSEC-2026-0387).
  - Verificación: el job está en verde con las excepciones documentadas y falla con una vulnerabilidad nueva.

- [ ] **4.2.4 — Job `size`**
  - `./scripts/check-file-size.sh`.
  - Verificación: el job falla con un archivo de producción de 801 líneas.

- [ ] **4.2.5 — Job `gui`**
  - `pnpm --dir crates/sw-gui install --frozen-lockfile`.
  - `pnpm --dir crates/sw-gui check`.
  - `pnpm --dir crates/sw-gui test`.
  - `pnpm --dir crates/sw-gui build`.
  - `cargo check --manifest-path crates/sw-gui/src-tauri/Cargo.toml --locked`.
  - Verificación: el job está en verde en un PR limpio.

- [ ] **4.2.6 — Limpiar comandos del workspace**
  - Quitar `--exclude sw-gui` de `cargo clippy` y `cargo test`: `sw-gui` ya está fuera del workspace y Cargo solo emite un warning.
  - Verificación: `cargo clippy --workspace --all-targets -- -D warnings` sin warnings de exclusión.

- [ ] **4.2.7 — Verificación de CI**
  - Un PR con un archivo de 801 líneas falla en `size`.
  - Un PR con un tipo TS desactualizado falla en `gui`.
  - Un PR con una vulnerabilidad no ignorada falla en `audit`.
  - DoD: los cinco jobs (`backend`, `coverage`, `audit`, `size`, `gui`) son obligatorios para mergear.

---

## 7. Fase 5 — Documentación y ADRs

### 5.1. ADRs

- [ ] **5.1.1 — `docs/adr/adr-0001-typed-ipc-contract.md`**
  - Contrato `Request`/`Response`, DTOs y eliminación de `serde_json::Value`.
  - Verificación: el archivo existe y sigue el formato de §11.1.

- [ ] **5.1.2 — `docs/adr/adr-0002-sw-client-facade.md`**
  - `sw-client` como fachada de conexión, no como dueño de rutas.
  - Verificación: el archivo existe y sigue el formato de §11.1.

- [ ] **5.1.3 — `docs/adr/adr-0003-agent-error-taxonomy.md`**
  - `AgentError`/`ClientError` y códigos estables.
  - Verificación: el archivo existe y sigue el formato de §11.1.

- [ ] **5.1.4 — `docs/adr/adr-0004-clock-port-and-tests.md`**
  - `Clock`, `FakeClock` y separación entre tiempo y sincronización.
  - Verificación: el archivo existe y sigue el formato de §11.1.

- [ ] **5.1.5 — `docs/adr/adr-0005-agent-state-decomposition.md`**
  - `AgentState` en 3 sub-contextos.
  - Verificación: el archivo existe y sigue el formato de §11.1.

- [ ] **5.1.6 — `docs/adr/adr-0006-frontend-gateway-and-fsm.md`**
  - Gateway, `ts-rs` y FSM.
  - Verificación: el archivo existe y sigue el formato de §11.1.

- [x] **5.1.7 — `docs/adr/adr-0007-vault-agent-ownership.md`**
  - **Estado real (2026-11-13):** existe desde `ca6a0ea`, con las 5 secciones del formato.
  - Un solo `VaultAgentServer` por proceso y ubicación neutral del tipo.
  - Verificación: el archivo existe y sigue el formato de §11.1.

- [x] **5.1.8 — `docs/adr/adr-0008-daemon-entrypoint-and-paths.md`**
  - **Estado real (2026-11-14):** existe desde 1.5.4, con las 5 secciones del formato (Contexto, Decisión, Alternativas Descartadas, Consecuencias y Grafo, Fecha de Revisión) y la cita de `cargo tree -p sw-cli | rg sw-agent`.
  - Quién arranca el daemon y dónde vive `default_socket_path`.
  - Verificación: el archivo existe y sigue el formato de §11.1.

- [ ] **5.1.9 — Verificación**
  - Cada ADR sigue el formato de la guía §11.1: contexto, decisión, alternativas, consecuencias, fecha de revisión.

### 5.2. README público

- [ ] **5.2.1 — Prerrequisitos**
  - Rust, Node, `webkit2gtk-4.1`, `pnpm`.
  - Verificación: las versiones mínimas están documentadas y comprobadas con `rustc --version`, `node --version` y `pnpm --version`.

- [ ] **5.2.2 — Docker Compose**
  - Crear `docker-compose.yml` con Vaultwarden + Caddy y TLS local.
  - Documentar cómo levantarlo.
  - Verificación: `docker compose up -d` levanta ambos servicios y el healthcheck responde.

- [ ] **5.2.3 — Comandos**
  - Build, tests, `silverwarden agent start`, GUI.
  - No documentar `cargo run -p sw-agent` como daemon: `crates/sw-agent/src/main.rs` crea el daemon y termina.
  - Verificación: un usuario limpio puede seguirlo sin pasos ocultos.

- [ ] **5.2.4 — Sin secretos ni rutas absolutas**
  - `grep -n "/home/" README.md` vacío.
  - `grep -n "password\|token" README.md` solo en ejemplos ficticios.
  - Verificación: los dos greps anteriores no encuentran rutas reales ni secretos.

- [ ] **5.2.5 — Actualizar el árbol de crates**
  - Añadir `sw-client`.
  - Corregir `~/.goldwarden.sock` → `~/.silverwarden.sock`.
  - Verificación: `grep -n "sw-client" README.md` y `grep -n "silverwarden.sock" README.md` aparecen.

- [ ] **5.2.6 — Verificación**
  - README reproducible en una máquina limpia.

---

## 8. Definition of Done

### 8.1. DoD por tarea (§8.5)

Toda tarea, antes de marcarse, cumple:

- [ ] Criterio de aceptación cumplido.
- [ ] Tests unitarios y de casos borde.
- [ ] Test de contrato si cruza una frontera.
- [ ] `cargo clippy` / `spotless` sin warnings.
- [ ] Cobertura de producción no baja.
- [ ] Documentación actualizada (ADR si aplica).
- [ ] Sin `TODO` sin issue.
- [ ] Verificado con salida real, adjunta al PR.

### 8.2. DoD global

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `./scripts/check-file-size.sh`
- [ ] `python3 ./scripts/coverage-production.py`
- [ ] `cargo audit`
- [ ] `pnpm --dir crates/sw-gui install --frozen-lockfile`
- [ ] `pnpm --dir crates/sw-gui check`
- [ ] `pnpm --dir crates/sw-gui test`
- [ ] `pnpm --dir crates/sw-gui build`
- [ ] `cargo check --manifest-path crates/sw-gui/src-tauri/Cargo.toml --locked`
- [ ] `git diff --exit-code crates/sw-gui/src/lib/types/generated/`
- [ ] `git status --porcelain` vacío

### 8.3. Evidencia

- [ ] El PR incluye la salida de cada comando, no un resumen.
- [ ] Los jobs de CI enlazados están en verde.
- [ ] Las excepciones de `cargo audit` están justificadas y con fecha.

---

## 9. Deuda técnica: cierre o diferimiento

El plan **no** cierra toda la deuda funcional. `docs/deuda-tecnica.md` tiene 23 fichas abiertas (2 mitigadas, 1 parcial) y 13 cerradas tras la auditoría 2026-11-13. Este plan cierra o difiere explícitamente cada una:

| DT    | Tema                                       | Disposición                                                 |
| ----- | ------------------------------------------ | ----------------------------------------------------------- |
| DT-2  | FIDO2 stub                                 | Fuera de alcance (post-MVP)                                 |
| DT-5  | GUI Tauri                                  | Parcial; se cubre en Fase 3                                 |
| DT-7  | `tokio` RUSTSEC-2026-0386                  | Fase 4: upgrade ≥1.53.3 + `cargo audit`                     |
| DT-12 | CLI SSH import/add (stub)                  | Fase 3.6 o tarea de CLI                                     |
| DT-13 | Claves SSH legacy                          | Mitigada; se mantiene el soporte dual (tipo 5 + SecureNote) |
| DT-14 | CLI notas/tarjetas/identidades             | Fuera de alcance                                            |
| DT-15 | Pwned Passwords                            | Fuera de alcance                                            |
| DT-16 | SSH legacy SecureNote                      | Mitigada; se mantiene                                       |
| DT-19 | CLI no consulta `Status` antes de `Unlock` | Diferido; documentar en README                              |
| DT-20 | `PinCache` con sleep real                  | **Cerrada** en 1.1.4 (`FakeClock`)                          |
| DT-21 | XDG Portal                                 | Fuera de alcance                                            |
| DT-22 | systemd-logind manual                      | Fuera de alcance                                            |
| DT-24 | Tests D-Bus manuales                       | Fuera de alcance                                            |
| DT-25 | 2FA Email sin verificar                    | Fuera de alcance                                            |
| DT-26 | Listado paginado                           | Fuera de alcance                                            |
| DT-33 | `From<String>` con `contains()`            | Fase 3.1.4                                                  |
| DT-34 | `json!` en `dispatch_request`              | Fase 3.1.4                                                  |
| DT-35 | `try_current` en `with_vault_agent`        | Parcial; tarea de inyección del handle                      |
| DT-36 | `Clone` + `expect` (asimétrica)            | Post-M7                                                     |
| DT-37 | `Clone` + `expect` (simétrica)             | Post-M7                                                     |
| DT-38 | `cipher.key` duplicado ×5                  | Fase 2.2.2                                                  |
| DT-39 | Tests de `sw-cli` dependen de `$HOME`      | Post-M7                                                     |
| DT-40 | `rustix 1.1.5` RUSTSEC-2026-0486           | Fase 4: upgrade ≥1.1.6                                      |
| DT-41 | `async-executor` yanked                    | Fase 4: `cargo update`                                      |
| DT-42 | 11 dependencias sin uso                    | **Cerrada** (2026-11-14)                                    |

- [ ] **9.1 — Actualizar `docs/deuda-tecnica.md`** con la disposición y el issue de cada ítem.
  - **Estado (2026-11-14):** las 23 fichas abiertas tienen disposición en la tabla
    "Auditoría 2026-11-13". Faltan los issues de GitHub para los diferidos
    (DT-2, DT-14, DT-15, DT-19, DT-21, DT-22, DT-24, DT-25, DT-26, DT-36, DT-37, DT-39).
- [ ] **9.2 — Revisar el título/subtítulo** para que no prometa “cero deuda” funcional; el alcance es deuda arquitectónica.
- [ ] **9.3 — Verificación:** ningún DT abierto queda sin disposición.

---

## 10. Orden de ejecución

1. **Fase 1** (1.1 → 1.5): primero el bug de los dos vaults y la composición única; después `Clock`, `AgentState` y rutas.
2. **Fase 2** (2.1 → 2.4): medición correcta, tests de caracterización y splits obligatorios.
3. **Fase 3** (3.1 → 3.7): DTOs y contrato antes que `ts-rs`; comandos Tauri antes que gateway; gateway antes que FSM.
4. **Fase 4** (4.1 → 4.2): scripts y CI al final, cuando ya hay algo que medir.
5. **Fase 5** (5.1 → 5.2): ADRs y README en paralelo, cerrando al final.
6. **Fase 9**: tabla de deuda y alcance.

**No se considera cerrado el plan hasta que 8.2 esté en verde en CI y 9.3 esté completo.**
