# Lecciones Aprendidas y Metodología de Trabajo

**Proyecto:** silverWarden-rs
**Fecha:** 2026-10-26
**Propósito:** Documentar principios generales de seguridad, diseño y metodología de trabajo en proyectos Rust que manejan secretos. Cada principio se ilustra con un ejemplo concreto de silverWarden-rs (entre paréntesis), pero la lección es aplicable a cualquier proyecto.

---

## 1. Principios de seguridad en Rust

### 1.1. Los secretos deben vivir en memoria bloqueada
**Principio:** Cualquier secreto (claves, contraseñas, PINs, tokens) debe almacenarse en un buffer que:
- Bloquee la memoria física (`mlock`) para evitar que se escriba a swap.
- Se excluya de los core dumps (`MADV_DONTDUMP`).
- Se borre explícitamente (`zeroize`) al liberarse o al bloquear.

**Ejemplo:** El trait `LockedBuffer` con `MemLockedBuffer` (real) y `MemoryBuffer` (para tests) en `sw-crypto/src/mem.rs`. Nunca se guarda una clave en un `Vec<u8>` normal.

**Lección:** Si el secreto no está en un `LockedBuffer` desde el día 1, es muy difícil migrarlo después. Hazlo parte de la arquitectura inicial.

### 1.2. Comparaciones de secretos en tiempo constante
**Principio:** Comparar hashes, MACs, PINs y tokens con `subtle::ConstantTimeEq`, nunca con `==`. El tiempo de comparación no debe filtrar información.

**Ejemplo:** `sw-config` verifica el PIN con `ConstantTimeEq`; `sw-crypto` verifica MACs con `ConstantTimeEq`.

**Lección:** Es fácil olvidar una comparación. Usa un linter o una revisión de código que busque `==` en contextos de secretos.

### 1.3. Escritura atómica de archivos críticos
**Principio:** Para archivos que contienen secretos o estado crítico, escribir en un archivo temporal (`tempfile`) y hacer `rename` al archivo final. Nunca borrar el archivo original antes de escribir el nuevo.

**Ejemplo:** El caché del vault (`sw-vault`) y la migración de config (`sw-config`) usan `tempfile` + `rename` con permisos `0600`.

**Lección:** El sistema de referencia (Go) borraba el archivo antes de escribir. Si el proceso moría a mitad, el archivo se perdía. Corregirlo es trivial y evita pérdida de datos.

### 1.4. Descifrado bajo demanda
**Principio:** No descifres todos los secretos al cargar. Guarda los datos cifrados en memoria y descifra solo cuando el usuario (o el agente) los pide. La clave de descifrado no se guarda en el store; se pasa como argumento.

**Ejemplo:** `VaultStore` guarda `EncString` (cifrados) y descifra bajo demanda cuando `decrypt_cipher` o `search` lo necesitan. La `user_symmetric_key` se pasa como argumento.

**Lección:** Cachear secretos descifrados amplía la superficie de ataque. Es mejor pagar el coste de descifrar (microsegundos) que tener secretos en memoria.

### 1.5. Rechazo de root y de conexiones no autenticadas
**Principio:** Un agente que sirve secretos a un usuario no debe aceptar conexiones de `root` (uid 0) ni de procesos no autenticados. Si el cliente no se puede identificar, rechazar.

**Ejemplo:** `CallingContext` en `sw-systemauth` rechaza `uid == 0` y devuelve `error: true` si no puede leer `/proc`.

**Lección:** Es fácil olvidar que `root` puede conectarse a un socket Unix. Rechazarlo explícitamente es una defensa simple y efectiva.

### 1.6. Sockets con permisos restrictivos
**Principio:** Los sockets Unix que sirven secretos deben tener permisos `0600` (solo el usuario dueño puede conectarse). El archivo debe limpiarse si queda huérfano.

**Ejemplo:** `sw-agent` crea `~/.silverwarden.sock` con `0600` y limpia sockets huérfanos. `sw-ssh-agent` hace lo mismo con `~/.silverwarden-ssh-agent.sock`.

**Lección:** Un socket con permisos `0777` es una puerta abierta. El valor por defecto de `UnixListener` no es `0600`; hay que asignarlo explícitamente.

### 1.7. RNG del sistema operativo
**Principio:** Para IVs, nonces, claves y sales, usar `OsRng` (entropía del SO), nunca `thread_rng` ni un RNG predecible.

**Ejemplo:** `sw-crypto` usa `OsRng` en `cipher.rs` (IVs) y `asymmetric.rs` (generación de claves).

**Lección:** `thread_rng` es un CSPRNG, pero `OsRng` es más directo y no depende del estado del hilo. Para secretos, `OsRng` es la opción correcta.

### 1.8. Validación completa de padding
**Principio:** En PKCS#7, verificar que **todos** los bytes de padding son iguales a `n`, no solo el último. Un padding inconsistente es un indicador de ataque.

**Ejemplo:** `sw-crypto/src/cipher.rs` valida todos los bytes. Go solo leía el último (bug D20).

**Lección:** Los bugs de validación de padding son clásicos. Verificar el padding completo es trivial y evita ataques de padding oracle.

### 1.9. Wipe al bloquear
**Principio:** Al bloquear el vault, limpiar todas las sesiones, borrar la clave de descifrado de memoria y cerrar cualquier conexión activa.

**Ejemplo:** `SessionStore::wipe()` (sw-systemauth) y `VaultStore::clear()` (sw-vault) al hacer `lock`.

**Lección:** El `wipe` debe ser explícito y verificable (test que comprueba que el buffer es cero después de `wipe`).

### 1.10. Verificar dependencias críticas y CVEs
**Principio:** Antes de añadir una dependencia crítica (criptografía, SSH, TLS), verificar:
- La versión en `Cargo.toml` y en `Cargo.lock`.
- Que no tenga CVEs conocidos (usar `cargo audit`).
- Que el repo oficial esté activo y mantenido.

**Ejemplo:** `russh` se bajó inicialmente en `0.45.0` (con CVE-2026-111061). Se actualizó a `0.65.0` tras detectar la versión obsoleta con `cargo tree -p russh`.

**Lección:** `cargo tree -p <crate>` es tu amigo. Si falla, es que la crate no está en `Cargo.toml`. Y no confíes en forks (`Eugeny/russh`) cuando el repo oficial es otro (`warp-tech/russh`).

---

## 2. Patrones de diseño que funcionan

### 2.1. Traits para abstraer implementaciones
**Principio:** Usa traits para abstraer variantes de una misma funcionalidad (memoria real vs. mock, cifrado real vs. stub, etc.). Facilita los tests y la evolución.

**Ejemplo:** `LockedBuffer` (real vs. memoria normal), `SymmetricKey` (enc + mac), `AsymmetricKey` (RSA PKCS#8).

### 2.2. Registry de acciones en el agente
**Principio:** En un agente que maneja muchas acciones, usa un `HashMap<String, Box<dyn Fn>>` en lugar de un `match` gigante. Permite añadir acciones sin tocar el núcleo.

**Ejemplo:** `ActionsRegistry` en `sw-agent`.

### 2.3. Cliente HTTP con refresh automático
**Principio:** Encapsula la lógica de token y refresh en un cliente HTTP. Si una petición devuelve 401, refresca el token y reintenta automáticamente, con un `Mutex` para evitar condiciones de carrera.

**Ejemplo:** `AuthenticatedClient` en `sw-bitwarden-api`.

### 2.4. Verificar paridad con el sistema de referencia
**Principio:** Si estás reescribiendo un sistema existente, extrae **vectores reales** del sistema original y úsalos como tests. No confíes en vectores sintéticos.

**Ejemplo:** Vectores Go↔Rust en KDF, stretch, cipher, RSA, login, config. Cada historia criptográfica tiene un test de paridad con datos reales.

**Lección:** Los tests de paridad han salvado el proyecto varias veces. Sin ellos, los bugs de padding, RSA y TOTP habrían pasado desapercibidos.

### 2.5. GUI como cliente IPC del agente
**Principio:** Si tienes CLI y GUI, que ambos sean clientes del mismo agente. El agente es el único dueño del estado (vault, claves, sesiones). La GUI no accede al vault ni al servidor directamente.

**Ejemplo:** CLI (`sw-cli`) y GUI (`sw-gui`) hablan el mismo protocolo (`sw-ipc`) con el agente (`sw-agent`). El agente expone acciones como `GetLogins`, `DecryptCipher`, `ListSSHKeys`.

**Lección:** Esto simplifica la seguridad (un solo punto de descifrado) y la consistencia (un solo estado).

---

## 3. Lecciones de metodología de trabajo

### 3.1. Leer el código de referencia completo antes de planificar
**Principio:** Antes de planificar una historia, lee el código de referencia completo (no solo las firmas de funciones). Extrae los vectores reales antes de implementar.

**Ejemplo:** El plan de M1 cambió tres veces porque no leímos `kdf.go`, `keyhierarchy.go`, y `config.go` completos antes de planificar. La lección: **leer primero, planificar después**.

**Generalización:** En cualquier reescritura, dedica una sesión a leer el código original completo antes de escribir una línea de código nuevo. Ahorra retrabajo.

### 3.2. Sin evidencia no hay aprobación
**Principio:** No aceptes un resumen de la IA como evidencia. Pide la salida real de los comandos (`cargo test`, `cargo clippy`, `cargo audit`, `cargo llvm-cov`). Si no hay salida, no está hecho.

**Ejemplo:** Varias veces el resumen afirmaba "paridad ✅" sin haber ejecutado Go. La lección: **el `03-ejecucion.md` debe tener salidas reales, no números inventados**.

**Generalización:** En cualquier proyecto con IA, la IA debe pegar la salida de los comandos. El humano verifica y aprueba.

### 3.3. Copiar funcionalidad, no bugs
**Principio:** Si el sistema de referencia tiene un bug (padding incompleto, migración que devuelve error, sesiones laxas), corrígelo. No lo copies por "paridad".

**Ejemplo:** Go tenía bugs en `unpadPKCS7` (solo leía el último byte), `ReadConfig` (devolvía error tras rename exitoso), y `verifySession` (no verificaba el PID). Rust los corrigió (D20, D34, D36).

**Generalización:** La paridad funcional no significa paridad de bugs. Copia el comportamiento esperado, no los errores.

### 3.4. Secuencia de implementación como relación causal
**Principio:** Cada orden para la IA debe incluir una secuencia de pasos numerados, con la relación causal (por qué el paso 1 antes que el 2). No se pasa al siguiente paso hasta que el anterior pase los tests.

**Ejemplo:** SW-042/043 (Sign) se dividió en 6 pasos: preparar `VaultAgent`, integrar `Sign`, detectar `SSHSIG`, aprobación con pinentry, flags RSA, verificación end-to-end. Cada paso con su test.

**Generalización:** Una historia grande se divide en pasos pequeños y verificables. La secuencia evita sorpresas (como el bug de `Clone` en SW-004, que se descubrió tarde porque no había un test de `try_clone`).

### 3.5. Acabar lo acabado
**Principio:** Cada historia se cierra con todos sus criterios de aceptación cumplidos. Si algo se pospone, se documenta explícitamente en el backlog como "post-MVP" y se justifica.

**Ejemplo:** FIDO2 se pospuso a post-MVP porque requiere hardware y la crate `ctap-hid-fido2` no está madura. Se documentó en el backlog y en el análisis.

**Generalización:** No dejes deuda técnica sin documentar. "Post-MVP" es aceptable; "lo dejamos para luego" sin trazabilidad, no.

### 3.6. No mezclar capas
**Principio:** Cada crate tiene una responsabilidad. `sw-crypto` no sabe de HTTP. `sw-bitwarden-api` no sabe de memoria bloqueada. `sw-vault` no sabe de sockets.

**Ejemplo:** El proyecto tiene 13 crates, cada uno con una responsabilidad clara. La comunicación entre crates es a través de traits e interfaces bien definidas.

**Generalización:** Si un crate empieza a importar cosas de otro que no le corresponden, es señal de que hay que extraer una abstracción.

### 3.7. Documentar los bugs corregidos
**Principio:** Si corriges un bug del sistema de referencia, documéntalo (en el plan, en el código, en un ADR). Que quede claro por qué Rust se comporta distinto.

**Ejemplo:** Los bugs D20 (padding), D34 (migración), D36 (sesiones) están documentados en `02-plan.md` y en `lecciones-aprendidas.md`.

**Generalización:** Un bug corregido sin documentar es un bug que volverá. La documentación evita que alguien "arregle" el código para que coincida con el sistema de referencia.

### 3.8. La cobertura no es calidad
**Principio:** 97% de cobertura no garantiza que no haya bugs. Los tests de paridad (con vectores reales) y los tests de integración (con OpenSSH, git, servidor real) son los que detectan bugs reales.

**Ejemplo:** `sw-crypto` tenía 93% de cobertura, pero el bug de padding no se detectó hasta que se añadió un test de paridad con Go.

**Generalización:** Mide la cobertura, pero no te obsesiones. Invierte más en tests de integración y paridad que en subir el porcentaje de cobertura.

---

## 4. Checklist de seguridad para futuros proyectos

Antes de empezar un proyecto que maneje secretos, verifica:

- [ ] ¿Los secretos están en `LockedBuffer` desde el día 1?
- [ ] ¿Hay wipe al `Drop` y al bloquear?
- [ ] ¿Las comparaciones de secretos son en tiempo constante?
- [ ] ¿Los archivos críticos se escriben de forma atómica (temp + rename)?
- [ ] ¿Los sockets Unix tienen permisos `0600`?
- [ ] ¿Se rechaza `uid == 0` en el agente?
- [ ] ¿Los IVs vienen de `OsRng`?
- [ ] ¿Hay un plan de paridad con el sistema de referencia?
- [ ] ¿Cada historia tiene un test de paridad o de integración real?
- [ ] ¿El CLI y la GUI son clientes del mismo agente (un solo dueño del estado)?
- [ ] ¿Los tests tienen vectores reales, no sintéticos?
- [ ] ¿Se ha documentado cada bug corregido del sistema de referencia?
- [ ] ¿Se ha verificado que las dependencias críticas no tienen CVEs conocidos?
- [ ] ¿Se ha leído el código de referencia completo antes de planificar?

---

## 5. Metodología de trabajo

### 5.1. Fases
1. **Conceptualización:** entender el problema y el alcance.
2. **Planificación:** plan cerrado, backlog, decisiones de diseño.
3. **Implementación:** historia por historia, con evidencia real.
4. **Validación:** verificación integral antes de cerrar un milestone.

### 5.2. Ciclo de una historia
1. Leer el código de referencia completo.
2. Extraer vectores reales (si aplica).
3. Planificar la historia con decisiones de diseño.
4. Implementar (con secuencia causal de pasos).
5. Ejecutar `cargo test`, `cargo clippy`, `cargo fmt`, `cargo audit`, `cargo llvm-cov`.
6. Pegar la salida real en `03-ejecucion.md`.
7. Commit y push.
8. Actualizar `backlog.md` a `Hecho`.

### 5.3. Reglas de oro
- **Nunca** afirmar paridad sin evidencia.
- **Nunca** copiar un bug del sistema de referencia.
- **Nunca** mezclar capas (crypto ≠ HTTP ≠ vault).
- **Siempre** documentar el bug corregido.
- **Siempre** tests con vectores reales.
- **Siempre** leer el código de referencia antes de planificar.
- **Siempre** verificar CVEs de dependencias críticas.
- **Siempre** secuencia causal de pasos en las órdenes a la IA.

---

## 6. Comparativa con la competencia (visión del producto)

| Feature | Bitwarden | KeePassXC | silverWarden (objetivo) |
|---|---|---|---|
| Generar Ed25519 | ✅ | ✅ | ✅ |
| Generar RSA | ❌ | ✅ | ✅ |
| Generar ECDSA | ❌ | ✅ | ✅ |
| `Add`/`Remove` desde `ssh-add` | ❌ | ❌ | ✅ |
| Sesión SSH cacheada | ✅ | ❌ (pide cada vez) | ✅ |
| Agente real (no proxy) | ✅ | ❌ (proxy) | ✅ |
| GUI ligera (no Electron) | ❌ (Electron) | ✅ (Qt) | ✅ (Tauri) |
| CLI + TUI + GUI | ❌ | ❌ | ✅ |
| Sincronización Vaultwarden | ✅ | ❌ | ✅ |

**Lección:** silverWarden tiene una ventaja competitiva clara si cumple con la visión. Cada historia debe evaluarse contra esta tabla.

---

## 7. Para la v2 (futuro)

Estos principios deben ser la base de la v2 (si se hace). La v2 debería:
- Analizar los patrones de diseño de silverWarden-rs.
- Mejorar la abstracción (por ejemplo, un trait `BitwardenClient` que abstraiga HTTP y WS).
- Añadir más tests de integración (E2E con servidor real).
- Documentar la API pública de cada crate.
- Añadir benchmarks de rendimiento.
- Generalizar el documento de lecciones aprendidas para que sirva a cualquier proyecto (no solo a silverWarden).
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

### 8.7. La cobertura puede subir por artefacto del denominador

**Problema:** En `sw-cli`, los tests unitarios viven en el mismo `main.rs` que la producción. Al añadir 1815 líneas de tests en el commit `0eefb93`, la cobertura de `cargo llvm-cov -p sw-cli --summary-only` subió de 78.93% a 85.19%. Pero parte de esa subida es porque las líneas de test (que se ejecutan al 100%) engordan el denominador, no porque se haya cubierto más producción. La cobertura de "producción pura" no se midió y se estima inferior al 85%.

**Solución:** Para métricas honestas de cobertura de producción, mover los tests a archivos separados (`tests/` para integración, `src/tests.rs` para unitarios con `#[path]`) o usar una herramienta que excluya tests (`tarpaulin --ignore-tests`, o `llvm-cov` con `--ignore-filename-regex` apuntando a archivos separados). **No usar `--ignore-filename-regex '.*tests.*'` sobre un archivo único**: el regex se aplica al nombre del archivo, no al contenido, así que no excluye `mod tests` dentro de `main.rs` (verificado empíricamente: la métrica no cambió).

**Generalización:** Mide la cobertura, pero entiende qué mide. Un 85% de líneas con tests en el mismo archivo no es lo mismo que un 85% de líneas con tests separados. La primera métrica es vulnerable a gaming; la segunda es más honesta. Si el gate del proyecto es "≥85% según `llvm-cov --summary-only`", se cumple; si el gate es "≥85% de producción pura", hay que medirlo con otra herramienta o estructura.

### 8.8. Verificación empírica: la IA puede duplicar bloques al editar docs largos

**Problema:** Al pedir a la IA que añadiera la subsección 8.7 a `lecciones-aprendidas.md`, la IA duplicó el bloque completo `## 8. Lecciones de M5` (con 8.1 a 8.7) **dos veces** en el mismo archivo. El error se detectó al revisar `git diff` (no `git diff --stat`, que solo mostraba `+44 líneas`).

**Solución:** Cuando se pida a la IA editar un documento largo existente, exigir:
1. Primero, `git diff` del archivo antes de cualquier `git add`.
2. Verificar con `grep -c "^## <sección>"` (con anclaje `^`) que no hay duplicados.
3. No commitear hasta que el humano revise el `git diff` completo, no solo el `--stat`.

**Generalización:** `git diff --stat` miente por omisión: dice cuántas líneas cambiaron, no **qué** cambió. En documentos largos, la IA puede duplicar bloques enteros sin que el `--stat` lo delate (44 líneas duplicadas se ven como "44 líneas añadidas", no como "bloque duplicado"). La regla del proyecto "sin evidencia no hay aprobación" se aplica también a la edición de docs: **verificar el diff real, no el resumen**.

**Verificación empírica 2026-11-01:** incidente durante el cierre documental de M5. La IA duplicó `## 8. Lecciones de M5` en `lecciones-aprendidas.md` tres veces consecutivas (3 intentos en total). Se detectó con `grep -c "^## 8"` (con anclaje) y se corrigió con `git checkout` + append manual. Lección aplicada a partir de ahora: **para docs largos, usar append atómico (`cat >> file << 'EOF'`), nunca edición in-place por IA.**

### 8.9. Inyección de traits para tests sin D-Bus real

**Problema:** Al implementar `sw-notify` y la integración con D-Bus (`org.freedesktop.Notifications`), los tests unitarios en entornos de integración continua (CI) o contenedores headless fallaban porque no existía un bus de sesión D-Bus activo ni un daemon de notificaciones (`org.freedesktop.Notifications`).

**Solución:** Desacoplar la infraestructura mediante el trait `Notifier` e inyectar `Arc<dyn Notifier>` en `AgentState` y `Option<Arc<dyn Notifier>>` en `VaultAgentServer`. Proveer un `MockNotifier` en memoria con grabación atómica de eventos para verificar las llamadas sin I/O, y aislar los tests con D-Bus real en `crates/sw-notify/tests/manual_dbus.rs` marcados con `#[ignore]` para ejecución manual explícita.

**Generalización:** Cualquier integración con servicios del sistema operativo (D-Bus, sockets del sistema, biometría, demonios de escritorio) debe interactuar a través de traits inyectables. Las pruebas automatizadas estándar deben ejecutarse 100% en memoria contra mocks; las pruebas reales deben ser pruebas de integración aisladas sin romper el pipeline de CI ni distorsionar la cobertura del código productivo.


### 8.10. Manejo de señales D-Bus del sistema y temporizadores de inactividad asíncronos

**Problema:** El bloqueo automático de una bóveda de contraseñas requiere coordinar dos fuentes independientes de eventos: señales del sistema operativo (`PrepareForSleep` y `Lock` emitidas por `systemd-logind` sobre el bus de sistema) y un temporizador deslizante de inactividad de peticiones IPC. En sistemas sin `systemd` o entornos de prueba/CI sin bus de sistema accesible, el demonio no debe fallar al iniciar, y el temporizador no debe generar condiciones de carrera o contención innecesaria al acceder al estado del agente.

**Solución:**
1. Desacoplar el timestamp de actividad en `Arc<tokio::sync::RwLock<tokio::time::Instant>>` para que `handle_message` lo actualice de forma inmediata sin retener bloqueos mutables durante el procesamiento de comandos largos.
2. Emplear tareas en segundo plano (`tokio::spawn`) coordinadas con receptores `tokio::sync::broadcast` para un apagado limpio y coordinado durante el shutdown del demonio.
3. En `spawn_logind_monitor`, aplicar degradación elegante con registro de advertencia (`tracing::warn!`) y retorno limpio si el bus de sistema D-Bus o el servicio `org.freedesktop.login1` no están disponibles.
4. Desacoplar la lógica de procesamiento de eventos (`handle_logind_event`) en funciones directas sobre `Arc<RwLock<AgentState>>`, permitiendo pruebas unitarias deterministas en memoria y aislando los tests reales contra D-Bus en `tests/manual_logind.rs` con `#[ignore]`.

**Generalización:** Las dependencias del sistema operativo para eventos de ciclo de vida (suspensión, bloqueo de pantalla) deben aislarse en monitores asíncronos con fallback tolerante a fallos. La lógica de negocio que responde a los eventos debe estar desacoplada de la capa de transporte que los recibe para garantizar la testabilidad unitaria en cualquier plataforma sin dependencias de infraestructura externa.
