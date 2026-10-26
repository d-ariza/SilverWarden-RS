# Lecciones Aprendidas y Metodología de Trabajo

**Proyecto:** silverWarden-rs
**Fecha:** 2026-10-24
**Propósito:** Documentar los patrones de seguridad, las decisiones de diseño y las lecciones aprendidas durante el desarrollo de M1 a M4. Este documento es una guía para futuros proyectos (v2 o cualquier otro proyecto en Rust).

---

## 1. Patrones de seguridad en Rust aplicados

Durante el desarrollo de silverWarden-rs, hemos aplicado los siguientes patrones de seguridad. Deben ser la base de cualquier proyecto que maneje secretos:

### 1.1. Memoria bloqueada para secretos
- **Qué:** Usar `mlock` + `MADV_DONTDUMP` + `zeroize` para evitar que los secretos se filtren a swap o a core dumps.
- **Cómo:** Trait `LockedBuffer` con implementaciones `MemLockedBuffer` (real) y `MemoryBuffer` (para tests).
- **Dónde:** `sw-crypto/src/mem.rs`.
- **Lección:** Nunca guardes secretos en un `Vec<u8>` normal. El `Drop` debe hacer `wipe()`.

### 1.2. Comparaciones en tiempo constante
- **Qué:** Usar `subtle::ConstantTimeEq` para comparar hashes, MACs y PINs.
- **Por qué:** Evita timing attacks.
- **Dónde:** `sw-config` (verificación de PIN), `sw-crypto` (verificación de MAC).

### 1.3. Escritura atómica de archivos críticos
- **Qué:** Escribir en un archivo temporal (`tempfile`) y hacer `rename` al archivo final.
- **Por qué:** Evita corrupción si el proceso muere a mitad de escritura.
- **Dónde:** `sw-vault` (caché del vault), `sw-config` (migración).
- **Lección:** Nunca hagas `os.Remove` antes de escribir. Go lo hacía mal (bug D34).

### 1.4. Descifrado bajo demanda
- **Qué:** Guardar los datos cifrados (`EncString`) en memoria y descifrar solo cuando el usuario los pide.
- **Por qué:** Minimiza la exposición de secretos en memoria.
- **Dónde:** `VaultStore` (sw-vault).
- **Lección:** No caches secretos descifrados. La `user_symmetric_key` se pasa como argumento, no se guarda en el store.

### 1.5. Rechazo de root
- **Qué:** Si el cliente del agente es `uid == 0`, rechazar la conexión.
- **Por qué:** Root no debe interactuar con el agente de usuario.
- **Dónde:** `CallingContext` (sw-systemauth).

### 1.6. Sockets Unix con permisos restrictivos
- **Qué:** Crear el socket con permisos `0600` (solo el usuario dueño puede conectarse).
- **Dónde:** `sw-agent` (run_agent).

### 1.7. RNG seguro
- **Qué:** Usar `OsRng` (entropía del SO) para IVs y claves, no `thread_rng`.
- **Dónde:** `sw-crypto/src/cipher.rs` (IVs), `sw-crypto/src/asymmetric.rs` (generación de claves).

### 1.8. Validación de padding completa
- **Qué:** En PKCS#7, verificar que **todos** los bytes de padding son iguales a `n` (no solo el último).
- **Por qué:** Go solo leía el último byte (bug D20).
- **Dónde:** `sw-crypto/src/cipher.rs`.

### 1.9. Detección de socket huérfano
- **Qué:** Si el archivo del socket existe pero nadie escucha, borrarlo antes de crear uno nuevo.
- **Dónde:** `sw-agent/src/lib.rs`.

### 1.10. Wipe al bloquear
- **Qué:** Al hacer `lock`, limpiar todas las sesiones y borrar la `user_symmetric_key` de memoria.
- **Dónde:** `SessionStore::wipe()` (sw-systemauth), `VaultStore` (sw-vault).

---

## 2. Patrones de diseño que han funcionado

### 2.1. Traits para abstraer implementaciones
- `LockedBuffer`: `MemLockedBuffer` vs `MemoryBuffer`.
- `SymmetricKey`: enc + mac (64 bytes).
- `AsymmetricKey`: RSA PKCS#8.

### 2.2. Actions Registry en el agente
- `HashMap<String, Box<dyn ActionFn>>`.
- Permite añadir acciones sin tocar el `match` principal.
- Dónde: `sw-agent/src/lib.rs`.

### 2.3. Cliente HTTP con refresh automático
- `AuthenticatedClient` encapsula la lógica de token y refresh.
- Envuelve `reqwest::Client` y `Arc<Mutex<LoginToken>>`.
- Dónde: `sw-bitwarden-api/src/lib.rs`.

### 2.4. Paridad verificada con el sistema de referencia
- Vectores Go↔Rust en KDF, stretch, cipher, RSA, login, config.
- Tests de paridad con `#[test]` y datos hardcodeados.
- Dónde: `sw-crypto/tests`, `sw-bitwarden-api/src/lib.rs`.

### 2.5. GUI como cliente IPC del agente
- El agente es el único dueño del estado.
- CLI y GUI hablan el mismo protocolo (`sw-ipc`).
- Decisión D42.

---

## 3. Lecciones aprendidas (lo que haríamos distinto)

### 3.1. No confiar en el "happy path"
- El plan cambió tres veces porque no leímos el código Go completo antes de planificar.
- **Lección:** Antes de planificar una historia, leer el código de referencia completo. Extraer vectores reales antes de implementar.

### 3.2. "Sin evidencia no hay aprobación"
- Varias veces el resumen de la IA afirmaba paridad sin haber ejecutado Go.
- **Lección:** El `03-ejecucion.md` debe tener salidas reales, no números inventados. La IA debe pegar la salida de los comandos.

### 3.3. Separar "funcional" de "seguro"
- Go tiene bugs (padding, migración, sesiones). Rust los ha corregido.
- **Lección:** Copiar funcionalidad, no bugs. Si el sistema de referencia tiene un fallo, corregirlo (D20, D34, D36).

### 3.4. Tests con vectores reales, no sintéticos
- Los vectores de Go han salvado el proyecto.
- **Lección:** Cada historia criptográfica debe tener un test de paridad con el sistema de referencia.

### 3.5. Cobertura no es calidad
- 97% de cobertura no garantiza que no haya bugs. Los tests de paridad sí.

### 3.6. No mezclar capas
- `sw-crypto` no sabe de HTTP. `sw-bitwarden-api` no sabe de memoria bloqueada.
- **Lección:** Cada crate tiene una responsabilidad.

### 3.7. Documentar los bugs corregidos
- Los bugs de Go (D20, D34, D36) están documentados en el plan.
- **Lección:** Si corriges un bug del sistema de referencia, documéntalo para que no se pierda el contexto.

---

## 4. Checklist de seguridad para futuros proyectos Rust

Antes de empezar un proyecto que maneje secretos, verificar:

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

---

## 5. Metodología de trabajo

### 5.1. Fases
- **Fase 1 — Conceptualización:** entender el problema.
- **Fase 2 — Planificación:** plan cerrado, backlog, decisiones.
- **Fase 3 — Implementación:** historia por historia, con evidencia.
- **Fase 4 — Validación:** verificación integral antes de cerrar un milestone.

### 5.2. Ciclo de una historia
1. Leer el código Go completo de referencia.
2. Extraer vectores reales (si aplica).
3. Planificar la historia con decisiones de diseño.
4. Implementar.
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

---

## 6. Para la v2 (futuro)

Estos patrones deben ser la base de la v2 (si se hace). La v2 debería:
- Analizar los patrones de diseño de silverWarden-rs.
- Mejorar la abstracción (por ejemplo, un trait `BitwardenClient` que abstraiga HTTP y WS).
- Añadir más tests de integración (E2E con servidor real).
- Documentar la API pública de cada crate.
- Añadir benchmarks de rendimiento.
