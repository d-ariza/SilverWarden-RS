# Backlog — silverWarden-rs (MVP)

**Fecha:** 2026-10-12 · **Estado general:** 🟡 Propuesto — pendiente aprobación
**Convenciones:** ID `SW-NNN` · Estados: `Pendiente` / `En curso` / `En revisión` / `Hecho` / `Bloqueado`
**Prioridad:** P0 (MVP) > P1 (post-MVP inmediato) > P2 (post-MVP lejano)
**Camino crítico MVP:** M1 → M2 → M3 → M4 → M5 (cripto → migración → agente → vault/API → SSH agent)
**Interfaz del MVP:** CLI (`silverwarden`). La GUI Tauri es post-MVP.
**Licencia:** GPL-3.0

## Reglas de cierre (aplican a todas las historias)

Una historia pasa a `Hecho` solo cuando:

1. Todos sus criterios de aceptación se cumplen y están verificados.
2. Los controles obligatorios del plan pasan: `cargo test` (100%), cobertura (≥85% global núcleo, ≥90% en `sw-crypto`), `clippy -D warnings` (0), `rustfmt --check` (0), `cargo audit` (0 crit/high).
3. Hay evidencia registrada en `docs/03-ejecucion.md`: comandos ejecutados y su salida real.
4. El usuario revisa y acepta el incremento.
5. No se reporta como exitoso nada que no se haya ejecutado. `No ejecutado` ≠ `Aprobado`.

---

## M1 — Núcleo criptográfico `sw-crypto` (P0 — MVP)

### [SW-001] Memoria segura bloqueada

**Historia:** Como desarrollador de silverWarden-rs, quiero una abstracción de memoria bloqueada para que los secretos (claves, contraseñas, PIN) no se filtren a swap ni a core dumps.

**Alcance:** trait `LockedBuffer` con dos implementaciones: `MemLockedBuffer` (mlock + MADV_DONTDUMP vía `rustix` + `zeroize`) y `MemoryBuffer` (sin mlock, paridad con el flag `useMemguard=false` de Go). Wipe explícito. Tests.

**Criterios de aceptación:**
- Existe el trait y las dos implementaciones; compilan en Linux.
- Test que verifica que el buffer bloqueado no aparece en core dump (o que mlock se invoca).
- `wipe()` pisa los bytes (verificado por test que comprueba que el contenido ya no es el original).
- `zeroize` se invoca en `Drop`.

**Cierre:** los 4 criterios pasan en CI; cobertura del crate ≥90%; evidencia en `03-ejecucion.md`.

**Depende de:** — · **Estado:** Hecho

---

### [SW-002] EncString: parser y serializador

**Historia:** Como núcleo criptográfico, quiero parsear y serializar `EncString` con el formato exacto de Bitwarden, para poder leer y escribir datos cifrados compatibles.

**Alcance:** tipo `EncString` con formato `tipo.iv|ct|mac` en base64; tipos 0 (`AesCbc256_B64`), 1 (`AesCbc128_HmacSha256_B64`), 2 (`AesCbc256_HmacSha256_B64`); errores en formatos inválidos; `IsNull()`.

**Criterios de aceptación:**
- Roundtrip parse→serialize con strings reales extraídos de un vault.
- Rechaza tipos desconocidos y partes faltantes con error tipado.
- `IsNull()` equivalente al de Go.
- Fuzz target sin crashes en corpus semilla.

**Cierre:** criterios pasan; fuzz target en repo; evidencia en `03-ejecucion.md`.

**Depende de:** — · **Estado:** Hecho

---

### [SW-003] KDF Bitwarden (argon2id / pbkdf2)

**Historia:** Como núcleo criptográfico, quiero derivar la master key desde la contraseña maestra con los parámetros que envía el servidor, para autenticarme igual que el cliente oficial.

**Alcance:** derivación según `KDFConfig` de prelogin (argon2id y pbkdf2), paridad de parámetros con Go.

**Criterios de aceptación:**
- Vectores de prueba conocidos de Bitwarden producen la misma master key que el código Go.
- Soporta ambos tipos de KDF (argon2id, pbkdf2).
- Parámetros (t, m, p, salt) leídos del prelogin, no hardcodeados.

**Cierre:** vectores cruzados Go↔Rust pasan; evidencia en `03-ejecucion.md`.

**Depende de:** SW-001 · **Estado:** Hecho (2026-10-13)

---

### [SW-004] Jerarquía de claves (HKDF stretch)

**Historia:** Como núcleo criptográfico, quiero derivar las claves de cifrado y MAC desde la master key, para descifrar el vault.

**Alcance:** `stretchKey` con HKDF-SHA256 (paridad con `keyhierarchy.go`), claves enc/mac de 32 bytes.

**Criterios de aceptación:**
- Bytes idénticos a Go para la misma entrada.
- Claves enc y mac separadas correctamente.

**Cierre:** vectores cruzados pasan; evidencia en `03-ejecucion.md`.

**Depende de:** SW-003 · **Estado:** Hecho (2026-10-13)

---

### [SW-005] Cifrado simétrico EncryptWith/DecryptWith

**Historia:** Como núcleo criptográfico, quiero cifrar y descifrar con AES-CBC-256 + HMAC-SHA256, para leer y escribir datos del vault con paridad criptográfica.

**Alcance:** AES-CBC-256 + PKCS7; verificación HMAC-SHA256 (msg = IV‖CT) antes de descifrar; tipo 0 sin MAC (warning, como Go).

**Criterios de aceptación:**
- Roundtrip encrypt→decrypt.
- MAC inválida → error (no se descifra).
- Mismo ciphertext que Go para mismo plaintext/IV en vector fijo.
- Fuzz target sin crashes.

**Cierre:** criterios pasan; evidencia en `03-ejecucion.md`.

**Depende de:** SW-002, SW-004 · **Estado:** Hecho (2026-10-13)

---

### [SW-006] RSA legacy OAEP-SHA1

**Historia:** Como núcleo criptográfico, quiero descifrar claves asimétricas legacy de Bitwarden, para poder descifrar el `encKey` de una cuenta que lo use.

**Alcance:** `EncryptWithAsymmetric`/`DecryptWithAsymmetric` con claves PKCS#8/PKIX, prefijo `4.` base64 (paridad `encstring.go`).

**Criterios de aceptación:**
- Descifra un `encKey` real de sync de Bitwarden (fixture de prueba, sin secretos reales).
- Formato de salida compatible con Go.

**Cierre:** criterio pasa con fixture; evidencia en `03-ejecucion.md`.

**Depende de:** SW-001 · **Estado:** Hecho (2026-10-13)

---

### [SW-007] Suite de fuzzing en sw-crypto

**Historia:** Como responsable de calidad, quiero fuzzing continuo en los parsers criptográficos, para detectar crashes y comportamientos inesperados antes de producción.

**Alcance:** targets fuzz para parser EncString y `DecryptWith`; corpus semilla en repo; ejecución 5 min en CI main.

**Criterios de aceptación:**
- Al menos 2 targets fuzz activos.
- CI corre 5 min en main sin crashes.
- Corpus semilla versionado.

**Cierre:** CI verde con fuzz; evidencia en `03-ejecucion.md`.

**Depende de:** SW-002, SW-005 · **Estado:** Hecho (2026-10-13)

---

### Estado de M1

| Historia | Estado |
|---|---|
| SW-001 Memoria segura | ✅ Hecho |
| SW-002 EncString | ✅ Hecho |
| SW-003 KDF | ✅ Hecho |
| SW-004 Jerarquía de claves | ✅ Hecho |
| SW-005 Cifrado simétrico | ✅ Hecho |
| SW-006 RSA legacy | ✅ Hecho |
| SW-007 Fuzzing | ✅ Hecho |

*7 de 7 de M1 completadas. Milestone M1 (Criptografía y Memoria Segura) 100% completado.*


---

## M2 — Config + migración `sw-config` (P0 — MVP)

### Decisiones técnicas aplicadas (M2)

- **D30:** KDF del config usa **Argon2i** (no id), $t=2, m=2048\text{ (2 GiB)}, p=8$ con salt = bytes de `DeviceUUID`.
- **D31:** Cifrado ChaCha20-Poly1305 con **formato Tink exacto** (cabecera de 5 bytes: `0x00` + key ID 4 bytes `0x00000000` + nonce 12 bytes + ciphertext + tag Poly1305 16 bytes). Implementación con crate `tink-rust` o wrapper `TinkChaCha20Poly1305` sobre RustCrypto. Los strings cifrados en `goldwarden.json` son este blob binario codificado en base64.
- **D32:** `ConfigKeyHash` = `hex(SHA3-256(key_derivado))` con verificación y comparación en tiempo constante (`subtle::ConstantTimeEq`).
- **D33:** Escritura atómica de archivos (archivo temporal + rename atómico) para evitar el bug de pérdida o corrupción de datos de Go.
- **D34:** La migración de ruta legacy devuelve `Ok` si el rename tiene éxito, corrigiendo el bug de Go que devolvía error tras mover el archivo.
- **D35:** `SW-013` realiza la migración del estado local con backup. La descarga y sincronización completa de claves SSH y ciphers se realiza en M4 (`silverwarden sync`), usando el export de Bitwarden como base.

---

### [SW-010] Estructura ConfigFile con serde

**Historia:** Como usuario migrante, quiero que silverWarden-rs lea y escriba mi `goldwarden.json` existente sin pérdida de datos, para mantener compatibilidad total con la configuración de Goldwarden.

**Alcance:**
- Struct `ConfigFile` con los 13 campos exactos del código Go (`IdentityUrl`, `ApiUrl`, `NotificationsUrl`, `VaultUrl`, `DeviceUUID`, `EncryptedClientID`, `EncryptedClientSecret`, `EncryptedPin`, `ConfigKeyHash`, `LoginToken`, `RuntimeConfig`, `DeviceName`, `LastSynced`).
- Struct `LoginToken` con los 5 campos JSON (`AccessToken`, `ExpiresIn`, `TokenType`, `RefreshToken`, `Key`).
- Struct `RuntimeConfig` para configuración en tiempo de ejecución.
- Serde: `#[serde(rename_all = "PascalCase")]` para paridad exacta con el JSON de Go.
- Defaults: URLs por defecto (`vault.bitwarden.com`, etc.), `DeviceUUID` v4 aleatorio, campos cifrados como strings vacíos.
- Escritura atómica de archivos (D33): tempfile + rename en el mismo directorio.

**Criterios de aceptación:**
- Parsear el `goldwarden.json` real sin pérdida de campos.
- Verificar que el JSON se serializa y deserializa de manera idéntica y estable (roundtrip completo sin pérdida de datos).
- Defaults coinciden exactamente con los de Go.
- Escritura atómica previene corrupción de archivo.

**Cierre:** criterios pasan con fixture real y tests de roundtrip; evidencia en `03-ejecucion.md`.

**Depende de:** — · **Estado:** Hecho (2026-10-18)

---

### [SW-011] Cifrado de campos de config

**Historia:** Como usuario, quiero que mis datos sensibles en config sigan cifrados con mi PIN bajo el formato Tink ChaCha20-Poly1305, para que nadie los lea sin desbloquear y mantengan compatibilidad con Goldwarden.

**Alcance:**
- Derivación de clave (D30): `Argon2i` (variante `i`, no `id`), password = PIN, salt = bytes de `DeviceUUID`, $t=2, m=2048\text{ (2 GiB)}, p=8$.
- Hash del PIN (D32): `hex(SHA3-256(derived_key))` y verificación en tiempo constante con `subtle::ConstantTimeEq`.
- Cifrado con formato Tink exacto (D31): cabecera de 5 bytes (`0x00` + key ID `0x00000000`) + nonce de 12 bytes + ciphertext + tag Poly1305 de 16 bytes. El archivo almacena estos blobs binarios codificados en base64 estándar. Uso de `tink-rust` o wrapper `TinkChaCha20Poly1305` sobre RustCrypto.
- Métodos del config: `encrypt_string`, `decrypt_string`, `VerifyPin`, `UpdatePin`, `Unlock`.

**Criterios de aceptación:**
- Desbloquear `goldwarden.json` real con el PIN real.
- Verificar que un PIN incorrecto falla sin timing leak.
- `UpdatePin` re-deriva la clave y re-cifra todos los campos sensibles (`EncryptedClientID`, `EncryptedClientSecret`, `EncryptedPin`).
- Formato binario coincide byte a byte con Tink (5B cabecera + 12B nonce + CT + 16B tag).

**Cierre:** criterios pasan con fixture real y PIN real/inválido; evidencia en `03-ejecucion.md`.

**Depende de:** SW-001, SW-010 · **Estado:** Hecho (2026-10-18)

---

### [SW-012] Lectura + migración de path viejo

**Historia:** Como usuario con instalación previa, quiero que mi configuración se migre de `~/.config/goldwarden.json` a `~/.config/goldwarden/goldwarden.json` con permisos estrictos y sin errores, para asegurar la continuidad de mis datos.

**Alcance:**
- Detección de ruta legacy: buscar `~/.config/goldwarden.json` y moverlo a `~/.config/goldwarden/goldwarden.json`.
- Crear el directorio padre con permisos `0700`.
- Archivo con permisos `0600`.
- Arreglo de bug de Go (D34): si el archivo viejo existe, el nuevo no, y el rename es exitoso, devolver `Ok(())` (en Go retornaba error al buscar el archivo viejo tras el movimiento).

**Criterios de aceptación:**
- Probar con directorio falso y fixtures simulando rutas legacy y nuevas.
- Permisos de directorio `0700` y archivo `0600` verificados.
- Devolución limpia de `Ok(())` en rename exitoso.
- No se sobrescribe destructivamente si el archivo de destino ya existe.

**Cierre:** criterios pasan con tests de filesystem; evidencia en `03-ejecucion.md`.

**Depende de:** SW-010 · **Estado:** Hecho (2026-10-18)

---

### [SW-013] Comando `silverwarden migrate` con backup

**Historia:** Como usuario migrante, quiero un comando explícito `silverwarden migrate` que importe mi configuración local desde Goldwarden Go, cree un backup preventivo y valide el desbloqueo, indicándome los pasos siguientes para sincronizar el vault.

**Alcance:**
- Backup preventivo obligatorio: crear `goldwarden.json.bak-<timestamp>` antes de modificar nada en disco.
- Migración local: importar el config al nuevo path y verificar que se puede desbloquear con el PIN.
- Delimitación de alcance Vault y SSH (D35): dado que no residen en texto claro en disco (o no deben presumirse locales), `SW-013` concluye con el mensaje informativo: *"Configuración migrada. Ejecuta silverwarden sync (M4) para descargar tus claves SSH y contraseñas."* La descarga completa de ciphers y claves SSH se realiza en M4.

**Criterios de aceptación:**
- Backup `goldwarden.json.bak-<timestamp>` creado y verificado antes de operar.
- Migración e importación del config verificadas con desbloqueo por PIN.
- Mensaje exacto de instrucción para `silverwarden sync` (M4) emitido en stdout.
- Simulación de migración desde cero con archivo de prueba exitosa.
- Procedimiento de rollback documentado y probado.

**Cierre:** criterios pasan con simulación completa de migración; evidencia en `03-ejecucion.md`.

**Depende de:** SW-011, SW-012 · **Estado:** Hecho (2026-10-18)

---

## M3 — Agente + IPC `sw-ipc`, `sw-agent`, `sw-systemauth`, `sw-cli` (P0 — MVP)

### [SW-020] Protocolo IPC propio (`sw-ipc`)

**Historia:** Como agente y cliente CLI/GUI, quiero un protocolo IPC tipado, estructurado y versionado, para que la comunicación sea segura, robusta y libre de complejidades legacy.

**Alcance:**
- Struct `IpcMessage`:
  ```rust
  #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
  pub struct IpcMessage {
      pub action: String,       // "Status", "Unlock", etc.
      pub payload: serde_json::Value,
  }
  ```
- Framing: Prefijo de longitud `u32` big-endian seguido de JSON en UTF-8. Buffer máximo definido de 4 MB; error controlado si se excede.
- Handshake y versionado: El cliente envía la versión de protocolo en el handshake inicial; el agente valida compatibilidad de versión.
- Decisión de diseño: Protocolo IPC propio en JSON limpio (sin tabla hash FNV-1a de Go).

**Criterios de aceptación:**
- Serialización y deserialización roundtrip de `IpcMessage` con framing length-prefixed.
- Límite de buffer de 4 MB respetado estrictamente; rechazo controlado con error tipado.
- Handshake con validación de versión semántica de protocolo.
- Manejo de payloads malformados sin panics.

**Cierre:** criterios pasan con tests unitarios y de framing; evidencia en `03-ejecucion.md`.

**Depende de:** — · **Estado:** Hecho (2026-10-19)

---

### [SW-021] Socket Unix del agente (`sw-agent`)

**Historia:** Como CLI, quiero conectarme al daemon `sw-agent` a través de un socket Unix con permisos restrictivos y gestión de sockets huérfanos, para garantizar comunicaciones locales exclusivas y resilientes.

**Alcance:**
- Ruta del socket: `~/.silverwarden.sock`.
- Permisos de seguridad: creado exclusivamente con permisos Unix `0600` (solo el usuario propietario tiene acceso).
- Ciclo de conexión: el agente escucha en el socket, acepta conexiones, procesa un mensaje por conexión y responde (arquitectura request-response limpia).
- Resiliencia y casos borde: detección de socket huérfano dejado por crash o terminación abrupta; verificación activa de proceso escuchando y reemplazo limpio si está huérfano.
- Limpieza en apagado: remoción ordenada del socket al cerrar el agente.

**Criterios de aceptación:**
- Socket creado en `~/.silverwarden.sock` con permisos `0600`.
- Conexión cliente/servidor funcional con procesamiento de request-response.
- Detección y recuperación automática de sockets huérfanos inactivos sin colisión.
- Cierre ordenado y eliminación de archivo socket.

**Cierre:** criterios pasan con tests de conexión y recuperación; evidencia en `03-ejecucion.md`.

**Depende de:** SW-020 · **Estado:** Hecho (2026-10-19)

---

### [SW-022] CallingContext y resolución de procesos (`sw-systemauth`)

**Historia:** Como agente, quiero inspeccionar de forma fidedigna y segura las credenciales y la jerarquía de procesos del cliente conectado, para aplicar políticas de autorización contextuales robustas.

**Alcance:**
- Credenciales del socket peer: extracción de UID y PID mediante `nix` o `rustix` (`SO_PEERCRED`).
- Jerarquía de procesos: resolución de PPID, Grand-PPID y nombre de ejecutable leyendo `/proc/<pid>/stat`, y ruta completa mediante `/proc/<pid>/exe`.
- Caso borde Git (anclaje): si el ejecutable es `ssh` o `ssh-keygen` y su padre es `git`, el contexto se ancla al proceso `git` (paridad funcional con Go).
- Seguridad extra: si la lectura de `/proc` falla o no se tienen permisos suficientes, el contexto falla de forma segura estableciendo `authenticated: false`.

**Criterios de aceptación:**
- Extracción correcta de UID, PID, PPID, Grand-PPID y ejecutable desde el socket.
- Anclaje de contexto al proceso `git` cuando invoca comandos SSH auxiliares.
- Comportamiento seguro ante denegación o inaccesibilidad de `/proc`.

**Cierre:** criterios pasan con tests simulados de procesos y socket; evidencia en `03-ejecucion.md`.

**Depende de:** SW-021 · **Estado:** Hecho (2026-10-20)

---

### [SW-023] Session store endurecido (`sw-systemauth`)

**Historia:** Como agente, quiero gestionar sesiones de autenticación contextuales en memoria con TTL y validación estricta de jerarquía de procesos, para evitar aprobaciones redundantes sin comprometer la seguridad frente a procesos hermanos o reutilización de PIDs.

**Alcance:**
- Struct `Session`: `pid`, `ppid`, `grand_ppid`, `expires_at`, `session_type` (`AccessVault`, `SSHKey`, `Pin`). TTL estándar de 60 minutos.
- Endurecimiento de sesiones (D36 — superior a Go):
  - **Para `AccessVault` y `Pin`:** validación estricta de los 3 PIDs (PID exacto, PPID y Grand-PPID). Si el proceso muere y su PID es reciclado por el SO, la sesión expira inmediatamente.
  - **Para `SSHKey`:** coincidencia laxa por tipo de sesión (`session_type == SSHKey`) permitida **únicamente** si el ejecutable solicitante es un cliente SSH/Git conocido (`ssh`, `ssh-keygen`, `git`) para preservar la experiencia fluida de firma de commits; para cualquier otro binario, se exige validación estricta de los 3 PIDs.
- Wipe de seguridad: ante cualquier evento de bloqueo (`lock`), todas las sesiones activas en el store son purgadas de inmediato.

**Criterios de aceptación:**
- Expiración estricta por TTL (60 min).
- Coincidencia exacta de jerarquía (PID, PPID, Grand-PPID) requerida para `AccessVault` y `Pin`.
- Excepción laxa de `SSHKey` restringida a binarios `ssh`, `ssh-keygen`, `git`.
- Purga total de sesiones tras llamada a `lock`.

**Cierre:** pruebas unitarias de política de sesiones pasando; evidencia en `03-ejecucion.md`.

**Depende de:** SW-022 · **Estado:** Hecho (2026-10-20)

---

### [SW-024] Actions Registry del agente (`sw-agent`)

**Historia:** Como agente, quiero un registro modular de acciones (`ActionsRegistry`), para procesar comandos tipados despachando el estado del vault y el contexto del llamante a sus respectivos handlers.

**Alcance:**
- Definición de tipos y handlers:
  ```rust
  pub type ActionFn = Box<dyn Fn(IpcMessage, &Arc<RwLock<AgentState>>, &CallingContext) -> Result<IpcMessage, AgentError> + Send + Sync>;
  pub struct ActionsRegistry {
      actions: HashMap<String, ActionFn>,
  }
  ```
- Acciones mínimas implementadas:
  - `Status`: reporta si el vault está bloqueado/desbloqueado, versión del agente y estado general.
  - `Unlock`: recibe PIN, verifica contra `sw-config`, deriva clave y pasa a estado desbloqueado.
  - `Lock`: borra la clave de memoria (`zeroize`/`LockedBuffer`) y purga todas las sesiones en `sw-systemauth`.
  - `PinSet` / `PinUpdate`: actualiza PIN y recifra el archivo de configuración delegando en `sw-config`.
  - `ConfigGet` / `ConfigSet`: consulta y actualiza parámetros de URLs o configuración general.

**Criterios de aceptación:**
- Despacho determinista de cada acción registrada con respuesta tipada.
- Acción desconocida retorna error controlado sin panic.
- `Lock` limpia efectivamente la clave de memoria y el store de sesiones.

**Cierre:** criterios pasan con tests de registro y handlers; evidencia en `03-ejecucion.md`.

**Depende de:** SW-021, SW-023, SW-011 · **Estado:** Hecho (2026-10-20)

---

### [SW-025] CLI `silverwarden` y daemonización (`sw-cli`)

**Historia:** Como usuario, quiero interactuar con el agente a través del CLI `silverwarden` con subcomandos claros, gestión del daemon y advertencias ante procesos conflictivos, para operar mi bóveda de forma segura y sencilla.

**Alcance:**
- Subcomandos `clap`:
  - `silverwarden migrate`: migración de configuración existente con backup.
  - `silverwarden status`: consulta estado del daemon y vault.
  - `silverwarden unlock [--pin <pin>]`: desbloqueo interactivo o por parámetro.
  - `silverwarden lock`: bloqueo inmediato del vault.
  - `silverwarden pin set` / `pin update`: gestión de PIN de bóveda.
  - `silverwarden agent start`: arranca el agente (daemoniza o bucle foreground).
- Detección de daemon inactivo: si `~/.silverwarden.sock` no existe, mostrar:
  `"El agente no está corriendo. Ejecuta 'silverwarden agent start'"`
- Detección de Goldwarden Go activo (D37): si se detecta `~/.goldwarden.sock` activo, mostrar advertencia clara:
  `"Goldwarden Go está corriendo. Te recomendamos detenerlo para evitar conflictos de estado"`

**Criterios de aceptación:**
- Subcomandos de CLI funcionales contra el agente vía socket Unix.
- Mensaje informativo claro cuando el agente no está corriendo.
- Advertencia emitida si el socket legacy de Go está activo.
- Flujo manual E2E de unlock → status → lock verificado.

**Cierre:** flujo CLI manual y unitario verificado; evidencia en `03-ejecucion.md`.

**Depende de:** SW-024 · **Estado:** Hecho (2026-10-20)

---

## M4 — Vault + API Bitwarden `sw-vault`, `sw-bitwarden-api` (P0 — MVP)

**Orden de Implementación:**
1. **[SW-030]** HTTP autenticado + Refresh Token (`sw-bitwarden-api`) $\rightarrow$ Base para todo el transporte.
2. **[SW-031]** Modelos SyncData/Cipher (`sw-vault`) $\rightarrow$ Base para estructurar el vault y ciphers.
3. **[SW-033]** Login (`sw-bitwarden-api`) $\rightarrow$ Flujo de obtención de tokens y claves del perfil.
4. **[SW-032]** Sync completo + Caché en disco (`sw-vault`, `sw-bitwarden-api`) $\rightarrow$ Población del vault y persistencia offline.
5. **[SW-036]** CRUD de ciphers (`sw-bitwarden-api`, `sw-vault`) $\rightarrow$ Operaciones y filtros sobre el vault activo.
6. **[SW-035]** Websocket de notificaciones (`sw-bitwarden-api`) $\rightarrow$ Sincronización en tiempo real vía hub.
7. **[SW-034]** 2FA (`sw-bitwarden-api`) $\rightarrow$ Integración de TOTP/Email en login (FIDO2 diferido).

---

### [SW-030] HTTP autenticado + refresh de token

**Historia:** Como núcleo de API, quiero un cliente REST autenticado con refresh automático, para que las operaciones contra el servidor no fallen por token caducado.

**Crate:** `sw-bitwarden-api`.  
**Dependencias:** `reqwest` (workspace), `tokio`, `serde_json`, `base64` (Auth-Email).

**Diseño técnico:**
- Struct `AuthenticatedClient` que envuelve un `reqwest::Client` y un `Arc<Mutex<LoginToken>>`.
- Método `fetch_with_auth(&self, method, url, body) -> Result<Response, ApiError>`.
- Inyección estricta de headers:
  - `Authorization: Bearer <token>`
  - `User-Agent: silverwarden/0.0.1`
  - `Device-Type: 10`
  - `Bitwarden-Client-Name: silverwarden`
  - `Bitwarden-Client-Version: 0.0.1`
- Si el cuerpo es `url::FormUrlEncoded`, añade cabecera `Auth-Email: base64(email)`.
- Si la respuesta es `401 Unauthorized`, realiza refresh automático del token protegido con `Mutex` (evitando ráfagas concurrentes) y reintenta la petición.

**Criterios de aceptación:**
- Mock server (wiremock/httpmock) simulando 401 y reintento exitoso 200.
- Headers exactos verificados.
- Token refrescado y persistido en memoria.

**Depende de:** SW-010 · **Estado:** Hecho (2026-10-24)

---

### [SW-031] Modelos SyncData/Cipher

**Historia:** Como núcleo de vault, quiero modelar toda la jerarquía de sync con paridad estricta con Bitwarden y Goldwarden Go, para representar el vault en memoria con fidelidad.

**Crate:** `sw-vault`.  
**Diseño técnico:**
- Structs serde con paridad de Go: `SyncData`, `Profile`, `Organization`, `Folder`, `Cipher`, `LoginCipher`, `Card`, `Identity`, `SSHKeyCipher`, `Field`, `URI`.
- Inclusión de `#[serde(default)]` en campos opcionales y `#[serde(rename_all = "camelCase")]` (wire format de Bitwarden).
- Soporte e integración nativa con `EncString` (SW-002) para todos los campos cifrados.

**Criterios de aceptación:**
- Deserialización completa y sin pérdidas de un JSON real de `/sync`.
- Serialización y deserialización roundtrip estable.
- Campos desconocidos o extensiones manejados sin panic.

**Depende de:** SW-002 · **Estado:** Hecho (2026-10-24)

---

### [SW-033] Login

**Historia:** Como usuario, quiero iniciar sesión con contraseña maestra y correo, derivando las claves necesarias para autenticarme y descifrar la clave simétrica del usuario.

**Crate:** `sw-bitwarden-api`.  
**Diseño técnico:**
- `prelogin(email) -> Result<KdfConfig, ApiError>`: `POST /accounts/prelogin`.
- `derive_master_key(password, email, kdf_config)`: delega en `sw_crypto::derive_master_key`.
- `derive_master_password_hash(master_key, password) -> String`: PBKDF2-HMAC-SHA256 con 1 iteración sobre bytes de masterKey y password, codificado en base64 (paridad exacta con Go).
- `login_with_password(email, master_password_hash, device_uuid) -> Result<LoginToken, ApiError>`:
  - `POST /connect/token` con `grant_type=password`, `client_id=web`, `scope=api offline_access`, `deviceType=10`, `deviceIdentifier=device_uuid`, `deviceName=firefox`.
- `decrypt_enc_key(enc_key_str, user_symmetric_key)`: descifrado con `sw_crypto` para obtener la `UserSymmetricKey` a partir de la `Key` del perfil.
- Persistencia de `LoginToken` y `UserSymmetricKey` en `sw-config` cifrados con el PIN.

**Criterios de aceptación:**
- Mock server simulando prelogin y login exitoso.
- Verificación de derivación del master password hash (1 iteración PBKDF2).
- Descifrado de la clave del perfil.

**Depende de:** SW-030, SW-011, SW-003 · **Estado:** En progreso (Parte 1: Login con mock server Hecho 2026-10-24; Parte 2: Persistencia/IPC pendiente)

---

### [SW-032] Sync completo + caché en disco

**Historia:** Como usuario, quiero sincronizar mi bóveda y conservarla en caché local con permisos restringidos, permitiendo operación rápida y offline.

**Crate:** `sw-vault` y `sw-bitwarden-api`.  
**Diseño técnico:**
- `DoFullSync(client, config, vault) -> Result<(), VaultError>`:
  - `GET /sync` vía `AuthenticatedClient`.
  - Deserialización en `SyncData`.
  - Persistencia en disco en `~/.cache/silverwarden/vault.json` con permisos `0600` (escritura atómica tempfile + rename).
  - Carga de los `EncString` en memoria (sin descifrar masivamente) en `VaultStore` (`HashMap<Uuid, Cipher>`).
- Métodos `load_from_disk()` y `save_to_disk()`.

**Criterios de aceptación:**
- Sync completo contra mock server.
- Verificación de archivo `~/.cache/silverwarden/vault.json` con permisos 0600.
- Carga íntegra de ciphers en memoria.

**Depende de:** SW-030, SW-031, SW-033 · **Estado:** Hecho (2026-10-24)

---

### [SW-036] CRUD de ciphers

**Historia:** Como usuario, quiero consultar, filtrar y gestionar ciphers de mi bóveda, sincronizando modificaciones con el servidor.

**Crate:** `sw-bitwarden-api` y `sw-vault`.  
**Diseño técnico:**
- Operaciones REST vía `fetch_with_auth`:
  - `get_cipher(uuid)`
  - `post_cipher(cipher)`
  - `put_cipher(uuid, cipher)`
  - `delete_cipher(uuid)`
- Filtros locales en `VaultStore`:
  - `get_logins_by_filter(name, username, uri)`: itera sobre los ciphers en memoria, descifrando campos bajo demanda para evaluar coincidencias.

**Criterios de aceptación:**
- Mock server validando ciclo CRUD completo (GET, POST, PUT, DELETE).
- Pruebas unitarias de filtros locales con descifrado bajo demanda.

**Depende de:** SW-032 · **Estado:** Hecho (2026-10-24)

---

### [SW-035] Websocket de notificaciones

**Historia:** Como usuario, quiero recibir notificaciones push en tiempo real, para que mi bóveda se actualice inmediatamente cuando ocurran cambios en otros clientes.

**Crate:** `sw-bitwarden-api`.  
**Diseño técnico:**
- `run_websocket_daemon(client, config, vault)`:
  - Conexión a `wss://<notifications_url>/hub?access_token=<token>`.
  - Handshake inicial: `{"protocol":"messagepack","version":1}` con delimitador de registro `0x1e`.
  - Lectura asíncrona de tramas con `tokio-tungstenite`.
  - Deserialización de payloads MessagePack con `rmp-serde`.
  - Despacho de eventos: `SyncCiphers` $\rightarrow$ full sync, `SyncCipherUpdate` $\rightarrow$ fetch y actualización puntual de cipher.
  - Mecanismo de reconexión con backoff exponencial ante pérdidas de conexión.

**Criterios de aceptación:**
- Mock server websocket emitiendo handshake y evento `SyncCipherUpdate`.
- Actualización reactiva del vault en memoria.
- Tolerancia a desconexiones y reintentos.

**Depende de:** SW-030, SW-032 · **Estado:** Hecho (2026-10-25)

---

### [SW-034] 2FA

**Historia:** Como usuario con doble factor de autenticación configurado, quiero autenticarme mediante TOTP o correo electrónico.

**Crate:** `sw-bitwarden-api`.  
**Diseño técnico:**
- Detección de requerimiento 2FA en respuesta de login (`TwoFactor`).
- Extracción de métodos disponibles (TOTP, Email).
- Soporte para TOTP (`twoFactorProvider = 0`) y Email (`twoFactorProvider = 1`):
  - Solicitud de código y re-envío a `POST /connect/token` con `twoFactorToken` y `twoFactorProvider`.
- FIDO2 (`twoFactorProvider = 4`): stub con `todo!()` y mensaje informativo para versión posterior.

**Criterios de aceptación:**
- Mock server simulando desafío 2FA TOTP con código válido e inválido.
- Manejo claro de errores en códigos expirados/incorrectos.

**Depende de:** SW-033 · **Estado:** Hecho (2026-10-25)

---

## M5 — SSH agent `sw-ssh-agent` (P0 — MVP — OBLIGATORIO)

### [SW-040] Servidor ssh-agent

**Historia:** Como usuario, quiero que silverWarden-rs exponga un ssh-agent, para usar mis claves del vault sin exportarlas a disco.

**Alcance:** socket `~/.goldwarden-ssh-agent.sock`, protocolo binario length-prefixed OpenSSH agent (REQUEST_IDENTITIES, SIGN_REQUEST, etc.).

**Criterios de aceptación:**
- `ssh-add -L` funciona contra el socket.
- Protocolo cumple el wire format OpenSSH.
- Mensajes malformados → error controlado.

**Cierre:** criterio pasa con OpenSSH real; evidencia en `03-ejecucion.md`.

**Depende de:** SW-021, SW-032 · **Estado:** Pendiente

---

### [SW-041] List de claves del vault

**Historia:** Como usuario, quiero ver mis claves SSH del vault listadas por el agente, para saber cuáles tengo disponibles.

**Alcance:** parseo de claves privadas OpenSSH del vault (notas con `custom-type: ssh-key` y ciphers SSHKey), comentario = nombre.

**Criterios de aceptación:**
- Mismas claves visibles que con el agente Go en la misma cuenta.
- Comentario = nombre de la clave.
- Claves no parseables → error claro, no panic.

**Cierre:** comparación con agente Go verificada; evidencia en `03-ejecucion.md`.

**Depende de:** SW-040 · **Estado:** Pendiente

---

### [SW-042] Sign + SignWithFlags

**Historia:** Como usuario, quiero firmar con mis claves del vault (incluido git), para autenticarme en SSH y firmar commits sin exportar claves.

**Alcance:** firma con flags rsa-sha2-256/512; detección de firma git (prefijo `SSHSIG`); default según clave.

**Criterios de aceptación:**
- `ssh -T git@github.com` funciona con clave del vault.
- `git commit -S` firma correctamente.
- Flags RSA sin regresión.

**Cierre:** criterios pasan con OpenSSH/git reales; evidencia en `03-ejecucion.md`.

**Depende de:** SW-041 · **Estado:** Pendiente

---

### [SW-043] Aprobación y sesiones SSH

**Historia:** Como usuario, quiero que la primera firma pida aprobación y las siguientes dentro de la sesión no, para no aprobar en cada operación.

**Alcance:** pinentry de aprobación con mensaje de contexto (paridad formato Go), sesión SSH 60 min, biometría/PIN fallback.

**Criterios de aceptación:**
- Primera firma pide aprobación.
- Segunda firma dentro de la sesión no pide.
- Mensaje de aprobación idéntico al de Go.
- Sesión expira a los 60 min.

**Cierre:** criterios pasan; evidencia en `03-ejecucion.md`.

**Depende de:** SW-042, SW-023 · **Estado:** Pendiente

---

### [SW-044] Interop y regresión SSH

**Historia:** Como responsable de calidad, quiero una suite que compare el comportamiento del agente Rust con el Go, para garantizar que no hay regresiones funcionales.

**Alcance:** pruebas contra OpenSSH real (`ssh-add`, `ssh-keygen -Y sign`) + comparación con agente Go.

**Criterios de aceptación:**
- Evidencia en `docs/03-ejecucion.md`.
- 0 diferencias funcionales en los casos probados.
- Casos límite documentados.

**Cierre:** criterios pasan; evidencia registrada.

**Depende de:** SW-043 · **Estado:** Pendiente

---

## Post-MVP (P1 / P2 — se detallan cuando se aborden)

Estos milestones **no** forman parte del cierre del MVP. Se listan para no perderlos.

### M6 — Seguridad de sesión y sistema (P1)
- [SW-050] PIN + pincache en agente
- [SW-051] Biometría polkit (trait `Biometrics`)
- [SW-052] Lock por inactividad
- [SW-053] Notificaciones (portal libportal)
- [SW-054] Setup systemd + verificación polkit

### M7 — GUI Tauri (P1)
- [SW-060] Scaffold Tauri v2 + Svelte 5 + TS
- [SW-061] Ventana login
- [SW-062] Quickaccess
- [SW-063] Settings
- [SW-064] Diálogos pinentry/approval

### M8 — Autotipo + TOTP UI (P2)
- [SW-070] TOTP
- [SW-071] Autotipo X11 (x11rb/XTest)
- [SW-072] Autotipo libportal

### M9 — Browser biometrics (P2)
- [SW-080] Bridge native-messaging
- [SW-081] Instalación/detección de navegadores
- [SW-082] E2E con extensión Bitwarden en Chrome

### M10 — Portabilidad y empaquetado (P2)
- [SW-090] macOS (TouchID, sockets, notificaciones, .dmg)
- [SW-091] Windows viable (CI check)
- [SW-092] Publicación crates.io
- [SW-093] Flatpak
- [SW-094] Migración a repo propio silverWarden-rs
- [SW-095] Release process
- **[SW-096] Documento de lecciones aprendidas y patrones de seguridad** (P2)
  - **Objetivo:** Crear `docs/lecciones-aprendidas.md` con los patrones de seguridad, diseño y metodología de trabajo.
  - **Criterios de cierre:** Documento creado, revisado y commiteado.
  - **Depende de:** M1–M4 (para tener contexto).
  - **Estado:** Hecho (2026-10-24) — ver `docs/lecciones-aprendidas.md`.

- **[SW-097] Checklist de seguridad para futuros proyectos** (P2)
  - **Objetivo:** Añadir el checklist de seguridad al `README.md` o a un documento separado.
  - **Criterios de cierre:** Checklist visible y referenciado.
  - **Depende de:** SW-096.
  - **Estado:** Hecho (2026-10-24) — incluido en `docs/lecciones-aprendidas.md`.

---

## Métricas del backlog

- **MVP:** 24 historias (M1: 7, M2: 4, M3: 6, M4: 7, M5: 5... ajustar al conteo real)
- **Post-MVP:** 20 tareas listadas sin detallar
- **Definición de avance:** una historia pasa a `Hecho` solo con evidencia de sus criterios + controles obligatorios del plan.