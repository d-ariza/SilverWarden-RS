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

**Depende de:** SW-002, SW-004 · **Estado:** Pendiente

---

### [SW-006] RSA legacy OAEP-SHA1

**Historia:** Como núcleo criptográfico, quiero descifrar claves asimétricas legacy de Bitwarden, para poder descifrar el `encKey` de una cuenta que lo use.

**Alcance:** `EncryptWithAsymmetric`/`DecryptWithAsymmetric` con claves PKCS#8/PKIX, prefijo `4.` base64 (paridad `encstring.go`).

**Criterios de aceptación:**
- Descifra un `encKey` real de sync de Bitwarden (fixture de prueba, sin secretos reales).
- Formato de salida compatible con Go.

**Cierre:** criterio pasa con fixture; evidencia en `03-ejecucion.md`.

**Depende de:** SW-001 · **Estado:** Pendiente

---

### [SW-007] Suite de fuzzing en sw-crypto

**Historia:** Como responsable de calidad, quiero fuzzing continuo en los parsers criptográficos, para detectar crashes y comportamientos inesperados antes de producción.

**Alcance:** targets fuzz para parser EncString y `DecryptWith`; corpus semilla en repo; ejecución 5 min en CI main.

**Criterios de aceptación:**
- Al menos 2 targets fuzz activos.
- CI corre 5 min en main sin crashes.
- Corpus semilla versionado.

**Cierre:** CI verde con fuzz; evidencia en `03-ejecucion.md`.

**Depende de:** SW-002, SW-005 · **Estado:** Pendiente

---

## M2 — Config + migración `sw-config` (P0 — MVP)

### [SW-010] Estructura ConfigFile con serde

**Historia:** Como usuario migrante, quiero que silverWarden-rs lea mi `goldwarden.json` existente sin pérdida de datos, para no reconfigurar nada.

**Alcance:** structs `ConfigFile`/`RuntimeConfig`/`LoginToken` con defaults idénticos a Go (URLs, DeviceUUID v4).

**Criterios de aceptación:**
- JSON de un `goldwarden.json` real parsea sin pérdida de campos.
- serialize→deserialize es estable (roundtrip).
- Defaults coinciden con Go.

**Cierre:** criterios pasan con fixture real; evidencia en `03-ejecucion.md`.

**Depende de:** — · **Estado:** Pendiente

---

### [SW-011] Cifrado de campos de config

**Historia:** Como usuario, quiero que mis datos sensibles en config sigan cifrados con mi PIN, para que nadie los lea sin desbloquear.

**Alcance:** ChaCha20-Poly1305 con clave argon2(PIN, salt=DeviceUUID, t=2, m=2GB, p=8, 32B); `ConfigKeyHash` = SHA3-256 hex; comparación en tiempo constante; `UpdatePin` re-cifra todos los campos.

**Criterios de aceptación:**
- Desbloquea un `goldwarden.json` real con su PIN.
- PIN incorrecto → false, sin timing leak evidente.
- `UpdatePin` re-cifra todos los campos (paridad con Go).

**Cierre:** criterios pasan con fixture real anonimizado; evidencia en `03-ejecucion.md`.

**Depende de:** SW-001, SW-003, SW-010 · **Estado:** Pendiente

---

### [SW-012] Lectura + migración de path viejo

**Historia:** Como usuario con instalación antigua, quiero que mi config se migre de `~/.config/goldwarden.json` a la ruta nueva, para no perderla.

**Alcance:** `ReadConfig` con migración de path (paridad Go), permisos 0700/0600.

**Criterios de aceptación:**
- Test con ambos layouts (viejo y nuevo).
- Permisos correctos tras migración.
- No se sobrescribe sin backup.

**Cierre:** criterios pasan; evidencia en `03-ejecucion.md`.

**Depende de:** SW-010 · **Estado:** Pendiente

---

### [SW-013] Comando `silverwarden migrate` con backup

**Historia:** Como usuario migrante, quiero un comando explícito que importe mi estado desde Goldwarden Go (config, vault, PIN y claves SSH), con backup automático, para poder volver atrás si algo falla.

**Alcance:** backup `goldwarden.json.bak-<ts>`; importación de config + vault + claves SSH; verificación de desbloqueo post-migración; reporte.

**Criterios de aceptación:**
- Se crea backup antes de tocar nada.
- Tras migrar, el desbloqueo con PIN funciona y el vault se lee.
- Las claves SSH importadas son visibles.
- Rollback documentado y probado: restaurar backup y arrancar Goldwarden Go funciona.
- Nada se sobrescribe sin backup verificado.

**Cierre:** criterios pasan con instalación Go real; evidencia en `03-ejecucion.md`.

**Depende de:** SW-011, SW-012 · **Estado:** Pendiente

---

## M3 — Agente + IPC `sw-ipc`, `sw-agent`, `sw-systemauth`, `sw-cli` (P0 — MVP)

### [SW-020] Protocolo IPC propio

**Historia:** Como agente, quiero un protocolo IPC claro y versionado, para que el CLI y (post-MVP) la GUI se comuniquen de forma estable.

**Alcance:** envelope serde + framing length-prefixed; versionado; errores tipados. **No** se replica el envelope Go (decisión: importar y seguir).

**Criterios de aceptación:**
- Roundtrip de mensajes con framing correcto.
- Buffer máximo definido (4MB) y error si se excede.
- Versión de protocolo en el handshake.
- Tests de mensajes malformados → error, no panic.

**Cierre:** criterios pasan; evidencia en `03-ejecucion.md`.

**Depende de:** — · **Estado:** Pendiente

---

### [SW-021] Socket Unix del agente

**Historia:** Como CLI, quiero conectarme al agente por un socket Unix con permisos restrictivos, para que solo mi usuario pueda hablar con él.

**Alcance:** servidor en `~/.goldwarden.sock`, un mensaje por conexión, buffer 4MB, permisos restrictivos.

**Criterios de aceptación:**
- El socket se crea con permisos correctos.
- Un cliente de prueba conecta y recibe respuestas válidas.
- Mensaje mayor de 4MB → error controlado.
- Socket se limpia al cerrar el agente.

**Cierre:** criterios pasan; evidencia en `03-ejecucion.md`.

**Depende de:** SW-020 · **Estado:** Pendiente

---

### [SW-022] CallingContext

**Historia:** Como agente, quiero saber qué proceso me llama, para aplicar reglas de sesión y seguridad.

**Alcance:** credenciales de par (`SO_PEERCRED`) + nombres de proceso vía `/proc` (paridad con `go-ps` + `peercred`).

**Criterios de aceptación:**
- Se obtiene PID, UID y nombre del proceso cliente.
- Mismo contexto que reporta el agente Go para el mismo cliente (validado con fixture).
- Casos: proceso sin permisos de lectura → error controlado.

**Cierre:** criterios pasan; evidencia en `03-ejecucion.md`.

**Depende de:** SW-021 · **Estado:** Pendiente

---

### [SW-023] Session store

**Historia:** Como agente, quiero gestionar sesiones con TTL y match por jerarquía de proceso, para no pedir aprobación en cada operación dentro de una sesión válida.

**Alcance:** sesiones `AccessVault`/`SSHKey`/`Pin`, TTL 60 min, match por jerarquía PID (SSHKey no exige ancestro — paridad Go); wipe en bloqueo.

**Criterios de aceptación:**
- Tests de expiración (TTL).
- Match por jerarquía PID correcto en los casos de Go.
- `SSHKey` no exige ancestro PID.
- Wipe de sesiones al bloquear.

**Cierre:** tabla de casos igual a Go verificada; evidencia en `03-ejecucion.md`.

**Depende de:** SW-022 · **Estado:** Pendiente

---

### [SW-024] Actions mínimas del agente

**Historia:** Como CLI, quiero ejecutar acciones contra el agente (status, vault status, lock/unlock, pin status/update, config get/set), para operar el gestor desde terminal.

**Alcance:** registry de acciones + handlers para las acciones del MVP.

**Criterios de aceptación:**
- Cada acción responde con payload correcto.
- Acción desconocida → error tipado, no panic.
- `lock`/`unlock` cambian el estado real del vault.

**Cierre:** criterios pasan; evidencia en `03-ejecucion.md`.

**Depende de:** SW-021, SW-023, SW-011 · **Estado:** Pendiente

---

### [SW-025] CLI `silverwarden` mínima

**Historia:** Como usuario, quiero una CLI con subcomandos básicos (status, unlock, lock, pin), para usar silverWarden-rs sin GUI.

**Alcance:** binario CLI (clap) con subcomandos status/unlock/lock/pin que hablan IPC.

**Criterios de aceptación:**
- Flujo completo unlock→status→lock funciona manualmente contra el agente Rust.
- Mensajes de error claros.
- `--help` documenta los subcomandos.

**Cierre:** flujo E2E manual verificado; evidencia en `03-ejecucion.md`.

**Depende de:** SW-024 · **Estado:** Pendiente

---

## M4 — Vault + API Bitwarden `sw-vault`, `sw-bitwarden-api` (P0 — MVP)

### [SW-030] HTTP autenticado + refresh de token

**Historia:** Como núcleo de API, quiero un cliente REST autenticado con refresh automático, para que las operaciones contra el servidor no fallen por token caducado.

**Alcance:** cliente REST con `Authorization`, refresh token, manejo de errores por status code (paridad `http.go`).

**Criterios de aceptación:**
- Request autenticado funciona contra vault.disroot.org.
- Token caducado → refresh automático y reintento.
- Errores HTTP mapeados a errores tipados.

**Cierre:** criterios pasan contra servidor real; evidencia en `03-ejecucion.md`.

**Depende de:** SW-010 · **Estado:** Pendiente

---

### [SW-031] Modelos SyncData/Cipher

**Historia:** Como núcleo de vault, quiero modelar toda la jerarquía de sync, para representar el vault en memoria con fidelidad.

**Alcance:** structs serde para Profile, Organizations, Ciphers, Folders, Sends.

**Criterios de aceptación:**
- JSON real de `/sync` de vault.disroot.org deserializa completo.
- Roundtrip serialize→deserialize estable.
- Campos desconocidos se preservan o se documenta su descarte.

**Cierre:** criterio pasa con fixture real; evidencia en `03-ejecucion.md`.

**Depende de:** — · **Estado:** Pendiente

---

### [SW-032] Sync completo + caché en disco

**Historia:** Como usuario, quiero que mi vault se sincronice y se guarde en disco cifrado, para trabajar offline y no re-sincronizar cada vez.

**Alcance:** `DoFullSync` (org keys, keyring init, clear, add ciphers por tipo), `WriteVault`/`ReadVault` con formato JSON idéntico al Go; stores en memoria con indexación.

**Criterios de aceptación:**
- Sync completo contra vault.disroot.org con cuenta de prueba.
- Caché generado por Rust lo lee el Go y viceversa.
- `lastSynced` correcto.
- Indexación por tipo y por URI funciona.

**Cierre:** criterios pasan; evidencia en `03-ejecucion.md`.

**Depende de:** SW-031, SW-005, SW-004 · **Estado:** Pendiente

---

### [SW-033] Login

**Historia:** Como usuario, quiero iniciar sesión con contraseña maestra o API key, para acceder a mi vault.

**Alcance:** prelogin (KDF config) → derivación → master password hash → login; también API key; persistencia de token/keys cifrada en config.

**Criterios de aceptación:**
- Login real contra cuenta de prueba en vault.disroot.org.
- Login con API key funciona.
- Token y claves persisten cifrados tras login.

**Cierre:** criterios pasan contra servidor real; evidencia en `03-ejecucion.md`.

**Depende de:** SW-030, SW-011, SW-003 · **Estado:** Pendiente

---

### [SW-034] 2FA

**Historia:** Como usuario con 2FA, quiero completar el segundo factor (TOTP o email primero, FIDO2 después), para poder iniciar sesión.

**Alcance:** TOTP y email primero; trait `TwoFactor` para FIDO2 posterior.

**Criterios de aceptación:**
- Login con 2FA TOTP real funciona.
- Trait `TwoFactor` permite stub para FIDO2.
- Error claro si el factor no está soportado aún.

**Cierre:** criterio pasa con cuenta de prueba; evidencia en `03-ejecucion.md`.

**Depende de:** SW-033 · **Estado:** Pendiente

---

### [SW-035] Websocket de notificaciones

**Historia:** Como usuario, quiero recibir notificaciones de sync en tiempo real, para que mi vault se actualice cuando cambia en otro dispositivo.

**Alcance:** conexión autenticada, mensajes msgpack, reconexión con backoff.

**Criterios de aceptación:**
- Recibe notificación de sync tras cambio en otro cliente.
- Reconexión con backoff ante caída.
- Mensajes malformados no tumban el daemon.

**Cierre:** criterios pasan; evidencia en `03-ejecucion.md`.

**Depende de:** SW-030 · **Estado:** Pendiente

---

### [SW-036] CRUD de ciphers

**Historia:** Como usuario, quiero listar, buscar, crear, editar y borrar ciphers, para gestionar mi vault desde la CLI.

**Alcance:** get/list por filtros (paridad `GetLoginByFilter`), add/update/delete con re-cifrado.

**Criterios de aceptación:**
- Roundtrip create→sync→read real.
- Filtros por URI y por tipo funcionan.
- Update y delete se reflejan en el servidor.

**Cierre:** criterios pasan; evidencia en `03-ejecucion.md`.

**Depende de:** SW-032 · **Estado:** Pendiente

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

---

## Métricas del backlog

- **MVP:** 24 historias (M1: 7, M2: 4, M3: 6, M4: 7, M5: 5... ajustar al conteo real)
- **Post-MVP:** 20 tareas listadas sin detallar
- **Definición de avance:** una historia pasa a `Hecho` solo con evidencia de sus criterios + controles obligatorios del plan.