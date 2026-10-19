# 02 — Plan (Fase 2 — Planificación y arquitectura)

**Proyecto:** silverWarden-rs — Reescritura de Goldwarden en Rust + Tauri
**Fecha:** 2026-10-12
**Estado:** 🟡 Propuesto — pendiente aprobación final del usuario
**Rol de la IA:** Project Manager / Arquitecto
**Basado en:** `docs/01-analisis.md` + inspección directa del código fuente de goldwarden (github.com/quexten/goldwarden).
**Licencia:** GPL-3.0

---

## 0. Decisiones de alcance confirmadas

| Tema | Decisión |
| --- | --- |
| Estrategia | **MVP primero, luego crecer sobre él** |
| MVP | **M1 → M2 → M3 → M4 → M5** (cripto → migración → agente → vault/API → SSH agent), interfaz CLI |
| Post-MVP | GUI Tauri, autotipo, TOTP UI, browser biometrics, Windows, empaquetado |
| Migración | Incluye config, vault, PIN y **claves SSH importadas** |
| Coexistencia Go/Rust | **Importar una vez y seguir** (no bidireccional en caliente) |
| Calidad estática | **Clippy** (Sonar descartado) |
| Cobertura | **≥85% líneas global núcleo; ≥90% en `sw-crypto`** |
| Repo | Rama en repo Go local → migración a repo propio en M10 |
| Licencia | GPL-3.0 |

---

## 1. Solución propuesta y arquitectura de alto nivel

Workspace de crates Rust con un núcleo multiplataforma y binarios delgados, más una GUI Tauri (post-MVP):
silverwarden-rs/ (rama en repo Go local; luego repo propio)
├── Cargo.toml # workspace
├── LICENSE # GPL-3.0
├── crates/
│ ├── sw-crypto/ # M1 — KDF, claves, EncString, AES, RSA, memoria bloqueada
│ ├── sw-config/ # M2 — goldwarden.json, cifrado de config, migración Go
│ ├── sw-vault/ # M4 — modelos SyncData/Cipher, stores en memoria
│ ├── sw-ipc/ # M3 — protocolo IPC propio (post-import)
│ ├── sw-agent/ # M3 — daemon: estado, actions, sesiones, sockets
│ ├── sw-bitwarden-api/ # M4 — REST + websocket + auth + sync
│ ├── sw-ssh-agent/ # M5 — servidor ssh-agent
│ ├── sw-systemauth/ # M3/M6 — sesiones, pinentry, biometría (abstracción por SO)
│ ├── sw-autotype/ # M8 — X11 (x11rb) / libportal [post-MVP]
│ ├── sw-notify/ # M6 — notificaciones (portal/dbus) [post-MVP]
│ ├── sw-browserbiometrics/ # M9 — native-messaging bridge [post-MVP]
│ ├── sw-cli/ # binario silverwarden (CLI contra el agente)
│ └── sw-gui/ # M7 — app Tauri (src-tauri + Svelte 5 + TS) [post-MVP]
└── .github/workflows/ # CI: tests, clippy, audit, matrix 3 SO

text

**Principio rector:** el núcleo (crypto→config→ipc→agent→vault→api→ssh) es código de librería sin GUI, testeable y publicable en crates.io. Tauri (post-MVP) es un cliente más del agente, al mismo nivel que la CLI.

---

## 2. Componentes, límites y flujo de datos

**Flujo principal (MVP):** `sw-cli` → socket Unix `~/.goldwarden.sock` → `sw-agent` (estado + sesiones) → `sw-vault` (ciphers en memoria) + `sw-bitwarden-api` (REST/WS). El SSH agent es un segundo socket `~/.goldwarden-ssh-agent.sock` servido por `sw-ssh-agent` contra el mismo vault.

**Compatibilidad verificada en inspección (formatos que M2/M4 deben replicar):**

| Formato | Evidencia en código Go | Requisito Rust |
| --- | --- | --- |
| Config `~/.config/goldwarden/goldwarden.json` (0600) | `config.go` | serde JSON idéntico (13 campos PascalCase); campos cifrados = **Tink ChaCha20-Poly1305** (header 5B + nonce 12B + ct + tag 16B) base64; clave = **Argon2i** (no id, t=2, m=2048, p=8, salt=DeviceUUID_bytes); `ConfigKeyHash` = **hex(SHA3-256(key))** |
| Migración de path viejo `~/.config/goldwarden.json` | `ReadConfig` | Replicar corrigiendo bug de Go (devolver `Ok` si el rename tiene éxito); directorio 0700, archivo 0600 |
| Caché de vault `SyncData` JSON en disco | `sync.go` WriteVault/ReadVault | serde con structs equivalentes; ruta exacta y descarga completa se consolida en M4 (`silverwarden sync`) |
| Claves SSH importadas | vault notes `custom-type: ssh-key` + ciphers SSHKey | Importar y sincronizar en M4 a partir de datos del vault |
| Sesiones `AccessVault` / `SSHKey` / `Pin`, TTL 60 min | `systemauth.go` | **Endurecido respecto a Go:** `AccessVault` y `Pin` con match exacto de 3 PIDs (PID, PPID, Grand-PPID) y expiración inmediata si el PID muere; `SSHKey` solo permite match laxo por tipo si el solicitante es cliente SSH/Git (`ssh`, `ssh-keygen`, `git`) |
| EncString `tipo.iv|ct|mac` base64, tipos 0/1/2; AES-CBC-256+HMAC-SHA256; RSA-OAEP-**SHA1** legacy | `encstring.go` | Paridad estricta; solo tipos 0 y 2 soportados para decrypt (como Go) |
| SSH agent: List/Sign/SignWithFlags; flags rsa-sha2-256/512; detección `SSHSIG` git | `ssh.go` | Semántica idéntica, aprobación por pinentry + sesión |

**Protocolo IPC (cambio respecto al borrador anterior):** al elegir "importar una vez y seguir", **no** se replica el envelope Go con tabla FNV-1a-64. Se define un protocolo propio en `sw-ipc` (JSON limpio `IpcMessage` + framing `u32` big-endian, buffer máx 4MB). El socket de silverWarden corre en `~/.silverwarden.sock` (0600). Para prevenir conflictos si Goldwarden Go sigue en segundo plano, la CLI detecta si `~/.goldwarden.sock` está activo y muestra una advertencia al usuario.

---

## 3. Decisiones técnicas y justificación

| # | Decisión | Alternativas | Justificación |
| --- | --- | --- | --- |
| D-1 | **RustCrypto** (`aes`, `cbc`, `hmac`, `sha2`, `sha3`, `hkdf`, `argon2`, `rsa`, `chacha20poly1305`) | `ring`, `sodiumoxide` | Única opción con cobertura exacta: AES-CBC+PKCS7, RSA-OAEP-SHA1 (legacy Bitwarden), ChaCha20-Poly1305 (config), argon2 con parámetros exactos, SHA3-256 |
| D-2 | **LockedBuffer propio** (trait `LockedBuffer`: `MemLockedBuffer` con mlock+MADV_DONTDUMP vía `rustix`, `MemoryBuffer` sin mlock) + `zeroize` | Crate `secrets`, `memsec` | Paridad con el flag `useMemguard` de Go; control total del wipe; testeable |
| D-3 | **tokio** | async-std, smol | Ecosistema: tungstenite, reqwest, Tauri, zbus async |
| D-4 | **Protocolo ssh-agent implementado directo** sobre el wire format OpenSSH + crate `ssh-key` para parseo de claves privadas | `russh` agent | El protocolo agente es simple (mensajes binarios length-prefixed); evitamos dependencia pesada |
| D-5 | **Importación única + IPC propio** (revisada) | Compatibilidad bidireccional con envelope Go | Decisión del usuario: importar una vez y seguir. Elimina tabla FNV y riesgo de interop frágil. La compatibilidad se limita a **formatos on-disk** (config, vault, claves SSH) |
| D-6 | **Tauri v2 + Svelte 5 + TS** (post-MVP) | Electron, GTK-rs | Tauri da empaquetado multiplataforma (msi/dmg) gratis |
| D-7 | **zbus** (D-Bus puro Rust) | `dbus` crate (libdbus C) | Sin dependencia C; polkit y notificaciones por portal |
| D-8 | **reqwest + tokio-tungstenite** | ureq, actix | Estándar de facto; TLS nativo |
| D-9 | **Serialización msgpack**: `rmp-serde` | — | Paridad con notificaciones websocket Bitwarden |
| D-10 | FIDO2 vía `fido2`/`ctap-hid-fido2` en M4, aislado detrás de trait | Solo TOTP | FIDO2 es el 2FA más riesgoso; el trait permite degradar a TOTP/email sin tocar el flujo de login |
| D30 | **KDF del config usa Argon2i (no id)**: $t=2, m=2048\text{ (2 GiB)}, p=8$ con salt = bytes de `DeviceUUID` | Argon2id, PBKDF2 | Paridad estricta con la derivación de clave de PIN en Goldwarden Go (`argon2.Key` variante `i`) |
| D31 | **Cifrado ChaCha20-Poly1305 con formato Tink exacto**: cabecera 5 bytes (0x00 + key ID 4B) + nonce 12B + CT + tag 16B | ChaCha20-Poly1305 plano | Goldwarden Go utiliza Google Tink. Los campos cifrados en `goldwarden.json` son strings base64 que envuelven este wire format binario de Tink |
| D32 | **ConfigKeyHash = hex(SHA3-256(key_derivado))** | SHA-256, bcrypt | Paridad exacta con Go para validar PIN; comparación segura en tiempo constante con `subtle::ConstantTimeEq` |
| D33 | **Escritura atómica de archivos (tempfile + rename)** | Sobrescritura directa | Previene corrupción o pérdida total de datos por interrupción abrupta observada en la implementación de Go |
| D34 | **Migración de ruta legacy devuelve Ok en éxito** | Replicar bug de Go | Go retornaba error tras un rename exitoso al buscar el archivo viejo inexistente; Rust retorna `Ok(())` si el movimiento es limpio |
| D35 | **SW-013 migra estado local; descarga de Vault/SSH en M4** | Descarga remota en M2 | El archivo en disco solo contiene configuración; la sincronización y descarga de ciphers/claves SSH se realiza en M4 vía `silverwarden sync` |
| D36 | **Endurecimiento de sesiones (D-IPC-3 mejorado)** | Semántica laxa de Go | Para `AccessVault` y `Pin`: coincidencia estricta de PID, PPID y Grand-PPID con expiración si el PID muere. Para `SSHKey`: coincidencia de tipo solo para clientes SSH/Git (`ssh`, `ssh-keygen`, `git`), exigiendo coincidencia completa de 3 PIDs para otros ejecutables |
| D37 | **Aislamiento de socket y advertencia de Go activo** | Reusar socket Go | Socket propio en `~/.silverwarden.sock` (0600) con limpieza de huérfanos. Si `~/.goldwarden.sock` está activo, la CLI muestra advertencia de recomendación de detención para evitar colisiones |

---

## 4. Estrategia de pruebas y aseguramiento de calidad

**Controles obligatorios (confirmados):**

| Control | Herramienta | Umbral | Desde |
| --- | --- | --- | --- |
| Tests unitarios + integración | `cargo test` | **100% pasan; 0 ignorados sin justificación** | M1 |
| Cobertura | `cargo-llvm-cov` | **≥85% líneas global núcleo; ≥90% en `sw-crypto`** | M1 |
| Linter / calidad estática | **`clippy -D warnings`** | **0 warnings** | M1 |
| Formato | `rustfmt --check` | 0 diffs | M1 |
| Vulnerabilidades deps | `cargo audit` | 0 advisories críticos/altos sin excepción aprobada | M1 |
| Licencias/deps | `cargo deny` | GPL-3.0 compatible | M2 |
| SAST | `semgrep` (reglas Rust) | **0 hallazgos critical/high** | M3 |
| Fuzzing cripto | `cargo-fuzz` | corpus en repo, 5 min en CI main | M1 |
| Interop de formatos | fixtures reales del repo Go | config/vault/claves leídos correctamente | M2, M4 |
| End-to-end | vault.disroot.org | login+sync+ssh-add+git sign | M4, M5 |

**Notas:**
- **Sonar descartado.** Clippy cubre el análisis estático de Rust mejor que Sonar (que no tiene analizador nativo de Rust). No se incluye servicio externo ni dashboard.
- La cobertura del 85%/90% aplica al **núcleo** (crates de librería). La GUI Tauri (post-MVP) no entra en ese umbral; se valida por E2E.
- Los umbrales son acordados con el usuario, no valores universales.

---

## 5. Estrategia de entrega, despliegue y reversión

- **Repo:** rama `silverwarden-rs` en el repo Go local; se migra a repo propio en M10.
- **Versionado:** semver por milestone; tags `v0.x.0-mN`.
- **Entrega:** cada milestone = conjunto de tareas del backlog aceptadas + evidencia de controles.
- **Empaquetado (M10, post-MVP):** crates.io (libs núcleo), Flatpak (Linux), .msi (Windows), .dmg (macOS), vía CI.
- **Migración y reversión:** `silverwarden migrate` hace **backup automático** (`goldwarden.json.bak-<timestamp>`) antes de tocar nada, importa la configuración local a la nueva ruta y verifica el desbloqueo con el PIN. Dado que las claves SSH y ciphers del vault no residen en texto claro en disco (o no deben presumirse locales), la migración local concluye guiando al usuario a ejecutar `silverwarden sync` (M4) para descargar y descifrar el vault completo. Rollback: detener silverWarden-rs, restaurar backup, arrancar Goldwarden Go.
- **Roll-forward:** si la migración falla a mitad, no se destruye nada sin backup verificado.
- **No hay coexistencia en caliente:** una vez migrado, el agente Go no se usa. El importador es de un solo sentido.

---

## 6. Riesgos y mitigaciones

| Riesgo | Impacto | Mitigación |
| --- | --- | --- |
| Paridad criptográfica (encstring tipos legacy, RSA-OAEP-SHA1) | Alto | M1 con vectores de prueba de datos reales; fuzzing |
| Migración incompleta (claves SSH, campos de config) | Alto | M2 temprano; fixtures reales del repo Go local; backup + verificación |
| Vaultwarden (vault.disroot.org) difiere de bitwarden.com | Medio | Validar M4 contra ese servidor real |
| Semántica de sesiones SSH (ancestro PID) | Medio | Tests con OpenSSH real en M5 |
| FIDO2 en Rust inmaduro | Medio | Trait de 2FA; TOTP/email primero |
| Ritmo 1h/día | Alto | Camino crítico MVP M1→M5; tareas chicas revisables |
| Protocolo IPC propio rompe interop con CLI Go | Bajo | Asumido por decisión de "importar y seguir"; el CLI Go no se usa tras migrar |

---

## 7. Criterios de éxito por etapa

- **M1:** vectores de prueba criptográficos pasan; cobertura ≥90% en `sw-crypto`.
- **M2:** `goldwarden.json` real parseado y serializado sin pérdida (13 campos PascalCase); campos descifrados con Argon2i + Tink ChaCha20-Poly1305; migración de ruta legacy con permisos 0700/0600 y corrección de bug; comando `silverwarden migrate` funcional con backup `goldwarden.json.bak-<timestamp>`.
- **M3:** el agente Rust arranca, el CLI `silverwarden` hace unlock→status→lock; importación de estado Go completada.
- **M4:** login + sync completos contra vault.disroot.org con cuenta de prueba; caché en disco con paridad de formato; descarga y sincronización de ciphers y claves SSH.
- **M5:** `ssh-add -L` lista claves del vault; `git commit -S` firma con aprobación; sin regresión en flags RSA.
- **M6–M10 (post-MVP):** criterios en backlog por tarea.

---

## 8. Estado de aprobación del plan

- [ ] Arquitectura de crates aprobada
- [ ] Decisiones D-1 a D-10 aceptadas
- [ ] Controles y umbrales de validación aceptados
- [ ] Estrategia de entrega/migración aceptada
- [ ] Backlog priorizado aceptado