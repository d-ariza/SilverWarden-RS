# 01 — Análisis (Fase 1 — Conceptualización)

**Proyecto:** silverWarden-rs — Reescritura de Goldwarden en Rust + Tauri
**Fecha:** 2026-10-24 (actualizado con arquitectura GUI y estado real)
**Estado:** 🟡 Borrador — decisiones de alcance registradas, pendiente aprobación final del usuario
**Rol de la IA:** Analista

**Leyenda:** `[HECHO]` = confirmado por evidencia (GRAPH_REPORT.md) · `[CONFIRMADO]` = decidido por el usuario el 2026-10-12 · `[SUPUESTO]` = inferencia de la IA · `[PENDIENTE]` = requiere decisión (no bloquea Fase 1).

---

## 1. Resumen del problema y objetivo

Goldwarden es un gestor de contraseñas compatible con la API de Bitwarden, hoy implementado en **Go** (núcleo: agente, CLI, IPC, cripto) y **Python** (GUIs GTK/libadwaita, monitores D-Bus, autotipo). El objetivo es una **reescritura total en Rust (núcleo) + Tauri (GUI)** que alcance **paridad funcional 1:1** con el sistema actual, ejecutada de forma incremental en fases, con migración garantizada desde la versión Go. El proyecto derivado se denomina **silverWarden-rs**.

**Problema a resolver:** el stack Go+Python multiplica superficies de mantenimiento (dos lenguajes, dos toolchains, bindings PyGObject, dependencias del sistema Python) y complica distribución. La reescritura unifica en un stack con seguridad de memoria, mejor rendimiento y empaquetado moderno.

## 2. Contexto y situación actual `[HECHO]`

Evidencia: GRAPH_REPORT.md (graphify-rs) sobre el repositorio actual.

- **1427 nodos, 1518 aristas, 138 comunidades** (85.6% extraído, 14.4% inferido).
- **Núcleo Go** (`cli/`):
  - `agent/`: config, vault, ssh, systemauth (pinentry, biometrics), notify, processsecurity, sockets, pincache, actions.
  - `agent/bitwarden/`: crypto (AES-CBC-256, RSA, HKDF, MAC), models, twofactor, sync, ciphers, send, passwordless.
  - `ipc/messages`: protocolo JSON sobre socket Unix.
  - `client` + `cmd` (cobra): CLI contra el agente vía IPC.
  - `browserbiometrics`: puente native-messaging con mensajes cifrados.
- **GUIs Python** (GTK 4 / libadwaita): login, quickaccess, settings, pinentry, approval, guías de setup, monitores D-Bus, autotipo (pyautogui / python-xlib / libportal), TOTP. `main()` con `tendo.singleton`, integración Flatpak.
- **Dependencias clave Go**: memguard (memoria bloqueada), gorilla/websocket, msgpack, cobra, godbus, go-libfido2, tink-go, go-pinentry, peercred, go-ps.
- Código presente para Linux, Windows y macOS; el foco inicial es Manjaro.

## 3. Resultado esperado `[CONFIRMADO]`

Aplicación Rust+Tauri con **paridad 1:1** funcional respecto al Goldwarden actual, lograda en fases incrementales. Todo el código pasa a Rust; la GUI pasa a Tauri (reescritura total, no envoltorio sobre el binario Go).

## 4. Alcance y exclusiones

### Decisiones de alcance `[CONFIRMADO 2026-10-12]`

| Tema | Decisión |
| --- | --- |
| Nombre | **silverWarden-rs** |
| Profundidad | Reescritura **1:1** total, ejecutada por fases (propuesta en §4.1) |
| SSH agent | **Incluido, obligatorio** — requisito explícito del usuario |
| Arquitectura | Todo a Rust; GUI en Tauri. El agente Go desaparece |
| Migración | **Requisito explícito**: la versión nueva debe migrar datos/config de la versión Go |
| Browser biometrics | **Incluido**. Ver nota en §4.2 |
| Plataformas | Arranque en **Linux (Manjaro) + macOS**; el diseño debe mantener **Windows viable**; soporte de **Chrome** deseado si es posible |
| Empaquetado | **crates.io** (cargo install), **Flatpak** (Linux), **.msi** (Windows), **.dmg** (macOS) |
| Repositorio | Inicialmente **rama** en el fork actual; luego migración a **repo nuevo** |
| Ritmo | **Muy urgente — ~1 hora de trabajo por día.** Ver §4.3 |

### 4.1 Estado real de las fases (actualizado 2026-10-24)

**Estado real a fecha 2026-10-24:**

- **M1 — Núcleo criptográfico:** ✅ **Completado.** KDF, jerarquía de claves, EncString, AES-CBC-256+HMAC, RSA, HKDF, memoria bloqueada, fuzzing. Paridad Go↔Rust verificada byte a byte.
- **M2 — Config + migración:** ✅ **Completado.** Config cifrado (Argon2i + Tink ChaCha20-Poly1305), migración de `goldwarden.json`, backup automático.
- **M3 — Agente + IPC:** ✅ **Completado.** Protocolo IPC propio, socket Unix (`~/.silverwarden.sock`), CallingContext con `SO_PEERCRED` y anclaje Git, session store endurecido, actions registry, CLI con clap.
- **M4 — Vault + API Bitwarden:** ✅ **Completado.** HTTP + refresh (SW-030) ✅, Modelos (SW-031) ✅, Login (SW-033) ✅, Sync + caché (SW-032) ✅, CRUD de ciphers (SW-036) ✅, Websocket (SW-035) ✅, 2FA TOTP/Email (SW-034) ✅. FIDO2 se pospone a post-MVP.
- **M5 — SSH agent:** ⏳ **Pendiente.** La base (agente + IPC + vault) ya está lista.
- **M6 — Seguridad de sesión:** ⏳ **Post-MVP.**
- **M7 — GUI Tauri:** ⏳ **Pendiente.** Ver sección 4.4 (nueva).
- **M8–M10 — Post-MVP.**

### 4.2 Nota sobre browser biometrics `[HECHO técnico]`

No existe vía "directa contra el servidor": en el ecosistema Bitwarden la clave de biometría **jamás sale del dispositivo**; la extensión de navegador la obtiene del app de escritorio vía native-messaging cifrado tras autenticación del SO. Por tanto la única vía real es **replicar el puente native-messaging** exactamente como lo hace la app de escritorio de Bitwarden (contrato de mensajes cifrados con la extensión). Se confirma como decisión de diseño en Fase 2.

### 4.3 Restricción de ritmo `[CONFIRMADO — riesgo de cronograma]`

- Disponibilidad: **~1 hora/día**, urgencia alta.
- Estimación realista: un 1:1 completo (1427 nodos) a 1h/día implica **varios meses** (orden de 4–8 meses según complejidad de M4–M9).
- Consecuencia: en Fase 2 se definirá un **camino crítico MVP** que entregue valor usable lo antes posible (cripto → migración → agente → vault → **SSH agent**), con las fases M6–M9 ordenadas para que el usuario tenga un sistema funcional cuanto antes. El compromiso 1:1 se mantiene; lo que se ajusta es el **orden de entrega**.

### 4.4 Arquitectura de la GUI

**Decisión confirmada (2026-10-24):** La GUI Tauri es un **cliente IPC del agente**, exactamente igual que el CLI.

```text
┌─────────────┐       ┌─────────────┐       ┌─────────────┐
│     CLI     │────▶  │   Agente    │  ◀────│     GUI     │
│  (sw-cli)   │  IPC  │ (sw-agent)  │  IPC  │  (sw-gui)   │
└─────────────┘       └─────────────┘       └─────────────┘
                             │
                             ▼
                      ┌─────────────┐
                      │    Vault    │
                      │ (sw-vault)  │
                      └─────────────┘
```

**Reglas de la arquitectura:**

1. **El agente es obligatorio.** Si no está corriendo, la GUI muestra un mensaje claro: "El agente no está disponible. Ejecuta `silverwarden agent start`". La GUI **no** accede directamente al vault ni al servidor.
2. **El agente es el único dueño del estado.** La `user_symmetric_key` vive en la memoria del agente. La GUI nunca la recibe. Cuando la GUI necesita datos descifrados, se los pide al agente (`DecryptCipher`, `SearchLogins`, etc.).
3. **La GUI no descifra.** El agente descifra bajo demanda y devuelve `DecryptedCipher` a la GUI.
4. **El CLI y la GUI comparten el mismo protocolo IPC.** Cualquier acción nueva que necesite la GUI debe ser una acción IPC en el agente (registry).

**Acciones IPC nuevas que el agente debe exponer para la GUI (a implementar en M7):**

- `GetLogins`: devuelve `Vec<Cipher>` (cifrados) o `Vec<DecryptedCipher>` (descifrados bajo demanda).
- `DecryptCipher`: recibe `uuid`, devuelve `DecryptedCipher`.
- `SearchLogins`: recibe filtro (nombre/username), devuelve `Vec<DecryptedCipher>`.
- `ListSSHKeys`: devuelve `Vec<SSHKeyPublic>` (nombre + clave pública, nunca la privada).
- `ImportSSHKey`: recibe clave privada + nombre, la cifra y la sube al vault.

### 4.5 Vistas de la GUI (M7)

La GUI Tauri tendrá las siguientes vistas (priorizadas):

1. **M7.1 — Scaffold + Status:** ventana básica que conecta al socket y muestra si el agente está corriendo, si el vault está bloqueado y el estado de sync.
2. **M7.2 — Login/Unlock:** formulario para desbloquear el vault con PIN o biometría.
3. **M7.3 — Quickaccess (Lista de logins):** lista de logins (nombre + username), con búsqueda. Al hacer click, muestra el password y permite copiar.
4. **M7.4 — Settings:** URLs del servidor, PIN, estado de sync, botón de "Lock".
5. **M7.5 — SSH Keys (requisito del usuario):** lista de claves SSH en el vault (nombre + fingerprint). Permite importar, renombrar y ver la clave pública. **Nunca muestra la clave privada.**
6. **M7.6 — Diálogos de pinentry/approval:** ventanas modales que el agente invoca cuando necesita aprobación (por ejemplo, para firmar un commit con SSH).

**Nota sobre M7.5 (SSH Keys):** Esta vista es un **requisito explícito del usuario**. Las claves privadas viven en el vault cifrado, se descifran en el agente solo cuando se necesitan para firmar, y la GUI nunca las recibe en claro.

## 5. Stack y arquitectura existente conocidos `[HECHO]`

- Arquitectura **agente + cliente**: daemon Go con socket Unix; CLI envía mensajes IPC JSON autenticados (sesiones + calling context vía peercred/go-ps).
- Vault persistido cifrado en disco; claves en memoria bloqueada (memguard), wipe al bloquear.
- Sync vía REST + websocket (msgpack) para notificaciones.
- Biometría Linux: polkit. Pinentry: binarios externos.
- **Diseño requerido para la reescritura `[CONFIRMADO]`:** capa de abstracción de plataforma desde el día 1 (systemauth, sockets, autotipo, notificaciones) para que Linux/macOS/Windows compartan el núcleo.

## 6. Requerimientos

### Funcionales `[SUPUESTO, derivados del reporte; alcance 1:1 confirmado]`

- RF-1: Login email+contraseña maestra, API key o device; 2FA (TOTP, FIDO2, email).
- RF-2: Sync completo del vault; notificaciones en tiempo real vía websocket.
- RF-3: CRUD y búsqueda de logins, notas seguras, tarjetas, identidades; match por URI.
- RF-4: Lock/unlock con PIN (cache temporal) y biometría (polkit en Linux).
- RF-5: **SSH agent completo: listar, firmar, importar/crear claves.** `[CONFIRMADO obligatorio]`
- RF-6: Autotipo de credenciales (X11/libportal).
- RF-7: TOTP.
- RF-8: GUIs Tauri: quickaccess, login, settings, pinentry/approval.
- RF-9: Browser biometrics vía native-messaging con extensión de Bitwarden en Chrome. `[CONFIRMADO]`
- RF-10: Passwordless y Bitwarden Send (parte del 1:1).
- RF-11: **Migración de datos/config desde la versión Go.** `[CONFIRMADO]`

### No funcionales `[SUPUESTO]`

- RNF-1: Paridad criptográfica con Bitwarden (interoperabilidad de datos).
- RNF-2: Manejo seguro de secretos en memoria (páginas bloqueadas, wipe).
- RNF-3: Rendimiento comparable o superior (arranque, autotipo).
- RNF-4: Empaquetado: crates.io + Flatpak + .msi + .dmg. `[CONFIRMADO]`
- RNF-5: Sin telemetría; comunicación solo con el servidor configurado.
- RNF-6: Código multiplataforma con Windows en compilación viable desde el inicio. `[CONFIRMADO]`

## 7. Restricciones y dependencias

- Entorno de desarrollo: **Manjaro Linux**.
- La GUI GTK actual desaparece; Tauri implica frontend web.
- Dependencias Rust probables (decisión Fase 2): rustcrypto/ring, tokio, serde, crate ssh-agent, zbus, tauri nativo-messaging.
- **Compatibilidad de formatos on-disk e IPC con el agente Go** para la migración. `[CONFIRMADO]`
- Ritmo de desarrollo: ~1h/día. `[CONFIRMADO]`
- **Frontend Tauri: Svelte 5 + TypeScript `[CONFIRMADO]`**. Razones: GUIs son listas/formularios simples; reactividad más simple que hooks de React; build rápido; TS de fábrica. El usuario domina Angular/React/TS — sin riesgo de curva de aprendizaje.

## 8. Riesgos y supuestos

**Riesgos mitigados:**
- **Paridad criptográfica:** mitigado. Verificado byte a byte en KDF, stretch, cipher, RSA y login.
- **Ritmo 1h/día:** mitigado. M1–M3 cerrados en menos tiempo del previsto.
- **Migración Go→Rust:** mitigado. SW-012/013 funcionan con datos reales.

**Riesgos activos:**
- **Contrato native-messaging (M9):** sin cambios. Sigue siendo un riesgo medio.
- **SSH agent (M5):** sin cambios. La base está lista, pero la semántica de firma aún no se ha probado con OpenSSH real.
- **GUI depende del agente:** nuevo riesgo. Si el agente no expone las acciones IPC necesarias, la GUI no puede funcionar. Se mitiga implementando las acciones en M5/M7.
- **2FA FIDO2:** pospuesto a post-MVP. TOTP y email son prioritarios.

| Tipo | Descripción | Impacto | Mitigación propuesta |
| --- | --- | --- | --- |
| Riesgo | **Ritmo 1h/día vs. urgencia alta** — el 1:1 completo no cabe en corto plazo | Alto | Camino crítico MVP en Fase 2; entregar valor usable desde M5 |
| Riesgo | Paridad criptográfica incompleta → datos ilegibles | Alto | M1 primero, vectores de prueba contra datos Go reales |
| Riesgo | Contrato native-messaging con extensión (biometrics) es frágil y no documentado oficialmente | Medio | M9 al final; inspeccionar fuente oficial Bitwarden |
| Riesgo | Semántica exacta del SSH agent (agente SSH) | Medio | Pruebas con OpenSSH real en M5 |
| Riesgo | Autotipo X11/Wayland en Rust | Medio | M8 aislado |
| Riesgo | Compatibilidad de migración Go→Rust | Alto | M2 temprano, antes que features |
| Supuesto | El usuario puede inspeccionar el repo Go/Python localmente en Fases 2–3 para confirmar formatos exactos | — | Pedir acceso/rutas en Fase 2 |

## 9. Preguntas abiertas y decisiones pendientes

**Resueltas (bloqueantes) — 2026-10-12:** alcance 1:1 por fases · arquitectura total Rust+Tauri · migración requerida · browser biometrics incluido · plataformas Linux+macOS con Windows vivo y Chrome deseado · nombre silverWarden-rs · empaquetado crates/Flatpak/msi/dmg · repo: rama → repo nuevo · ritmo 1h/día urgente.

**No bloqueantes (para Fase 2):**

1. **Licencia: GPL-3.0 `[CONFIRMADO]`** — compatible con Goldwarden original (GPL-3.0). Verificar `LICENSE` del repo en Fase 2.
2. **Servidor de pruebas/MVP: vault.disroot.org `[CONFIRMADO]`** — instancia **Vaultwarden** (implementación Rust compatible con API Bitwarden). Nota Fase 2: validar comportamiento de endpoints contra Vaultwarden, no solo bitwarden.com.
3. Acceso al repositorio Go/Python (ruta local o URL) para inspección de formatos exactos de config/vault/IPC en Fases 2–3. `[PENDIENTE]`

**Resueltas también (2026-10-12 tarde):** frontend Svelte 5 + TS · licencia GPL-3.0 · servidor vault.disroot.org (Vaultwarden).

## 10. Definition of Done (inicial, propuesta)

- [ ] DoD-1: La app Rust+Tauri compila y ejecuta en Manjaro y macOS.
- [ ] DoD-2: Login + 2FA (TOTP mínimo) contra servidor Bitwarden real o de pruebas.
- [ ] DoD-3: Sync completo y lectura de ciphers cifrados con paridad de formatos.
- [ ] DoD-4: Lock/unlock con PIN funcional.
- [ ] DoD-5: **SSH agent funcional** (verificable con `ssh-add -L` y `ssh -T`). `[CONFIRMADO obligatorio]`
- [ ] DoD-6: GUIs principales Tauri operativas (login, quickaccess, settings).
- [ ] DoD-7: **Migración de una instalación Go real preservando datos y config.** `[CONFIRMADO]`
- [ ] DoD-8: Browser biometrics operativo con extensión en Chrome. `[CONFIRMADO]`
- [ ] DoD-9: Suite de pruebas con evidencia (se define en Fase 2).
- [ ] DoD-10: Windows compila (ci check) aunque no sea target primario. `[CONFIRMADO]`
- [ ] DoD-11: Empaquetado publicado: crate en crates.io, Flatpak, .msi y .dmg. `[CONFIRMADO]`
- [ ] DoD-12: **La GUI Tauri funciona como cliente IPC del agente.** (M7)
- [ ] DoD-13: **Vista de SSH Keys funcional en la GUI.** (M7.5)
- [ ] DoD-14: **El agente expone las acciones IPC necesarias para la GUI.** (M5/M7)

---

## Estado de aprobación

- [x] Problema y objetivo — confirmado
- [x] Nombre silverWarden-rs — confirmado
- [x] Alcance 1:1 por fases con SSH agent obligatorio — confirmado
- [x] Arquitectura total Rust + Tauri — confirmado
- [x] Migración Go→Rust requerida — confirmado
- [x] Browser biometrics incluido — confirmado
- [x] Plataformas (Linux+macOS arranque, Windows vivo, Chrome) — confirmado
- [x] Empaquetado (crates/Flatpak/msi/dmg) — confirmado
- [x] Repositorio (rama → repo nuevo) — confirmado
- [x] Ritmo 1h/día urgente — confirmado (con ajuste de camino crítico)
- [x] Frontend Svelte 5 + TS — confirmado
- [x] Licencia GPL-3.0 — confirmado
- [x] Servidor vault.disroot.org (Vaultwarden) — confirmado
- [ ] Propuesta de fases M1–M10 — **pendiente aprobación del usuario**
- [ ] DoD aceptado — pendiente

**Puerta de transición:** esta fase solo se cierra cuando el usuario diga exactamente: `fase 1 acabada, pasamos a fase 2`.
