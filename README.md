# silverWarden-rs

> **silverWarden-rs** es una reescritura completa en **Rust** (núcleo y CLI) y **Tauri + Svelte 5** (GUI) de Goldwarden, con paridad funcional 1:1, compatibilidad de formatos de almacenamiento on-disk, migración transparente y soporte de SSH agent.

## 🚀 Arquitectura del Workspace

El proyecto está organizado como un Cargo Workspace con separación estricta de responsabilidades:

```text
silverWarden-Rs/
├── Cargo.toml                  # Cargo Workspace raíz
├── LICENSE                     # GPL-3.0
├── README.md
├── docs/                       # Análisis, Plan, Backlog y Registro de Ejecución
│   ├── 01-analisis.md
│   ├── 02-plan.md
│   ├── 03-ejecucion.md
│   ├── backlog.md
│   └── GRAPH_REPORT.md         # Mapeo de paridad Go (1427 nodos)
└── crates/
    ├── sw-crypto/              # M1 — KDF (argon2id/pbkdf2), AES-CBC-256+HMAC, RSA, ChaCha20, memoria bloqueada
    ├── sw-config/              # M2 — Lectura/escritura de goldwarden.json y migración desde Go
    ├── sw-ipc/                 # M3 — Protocolo IPC propio (framing length-prefixed + serde)
    ├── sw-systemauth/          # M3/M6 — CallingContext, peercred, sesiones y biometría
    ├── sw-agent/               # M3 — Daemon de fondo, socket Unix (~/.goldwarden.sock)
    ├── sw-vault/               # M4 — Modelos SyncData/Cipher y almacén en memoria
    ├── sw-bitwarden-api/       # M4 — Cliente Bitwarden REST + WebSockets (msgpack)
    ├── sw-ssh-agent/           # M5 — Servidor OpenSSH agent (~/.goldwarden-ssh-agent.sock)
    ├── sw-cli/                 # Binario principal de CLI (`silverwarden`)
    ├── sw-gui/                 # M7 — Interfaz gráfica Tauri v2 (Svelte 5 + TypeScript)
    ├── sw-notify/              # M6 — Abstracción de notificaciones (Portal / D-Bus)
    ├── sw-autotype/            # M8 — Motor de autotipo (X11 / libportal)
    └── sw-browserbiometrics/   # M9 — Puente de Native Messaging con extensión Bitwarden
```

## 📋 Hoja de Ruta de Milestones (MVP)

- **M1 — Núcleo criptográfico (`sw-crypto`):** Memoria bloqueada (`mlock` + `MADV_DONTDUMP` + `zeroize`), `EncString`, KDF Bitwarden, derivación HKDF, AES-CBC-256+HMAC-SHA256, RSA-OAEP-SHA1, ChaCha20-Poly1305.
- **M2 — Configuración y Migración (`sw-config`):** Cifrado de configuración, compatibilidad directa con `goldwarden.json`, comando `silverwarden migrate` con copia de seguridad garantizada.
- **M3 — Agente e IPC (`sw-ipc`, `sw-agent`, `sw-systemauth`):** Daemon Unix socket con contexto de llamada (`SO_PEERCRED`), gestión de sesiones y CLI básico.
- **M4 — Vault y API Bitwarden (`sw-vault`, `sw-bitwarden-api`):** Sincronización REST y notificaciones WebSockets, descifrado completo de ciphers y notas.
- **M5 — SSH Agent (`sw-ssh-agent`):** Soporte de claves OpenSSH en memoria, firma con flags (`rsa-sha2-256/512`), firma de commits Git (`SSHSIG`) y aprobaciones por sesión.

## 🛠️ Requisitos de Desarrollo

- Rust `>= 1.80` (verificado con `rustc 1.99.0` y `cargo 1.99.0`)
- Node.js `>= 20` (verificado con `v22.22.3`)
- `webkit2gtk-4.1` (Linux)

## 🧪 Pruebas y Control de Calidad

```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --check
```
