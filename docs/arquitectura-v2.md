# Arquitectura v2 — Visión y Patrones

## 1. Núcleo como Microservicio (REST / IPC)
El agente (`sw-agent`) dejará de ser solo un daemon de socket Unix para exponer un servidor REST local (`127.0.0.1`) con un token efímero. Esto permitirá que clientes ligeros (la GUI, una app Android, un script en Python) consuman el vault de forma segura.
- **Seguridad:** Socket Unix para clientes locales de confianza (CLI/SSH), REST local con token para el resto.

## 2. Patrón Local-First
SilverWarden podrá funcionar como KeePassXC (100% local y offline) y como Bitwarden (sincronizado).
- El `VaultStore` local será la fuente de verdad primaria.
- La sincronización con Vaultwarden será opcional.
- En caso de conflicto, se usará `Last-Write-Wins` basado en `revisionDate`, o se preguntará al usuario.

## 3. Sistema de Extensiones Seguras (Wasmtime)
Las extensiones no tocarán el núcleo.
- El núcleo define un trait (`VaultAuditExtension`).
- La extensión se compila a `.wasm`.
- `wasmtime` ejecuta la extensión en un sandbox con permisos de red limitados (ej. solo `api.pwnedpasswords.com`).
- El núcleo solo pasa datos públicos (email, hash SHA-1) a la extensión.

## 4. Responsive Multiplataforma (Tauri v2)
- Uso de **CSS Container Queries** (no solo media queries) para que los componentes se adapten a su contenedor.
- Uso de **Design Tokens** para los 3 estilos (KDE, Mac, Win11).
- Preparado para compilar a Android e iOS (Tauri v2 Mobile).

