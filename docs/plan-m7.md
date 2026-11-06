# M7 — GUI Tauri (Svelte 5 + TS)

**Objetivo:** Construir una interfaz gráfica ligera, rápida y multiplataforma como cliente IPC del agente, con soporte para 3 estilos visuales y preparada para extensiones.

## Fases de Implementación

### Fase 1: Cimientos y Tema (Design System)
- [ ] Crear `crates/sw-gui` con Tauri v2 + Svelte 5 + TS.
- [ ] Configurar `tokens.css` con variables CSS (colores, espaciados, tipografías).
- [ ] Implementar el toggle Claro/Oscuro.
- [ ] Definir los 3 temas base: `tema-fluent` (Win11), `tema-cupertino` (Mac), `tema-breeze` (KDE).

### Fase 2: Componentes UI Base (Skeletons, Botones, Inputs)
- [ ] `Button.svelte` (con estados hover, active, disabled, focus).
- [ ] `Input.svelte` (con labels y errores accesibles).
- [ ] `Skeleton.svelte` (para estados de carga).
- [ ] `Modal.svelte` (para aprobaciones).

### Fase 3: Vistas Core (KeePassXC Style)
- [ ] `LoginView.svelte`: Pantalla de desbloqueo (PIN / Biometría).
- [ ] `QuickaccessView.svelte`: Lista de logins con buscador (Splitter 3 paneles).
- [ ] `SettingsView.svelte`: Configuración (URLs, PIN, Tema).
- [ ] `SSHKeysView.svelte`: Lista de claves SSH (nombre + fingerprint).
- [ ] `ExtensionSlot.svelte`: Componente para inyectar extensiones futuras (stub).

### Fase 4: Conexión IPC y Responsive
- [ ] Implementar el cliente IPC en TypeScript (`ipc/client.ts`).
- [ ] Conectar las vistas al agente (Status, Unlock, Sync).
- [ ] Asegurar Container Queries para que la UI sea responsive (Android, Tablet, Desktop).

## Criterios de Cierre (Quality Gates)
- La GUI arranca sin errores.
- Se conecta al agente vía IPC.
- `cargo clippy --workspace` y `cargo test` pasan en el workspace.
- Los 3 temas visuales cambian los colores sin romper la estructura.

