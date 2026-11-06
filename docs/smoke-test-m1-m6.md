# Smoke Test Integral M1–M6

**Fecha:** 2026-11-01  
**Entorno:** Vaultwarden local (Docker, https://localhost) + Vaultwarden Disroot (https://vault.disroot.org)  
**Objetivo:** Verificar manualmente que todos los flujos críticos de M1–M6 funcionan end-to-end contra servidores reales.

## Prerrequisitos

- Vaultwarden local corriendo (`docker compose up -d`).
- `silverwarden` instalado (`cargo install --path crates/sw-cli --force`).
- Agente no corriendo (`pkill -9 -f "silverwarden agent"`).
- Sockets limpios (`rm -f ~/.silverwarden.sock ~/.silverwarden-ssh-agent.sock`).
- `ssh-add`, `ssh-keygen`, `git` instalados.
- D-Bus de sesión disponible (para notificaciones y logind).
- Polkit disponible (para biometría).

## M1 — Núcleo criptográfico (verificación indirecta)

M1 se cubre con tests unitarios (paridad Go↔Rust). **No requiere smoke test manual.** Si el login funciona (M4), M1 funciona.

## M2 — Config + migración

```bash
# 1. Migrar config de Goldwarden Go (si existe)
silverwarden migrate
# Esperado: "Config migrado. Ejecuta 'silverwarden sync' para descargar claves SSH y contraseñas."

# 2. Configurar servidor local
silverwarden config setup
# Opción 2 (Vaultwarden), URL https://localhost, cert autofirmado S

# 3. Verificar config
silverwarden config get
# Esperado: URLs correctas, "Sesión iniciada: No"
```

## M3 — Agente + IPC

```bash
# 1. Arrancar agente
silverwarden agent start &
sleep 2

# 2. Verificar sockets
ls -la ~/.silverwarden.sock ~/.silverwarden-ssh-agent.sock
# Esperado: ambos sockets con permisos 0600

# 3. Status
silverwarden status
# Esperado: "Bloqueado: Sí", "PIN configurado: No", "Sesión iniciada: No"

# 4. PIN set
silverwarden pin set
# Introducir PIN (ej. 1234)
# Esperado: "PIN configurado exitosamente."

# 5. Status de nuevo
silverwarden status
# Esperado: "PIN configurado: Sí"
```

## M4 — Vault + API Bitwarden

```bash
# 1. Login
silverwarden login --email dariza@disroot.org
# Introducir contraseña maestra local
# Esperado: "Sesión iniciada con éxito para dariza@disroot.org."

# 2. Unlock (con PIN)
silverwarden unlock
# Introducir PIN 1234
# Esperado: "Bóveda desbloqueada con éxito."

# 3. Sync
silverwarden sync
# Esperado: "Sincronización completada: 8 elementos (3 logins, 2 claves SSH, 1 nota, 1 tarjeta, 1 identidad)."

# 4. Listar logins
silverwarden logins list
# Esperado: 3 logins con nombre y usuario

# 5. Crear login
silverwarden logins create --name "SmokeTest-M6" --username "test" --password "test123"
# Esperado: "Acceso 'SmokeTest-M6' creado exitosamente."

# 6. Listar de nuevo
silverwarden logins list
# Esperado: 4 logins (incluye SmokeTest-M6)

# 7. Borrar login
silverwarden logins delete --name "SmokeTest-M6"
# Esperado: "Acceso 'SmokeTest-M6' eliminado exitosamente."

# 8. Edge case: crear con nombre vacío
silverwarden logins create --name "" --username "x" --password "y"
# Esperado: "Error: El nombre del acceso no puede estar vacío."
```

## M5 — SSH Agent

```bash
# 1. ssh-add -L
ssh-add -L
# Esperado: 2 claves ed25519 ("clave ssh", "ssh test")

# 2. Firma SSH real (opcional, requiere cuenta GitHub configurada)
ssh -T git@github.com
# Esperado: firma exitosa (o "Permission denied" si no tienes acceso, pero la firma se intenta)

# 3. git commit firmado (opcional)
cd /tmp && git init test-repo && cd test-repo
git config user.email "test@example.com" && git config user.name "Test"
echo "test" > test.txt && git add test.txt
git commit -S -m "test signed commit"
git log -1 --show-signature
# Esperado: "Good 'git' signature"

# 4. ssh-add -D (limpiar claves, opcional)
ssh-add -D
# Esperado: "All identities removed."

# 5. Restaurar claves (sync de nuevo)
silverwarden sync
ssh-add -L
# Esperado: 2 claves de nuevo
```

## M6 — Seguridad de sesión

### SW-050: PIN cache

```bash
# 1. Status inicial (sin caché)
silverwarden status
# Esperado: "pin_cached: false" (o similar)

# 2. Unlock con PIN (llena el caché)
silverwarden unlock
# Introducir PIN 1234
# Esperado: "Bóveda desbloqueada con éxito."

# 3. Lock
silverwarden lock
# Esperado: "Bóveda bloqueada y sesiones en memoria eliminadas."

# 4. Unlock SIN PIN (cache hit)
silverwarden unlock
# Esperado: NO pide PIN, desbloquea inmediatamente
# Nota: el CLI actual (DT-19) puede seguir pidiendo PIN; verificar comportamiento real
```

### SW-053: Notificaciones D-Bus

```bash
# 1. Asegurarse de que el daemon de notificaciones está corriendo
# (en GNOME/KDE, lo está por defecto; en otros, `notify-send` debe funcionar)

# 2. Lock (dispara notificación)
silverwarden lock
# Esperado: notificación de escritorio "SilverWarden: Bóveda bloqueada"

# 3. Firma SSH (dispara notificación, si hay claves)
silverwarden sync
ssh-add -L
ssh-keygen -Y sign -n file -f <(ssh-add -L | head -1 | awk '{print $2}') /tmp/test.txt
# Esperado: notificación "SilverWarden: Firma SSH con clave 'X'"

# 4. Fallback silencioso: parar el daemon de notificaciones
# (en GNOME: `systemctl --user stop org.gnome.Shell` no es trivial; saltar este paso o usar un entorno sin notificaciones)
# El lock y la firma deben seguir funcionando aunque la notificación falle.
```

### SW-052: Lock por inactividad

```bash
# 1. Configurar TTL corto en config (opcional, editar ~/.config/goldwarden/goldwarden.json)
# Cambiar "IdleTtlSecs": 600 a "IdleTtlSecs": 30 (30s) para test rápido

# 2. Unlock, dejar el agente inactivo 30s
silverwarden unlock
sleep 35

# 3. Status
silverwarden status
# Esperado: "Bloqueado: Sí" (se bloqueó por inactividad)

# 4. Verificar notificación (si SW-053 funciona)
# Esperado: notificación "Bóveda bloqueada por inactividad"

# 5. Suspensión del sistema (opcional, si es seguro suspender)
# systemctl suspend
# Al despertar, el vault debe estar bloqueado.
```

### SW-051: Biometría Polkit

```bash
# 1. Activar biometría en config (editar ~/.config/goldwarden/goldwarden.json)
# Cambiar "BiometricsEnabled": false a "BiometricsEnabled": true

# 2. Reiniciar agente
pkill -9 -f "silverwarden agent"
rm -f ~/.silverwarden.sock ~/.silverwarden-ssh-agent.sock
silverwarden agent start &
sleep 2

# 3. Login, unlock, lock (llenar caché)
silverwarden login --email dariza@disroot.org
silverwarden unlock
silverwarden lock

# 4. Unlock sin PIN (debe pedir biometría)
silverwarden unlock
# Esperado: diálogo Polkit pidiendo autenticación (huella, contraseña, etc.)
# Si OK: "Bóveda desbloqueada con éxito."
# Si cancelas: "Biometría cancelada o fallida"

# 5. Desactivar biometría (restaurar)
# Cambiar "BiometricsEnabled": true a false en config
```

### SW-054: Setup Systemd + Polkit

```bash
# 1. Dry run (no instala nada)
silverwarden setup-systemd --dry-run
# Esperado: imprime el contenido de silverwarden.service y org.silverwarden.unlock.policy

# 2. Instalar sin habilitar
silverwarden setup-systemd --no-enable
# Esperado: crea ~/.config/systemd/user/silverwarden.service y
# ~/.local/share/polkit-1/actions/org.silverwarden.unlock.policy

# 3. Verificar archivos
cat ~/.config/systemd/user/silverwarden.service
cat ~/.local/share/polkit-1/actions/org.silverwarden.unlock.policy
# Esperado: contenido correcto, ExecStart apunta al binario correcto

# 4. Instalar y habilitar (con systemctl)
silverwarden setup-systemd
# Esperado: "Servicio silverwarden.service habilitado y arrancado"

# 5. Verificar servicio
systemctl --user status silverwarden.service
# Esperado: "Active: active (running)"

# 6. Deshabilitar y limpiar (opcional)
systemctl --user disable --now silverwarden.service
rm ~/.config/systemd/user/silverwarden.service
rm ~/.local/share/polkit-1/actions/org.silverwarden.unlock.policy
```

### M6 — Edge cases y errores controlados

```bash
# 1. Agente caído
pkill -9 -f "silverwarden agent"
silverwarden logins list
# Esperado: "Error: El agente no está corriendo o el socket no existe. Ejecuta 'silverwarden agent start'."

# 2. PIN incorrecto
silverwarden agent start &
silverwarden unlock --pin 9999
# Esperado: "Error: PIN incorrecto"

# 3. Item inexistente
silverwarden logins delete --name "NoExiste"
# Esperado: "Error: No se encontró ningún acceso con el nombre 'NoExiste'"

# 4. Sync sin login
rm ~/.config/goldwarden/goldwarden.json
silverwarden sync
# Esperado: "Error: No hay sesión iniciada. Ejecuta 'silverwarden login' primero."
```

## Criterio de cierre

- [ ] M2: config setup + migrate funcionan.
- [ ] M3: agente arranca, sockets 0600, status correcto, pin set funciona.
- [ ] M4: login, unlock, sync (8 items), logins CRUD.
- [ ] M5: ssh-add -L (2 claves), firma SSH, git commit firmado.
- [ ] M6: PIN cache (unlock sin PIN tras lock), notificaciones (lock + firma), lock por inactividad, biometría Polkit, setup systemd.
- [ ] Edge cases: agente caído, PIN incorrecto, item inexistente, sync sin login.
- [ ] Evidencia registrada en 03-ejecucion.md §7 (nueva sección "Smoke test M1-M6").

## Ejecución real (a completar por el humano)

> **Nota:** Los pasos M4.1, M4.3 y M5.1 fueron validados exitosamente el 2026-11-05 contra Vaultwarden en Disroot (https://vault.disroot.org), comprobando el funcionamiento del flujo de 2FA (TOTP) y la extracción de claves SSH desde Notas Seguras.

| Paso | Comando | Resultado esperado | Resultado real | OK |
|---|---|---|---|---|
| M2.1 | `silverwarden migrate` | config migrado | [PENDIENTE] | [ ] |
| M2.2 | `silverwarden config setup` | URLs guardadas | [PENDIENTE] | [ ] |
| M3.1 | `silverwarden agent start &` | sockets 0600 | [PENDIENTE] | [ ] |
| M3.2 | `silverwarden status` | bloqueado, sin PIN | [PENDIENTE] | [ ] |
| M3.3 | `silverwarden pin set` | PIN configurado | [PENDIENTE] | [ ] |
| M4.1 | `silverwarden login` | sesión iniciada | Login exitoso con 2FA (TOTP). | [x] |
| M4.2 | `silverwarden unlock` | bóveda desbloqueada | [PENDIENTE] | [ ] |
| M4.3 | `silverwarden sync` | 8 items | Sincronización completada: 278 elementos (274 logins, 3 notas, 1 identidad). | [x] |
| M4.4 | `silverwarden logins list` | 3 logins | [PENDIENTE] | [ ] |
| M4.5 | `silverwarden logins create` | creado | [PENDIENTE] | [ ] |
| M4.6 | `silverwarden logins delete` | eliminado | [PENDIENTE] | [ ] |
| M5.1 | `ssh-add -L` | 2 claves | Listó 3 claves ed25519 ("Manjaro-TCS-SegBolivar", "Codeberg-dariza", "Dariza-GitHub"). | [x] |
| M5.2 | `ssh -T git@github.com` | firma exitosa | [PENDIENTE] | [ ] |
| M5.3 | `git commit -S` | firma verificada | [PENDIENTE] | [ ] |
| M6.1 | `silverwarden lock + unlock sin PIN` | desbloquea sin PIN | [PENDIENTE] | [ ] |
| M6.2 | `silverwarden lock` | notificación | [PENDIENTE] | [ ] |
| M6.3 | `ssh-keygen -Y sign` | notificación | [PENDIENTE] | [ ] |
| M6.4 | `idle 30s` | bloqueo automático | [PENDIENTE] | [ ] |
| M6.5 | `silverwarden unlock con biometría` | diálogo Polkit | [PENDIENTE] | [ ] |
| M6.6 | `silverwarden setup-systemd --dry-run` | imprime templates | [PENDIENTE] | [ ] |
| M6.7 | `silverwarden setup-systemd` | servicio habilitado | [PENDIENTE] | [ ] |
| Edge.1 | agente caído | error claro | [PENDIENTE] | [ ] |
| Edge.2 | PIN incorrecto | "PIN incorrecto" | [PENDIENTE] | [ ] |
| Edge.3 | item inexistente | error claro | [PENDIENTE] | [ ] |
| Edge.4 | sync sin login | error claro | [PENDIENTE] | [ ] |

