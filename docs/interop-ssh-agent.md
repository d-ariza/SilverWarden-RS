# Interoperabilidad y Regresión del Agente SSH (SW-046)

Este documento describe la matriz de compatibilidad, casos límite y limitaciones conocidas de la implementación del Agente SSH en SilverWarden (`sw-ssh-agent`) en comparación con OpenSSH nativo (`ssh-agent`) y Goldwarden Go.

---

## 1. Matriz de Características

| Característica / Comando | OpenSSH Nativo | Goldwarden Go | SilverWarden (`sw-ssh-agent`) | Notas de Compatibilidad |
| :--- | :---: | :---: | :---: | :--- |
| `ssh-add -L` (Listar claves públicas) | ✅ | ✅ | ✅ | Devuelve claves tipo `SshKey` y notas compatibles en vault |
| `ssh-add <key>` (Añadir clave al agente) | ✅ | ❌ | ✅ | Cifra y sincroniza automáticamente con el vault |
| `ssh-add -d <key>` (Eliminar clave específica) | ✅ | ❌ | ✅ | Elimina por fingerprint o coincidencia de blob público |
| `ssh-add -D` (Eliminar todas las claves) | ✅ | ❌ | ✅ | Limpia identidades del vault |
| `ssh-add -t <ttl>` (Claves con expiración) | ✅ | ❌ | ✅ | Soporta `SSH_AGENT_CONSTRAIN_LIFETIME` en memoria |
| Firma **Ed25519** (`ssh-ed25519`) | ✅ | ✅ | ✅ | Implementación estándar de alta velocidad |
| Firma **RSA** (`rsa-sha2-256`, `rsa-sha2-512`, `ssh-rsa`) | ✅ | ✅ | ✅ | Respeta flags de protocolo `SSH_AGENT_RSA_SHA2_*` |
| Firma **ECDSA** (`ecdsa-sha2-nistp256`) | ✅ | ❌ | ✅ | Curva NIST P-256 con hash SHA-256 |
| Firma con **SSHSIG** (`git commit -S`, `ssh-keygen -Y`) | ✅ | ✅ | ✅ | Detección de prefijo mágico `SSHSIG\0\0\0\x03git` |
| Aprobación por diálogo (pinentry / systemauth) | ❌ | ✅ | ✅ | Requiere autorización de usuario si no hay sesión |
| Sesión SSH cacheada (60 min) | ❌ | ✅ | ✅ | Autorización persistente en `SessionStore` |

---

## 2. Casos Límite

### 2.1 Claves protegidas con Passphrase
- **Comportamiento en SilverWarden:** Las claves privadas OpenSSH cifradas con contraseña (`bcrypt` + `aes256-cbc`/`ctr`) **no se soportan para importación directa**.
- **Razón técnica:** La importación de claves cifradas requeriría un flujo interactivo de solicitud de contraseña en la terminal o UI durante la operación de socket.
- **Manejo:** El método `add_ssh_key` y la acción `ImportSSHKey` detectan `priv_key.is_encrypted()` y devuelven un error descriptivo: `"Encrypted private keys with passphrase are not supported"`. Para usar la clave en SilverWarden, el usuario debe descifrarla previamente (`ssh-keygen -p`). Una vez en SilverWarden, la clave queda protegida bajo el cifrado AES-256 del Vault.

### 2.2 Claves DSA (`ssh-dss`)
- **Comportamiento en SilverWarden:** **No soportadas**.
- **Razón técnica:** DSA está formalmente deprecado y deshabilitado por defecto en OpenSSH desde la versión 7.0 (2015) debido a su longitud de clave fija insegura (1024 bits).
- **Manejo:** Intentar importar o generar claves DSA retorna un error: `Unsupported key type`.

### 2.3 Claves de Seguridad Hardware (`sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com`)
- **Comportamiento en SilverWarden:** **No soportadas**.
- **Razón técnica:** Requieren interacción física mediante controladores FIDO2/U2F (libfido2) que se delegan habitualmente al middleware del sistema operativo o hardware externo, no al almacén de software del vault.

### 2.4 Restricciones de Claves (`Constraints`)
- **`SSH_AGENT_CONSTRAIN_LIFETIME`:** Soportado. Si se añade una clave con restricción de tiempo de vida (`ssh-add -t`), la clave expira automáticamente una vez transcurrido el TTL.
- **`SSH_AGENT_CONSTRAIN_CONFIRM`:** No implementado como flag por clave individual. En SilverWarden, la confirmación/aprobación es una política global gestionada por el daemon mediante `pinentry` y sesiones de 60 minutos en `SessionStore`.

---

## 3. Limitaciones Conocidas

1. **Lock/Unlock del Protocolo SSH (`SSH_AGENTC_LOCK` / `SSH_AGENTC_UNLOCK`):**
   - El protocolo estándar de OpenSSH define mensajes para bloquear el socket SSH mediante una contraseña arbitraria.
   - SilverWarden **no implementa el bloqueo a nivel de socket SSH individual**; el bloqueo está unificado a nivel de agente/vault (`VaultLocked`). Si el vault está bloqueado, cualquier operación de firma o listado de claves falla inmediatamente con `VaultLocked`.

2. **Extensiones del Protocolo (`SSH_AGENTC_EXTENSION`):**
   - Extensiones propietarias no están implementadas y devuelven `SSH_AGENT_FAILURE` conforme a la especificación estándar RFC de OpenSSH.

3. **Interactividad en Importación:**
   - La importación requiere texto plano OpenSSH PEM. No se solicita contraseña interactiva para descifrar archivos de clave privada sobre la marcha.

---

## 4. Batería de Pruebas Automatizadas

La suite `sw-ssh-agent` contiene 40 pruebas unitarias e integradas que validan todas las operaciones con >94% de cobertura:

- **Listado y gestión:** `test_list_empty_vault`, `test_list_with_keys`, `test_list_with_rsa_key`, `test_ssh_add_l`, `test_ssh_add_l_empty_vault`.
- **Comandos CLI ssh-add:** `test_ssh_add_command`, `test_ssh_add_d_command`, `test_ssh_add_remove_all`, `test_remove_all_with_multiple_keys`, `test_ssh_add_duplicate`, `test_add_constrained_lifetime`, `test_ssh_add_full_cycle`.
- **Firmas criptográficas:** `test_sign_with_key_ed25519`, `test_sign_with_ecdsa_key`, `test_rsa_signing_flags` (SHA-256 y SHA-512).
- **Interoperabilidad Git y OpenSSH:** `test_ssh_keygen_y_sign_and_verify`, `test_git_commit_signed_with_agent`, `test_detect_git_sshsig_payload`.
- **Casos límite y validaciones:** `test_import_rsa_key`, `test_import_ecdsa_key`, `test_import_unsupported_key_type`, `test_add_key_with_passphrase`, `test_vault_agent_locked_and_edge_branches`, `test_handle_connection_more_edge_cases`.
- **Control de acceso y sesiones:** `test_confirm_request`, `test_add_requires_approval`, `test_sign_with_key_approval_denied`, `test_sign_with_key_context_approval_caching`, `test_pinentry_runner_and_mock_provider`.
