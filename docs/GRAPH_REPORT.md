# 📊 Graph Analysis Report

**Root:** `.`

## Summary

| Metric | Value |
|--------|-------|
| Nodes | 1427 |
| Edges | 1518 |
| Communities | 138 |
| Hyperedges | 0 |

### Confidence Breakdown

| Level | Count | Percentage |
|-------|-------|------------|
| EXTRACTED | 1299 | 85.6% |
| INFERRED | 219 | 14.4% |
| AMBIGUOUS | 0 | 0.0% |

## 🌟 God Nodes (Most Connected)

| Node | Degree | Community |
|------|--------|-----------|
| config | 52 | 0 |
| vault | 34 | 1 |
| goldwarden | 33 | 2 |
| crypto | 33 | 4 |
| auth | 30 | 7 |
| ssh | 29 | 3 |
| encstring | 26 | 5 |
| unixsocketagent | 24 | 6 |
| send_authenticated_command() | 21 | 2 |
| websocket | 20 | 9 |

## 🔮 Surprising Connections

- **cli_agent_config_config_go_islocked** → **cli_agent_config_config_go_haspin** (calls)
- **cli_agent_config_config_go_unlock** → **cli_agent_config_config_go_islocked** (calls)
- **cli_agent_config_config_go_lock** → **cli_agent_config_config_go_islocked** (calls)
- **cli_agent_config_config_go_updatepin** → **cli_agent_config_config_go_decryptstring** (calls)
- **cli_agent_config_config_go_updatepin** → **cli_agent_config_config_go_encryptstring** (calls)

## 🏘️ Communities

### Community 0 — VerifyPin() (37 nodes, cohesion: 0.07)

- config
- Config
- ConfigFile
- DefaultConfig()
- HasPin()
- bytes
- crypto/subtle
- encoding/base64
- encoding/hex
- encoding/json
- errors
- fmt
- github.com/google/uuid
- github.com/quexten/goldwarden/cli/agent/bitwarden/crypto
- github.com/quexten/goldwarden/cli/agent/notify
- github.com/quexten/goldwarden/cli/agent/pincache
- github.com/quexten/goldwarden/cli/agent/systemauth/pinentry
- github.com/quexten/goldwarden/cli/agent/vault
- github.com/quexten/goldwarden/cli/logging
- github.com/tink-crypto/tink-go/v2/aead/subtle
- _…and 17 more_

### Community 1 — Vault (35 nodes, cohesion: 0.12)

- vault
- AddOrUpdateLogin()
- AddOrUpdateSecureNote()
- AddOrUpdateSSHKey()
- Clear()
- DeleteCipher()
- extractKeyMarker()
- GetEnvCredentialForExecutable()
- GetLastSynced()
- GetLogin()
- GetLoginByFilter()
- GetLogins()
- GetNoteByFilter()
- GetNotes()
- GetSecureNote()
- GetSSHKeys()
- errors
- fmt
- github.com/quexten/goldwarden/cli/agent/bitwarden/crypto
- github.com/quexten/goldwarden/cli/agent/bitwarden/models
- _…and 15 more_

### Community 2 — version() (34 nodes, cohesion: 0.10)

- goldwarden
- autotype()
- create_authenticated_connection()
- enable_pin()
- get_environment()
- get_runtime_config()
- get_vault_logins()
- get_vault_status()
- json
- os
- pathlib.Path
- shutil.which
- subprocess
- sys
- threading.Thread
- is_daemon_running()
- is_pin_enabled()
- listen_for_pinentry()
- lock()
- login_passwordless()
- _…and 14 more_

### Community 3 — vaultAgent (30 nodes, cohesion: 0.07)

- ssh
- Add()
- Eq()
- Extension()
- bytes
- crypto/rand
- errors
- fmt
- github.com/quexten/goldwarden/cli/agent/config
- github.com/quexten/goldwarden/cli/agent/notify
- github.com/quexten/goldwarden/cli/agent/sockets
- github.com/quexten/goldwarden/cli/agent/systemauth
- github.com/quexten/goldwarden/cli/agent/systemauth/pinentry
- github.com/quexten/goldwarden/cli/agent/vault
- github.com/quexten/goldwarden/cli/logging
- golang.org/x/crypto/ssh
- golang.org/x/crypto/ssh/agent
- time
- List()
- Lock()
- _…and 10 more_

### Community 4 — unpadPKCS7() (29 nodes, cohesion: 0.07)

- crypto
- AsymmetricEncryptionKey
- decryptAESCBC256()
- encryptAESCBC256()
- crypto/aes
- crypto/cipher
- crypto/hmac
- crypto/rand
- crypto/rsa
- crypto/sha256
- crypto/x509
- encoding/base64
- errors
- fmt
- github.com/awnumar/memguard
- io
- math
- isMacValid()
- MemguardAsymmetricEncryptionKey
- MemguardAsymmetricEncryptionKeyFromBytes()
- _…and 9 more_

### Community 5 — UnmarshalText() (5) (27 nodes, cohesion: 0.09)

- encstring
- b64decode()
- b64encode()
- DecryptWith()
- DecryptWithAsymmetric()
- EncryptWith()
- EncryptWithAsymmetric()
- EncryptWithToString()
- EncString
- EncStringType
- GenerateAsymmetric()
- HasMAC()
- bytes
- crypto/hmac
- crypto/rand
- crypto/rsa
- crypto/sha1
- crypto/sha256
- crypto/x509
- errors
- _…and 7 more_

### Community 6 — writeError() (25 nodes, cohesion: 0.09)

- unixsocketagent
- AgentState
- context
- crypto/subtle
- encoding/json
- fmt
- github.com/quexten/goldwarden/cli/agent/actions
- github.com/quexten/goldwarden/cli/agent/bitwarden
- github.com/quexten/goldwarden/cli/agent/bitwarden/crypto
- github.com/quexten/goldwarden/cli/agent/config
- github.com/quexten/goldwarden/cli/agent/notify
- github.com/quexten/goldwarden/cli/agent/processsecurity
- github.com/quexten/goldwarden/cli/agent/sockets
- github.com/quexten/goldwarden/cli/agent/ssh
- github.com/quexten/goldwarden/cli/agent/systemauth
- github.com/quexten/goldwarden/cli/agent/systemauth/pinentry
- github.com/quexten/goldwarden/cli/agent/vault
- github.com/quexten/goldwarden/cli/ipc/messages
- github.com/quexten/goldwarden/cli/logging
- net
- _…and 5 more_

### Community 7 — preLoginResponse (24 nodes, cohesion: 0.08)

- auth
- bytes
- context
- crypto/sha256
- encoding/base64
- encoding/json
- fmt
- github.com/quexten/goldwarden/cli/agent/bitwarden/crypto
- github.com/quexten/goldwarden/cli/agent/bitwarden/twofactor
- github.com/quexten/goldwarden/cli/agent/config
- github.com/quexten/goldwarden/cli/agent/notify
- github.com/quexten/goldwarden/cli/agent/systemauth/pinentry
- github.com/quexten/goldwarden/cli/agent/vault
- github.com/quexten/goldwarden/cli/logging
- golang.org/x/crypto/pbkdf2
- math/rand
- net/url
- runtime
- strconv
- strings
- _…and 4 more_

### Community 8 — WipeSessions() (21 nodes, cohesion: 0.13)

- systemauth
- CheckBiometrics()
- CreatePinSession()
- CreateSession()
- CreateSSHSession()
- GetPermission()
- GetSSHSession()
- fmt
- github.com/quexten/goldwarden/cli/agent/config
- github.com/quexten/goldwarden/cli/agent/sockets
- github.com/quexten/goldwarden/cli/agent/systemauth/biometrics
- github.com/quexten/goldwarden/cli/agent/systemauth/pinentry
- github.com/quexten/goldwarden/cli/logging
- math
- time
- Session
- SessionStore
- SessionType
- VerifyPinSession()
- verifySession()
- _…and 1 more_

### Community 9 — websocketMessageType() (21 nodes, cohesion: 0.11)

- websocket
- connectToWebsocket()
- bytes
- context
- github.com/awnumar/memguard
- github.com/gorilla/websocket
- github.com/quexten/goldwarden/cli/agent/bitwarden/models
- github.com/quexten/goldwarden/cli/agent/config
- github.com/quexten/goldwarden/cli/agent/notify
- github.com/quexten/goldwarden/cli/agent/systemauth/biometrics
- github.com/quexten/goldwarden/cli/agent/systemauth/pinentry
- github.com/quexten/goldwarden/cli/agent/vault
- github.com/quexten/goldwarden/cli/logging
- github.com/vmihailenco/msgpack/v5
- net/url
- os
- time
- NotificationMessageType
- parseMessageTypeFromMessagePack()
- RunWebsocketDaemon()
- _…and 1 more_

### Community 10 — URIMatch (21 nodes, cohesion: 0.10)

- models
- Card
- Cipher
- CipherType
- Field
- FieldType
- Folder
- GetKeyForCipher()
- Identity
- github.com/google/uuid
- github.com/quexten/goldwarden/cli/agent/bitwarden/crypto
- time
- LoginCipher
- Organization
- Profile
- SecureNoteCipher
- SecureNoteType
- SSHKeyCipher
- SyncData
- URI
- _…and 1 more_

### Community 11 — SetInitError() (21 nodes, cohesion: 0.14)

- pinentry
- Close()
- descEncode()
- FindProgram()
- Get()
- bufio
- fmt
- github.com/keybase/client/go/logger
- github.com/keybase/client/go/protocol/keybase1
- io
- os
- os/exec
- strings
- Init()
- New()
- Pinentry
- pinentryInstance
- resDecode()
- Run()
- Set()
- _…and 1 more_

### Community 12 — sync() (20 nodes, cohesion: 0.12)

- actions
- Action
- ActionsRegistry
- ensureBiometricsAuthorized()
- ensureEverything()
- ensureIsLoggedIn()
- ensureIsNotLocked()
- Get()
- context
- github.com/quexten/goldwarden/cli/agent/bitwarden
- github.com/quexten/goldwarden/cli/agent/bitwarden/crypto
- github.com/quexten/goldwarden/cli/agent/config
- github.com/quexten/goldwarden/cli/agent/sockets
- github.com/quexten/goldwarden/cli/agent/systemauth
- github.com/quexten/goldwarden/cli/agent/vault
- github.com/quexten/goldwarden/cli/ipc/messages
- github.com/quexten/goldwarden/cli/logging
- newActionsRegistry()
- Register()
- sync()

### Community 13 — GoldwardenSSHSetupGuideApp (19 nodes, cohesion: 0.11)

- ssh
- GoldwardenSSHSetupGuideApp
- .__init__()
- .load()
- .on_activate()
- ..components
- gi
- gi.repository.Adw
- gi.repository.Gdk
- gi.repository.Gio
- gi.repository.GLib
- gi.repository.Gtk
- os
- .resource_loader.load_json
- .resource_loader.load_template
- ..services.goldwarden
- subprocess
- sys
- threading.Thread

### Community 14 — GoldwardenBrowserBiometricsSetupGuideApp (19 nodes, cohesion: 0.11)

- browserbiometrics
- GoldwardenBrowserBiometricsSetupGuideApp
- .__init__()
- .load()
- .on_activate()
- ..components
- gi
- gi.repository.Adw
- gi.repository.Gdk
- gi.repository.Gio
- gi.repository.GLib
- gi.repository.Gtk
- os
- .resource_loader.load_json
- .resource_loader.load_template
- ..services.goldwarden
- subprocess
- sys
- threading.Thread

### Community 15 — init() (15) (19 nodes, cohesion: 0.11)

- config
- ConfigResponse
- handleGetConfigEnvironment()
- handleGetRuntimeConfig()
- handleSetApiURL()
- handleSetClientID()
- handleSetClientSecret()
- handleSetIdentity()
- handleSetNotifications()
- handleSetURLsAutomatically()
- handleSetVaultURL()
- encoding/json
- github.com/quexten/goldwarden/cli/agent/config
- github.com/quexten/goldwarden/cli/agent/sockets
- github.com/quexten/goldwarden/cli/agent/vault
- github.com/quexten/goldwarden/cli/ipc/messages
- io
- net/http
- init()

### Community 16 — GoldwardenShortcutsSetupGuideApp (18 nodes, cohesion: 0.12)

- shortcuts
- GoldwardenShortcutsSetupGuideApp
- .__init__()
- .load()
- .on_activate()
- ..components
- gi
- gi.repository.Adw
- gi.repository.Gdk
- gi.repository.Gio
- gi.repository.GLib
- gi.repository.Gtk
- os
- .resource_loader.load_template
- ..services.goldwarden
- subprocess
- sys
- threading.Thread

### Community 17 — SendTextMetadata (17 nodes, cohesion: 0.12)

- send
- CreateSend()
- context
- crypto/rand
- crypto/sha256
- encoding/base64
- github.com/quexten/goldwarden/cli/agent/bitwarden/crypto
- github.com/quexten/goldwarden/cli/agent/config
- github.com/quexten/goldwarden/cli/agent/vault
- golang.org/x/crypto/hkdf
- io
- strings
- time
- SendCreateRequest
- SendFileMetadata
- SendMetadata
- SendTextMetadata

### Community 18 — init() (17 nodes, cohesion: 0.12)

- vault
- handleLockVault()
- handlePinStatus()
- handleUnlockVault()
- handleUpdateVaultPin()
- handleVaultStatus()
- handleWipeVault()
- context
- github.com/quexten/goldwarden/cli/agent/bitwarden
- github.com/quexten/goldwarden/cli/agent/bitwarden/crypto
- github.com/quexten/goldwarden/cli/agent/config
- github.com/quexten/goldwarden/cli/agent/sockets
- github.com/quexten/goldwarden/cli/agent/systemauth/biometrics
- github.com/quexten/goldwarden/cli/agent/systemauth/pinentry
- github.com/quexten/goldwarden/cli/agent/vault
- github.com/quexten/goldwarden/cli/ipc/messages
- init()

### Community 19 — WriteMessage() (17 nodes, cohesion: 0.16)

- unixsocketclient
- Close()
- Connect()
- encoding/json
- github.com/quexten/goldwarden/cli/agent/config
- github.com/quexten/goldwarden/cli/ipc/messages
- io
- net
- os
- NewUnixSocketClient()
- Reader()
- ReadMessage()
- SendCommand()
- SendToAgent()
- UnixSocketClient
- UnixSocketConnection
- WriteMessage()

### Community 20 — rsaEncrypt() (17 nodes, cohesion: 0.13)

- crypto
- decryptStringSymmetric()
- encryptStringSymmetric()
- generateTransportKey()
- bytes
- crypto/aes
- crypto/cipher
- crypto/rand
- crypto/rsa
- crypto/sha1
- crypto/x509
- encoding/base64
- errors
- io
- pkcs7Pad()
- pkcs7Unpad()
- rsaEncrypt()

### Community 21 — setupSystemd() (16 nodes, cohesion: 0.14)

- setup_linux
- embed
- fmt
- github.com/quexten/goldwarden/cli/agent/systemauth/biometrics
- github.com/quexten/goldwarden/cli/browserbiometrics
- github.com/spf13/cobra
- log
- os
- os/exec
- os/user
- strings
- init()
- IsPolkitSetup()
- isRoot()
- setupPolkit()
- setupSystemd()

### Community 22 — main() (22) (15 nodes, cohesion: 0.13)

- main
- .monitors.dbus_autofill_monitor
- .monitors.dbus_monitor
- .monitors.locked_monitor
- os
- secrets
- src.linux.flatpak.api
- src.services.goldwarden
- src.services.pinentry
- subprocess
- sys
- tendo.singleton
- threading.Thread
- time
- main()

### Community 23 — time (23) (15 nodes, cohesion: 0.13)

- quickaccess
- gc
- gi
- gi.repository.Adw
- gi.repository.Gdk
- gi.repository.GLib
- gi.repository.Gtk
- os
- .resource_loader.load_template
- ..services.autotype.autotype
- ..services.goldwarden
- ..services.totp
- sys
- threading.Thread
- time

### Community 24 — MasterKeyFromBytes() (15 nodes, cohesion: 0.13)

- kdf
- DeriveMasterKey()
- GetBytes()
- bytes
- crypto/sha256
- fmt
- github.com/awnumar/memguard
- golang.org/x/crypto/argon2
- golang.org/x/crypto/pbkdf2
- runtime/debug
- strings
- KDFConfig
- KDFType
- MasterKey
- MasterKeyFromBytes()

### Community 25 — PutAuthRequest() (15 nodes, cohesion: 0.13)

- passwordless
- AuthRequestData
- AuthRequestResponseData
- CreateAuthRequest()
- CreateAuthRequestData
- CreateAuthResponse()
- GetAuthRequest()
- GetAuthRequests()
- GetAuthResponse()
- context
- encoding/base64
- github.com/quexten/goldwarden/cli/agent/bitwarden/crypto
- github.com/quexten/goldwarden/cli/agent/config
- time
- PutAuthRequest()

### Community 26 — WriteVault() (15 nodes, cohesion: 0.14)

- sync
- DoFullSync()
- context
- encoding/json
- fmt
- github.com/quexten/goldwarden/cli/agent/bitwarden/crypto
- github.com/quexten/goldwarden/cli/agent/bitwarden/models
- github.com/quexten/goldwarden/cli/agent/config
- github.com/quexten/goldwarden/cli/agent/vault
- github.com/quexten/goldwarden/cli/logging
- os
- time
- ReadVault()
- Sync()
- WriteVault()

### Community 27 — errStatusCode (14 nodes, cohesion: 0.14)

- http
- AuthToken
- Error()
- errStatusCode
- bytes
- context
- encoding/base64
- encoding/json
- fmt
- io
- net/http
- net/url
- strings
- time

### Community 28 — init() (28) (14 nodes, cohesion: 0.14)

- ssh
- handleAddSSH()
- handleImportSSH()
- handleListSSH()
- context
- github.com/quexten/goldwarden/cli/agent/bitwarden
- github.com/quexten/goldwarden/cli/agent/config
- github.com/quexten/goldwarden/cli/agent/sockets
- github.com/quexten/goldwarden/cli/agent/ssh
- github.com/quexten/goldwarden/cli/agent/systemauth
- github.com/quexten/goldwarden/cli/agent/vault
- github.com/quexten/goldwarden/cli/ipc/messages
- strings
- init()

### Community 29 — SetVaultURLRequest (14 nodes, cohesion: 0.14)

- config
- GetConfigEnvironmentRequest
- GetConfigEnvironmentResponse
- GetRuntimeConfigRequest
- GetRuntimeConfigResponse
- encoding/json
- init()
- SetApiURLRequest
- SetClientIDRequest
- SetClientSecretRequest
- SetIdentityURLRequest
- SetNotificationsURLRequest
- SetURLsAutomaticallyRequest
- SetVaultURLRequest

### Community 30 — time (30) (14 nodes, cohesion: 0.14)

- login
- gc
- gi
- gi.repository.Adw
- gi.repository.Gdk
- gi.repository.GLib
- gi.repository.Gtk
- gi.repository.Notify
- os
- .resource_loader.load_template
- ..services.goldwarden
- sys
- threading.Thread
- time

### Community 31 — run_daemon() (31) (14 nodes, cohesion: 0.14)

- dbus_monitor
- daemon()
- GoldwardenDBUSService
- .__init__()
- .quickaccess()
- .settings()
- dbus
- dbus.mainloop.glib.DBusGMainLoop
- dbus.service
- gi.repository.Gtk
- os
- subprocess
- threading.Thread
- run_daemon()

### Community 32 — init() (32) (14 nodes, cohesion: 0.14)

- browserbiometrics
- handleGetBiometricsKey()
- context
- encoding/base64
- fmt
- github.com/quexten/goldwarden/cli/agent/config
- github.com/quexten/goldwarden/cli/agent/notify
- github.com/quexten/goldwarden/cli/agent/sockets
- github.com/quexten/goldwarden/cli/agent/systemauth/biometrics
- github.com/quexten/goldwarden/cli/agent/systemauth/pinentry
- github.com/quexten/goldwarden/cli/agent/vault
- github.com/quexten/goldwarden/cli/ipc/messages
- time
- init()

### Community 33 — readLoop() (14 nodes, cohesion: 0.18)

- protocol
- handlePayloadMessage()
- handleUnencryptedMessage()
- bufio
- encoding/json
- fmt
- github.com/quexten/goldwarden/cli/agent/config
- github.com/quexten/goldwarden/cli/browserbiometrics/logging
- github.com/quexten/goldwarden/cli/client
- github.com/quexten/goldwarden/cli/ipc/messages
- io
- os
- parseMessage()
- readLoop()

### Community 34 — run_daemon() (34) (14 nodes, cohesion: 0.14)

- dbus_autofill_monitor
- daemon()
- GoldwardenDBUSService
- .autofill()
- .__init__()
- dbus
- dbus.mainloop.glib.DBusGMainLoop
- dbus.service
- gi.repository.Gtk
- gi.require_version
- os
- subprocess
- threading.Thread
- run_daemon()

### Community 35 — time (35) (13 nodes, cohesion: 0.15)

- pinentry_approval
- gc
- gi
- gi.repository.Adw
- gi.repository.Gdk
- gi.repository.GLib
- gi.repository.Gtk
- gi.repository.Notify
- os
- .resource_loader.load_template
- sys
- threading.Thread
- time

### Community 36 — run_daemon() (13 nodes, cohesion: 0.15)

- locked_monitor
- daemon()
- dbus
- dbus.mainloop.glib.DBusGMainLoop
- dbus.service
- gi.repository.Gtk
- os
- src.linux.flatpak.api
- src.services.goldwarden
- subprocess
- threading.Thread
- time
- run_daemon()

### Community 37 — time (13 nodes, cohesion: 0.15)

- pinentry
- gc
- gi
- gi.repository.Adw
- gi.repository.Gdk
- gi.repository.GLib
- gi.repository.Gtk
- gi.repository.Notify
- os
- .resource_loader.load_template
- sys
- threading.Thread
- time

### Community 38 — init() (38) (13 nodes, cohesion: 0.15)

- login
- handleLogin()
- context
- fmt
- github.com/quexten/goldwarden/cli/agent/bitwarden
- github.com/quexten/goldwarden/cli/agent/bitwarden/crypto
- github.com/quexten/goldwarden/cli/agent/config
- github.com/quexten/goldwarden/cli/agent/notify
- github.com/quexten/goldwarden/cli/agent/sockets
- github.com/quexten/goldwarden/cli/agent/vault
- github.com/quexten/goldwarden/cli/ipc/messages
- time
- init()

### Community 39 — init() (39) (13 nodes, cohesion: 0.15)

- logins
- handleGetLoginCipher()
- handleListLoginsRequest()
- fmt
- github.com/quexten/goldwarden/cli/agent/bitwarden/crypto
- github.com/quexten/goldwarden/cli/agent/config
- github.com/quexten/goldwarden/cli/agent/sockets
- github.com/quexten/goldwarden/cli/agent/systemauth
- github.com/quexten/goldwarden/cli/agent/systemauth/pinentry
- github.com/quexten/goldwarden/cli/agent/vault
- github.com/quexten/goldwarden/cli/ipc/messages
- runtime/debug
- init()

### Community 40 — threading.Thread (13 nodes, cohesion: 0.15)

- settings
- gi
- gi.repository.Adw
- gi.repository.Gdk
- gi.repository.Gio
- gi.repository.GLib
- gi.repository.Gtk
- os
- .resource_loader.load_template
- ..services.goldwarden
- subprocess
- sys
- threading.Thread

### Community 41 — writeMessageLength() (13 nodes, cohesion: 0.18)

- communication
- dataToBytes()
- bytes
- encoding/binary
- encoding/json
- fmt
- github.com/quexten/goldwarden/cli/browserbiometrics/logging
- os
- unsafe
- readMessageLength()
- send()
- setupCommunication()
- writeMessageLength()

### Community 42 — registerPayloadParser() (13 nodes, cohesion: 0.19)

- messages
- hash()
- encoding/json
- errors
- github.com/quexten/goldwarden/cli/logging
- hash/fnv
- reflect
- IPCMessage
- IPCMessageFromPayload()
- IPCMessageType
- MessageTypeForEmptyPayload()
- parsePayload
- registerPayloadParser()

### Community 43 — GoldwardenQuickAccessApp (12 nodes, cohesion: 0.29)

- GoldwardenQuickAccessApp
- .__init__()
- .key_press()
- .load()
- .on_activate()
- .on_type()
- .render_list()
- .run_autotype()
- .set_clipboard()
- .update()
- .update_list()
- .update_logins()

### Community 44 — HasWindows() (44) (12 nodes, cohesion: 0.17)

- pinentry_windows
- canExec()
- FindPinentry()
- GetTerminalName()
- HasWindows()
- fmt
- github.com/keybase/client/go/logger
- golang.org/x/sys/windows/registry
- os
- os/exec
- path/filepath
- strings

### Community 45 — ListLogins() (12 nodes, cohesion: 0.17)

- logins
- encoding/json
- errors
- fmt
- github.com/icza/gox/stringsx
- github.com/quexten/goldwarden/cli/client
- github.com/quexten/goldwarden/cli/ipc/messages
- github.com/spf13/cobra
- os
- strings
- init()
- ListLogins()

### Community 46 — SSHKeyCipherFromKey() (11 nodes, cohesion: 0.18)

- keys
- crypto/ed25519
- crypto/rand
- encoding/pem
- github.com/mikesmitty/edkey
- github.com/quexten/goldwarden/cli/agent/bitwarden/crypto
- github.com/quexten/goldwarden/cli/agent/bitwarden/models
- golang.org/x/crypto/ssh
- io
- NewSSHKeyCipher()
- SSHKeyCipherFromKey()

### Community 47 — UnlockWithAccountKey() (11 nodes, cohesion: 0.18)

- keyring
- GetAccountKey()
- GetSymmetricKeyForOrganization()
- errors
- github.com/quexten/goldwarden/cli/logging
- IsLocked()
- Keyring
- Lock()
- NewMemguardKeyring()
- NewMemoryKeyring()
- UnlockWithAccountKey()

### Community 48 — SessionAuthResponse (11 nodes, cohesion: 0.18)

- session
- encoding/json
- init()
- PinentryApprovalRequest
- PinentryApprovalResponse
- PinentryPinRequest
- PinentryPinResponse
- PinentryRegistrationRequest
- PinentryRegistrationResponse
- SessionAuthRequest
- SessionAuthResponse

### Community 49 — UnmarshalText() (11 nodes, cohesion: 0.18)

- twofactor
- errors
- fmt
- github.com/quexten/goldwarden/cli/agent/config
- github.com/quexten/goldwarden/cli/agent/systemauth/pinentry
- github.com/quexten/goldwarden/cli/logging
- strconv
- PerformSecondFactor()
- TwoFactorProvider
- TwoFactorResponse
- UnmarshalText()

### Community 50 — Fido2TwoFactor() (50) (11 nodes, cohesion: 0.18)

- fido2twofactor
- Fido2Response
- Fido2TwoFactor()
- crypto/sha256
- encoding/base64
- encoding/json
- errors
- github.com/keys-pub/go-libfido2
- github.com/quexten/goldwarden/cli/agent/config
- github.com/quexten/goldwarden/cli/agent/systemauth/pinentry
- net/url

### Community 51 — loginIfRequired() (11 nodes, cohesion: 0.18)

- root
- Execute()
- handleSendToAgentError()
- fmt
- github.com/quexten/goldwarden/cli/agent/config
- github.com/quexten/goldwarden/cli/client
- github.com/quexten/goldwarden/cli/ipc/messages
- github.com/spf13/cobra
- os
- init()
- loginIfRequired()

### Community 52 — Main() (10 nodes, cohesion: 0.20)

- main
- DetectAndInstallBrowsers()
- embed
- fmt
- github.com/quexten/goldwarden/cli/agent/config
- github.com/quexten/goldwarden/cli/browserbiometrics/logging
- os
- path/filepath
- strings
- Main()

### Community 53 — init() (53) (10 nodes, cohesion: 0.20)

- send
- handleCreateSend()
- context
- fmt
- github.com/quexten/goldwarden/cli/agent/bitwarden
- github.com/quexten/goldwarden/cli/agent/config
- github.com/quexten/goldwarden/cli/agent/sockets
- github.com/quexten/goldwarden/cli/agent/vault
- github.com/quexten/goldwarden/cli/ipc/messages
- init()

### Community 54 — init() (54) (10 nodes, cohesion: 0.20)

- getclicredentials
- handleGetCliCredentials()
- fmt
- github.com/quexten/goldwarden/cli/agent/config
- github.com/quexten/goldwarden/cli/agent/sockets
- github.com/quexten/goldwarden/cli/agent/systemauth
- github.com/quexten/goldwarden/cli/agent/systemauth/pinentry
- github.com/quexten/goldwarden/cli/agent/vault
- github.com/quexten/goldwarden/cli/ipc/messages
- init()

### Community 55 — stretchKey() (10 nodes, cohesion: 0.24)

- keyhierarchy
- crypto/sha256
- fmt
- github.com/awnumar/memguard
- golang.org/x/crypto/hkdf
- io
- InitKeyringFromMasterKey()
- InitKeyringFromMasterPassword()
- InitKeyringFromUserSymmetricKey()
- stretchKey()

### Community 56 — get_pin() (10 nodes, cohesion: 0.20)

- pinentry
- daemon()
- daemonize()
- get_approval()
- get_pin()
- os
- src.services.goldwarden
- subprocess
- threading.Thread
- time

### Community 57 — ListLoginsRequest (10 nodes, cohesion: 0.20)

- notes
- AddLoginRequest
- AddLoginResponse
- DecryptedLoginCipher
- GetLoginRequest
- GetLoginResponse
- GetLoginsResponse
- encoding/json
- init()
- ListLoginsRequest

### Community 58 — WipeVaultRequest (10 nodes, cohesion: 0.20)

- vault
- GetVaultPINRequest
- encoding/json
- init()
- LockVaultRequest
- UnlockVaultRequest
- UpdateVaultPINRequest
- VaultStatusRequest
- VaultStatusResponse
- WipeVaultRequest

### Community 59 — TypeString() (10 nodes, cohesion: 0.24)

- libportalautotype
- fmt
- github.com/godbus/dbus/v5
- github.com/quexten/goldwarden/cli/logging
- io/ioutil
- os
- time
- persistToken()
- readToken()
- TypeString()

### Community 60 — main() (60) (9 nodes, cohesion: 0.22)

- main
- os
- secrets
- src.services.goldwarden
- src.services.pinentry
- subprocess
- sys
- time
- main()

### Community 61 — SetExternalPinentry() (9 nodes, cohesion: 0.22)

- pinentry
- GetApproval()
- GetPassword()
- errors
- github.com/quexten/goldwarden/cli/logging
- os
- init()
- Pinentry
- SetExternalPinentry()

### Community 62 — Wipe() (9 nodes, cohesion: 0.22)

- lockedbuffer
- Bytes()
- github.com/awnumar/memguard
- LockedBuffer
- MemGuardLockedBuffer
- MemoryLockedBuffer
- NewBuffer()
- NewBufferFromBytes()
- Wipe()

### Community 63 — init() (63) (9 nodes, cohesion: 0.22)

- sshkeys
- CreateSSHKeyRequest
- CreateSSHKeyResponse
- GetSSHKeysRequest
- GetSSHKeysResponse
- encoding/json
- ImportSSHKeyRequest
- ImportSSHKeyResponse
- init()

### Community 64 — request_autostart() (9 nodes, cohesion: 0.22)

- autostart
- gi
- gi.repository.Gio
- gi.repository.GLib
- random.randint
- sys
- threading.Timer
- receive_autostart()
- request_autostart()

### Community 65 — GetTerminalName() (9 nodes, cohesion: 0.25)

- pinentry_nix
- canExec()
- FindPinentry()
- GetTerminalName()
- fmt
- github.com/keybase/client/go/logger
- os
- os/exec
- path/filepath

### Community 66 — IsLocked() (8 nodes, cohesion: 0.46)

- decryptString()
- GetClientID()
- GetClientSecret()
- GetMasterKey()
- GetMasterPasswordHash()
- GetToken()
- GetUserSymmetricKey()
- IsLocked()

### Community 67 — SetPin() (8 nodes, cohesion: 0.25)

- pincache
- ClearPin()
- GetPin()
- HasPin()
- errors
- github.com/awnumar/memguard
- github.com/quexten/goldwarden/cli/agent/systemauth/biometrics
- SetPin()

### Community 68 — WriteConfig() (8 nodes, cohesion: 0.43)

- encryptString()
- SetClientID()
- SetClientSecret()
- SetMasterKey()
- SetMasterPasswordHash()
- SetToken()
- SetUserSymmetricKey()
- WriteConfig()

### Community 69 — init() (69) (8 nodes, cohesion: 0.25)

- session
- bufio
- fmt
- github.com/quexten/goldwarden/cli/ipc/messages
- github.com/spf13/cobra
- os
- strings
- init()

### Community 70 — ListSendsRequest (8 nodes, cohesion: 0.25)

- send
- CreateSendRequest
- CreateSendResponse
- GetSendRequest
- GetSendResponse
- encoding/json
- init()
- ListSendsRequest

### Community 71 — run_window() (8 nodes, cohesion: 0.39)

- GoldwardenSettingsApp
- .__init__()
- .load()
- .on_activate()
- .render()
- .show_about()
- .update()
- run_window()

### Community 72 — StatusIcon (8 nodes, cohesion: 0.36)

- components
- gi.repository.Gtk
- status_icon_error()
- status_icon_ok()
- status_icon_warning()
- StatusIcon
- .__init__()
- .set_icon()

### Community 73 — MonitorLocks() (8 nodes, cohesion: 0.25)

- unix
- DisableDumpable()
- github.com/godbus/dbus/v5
- github.com/quexten/goldwarden/cli/agent/processsecurity/isdelve
- golang.org/x/sys/unix
- time
- MonitorIdle()
- MonitorLocks()

### Community 74 — PutCipher() (8 nodes, cohesion: 0.25)

- ciphers
- DeleteCipher()
- GetCipher()
- context
- github.com/quexten/goldwarden/cli/agent/bitwarden/models
- github.com/quexten/goldwarden/cli/agent/config
- PostCipher()
- PutCipher()

### Community 75 — writeLog() (8 nodes, cohesion: 0.36)

- debuglogger
- Debugf()
- Errorf()
- fmt
- os
- time
- Panicf()
- writeLog()

### Community 76 — UnencryptedRecvMessage (8 nodes, cohesion: 0.25)

- messages
- EncryptedRecvMessage
- EncryptedString
- GenericRecvMessage
- PayloadMessage
- ReceiveMessage
- SendMessage
- UnencryptedRecvMessage

### Community 77 — totp() (8 nodes, cohesion: 0.29)

- totp
- hotp()
- base64
- hmac
- struct
- sys
- time
- totp()

### Community 78 — init() (78) (8 nodes, cohesion: 0.25)

- ssh
- bytes
- fmt
- github.com/atotto/clipboard
- github.com/quexten/goldwarden/cli/ipc/messages
- github.com/spf13/cobra
- os
- init()

### Community 79 — _type_lt245() (8 nodes, cohesion: 0.29)

- x11autotype
- os
- time
- Xlib.display.Display
- Xlib.ext.xtest.fake_input
- Xlib.X
- type()
- _type_lt245()

### Community 80 — init() (80) (8 nodes, cohesion: 0.25)

- daemonize
- fmt
- github.com/awnumar/memguard
- github.com/quexten/goldwarden/cli/agent
- github.com/spf13/cobra
- os
- syscall
- init()

### Community 81 — init() (81) (7 nodes, cohesion: 0.29)

- autofill
- bufio
- encoding/hex
- github.com/quexten/goldwarden/cli/autotype
- github.com/spf13/cobra
- os
- init()

### Community 82 — init() (82) (7 nodes, cohesion: 0.29)

- config
- encoding/json
- fmt
- github.com/quexten/goldwarden/cli/ipc/messages
- github.com/spf13/cobra
- strings
- init()

### Community 83 — main() (7 nodes, cohesion: 0.29)

- main
- github.com/quexten/goldwarden/cli/agent/config
- github.com/quexten/goldwarden/cli/browserbiometrics
- github.com/quexten/goldwarden/cli/cmd
- os
- strings
- main()

### Community 84 — init() (84) (7 nodes, cohesion: 0.29)

- logins
- DecryptedNoteCipher
- GetNoteResponse
- GetNotesRequest
- GetNotesResponse
- encoding/json
- init()

### Community 85 — GetCallingContext() (7 nodes, cohesion: 0.29)

- callingcontext
- CallingContext
- GetCallingContext()
- github.com/mitchellh/go-ps
- github.com/tailscale/peercred
- net
- os/user

### Community 86 — init() (86) (7 nodes, cohesion: 0.29)

- run
- fmt
- github.com/quexten/goldwarden/cli/ipc/messages
- github.com/spf13/cobra
- os
- os/exec
- init()

### Community 87 — set_status() (87) (7 nodes, cohesion: 0.29)

- status
- gi
- gi.repository.Gio
- gi.repository.GLib
- sys
- threading.Timer
- set_status()

### Community 88 — init() (88) (7 nodes, cohesion: 0.29)

- vault
- encoding/json
- fmt
- github.com/quexten/goldwarden/cli/ipc/messages
- github.com/spf13/cobra
- time
- init()

### Community 89 — getPassword() (7 nodes, cohesion: 0.38)

- go-pinentry
- getApproval()
- getBinaryClientOption()
- getPassword()
- errors
- github.com/twpayne/go-pinentry
- runtime

### Community 90 — getPassword() (90) (7 nodes, cohesion: 0.29)

- keybase-pinentry
- getApproval()
- getPassword()
- errors
- github.com/keybase/client/go/logger
- github.com/keybase/client/go/protocol/keybase1
- github.com/quexten/goldwarden/cli/agent/systemauth/pinentry/keybase-pinentry

### Community 91 — urlValues() (7 nodes, cohesion: 0.43)

- deviceType()
- LoginWithApiKey()
- LoginWithDevice()
- LoginWithMasterpassword()
- Perform2FA()
- RefreshToken()
- urlValues()

### Community 92 — mainloop() (6 nodes, cohesion: 0.33)

- defaultmainloop
- fmt
- os
- os/signal
- syscall
- mainloop()

### Community 93 — init() (93) (6 nodes, cohesion: 0.33)

- send
- fmt
- github.com/quexten/goldwarden/cli/ipc/messages
- github.com/spf13/cobra
- os
- init()

### Community 94 — useSecretStore() (6 nodes, cohesion: 0.33)

- pinentry_osx
- HasWindows()
- os
- pinentrySecretStoreInfo
- shouldStoreSecret()
- useSecretStore()

### Community 95 — GoldwardenPinentryApp (6 nodes, cohesion: 0.40)

- GoldwardenPinentryApp
- .__init__()
- .load()
- .on_activate()
- .on_approve_button_clicked()
- .on_cancel_button_clicked()

### Community 96 — Serve() (96) (6 nodes, cohesion: 0.33)

- sshsocketunix
- github.com/quexten/goldwarden/cli/agent/sockets
- golang.org/x/crypto/ssh/agent
- net
- os
- Serve()

### Community 97 — GoldwardenPinentryApprovalApp (6 nodes, cohesion: 0.40)

- GoldwardenPinentryApprovalApp
- .__init__()
- .load()
- .on_activate()
- .on_approve_button_clicked()
- .on_cancel_button_clicked()

### Community 98 — Write() (6 nodes, cohesion: 0.33)

- llamalogger
- GetLogger()
- github.com/LlamaNite/llamalog
- os
- SilentWriter
- Write()

### Community 99 — GoldwardenLoginApp (6 nodes, cohesion: 0.53)

- GoldwardenLoginApp
- .__init__()
- .key_press()
- .load()
- .on_activate()
- .on_login()

### Community 100 — load_template() (6 nodes, cohesion: 0.33)

- resource_loader
- gi.repository.Gtk
- json
- os
- load_json()
- load_template()

### Community 101 — init() (101) (5 nodes, cohesion: 0.40)

- version
- embed
- fmt
- github.com/spf13/cobra
- init()

### Community 102 — makeAuthenticatedHTTPRequest() (5 nodes, cohesion: 0.40)

- authenticatedHTTPDelete()
- authenticatedHTTPGet()
- authenticatedHTTPPost()
- authenticatedHTTPPut()
- makeAuthenticatedHTTPRequest()

### Community 103 — Serve() (5 nodes, cohesion: 0.40)

- sshsocketwindows
- github.com/Microsoft/go-winio
- github.com/quexten/goldwarden/cli/agent/sockets
- golang.org/x/crypto/ssh/agent
- Serve()

### Community 104 — init() (104) (5 nodes, cohesion: 0.40)

- getclicredentials
- GetCLICredentialsRequest
- GetCLICredentialsResponse
- encoding/json
- init()

### Community 105 — notifyDBus() (5 nodes, cohesion: 0.40)

- dbus
- github.com/godbus/dbus/v5
- time
- listenForNotificationsDBus()
- notifyDBus()

### Community 106 — Notify() (106) (5 nodes, cohesion: 0.40)

- beeep
- github.com/gen2brain/beeep
- time
- ListenForNotifications()
- Notify()

### Community 107 — PublicBytes() (5 nodes, cohesion: 0.40)

- Bytes()
- EncryptionKeyBytes()
- MacKeyBytes()
- PrivateBytes()
- PublicBytes()

### Community 108 — set_status() (5 nodes, cohesion: 0.40)

- api
- os
- subprocess
- register_autostart()
- set_status()

### Community 109 — init() (109) (5 nodes, cohesion: 0.40)

- biometrics
- GetBiometricsKeyRequest
- GetBiometricsKeyResponse
- encoding/json
- init()

### Community 110 — Notify() (5 nodes, cohesion: 0.40)

- windows
- github.com/go-toast/toast
- time
- ListenForNotifications()
- Notify()

### Community 111 — VerifySetup() (111) (5 nodes, cohesion: 0.40)

- setup_linux
- fmt
- github.com/quexten/goldwarden/cli/agent/config
- github.com/quexten/goldwarden/cli/cmd
- VerifySetup()

### Community 112 — init() (112) (5 nodes, cohesion: 0.40)

- login
- fmt
- github.com/quexten/goldwarden/cli/ipc/messages
- github.com/spf13/cobra
- init()

### Community 113 — init() (113) (5 nodes, cohesion: 0.40)

- pin
- fmt
- github.com/quexten/goldwarden/cli/ipc/messages
- github.com/spf13/cobra
- init()

### Community 114 — Notify() (114) (5 nodes, cohesion: 0.40)

- linux
- github.com/quexten/goldwarden/cli/logging
- time
- ListenForNotifications()
- Notify()

### Community 115 — init() (115) (4 nodes, cohesion: 0.50)

- actionresponse
- ActionResponse
- encoding/json
- init()

### Community 116 — Panicf() (4 nodes, cohesion: 0.50)

- nooplogger
- Debugf()
- Errorf()
- Panicf()

### Community 117 — Fido2TwoFactor() (4 nodes, cohesion: 0.50)

- fido2twofactorunsupported
- Fido2TwoFactor()
- errors
- github.com/quexten/goldwarden/cli/agent/config

### Community 118 — notifyLibPortal() (4 nodes, cohesion: 0.50)

- libportal
- github.com/rymdport/portal/notification
- time
- notifyLibPortal()

### Community 119 — CheckBiometrics() (119) (4 nodes, cohesion: 0.50)

- touchid
- BiometricsWorking()
- CheckBiometrics()
- github.com/lox/go-touchid

### Community 120 — src.macos.main (4 nodes, cohesion: 0.50)

- goldwarden_ui_main
- platform
- src.linux.main
- src.macos.main

### Community 121 — getPassword() (121) (4 nodes, cohesion: 0.50)

- unimplemented
- getApproval()
- getPassword()
- errors

### Community 122 — autotype() (4 nodes, cohesion: 0.50)

- autotype
- autotype()
- os
- sys

### Community 123 — CheckBiometrics() (123) (4 nodes, cohesion: 0.50)

- polkit
- BiometricsWorking()
- CheckBiometrics()
- github.com/amenzhinsky/go-polkit

### Community 124 — MonitorLocks() (124) (4 nodes, cohesion: 0.50)

- unimplemented
- DisableDumpable()
- MonitorIdle()
- MonitorLocks()

### Community 125 — init() (125) (4 nodes, cohesion: 0.50)

- dologin
- DoLoginRequest
- encoding/json
- init()

### Community 126 — ParsedPayload() (4 nodes, cohesion: 0.50)

- ipc
- github.com/quexten/goldwarden/cli/ipc/messages
- IPCMessageFromPayload()
- ParsedPayload()

### Community 127 — String() (4 nodes, cohesion: 0.50)

- biometrics
- Approval
- github.com/quexten/goldwarden/cli/logging
- String()

### Community 128 — useSecretStore() (128) (4 nodes, cohesion: 0.50)

- pinentry_not_osx
- pinentrySecretStoreInfo
- shouldStoreSecret()
- useSecretStore()

### Community 129 — autotype_pyautogui() (3 nodes, cohesion: 0.67)

- pyautogui_autotype
- autotype_pyautogui()
- pyautogui

### Community 130 — VerifySetup() (3 nodes, cohesion: 0.67)

- setup_other
- github.com/quexten/goldwarden/cli/agent/config
- VerifySetup()

### Community 131 — CheckBiometrics() (3 nodes, cohesion: 0.67)

- windows
- BiometricsWorking()
- CheckBiometrics()

### Community 132 — HasWindows() (3 nodes, cohesion: 0.67)

- pinentry_x11
- HasWindows()
- os

### Community 133 — autotype_libportal() (3 nodes, cohesion: 0.67)

- libportal_autotype
- autotype_libportal()
- ..goldwarden.autotype

### Community 134 — nodelve (1 nodes, cohesion: 1.00)

- nodelve

### Community 135 — global_shortcut_portal (1 nodes, cohesion: 1.00)

- global_shortcut_portal

### Community 136 — __init__ (1 nodes, cohesion: 1.00)

- __init__

### Community 137 — isdelve (1 nodes, cohesion: 1.00)

- isdelve

## 🕳️ Knowledge Gaps

**Isolated nodes** (4):
- isdelve
- nodelve
- __init__
- global_shortcut_portal

**Thin communities** (< 3 nodes): 4 communities

## 💰 Token Cost

| File | Tokens |
|------|--------|
| input | 0 |
| output | 0 |
| **Total** | **0** |

## ❓ Suggested Questions

1. How does 'cli_agent_config_config_go_setclientid' relate to 3 different communities (WriteConfig(), VerifyPin(), IsLocked())?
1. How does 'cli_agent_config_config_go_setmasterpasswordhash' relate to 3 different communities (WriteConfig(), IsLocked(), VerifyPin())?
1. How does 'cli_agent_config_config_go_updatepin' relate to 3 different communities (VerifyPin(), WriteConfig(), IsLocked())?
1. How does 'cli_agent_config_config_go_setmasterkey' relate to 3 different communities (WriteConfig(), VerifyPin(), IsLocked())?
1. How does 'cli_agent_config_config_go_settoken' relate to 3 different communities (WriteConfig(), IsLocked(), VerifyPin())?
1. How does 'cli_agent_config_config_go_setusersymmetrickey' relate to 3 different communities (VerifyPin(), WriteConfig(), IsLocked())?
1. How does 'cli_agent_config_config_go_lock' relate to 3 different communities (WriteConfig(), IsLocked(), VerifyPin())?

---
_Generated by graphify-rs_
