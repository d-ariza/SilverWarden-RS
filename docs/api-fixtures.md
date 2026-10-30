# Fixtures de API (Vaultwarden / Bitwarden)

Estos son los JSON exactos que Vaultwarden espera en el endpoint `POST /api/ciphers` para cada tipo de item. Sirven como contrato de referencia para la implementación de `sw-bitwarden-api` y la futura GUI.

---

## Tipo 1 — Login (Inicio de sesión)
**Campos requeridos:** `type: 1`, `encryptedFor`, `name` (EncString), `login.uris`, `login.username`, `login.password`.

```json
{
  "type": 1,
  "encryptedFor": "22cadb2c-d706-471a-a3e9-9fb725925639",
  "name": "2.xxx",
  "notes": "2.xxx",
  "favorite": false,
  "reprompt": 0,
  "login": {
    "uris": [ { "uri": "2.xxx", "match": null, "uriChecksum": "2.xxx" } ],
    "username": "2.xxx",
    "password": "2.xxx",
    "totp": null
  },
  "fields": [],
  "attachments": {}
}
```

---

## Tipo 2 — Nota Segura
**Campos requeridos:** `type: 2`, `secureNote: { type: 0 }`.

```json
{
  "type": 2,
  "encryptedFor": "22cadb2c-d706-471a-a3e9-9fb725925639",
  "name": "2.xxx",
  "notes": "2.xxx",
  "favorite": false,
  "reprompt": 0,
  "secureNote": { "type": 0 },
  "fields": [],
  "attachments": {}
}
```

---

## Tipo 3 — Tarjeta
**Campos requeridos:** `type: 3`, `card: { cardholderName, brand, number, expMonth, expYear, code }`.

```json
{
  "type": 3,
  "encryptedFor": "22cadb2c-d706-471a-a3e9-9fb725925639",
  "name": "2.xxx",
  "notes": "2.xxx",
  "favorite": false,
  "reprompt": 0,
  "card": {
    "cardholderName": "2.xxx",
    "brand": "2.xxx",
    "number": "2.xxx",
    "expMonth": "2.xxx",
    "expYear": "2.xxx",
    "code": "2.xxx"
  },
  "fields": [],
  "attachments": {}
}
```

---

## Tipo 4 — Identidad
**Campos requeridos:** `type: 4`, `identity: { title, firstName, lastName, address1, city, state, postalCode, country, email, phone, ssn, username, ... }`.

```json
{
  "type": 4,
  "encryptedFor": "22cadb2c-d706-471a-a3e9-9fb725925639",
  "name": "2.xxx",
  "notes": "2.xxx",
  "favorite": false,
  "reprompt": 0,
  "identity": {
    "title": "2.xxx",
    "firstName": "2.xxx",
    "middleName": "2.xxx",
    "lastName": "2.xxx",
    "address1": "2.xxx",
    "city": "2.xxx",
    "state": "2.xxx",
    "postalCode": "2.xxx",
    "country": "2.xxx",
    "email": "2.xxx",
    "phone": "2.xxx",
    "ssn": "2.xxx",
    "username": "2.xxx",
    "passportNumber": "2.xxx",
    "licenseNumber": "2.xxx"
  },
  "fields": [],
  "attachments": {}
}
```

---

## Tipo 5 — Clave SSH
**Campos requeridos:** `type: 5`, `sshKey: { privateKey, publicKey, keyFingerprint }`.

```json
{
  "type": 5,
  "encryptedFor": "22cadb2c-d706-471a-a3e9-9fb725925639",
  "name": "2.xxx",
  "notes": "2.xxx",
  "favorite": false,
  "reprompt": 0,
  "sshKey": {
    "privateKey": "2.xxx",
    "publicKey": "2.xxx",
    "keyFingerprint": "2.xxx"
  },
  "fields": [],
  "attachments": {}
}
```

---

## Validación de contraseñas (Pwned Passwords)

**Endpoint:** `GET https://api.pwnedpasswords.com/range/{primeros_5_chars_sha1}`  
**Uso:** Se calcula el SHA-1 de la contraseña, se envían los primeros 5 caracteres, y la API responde con los sufijos de los hashes comprometidos. Si el sufijo coincide, la contraseña está filtrada. No envía la contraseña completa.
