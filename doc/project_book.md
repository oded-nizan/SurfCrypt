# SurfCrypt — Project Book

> **Document type:** Comprehensive Technical Reference  
> **Project:** SurfCrypt — Secure Password Manager + URL Analyzer  
> **Language:** Python 3.10+  
> **Platform:** Desktop (Windows primary, cross-platform compatible)  
> **Status:** Phase 1 — Core MVP

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Security Architecture — The Zero-Knowledge Envelope Model](#2-security-architecture--the-zero-knowledge-envelope-model)
   - 2.1 [Industry Precedent](#21-industry-precedent)
   - 2.2 [The Envelope Encryption Model Explained](#22-the-envelope-encryption-model-explained)
   - 2.3 [Registration Flow](#23-registration-flow)
   - 2.4 [Login Flow](#24-login-flow)
   - 2.5 [Secret Storage and Retrieval](#25-secret-storage-and-retrieval)
   - 2.6 [Password Change — The Envelope Advantage](#26-password-change--the-envelope-advantage)
3. [Cryptographic Foundation (`crypto.py`)](#3-cryptographic-foundation-cryptopy)
   - 3.1 [Library Choice: argon2-cffi](#31-library-choice-argon2-cffi)
   - 3.2 [KDF Parameters: RFC 9106 Compliance](#32-kdf-parameters-rfc-9106-compliance)
   - 3.3 [Library Choice: PyNaCl SecretBox](#33-library-choice-pynacl-secretbox)
   - 3.4 [Module Constants](#34-module-constants)
   - 3.5 [Custom Exception Hierarchy](#35-custom-exception-hierarchy)
   - 3.6 [Function Reference](#36-function-reference)
4. [Database Layer (`db.py` + `schema.sql`)](#4-database-layer-dbpy--schemasql)
   - 4.1 [Database Engine Choice: SQLite3](#41-database-engine-choice-sqlite3)
   - 4.2 [Concurrency Control: threading.Lock](#42-concurrency-control-threadinglock)
   - 4.3 [Database Schema](#43-database-schema)
   - 4.4 [Class Reference: DatabaseManager](#44-class-reference-databasemanager)
5. [Server Architecture (`server.py`)](#5-server-architecture-serverpy)
   - 5.1 [Transport Security: TLS over TCP](#51-transport-security-tls-over-tcp)
   - 5.2 [Session Management](#52-session-management)
   - 5.3 [Message Protocol](#53-message-protocol)
6. [Client Network & Identity Workflows (`network.py` & `identity.py`)](#6-client-network--identity-workflows-networkpy--identitypy)
   - 6.1 [Stateless Request Protocol](#61-stateless-request-protocol)
   - 6.2 [Class Reference: NetworkClient](#62-class-reference-networkclient)
   - 6.3 [Class Reference: IdentityManager](#63-class-reference-identitymanager)
   - 6.4 [Memory Isolation & Secrets Handling](#64-memory-isolation--secrets-handling)
7. [URL Threat Analyzer (`analyzer.py`)](#7-url-threat-analyzer-analyzerpy)
8. [GUI Framework: Tkinter](#8-gui-framework-tkinter)
9. [Technology Stack Justification Summary](#9-technology-stack-justification-summary)
10. [Testing Strategy](#10-testing-strategy)

---

## 1. Project Overview

SurfCrypt is a desktop application for managing credentials and analyzing URLs for security threats. Its primary design constraint is **zero-knowledge security**: even if the server database is compromised in its entirety, an attacker learns nothing useful because every secret is encrypted client-side before it ever leaves the user's device.

**Core capabilities (Phase 1):**
- User registration and authenticated login
- Encrypted credential vault (store, retrieve, update, delete)
- Password generator
- URL threat analysis (offline heuristics + local blacklists)
- 15-minute idle session management

**Architecture summary:**

```
+------------+  TLS/TCP (JSON)  +----------------+  SQL  +--------------+
|  TKinter   | <--------------> |   TCP Server   | <---> |   SQLite3    |
|   Client   |                  |  (Python ssl)  |       |   Database   |
+------------+                  +----------------+       +--------------+
      |
      |  ALL encryption/decryption happens here
      |  Master password and VaultKey never leave this process

**Execution Entry Points:**
The project uses standard Python module execution from the project root:
- Start Server: `python -m src.server`
- Start Client: `python -m src.client`

*Note: Always use dots (`.`) instead of slashes (`/`) when using the `-m` flag.*
```

---

## 2. Security Architecture — The Zero-Knowledge Envelope Model

### 2.1 Industry Precedent

The decision to implement a zero-knowledge encryption architecture was inspired directly by the security models employed by the leading commercial password managers. Their published security documentation provides authoritative justification for every design choice in SurfCrypt.

**Bitwarden** describes its core security guarantee in its publicly available [Security Whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/) (Bitwarden, Inc.) as follows:

> "Zero knowledge encryption: Bitwarden team members cannot see your passwords. Your data remains end-to-end encrypted with your individual email and master password. Bitwarden never stores and cannot access your master password or your cryptographic keys."

> "Privacy by design: Bitwarden stores all of your logins in an encrypted vault that syncs across all of your devices. Since it's fully encrypted before it ever leaves your device, only you have access to your data. Not even the team at Bitwarden can read your data (even if we wanted to)."

> "All cryptographic keys are generated and managed by the client on your devices, and all encryption is done locally."

The whitepaper also confirms that the master password is treated with strict memory isolation:

> "Master passwords are: Cleared or marked for removal from memory after usage. Never transmitted over the internet to Bitwarden servers. Unable to be seen, read, or reverse engineered by anyone at Bitwarden."

**1Password** describes the same model in its [Security Design document](https://1password.com/files/1Password-White-Paper.pdf) (AgileBits Inc.):

> "1Password is designed so that neither AgileBits nor anyone who can access your data on our systems is able to decrypt your data. Your account password never leaves your devices."

> "The Secret Key and account password are combined to derive the Master Unlock Key (MUK) locally on your device. The MUK is used to encrypt and decrypt your vault keys, and vault keys are used to encrypt and decrypt your vaults."

SurfCrypt adopts precisely this model: all encryption and decryption occurs on the client. The server stores only encrypted blobs. The master password is never transmitted.

---

### 2.2 The Envelope Encryption Model Explained

The term "envelope encryption" describes a two-layer key hierarchy. This is the same model used by cloud key management services (AWS KMS, Google Cloud KMS) and consumer password managers alike.

**The two layers:**

| Key | Name | Purpose | Where it lives |
|-----|------|---------|----------------|
| Layer 1 (outer) | **KEK** — Key Encryption Key | Encrypts the VaultKey | Derived on demand; never stored |
| Layer 2 (inner) | **VaultKey** | Encrypts all secrets | Stored encrypted (as WrappedVaultKey) |

```
Master Password
      |
      v  Argon2id(master_password, kek_salt)
     KEK  ---- encrypts ---->  WrappedVaultKey  (stored in DB)
                                      |  KEK decrypts
                                      v
                                 VaultKey  (held in memory only)
                                      |
                           encrypts each credential field
```

**Why two layers instead of directly encrypting secrets with the master password?**

Using the master password directly to encrypt secrets creates a catastrophic coupling: changing the password requires re-encrypting every single secret. With the envelope model:

- The **VaultKey** is fixed for the lifetime of the account.
- Only the **WrappedVaultKey** needs to be re-encrypted when the password changes.
- All secrets remain untouched.

This is identical to how Bitwarden handles key rotation:

> "A key rotation involves generating a new, random encryption key for the account and re-encrypting all vault data using this new key."

— [Bitwarden Security Whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/)

In SurfCrypt, an equivalent password change operation only re-wraps the 32-byte VaultKey rather than re-encrypting a potentially large vault — an O(1) operation regardless of vault size.

---

### 2.3 Registration Flow

```
Client                                               Server
  |                                                    |
  |  1. User enters username + master password         |
  |                                                    |
  |  2. VaultKey = nacl.utils.random(32 bytes)         |
  |  3. kek_salt = nacl.utils.random(16 bytes)         |
  |     auth_salt = nacl.utils.random(16 bytes)        |
  |                                                    |
  |  4. KEK = Argon2id(master_password, kek_salt)      |
  |                                                    |
  |  5. WrappedVaultKey, nonce = SecretBox(KEK).encrypt(VaultKey)
  |                                                    |
  |  6. AuthHash = base64(Argon2id(master_password, auth_salt))
  |                                                    |
  |  7. Send: {username, AuthHash, WrappedVaultKey, -->|
  |            kek_salt, auth_salt, nonce_wvk}         |
  |                                                    |  INSERT INTO users
  |  8. <-- {session_token} -----------------------   |
  |                                                    |
  |  9. Keep VaultKey in memory; discard master pass   |
```

**What the server never sees:** master password, KEK, plaintext VaultKey.

---

### 2.4 Login Flow

```
Client                                               Server
  |                                                    |
  |  1. User enters username + master password         |
  |                                                    |
  |  2. Request auth data --------------------------> |
  |  3. <-- {WrappedVaultKey, kek_salt,               |
  |           auth_salt, nonce_wvk}                    |
  |                                                    |
  |  4. AuthHash = Argon2id(master_password, auth_salt)|
  |  5. Send: {username, AuthHash} --------------->   |
  |                                           compare with stored hash
  |  6. <-- {session_token} ------------------------  |
  |                                                    |
  |  7. KEK = Argon2id(master_password, kek_salt)      |
  |  8. VaultKey = SecretBox(KEK).decrypt(WrappedVaultKey, nonce)
  |                                                    |
  |  9. Discard master password; keep VaultKey + token |
```

**Key observation:** The authentication hash and the KEK each use a **different salt** (`auth_salt` vs `kek_salt`), making them cryptographically independent. An attacker who steals the database and compromises `auth_hash` gains no ability to derive the KEK.

---

### 2.5 Secret Storage and Retrieval

**Storing a credential:**
```python
# For each field (name, url, username, password, notes):
ciphertext, nonce = encrypt_field(plaintext_field, vault_key)
# Send ciphertext + nonce to server; plaintext_field is never transmitted
```

**Retrieving a credential:**
```python
# Fetch {ciphertext, nonce} from server
plaintext = decrypt_field(ciphertext, vault_key, nonce)
# Display in GUI; never write to disk or network
```

Every field receives its own **independent nonce**. This is a cryptographic requirement: reusing nonces with XSalsa20-Poly1305 would allow an attacker to compute the XOR of two plaintexts, completely breaking confidentiality. SurfCrypt generates a fresh `nacl.utils.random(NONCE_LENGTH)` before every call to `encrypt_field` and `wrap_vault_key`.

---

### 2.6 Password Change — The Envelope Advantage

1. User provides old password → derive `old_KEK` → decrypt `WrappedVaultKey` → obtain `VaultKey`
2. User provides new password → derive `new_KEK` (with fresh `new_kek_salt`)
3. `new_WrappedVaultKey, new_nonce = SecretBox(new_KEK).encrypt(VaultKey)`
4. Send only `new_WrappedVaultKey`, `new_kek_salt`, `new_nonce_wvk`, `new_auth_hash`, `new_auth_salt` to server
5. All rows in `secrets` table are **untouched** — they remain encrypted with the same VaultKey

This is the defining advantage of the envelope model: the password change operation is O(1) regardless of how many secrets the user has stored.

---

## 3. Cryptographic Foundation (`crypto.py`)

**File:** `src/common/crypto.py`  
**Purpose:** Provides all cryptographic primitives required by both the client and server. Implements the envelope encryption model described in Section 2. Also provides a `generate_password()` function for secure password generation in the UI.

### 3.1 Library Choice: argon2-cffi

`argon2-cffi` was selected as the key derivation library for the following reasons:

**1. Argon2id is the Password Hashing Competition winner.**  
Argon2 was selected as the winner of the [Password Hashing Competition](https://password-hashing.net/) in 2015 after a multi-year open evaluation by the cryptography community. The `id` variant (Argon2id) was designated as the recommended general-purpose variant because it combines two complementary properties:
- Resistance to **side-channel attacks** (inherited from Argon2i, which uses data-independent memory access patterns)
- Resistance to **GPU/ASIC brute-force attacks** (inherited from Argon2d, which uses data-dependent memory access to maximise the cost of parallel cracking hardware)

**2. It is mandated by RFC 9106.**  
The Internet Engineering Task Force formally standardized Argon2 in [RFC 9106 (September 2021)](https://www.rfc-editor.org/rfc/rfc9106). The RFC specifies:

> "Argon2id MUST be used if the output of the function is used for both authentication (e.g., key derivation) and as a password hash for storage."

SurfCrypt uses Argon2 output for both the KEK (key derivation for encryption) and the AuthHash (password verification for authentication), making the `id` variant the mandatory choice per the standard.

**3. `argon2-cffi` provides correct lower-level access.**  
The library exposes `argon2.low_level.hash_secret_raw()`, which returns raw bytes directly — essential for using the output as a 32-byte cryptographic key. The high-level API returns a formatted password hash string (suitable for `$argon2id$v=19$...` storage), which is not appropriate as a raw key input to `SecretBox`.

**Why not `hashlib.scrypt` or `bcrypt`?**
- `bcrypt` has a hard maximum password length of 72 characters and cannot produce raw key bytes of arbitrary length.
- `scrypt` (via `hashlib`) is a valid alternative but lacks the hybrid side-channel resistance of Argon2id. RFC 9106 positions Argon2id as the modern successor.
- OWASP's [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) places Argon2id as the first recommendation: "Use Argon2id with a minimum configuration of 19 MiB of memory, an iteration count of 2, and 1 degree of parallelism."

---

### 3.2 KDF Parameters: RFC 9106 Compliance

```python
KDF_TIME_COST   = 3      # Number of passes over memory
KDF_MEMORY_COST = 65536  # 64 MB in KiB (1 KiB = 1024 bytes)
KDF_PARALLELISM = 4      # Parallel threads / lanes
```

RFC 9106 defines two reference parameter configurations for Argon2:

> "The first recommended option is Argon2id with t=1 iteration, p=4 lanes, and 2 GiB of RAM.
> The second recommended option is Argon2id with t=3 iterations, p=4 lanes, and 64 MiB of RAM."

— [RFC 9106, Section 4](https://www.rfc-editor.org/rfc/rfc9106#section-4)

SurfCrypt uses the **second recommended option** verbatim: `t=3, p=4, m=65536` (64 MB). This is the appropriate choice for a school lab environment where:
- Multiple users log in concurrently from machines with 8–16 GB of RAM.
- Reserving 2 GB per login (the first option) would cause resource exhaustion.
- 64 MB per login still forces an attacker to maintain 64 MB of RAM per parallel brute-force attempt, making GPU-based cracking impractical. Modern GPUs offer high parallelism but limited VRAM per compute unit; at 64 MB per attempt, the number of simultaneous guesses is tightly bounded.

**What the parameters mean in practice:**

| Parameter | Value | Security effect |
|-----------|-------|----------------|
| `time_cost=3` | 3 passes over memory | KDF must traverse the full 64 MB allocation 3 times, increasing sequential computation time |
| `memory_cost=65536` | 64 MB | Each derivation allocates 64 MB; GPU parallelism is bounded by available VRAM |
| `parallelism=4` | 4 lanes | Exploits multi-core CPUs for a legitimate user; increases total memory cost linearly |

**Expected timing on target hardware:** A single Argon2id derivation with these parameters takes approximately 0.3–0.5 seconds on a modern multi-core CPU. This delay is imperceptible to a human user (login takes ~1 second total) but means an attacker can test at most a few password guesses per second per core — versus billions per second with an unsalted SHA-256.

---

### 3.3 Library Choice: PyNaCl SecretBox

PyNaCl's `SecretBox` implements **XSalsa20-Poly1305 authenticated encryption** (an AEAD construction). It was chosen over direct AES usage for the following reasons:

**1. Single correct API for authenticated encryption.**  
`SecretBox` exposes one method for encryption and one for decryption. It is architecturally impossible to call the cipher without the authentication tag, or to accept plaintext without verifying the tag first. The NaCl design philosophy explicitly targets misuse resistance:

> "NaCl eliminates the possibility of using these functions incorrectly."

— Daniel J. Bernstein et al., [Cryptography in NaCl](https://nacl.cr.yp.to/)

**2. Constant-time MAC verification.**  
PyNaCl's `decrypt()` verifies the Poly1305 MAC before returning any plaintext bytes, and the comparison is performed in constant time. This prevents timing side-channel attacks that could leak information about the MAC value under repeated verification attempts.

**3. No lookup tables — immune to cache-timing attacks.**  
XSalsa20 is a stream cipher that operates entirely on ARX (add–rotate–XOR) operations. Unlike AES (which uses S-box lookups that are vulnerable to cache-timing attacks on machines without hardware AES-NI), XSalsa20 has no data-dependent memory accesses. In a school lab where multiple users share machines, this is a meaningful security property.

**4. Large nonce space eliminates collision risk.**  
XSalsa20 uses a 192-bit (24-byte) nonce, compared to the 96-bit IV used in AES-GCM. Even without careful nonce management, the probability of accidental nonce collision across the life of an account is negligible.

**5. Well-audited, battle-tested implementation.**  
PyNaCl wraps libsodium, which has received multiple independent security audits and is used in production by prominent security-critical systems.

**Why not `cryptography` (Python) with AES-256-GCM?**  
AES-256-GCM is equally secure in theory, but:
- AES-GCM nonces are 96 bits — collision becomes likely after 2^32 encryptions under a single key if nonces are random.
- AES implementations without hardware `AES-NI` fall back to table-based code vulnerable to cache-timing on older hardware.
- The `cryptography` library API requires correct composition of cipher + mode + tag — more opportunities for developer error.

---

### 3.4 Module Constants

```python
SALT_LENGTH         = 16                               # bytes (128 bits) — Argon2id salt
NONCE_LENGTH        = nacl.secret.SecretBox.NONCE_SIZE # 24 bytes (192 bits) — XSalsa20 nonce
KEY_LENGTH          = nacl.secret.SecretBox.KEY_SIZE   # 32 bytes (256 bits) — symmetric key
SESSION_TOKEN_BYTES = 32                               # bytes (256 bits) — random session token

KDF_TIME_COST   = 3
KDF_MEMORY_COST = 65536   # 64 MB (expressed in KiB)
KDF_PARALLELISM = 4
```

All values are module-level constants rather than magic numbers embedded in function calls. Upgrading parameters (e.g., increasing `KDF_MEMORY_COST` as hardware improves) requires a single edit.

`SALT_LENGTH = 16` (128 bits) satisfies the RFC 9106 minimum:

> "The length of the salt is at least 128 bits."

— [RFC 9106, Section 3.1](https://www.rfc-editor.org/rfc/rfc9106#section-3.1)

`NONCE_LENGTH` and `KEY_LENGTH` are read directly from the `SecretBox` class constants rather than hardcoded, ensuring they remain correct if the library ever changes the default values.

---

### 3.5 Custom Exception Hierarchy

```
Exception
└── CryptoError                 # Base for all crypto failures; catch for general errors
    ├── DecryptionError         # Wrong key, tampered ciphertext, or invalid UTF-8 output
    └── KeyDerivationError      # Argon2id invocation failure
```

Errors are confined to the `crypto.py` module. Callers catch `CryptoError` (or the specific subclass) and translate it into a user-facing message that reveals no cryptographic detail. A caller should never let a raw `nacl.exceptions.CryptoError` or `argon2.exceptions.VerifyMismatchError` propagate to the GUI layer.

---

### 3.6 Function Reference

#### `generate_salt() -> bytes`

**Returns:** 16 cryptographically random bytes via `nacl.utils.random()`.

`nacl.utils.random()` delegates to the operating system's CSPRNG (`/dev/urandom` on Linux/macOS, `BCryptGenRandom` on Windows). Used to generate `kek_salt` and `auth_salt` independently during registration.

**Why separate salts for KEK and AuthHash?**  
If both derivations shared the same salt, the base64-encoded `auth_hash` stored on the server would equal `base64(Argon2id(password, shared_salt))` — which is also the KEK. An attacker who obtained the database could use the stored `auth_hash` directly as the KEK to decrypt `wrapped_vault_key`. Independent salts make the two values cryptographically unrelated.

---

#### `generate_nonce() -> bytes`

**Returns:** 24 cryptographically random bytes via `nacl.utils.random()`.

Called before each invocation of `SecretBox.encrypt()`. In XSalsa20-Poly1305, reusing a nonce with the same key reveals the XOR of the two plaintexts and destroys authentication. Generating a fresh random nonce for every encryption call is the correct practice.

---

#### `derive_kek(master_password: str, salt: bytes) -> bytes`

Derives a 32-byte Key Encryption Key from the user's master password.

| Parameter | Type | Description |
|-----------|------|-------------|
| `master_password` | `str` | User's master password in plaintext |
| `salt` | `bytes` | 16-byte `kek_salt` retrieved from the `users` table |

**Returns:** 32-byte raw key suitable as a `SecretBox` key.  
**Raises:** `KeyDerivationError` — wraps any exception from the Argon2 call.

**Implementation note:** `argon2.low_level.hash_secret_raw()` is used rather than `argon2.PasswordHasher` because the low-level API returns raw bytes at a specified length, while the high-level API returns a formatted hash string. The `type=Type.ID` argument selects the Argon2id variant.

---

#### `derive_auth_hash(master_password: str, salt: bytes) -> str`

Derives a base64-encoded authentication credential from the master password.

| Parameter | Type | Description |
|-----------|------|-------------|
| `master_password` | `str` | User's master password in plaintext |
| `salt` | `bytes` | 16-byte `auth_salt` — must differ from `kek_salt` |

**Returns:** Base64-encoded ASCII string stored in `users.auth_hash`.  
**Raises:** `KeyDerivationError`

Base64 encoding is applied because SQLite's `TEXT` column stores Unicode strings, and raw Argon2 output is arbitrary bytes. Base64 produces a safe ASCII representation with no null bytes or ambiguous encoding.

**Same Argon2id parameters as `derive_kek`:** Both derivations use identical cost parameters. An attacker cracking the auth hash faces the same Argon2id cost as an attacker attempting to derive the KEK directly — no asymmetry that could be exploited.

---

#### `generate_vault_key() -> bytes`

**Returns:** 32 random bytes via `nacl.utils.random()`.

This is the VaultKey — the single symmetric key that encrypts every credential in the user's vault. Generated once at registration; never regenerated unless explicitly rotated.

**Why not derive the VaultKey from the master password?**  
If the VaultKey were derived from the password, changing the password would change the VaultKey, requiring every secret to be re-encrypted. By generating a random VaultKey and wrapping it with the KEK, the VaultKey is stable across password changes. This is the defining property of envelope encryption.

---

#### `wrap_vault_key(vault_key: bytes, kek: bytes) -> tuple[bytes, bytes]`

Encrypts the VaultKey with the KEK using `SecretBox`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `vault_key` | `bytes` | 32-byte VaultKey to be protected |
| `kek` | `bytes` | 32-byte Key Encryption Key |

**Returns:** `(ciphertext, nonce)` — both stored in the `users` table as `wrapped_vault_key` and `nonce_wvk`.

**Implementation note:** `SecretBox.encrypt()` returns an `EncryptedMessage` object that combines nonce and ciphertext. This function extracts `encrypted.ciphertext` separately and stores the nonce independently, which keeps the database schema explicit and avoids any ambiguity about byte offsets when reconstructing the message.

**Raises:** `CryptoError`

---

#### `unwrap_vault_key(wrapped_vault_key: bytes, kek: bytes, nonce: bytes) -> bytes`

Decrypts the WrappedVaultKey to recover the VaultKey.

**Returns:** 32-byte VaultKey.  
**Raises:** `DecryptionError` — if the KEK is wrong (wrong password) or the ciphertext has been tampered with. PyNaCl verifies the Poly1305 MAC before returning any output, so a failed MAC verification means either the password is incorrect or the data has been modified.

---

#### `encrypt_field(plaintext: str, vault_key: bytes) -> tuple[bytes, bytes]`

Encrypts a single credential field (e.g., one password or one URL) using the VaultKey.

| Parameter | Type | Description |
|-----------|------|-------------|
| `plaintext` | `str` | Credential field value in plaintext |
| `vault_key` | `bytes` | 32-byte VaultKey held in client memory |

**Returns:** `(ciphertext, nonce)` — stored as, for example, `password_encrypted` + `nonce_password`.

A fresh nonce is generated at the start of every call. This means two credentials with identical plaintext values (e.g., two accounts with the same password) produce different ciphertexts, preventing a statistical attack that could identify credential reuse from the database.

**Raises:** `CryptoError`

---

#### `decrypt_field(ciphertext: bytes, vault_key: bytes, nonce: bytes) -> str`

Decrypts a single credential field.

**Returns:** Plaintext string.  
**Raises:**
- `DecryptionError` — if MAC verification fails (wrong VaultKey or tampered data)
- `DecryptionError` — if decrypted bytes are not valid UTF-8 (wraps `UnicodeDecodeError`)

All three failure modes are unified under `DecryptionError` so callers do not need to handle multiple exception types for a single decrypt operation.

---

## 4. Database Layer (`db.py` + `schema.sql`)

**Files:**
- `src/server/db.py`
- `src/server/schema.sql`

### 4.1 Database Engine Choice: SQLite3

SQLite3 was chosen as the database engine for the following reasons:

**1. Zero-configuration deployment.**  
SQLite requires no external server process. The database is a single file on disk. Deploying to a new machine requires only copying the file — no PostgreSQL installation, connection strings, user accounts, or firewall configuration. For a school lab environment with one designated server machine, this is precisely the correct trade-off.

**2. Full ACID compliance.**  
Despite being embedded, SQLite provides complete ACID guarantees. The [SQLite documentation](https://www.sqlite.org/transactional.html) states:

> "SQLite is transactional. All changes within a single transaction in SQLite either complete completely or rollback completely."

A partial write mid-crash cannot leave the `users` table with an inconsistent key material state.

**3. Standard library inclusion.**  
Python's `sqlite3` module is part of the standard library — no additional dependencies. This reduces the attack surface and simplifies deployment in environments where outbound `pip install` may be restricted.

**4. Adequate performance for target load.**  
The project targets approximately 10 concurrent users in a school lab. SQLite handles thousands of concurrent reads and hundreds of writes per second — several orders of magnitude beyond the requirement.

**5. Forward path to WAL mode.**  
Should Phase 2 demand higher write concurrency, WAL (Write-Ahead Logging) mode can be enabled with `PRAGMA journal_mode=WAL`, allowing concurrent readers during a write without any application code changes.

---

### 4.2 Concurrency Control: threading.Lock

The TCP server services each client connection in a dedicated thread. Multiple threads may attempt simultaneous writes (e.g., two users creating secrets concurrently). SQLite's default locking model raises `sqlite3.OperationalError: database is locked` when this occurs.

`DatabaseManager` uses a single `threading.Lock` object (`self._write_lock`) to serialize all write operations:

```python
self._write_lock = threading.Lock()

# Applied in every write method:
with self._write_lock:
    cursor.execute(query, params)
    self._commit()
```

The Python standard library describes the primitive:

> "A primitive lock is in one of two states, 'locked' or 'unlocked'... If a thread tries to acquire a locked lock, the thread will block until the lock is released."

— [Python threading documentation](https://docs.python.org/3/library/threading.html#lock-objects)

**Why a single global lock rather than table-level locks?**  
A single write lock is sufficient for Phase 1's ten-user load and eliminates any possibility of deadlock (only one lock means no circular wait condition is possible). Table-level locks would add implementation complexity — and the potential for deadlock — for negligible throughput benefit at the current scale.

**Why does the lock only protect writes and not reads?**  
SQLite allows multiple concurrent readers. Read methods (`get_user_by_username`, `get_secrets_by_user`, etc.) go through `_execute_query` and do not acquire `_write_lock`. Vault fetches by multiple simultaneous users therefore proceed in parallel, and the write lock only serializes the typically short INSERT/UPDATE/DELETE operations.

---

### 4.3 Database Schema

#### `users` table

```sql
CREATE TABLE IF NOT EXISTS users (
    id                INTEGER  PRIMARY KEY AUTOINCREMENT,
    username          TEXT     UNIQUE NOT NULL,
    auth_hash         TEXT     NOT NULL,     -- base64-encoded Argon2id output
    wrapped_vault_key BLOB     NOT NULL,     -- SecretBox-encrypted VaultKey ciphertext
    kek_salt          BLOB     NOT NULL,     -- 16-byte salt for KEK derivation
    auth_salt         BLOB     NOT NULL,     -- 16-byte salt for AuthHash derivation
    nonce_wvk         BLOB     NOT NULL,     -- 24-byte nonce used to wrap VaultKey
    created_at        DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

**Security analysis of what a breach reveals:**  
A complete database dump exposes: `username`, `auth_hash`, `wrapped_vault_key`, `kek_salt`, `auth_salt`, `nonce_wvk`. None of these values alone (or in combination) can decrypt the vault. An attacker must brute-force the master password through Argon2id (64 MB, 3 passes per guess). The `nonce_wvk` and both salts are non-secret inputs to the KDF and cipher — they provide no shortcut without the password itself.

The separation of `kek_salt` and `auth_salt` means `auth_hash` and the KEK are cryptographically independent: compromising one does not weaken the other.

---

#### `secrets` table

```sql
CREATE TABLE IF NOT EXISTS secrets (
    id                   INTEGER  PRIMARY KEY AUTOINCREMENT,
    user_id              INTEGER  NOT NULL,
    name_encrypted       BLOB     NOT NULL,
    url_encrypted        BLOB     NOT NULL,
    username_encrypted   BLOB     NOT NULL,
    password_encrypted   BLOB     NOT NULL,
    notes_encrypted      BLOB     NOT NULL,
    nonce_name           BLOB     NOT NULL,
    nonce_url            BLOB     NOT NULL,
    nonce_username       BLOB     NOT NULL,
    nonce_password       BLOB     NOT NULL,
    nonce_notes          BLOB     NOT NULL,
    created_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

**Key design decisions:**

- **Per-field encryption:** Each of the five text fields is encrypted with an independent key invocation and a unique nonce. This prevents structural attacks where an adversary uses field boundaries as a plaintext oracle.
- **Per-field nonce columns:** If a single nonce were used for all five fields, and an attacker knew one field's plaintext, they could XOR-recover plaintext from adjacent fields. Independent nonces prevent any such cross-field attack.
- **BLOB columns for ciphertext and nonces:** SQLite stores raw bytes in BLOB columns without charset interpretation — unlike TEXT columns, which impose UTF-8 validation that would reject arbitrary ciphertext bytes.
- **`ON DELETE CASCADE`:** Deleting a user atomically removes all their secrets. No orphaned encrypted records remain, which would otherwise reveal vault size to an attacker with partial access.

---

#### `sessions` table

```sql
CREATE TABLE IF NOT EXISTS sessions (
    id            INTEGER  PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER  NOT NULL,
    session_token TEXT     UNIQUE NOT NULL,
    expires_at    DATETIME NOT NULL,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

Session tokens are `SESSION_TOKEN_BYTES = 32` bytes of CSPRNG output — effectively 256 bits of entropy. The `UNIQUE` constraint enforces single-token semantics where a collision would raise an integrity error. At 2^256 possible tokens, collision is computationally infeasible.

Tokens expire after 15 minutes of inactivity. The server extends `expires_at` on every successful authenticated request, so active users are not interrupted mid-session.

---

#### `url_history` table

```sql
CREATE TABLE IF NOT EXISTS url_history (
    id             INTEGER   PRIMARY KEY AUTOINCREMENT,
    url            TEXT      UNIQUE NOT NULL,
    rating         INTEGER   NOT NULL,      -- 1 (dangerous) to 5 (safe)
    recommendation TEXT      NOT NULL,      -- 'safe', 'warning', 'danger'
    is_shortened   BOOLEAN   DEFAULT FALSE,
    expanded_url   TEXT,
    analysis_data  TEXT      NOT NULL,      -- JSON blob with full analysis detail
    analyzed_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

URL analysis results are **shared globally** across all users. When a URL is analyzed, the result is persisted and returned directly to all subsequent requests for the same URL, avoiding redundant network activity and building a shared reputation database over time. The `UNIQUE` constraint on `url` enforces this single-record-per-URL policy.

---

### 4.4 Class Reference: DatabaseManager

**Class:** `DatabaseManager`  
**File:** `src/server/db.py`  
**Purpose:** Encapsulates all SQLite3 interactions. Provides a typed CRUD interface and enforces write-lock discipline across all mutating operations.

#### Constructor

```python
def __init__(self, db_path=DEFAULT_DB_PATH)
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `db_path` | `'./data/surfcrypt.db'` | Filesystem path to the SQLite database file |

Initialises `self.conn = None` (connection not opened yet) and `self._write_lock = threading.Lock()`. The connection is opened lazily on the first call to `connect()`.

---

#### `connect()`
Opens the SQLite connection and configures `row_factory = sqlite3.Row`. The row factory enables column access by name (e.g., `row['username']`) in addition to positional indexing. Idempotent — does nothing if `self.conn` is already set.

#### `init_db()`
Reads `schema.sql` from the same directory and executes it with `executescript()`. All schema statements use `CREATE TABLE IF NOT EXISTS`, making `init_db()` safely idempotent on server restart — existing tables and data are not affected.

#### `disconnect()`
Closes the connection gracefully. Swallows `sqlite3.Error` on close to prevent shutdown failures from masking higher-level cleanup logic. Sets `self.conn = None` in the `finally` block.

---

#### Internal Methods

**`_row_to_dict(row)`** — Converts a `sqlite3.Row` to a plain Python `dict`. Allows callers to process results as standard dictionaries without importing or checking for `sqlite3.Row`.

**`_execute_query(query, params=None, fetch=None)`** — Central read-path execution method. Accepts `fetch="one"` (returns a single dict or `None`) or `fetch="all"` (returns a list of dicts). Rolls back and raises `DatabaseError` on any `sqlite3.Error`.

**`_commit()` / `_rollback()`** — Thin wrappers over `conn.commit()` and `conn.rollback()` respectively. Used by write methods to commit after a successful operation or roll back on failure.

---

#### Write Methods (all acquire `_write_lock`)

| Method | Table | Returns | Notes |
|--------|-------|---------|-------|
| `create_user(username, auth_hash, wrapped_vault_key, kek_salt, auth_salt, nonce_wvk)` | `users` | `int` user_id | Raises `UserExistsError` on UNIQUE violation |
| `update_user_credentials(user_id, auth_hash, wrapped_vault_key, kek_salt, auth_salt, nonce_wvk)` | `users` | `bool` updated | Used for password change |
| `delete_user(user_id)` | `users` | `bool` deleted | Cascades to secrets + sessions |
| `create_secret(user_id, encrypted_fields, nonces)` | `secrets` | `int` secret_id | Both dicts keyed by field name |
| `update_secret(secret_id, encrypted_fields, nonces)` | `secrets` | `bool` updated | Also updates `updated_at` |
| `delete_secret(secret_id)` | `secrets` | `bool` deleted | |
| `create_session(user_id, session_token, expires_at)` | `sessions` | `int` session_id | `expires_at` is `datetime` object |
| `update_session_expiry(session_token, new_expires_at)` | `sessions` | `bool` updated | Called on every authenticated request |
| `delete_session(session_token)` | `sessions` | `bool` deleted | Logout |
| `delete_user_sessions(user_id)` | `sessions` | `int` count | Purge all sessions for a user |
| `delete_other_sessions(user_id, keep_session_token)` | `sessions` | `int` count | Revoke old sessions on new login |
| `delete_expired_sessions()` | `sessions` | `int` count | Periodic cleanup job |
| `create_url_analysis(url, rating, recommendation, is_shortened, expanded_url, analysis_data)` | `url_history` | `int` analysis_id | `analysis_data` is JSON-serialised dict |

#### Read Methods (no lock required)

| Method | Returns |
|--------|---------|
| `get_user_by_username(username)` | `dict` or `None` |
| `get_user_by_id(user_id)` | `dict` or `None` |
| `get_secrets_by_user(user_id)` | `list[dict]` — ordered by `created_at DESC` |
| `get_secrets_by_user_paginated(user_id, offset, limit)` | `list[dict]` |
| `count_secrets_by_user(user_id)` | `int` |
| `get_secret_by_id(secret_id)` | `dict` or `None` |
| `get_secret_owner(secret_id)` | `int` user_id or `None` |
| `get_session(session_token)` | `dict` or `None` |
| `get_url_analysis(url)` | `dict` or `None` |
| `get_url_analysis_by_id(analysis_id)` | `dict` or `None` |

---

#### Custom Exception Hierarchy

```
DatabaseError           # Base; raised on any sqlite3.Error that reaches callers
└── UserExistsError     # sqlite3.IntegrityError on UNIQUE violation in create_user
```

---

## 5. Server Architecture (`server.py`)

**File:** `src/server/server.py`

### 5.1 Transport Security: TLS over TCP

All client-server communication is wrapped in TLS using Python's built-in `ssl` module. A self-signed X.509 certificate is generated once at deployment and distributed to clients for certificate pinning. This configuration:

- **Prevents passive eavesdropping:** All traffic between client and server is symmetrically encrypted.
- **Prevents active MITM attacks:** The client verifies the server's certificate against the pinned copy before sending any data.
- **Requires no CA infrastructure:** Appropriate for a closed school network without internet-facing certificate requirements.

**Certificate generation command:**
```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key \
            -out server.crt -days 365 -nodes \
            -subj "/CN=surfcrypt-server"
```

### 5.2 Session Management

| Property | Value |
|----------|-------|
| Token length | 32 bytes (256 bits) from OS CSPRNG |
| Idle timeout | 15 minutes |
| Maximum concurrent sessions | 1 per user |
| On new login | Previous session revoked (`delete_other_sessions`) |
| Token transmission | Included as JSON field in every authenticated request |
| Token storage | `sessions.session_token` (TEXT, UNIQUE) |

On every authenticated request, the server: (1) retrieves the session row, (2) checks `expires_at` against `datetime.utcnow()`, (3) updates `expires_at` to `now + 15 minutes` on success, (4) processes the request. Expired tokens are rejected with a generic "Session expired" response.

### 5.3 Message Protocol

**Client → Server:**
```json
{
  "action": "register|login|save_secret|get_secrets|delete_secret|analyze_url|...",
  "session_token": "<base64-or-hex-token>",
  "data": { }
}
```

**Server → Client:**
```json
{
  "status": "success|error",
  "message": "User-facing message (generic for security)",
  "data": { }
}
```

Messages are **length-prefixed** using a 4-byte big-endian integer that precedes each JSON payload. This resolves the TCP stream framing problem — the receiver reads exactly 4 bytes first, interprets them as the payload length, then reads that many bytes for the full message. This eliminates any ambiguity about message boundaries.

Error messages returned to clients are intentionally vague ("Invalid credentials", "Session expired") to prevent information leakage such as username enumeration (distinguishing "username not found" from "wrong password" would let an attacker confirm which usernames are registered).

---

## 6. Client Network & Identity Workflows (`network.py` & `identity.py`)

**Files:**
- `src/client/network.py`
- `src/client/identity.py`

### 6.1 Stateless Request Protocol

Client-server communication is handled statelessly. Although a single TCP connection *could* be held open for performance, the current design opens and closes a socket for every request. This was a deliberate architectural choice for Phase 1:

1. **Simplicity and Reliability:** Network drops or sleep-cycles do not require complex reconnection logic; the next request will establish a fresh connection.
2. **Server Resource Conservation:** The server only ties up a thread and a socket file descriptor for the few milliseconds required to process a single logical request.
3. **Graceful Failures:** If an operation fails mid-flight, only that isolated request errors out, leaving the client and server in clean states.

Performance costs of repeated TLS handshakes are acceptable given the low frequency of requests a password manager generates (fetch vault once on login, discrete updates on edits/saves).

---

### 6.2 Class Reference: `NetworkClient`

**Class:** `NetworkClient`  
**Purpose:** Abstracts socket IO, TLS framing, and JSON serialization.

#### `_build_ssl_context()`
Constructs a TLS 1.2+ `SSLContext`. Depending on the environment configuration, it either requires verification against a pinned certificate (`self.cert_path`) or gracefully falls back to skipping hostname alignment (useful for raw IP operation in a controlled lab where fully-qualified domain names are unavailable).

#### `send_request(action, data, session_token=None)`
The sole entry point for network transmission. 
- Formats request into `{action, data, session_token}` dictionary.
- Wraps raw socket in TLS context.
- Serializes via `common.protocol.send_message` (applies the 4-byte big-endian framing).
- Awaits parsed JSON response.
- Traps and aggregates low-level exceptions (`socket.timeout`, `ssl.SSLError`, `json.JSONDecodeError`) into unified `NetworkError` instances.
- Translates `status != "success"` into application-level `ServerError` exceptions.

---

### 6.3 Class Reference: `IdentityManager`

**Class:** `IdentityManager`  
**Purpose:** Orchestrates the Envelope Encryption workflow entirely on the client, acting as the cryptographic gateway between the user's keystrokes and the unauthenticated network tier. It stores the `session_token` and unencrypted `vault_key` sequentially for authorized vaults.

#### `register(username, password)`
Performs the entirety of the cryptographic generation phase:
1. Invokes `generate_vault_key()` and `generate_salt()` from `crypto.py`.
2. Evaluates `derive_kek()` locally.
3. Evaluates `derive_auth_hash()`.
4. Executes `wrap_vault_key()` to construct ciphertext boundaries.
5. Transmits only safe, derived primitives to the server. Original password and plaintext key are destroyed locally after the block completes.

#### `login(username, password)`
Negotiates the split-factor workflow required by zero-knowledge systems:
1. **Fetch:** Requests the user's unique `auth_salt` anonymously from the server.
2. **Proof:** Derives the `auth_hash` locally and submits it to claim the session.
3. **Unwrap:** Upon session approval, derives the `KEK` from the password, pulling `wrapped_vault_key` + `nonce_wvk` from the server payload.
4. **Acquire:** Exposes the VaultKey to active memory via `unwrap_vault_key()`.

#### `logout()`
Explicitly targets and sanitises the active variables (`session_token`, `vault_key`, `username`) resetting them to `None`. This severs cryptographic capability for the current UI process without requiring termination.

---

### 6.4 Memory Isolation & Secrets Handling

A defining property of the client tier architecture is strict credential handling:

1. The `IdentityManager` holds the `VaultKey` but **never holds the master password**. The password is mathematically squashed via Argon2id immediately upon UI submission.
2. The `NetworkClient` holds no cryptographic variables and is fundamentally stateless regarding users. It is passed `session_token` manually on invoking `send_request`.

This boundary guarantees that even if the `NetworkClient` buffer encounters serialization bugs, the unencrypted credentials and the master password are not exposed to the wire formatting subsystem.

---

## 7. URL Threat Analyzer (`analyzer.py`)

**File:** `src/common/analyzer.py`  
**Purpose:** Provides a heuristic engine to analyze URLs for malicious traits. It evaluates domain blacklists, URL shorteners, and structural anomalies (e.g., suspicious TLDs, IP addresses in the host, excess subdomains).

Results are submitted to the server for caching across all clients, creating a shared threat intelligence pool (`url_history` table).

**Files:**
- `resources/malicious_domains.txt`: Curated blacklist of known phishing/malware domains (O(1) memory lookup).
- `src/common/analyzer.py`: Contains `UrlAnalyzer` class and rulesets.
- `src/client/gui_analyzer.py`: UI panel for submitting URLs and viewing results.

---

## 8. GUI Framework: Tkinter

Tkinter is Python's standard GUI toolkit, included with every CPython installation since Python 1.x. It was selected because:

**1. No additional dependencies.**  
Installation of the SurfCrypt client requires no GUI framework `pip install`. This is critical for a school lab environment where machines may have restricted package installation policies.

**2. Cross-platform without platform-specific code.**  
Tkinter runs on Windows, macOS, and Linux using the same Python source. The target platform is Windows (school lab), but cross-platform support means the client can be tested on any development machine.

**3. Sufficient capability for the required screens.**  
A password manager GUI requires: login/register forms, a credential list view, modal dialogs for add/edit, a password generator panel, a URL analyzer panel, and a settings screen. All of these are standard Tkinter capabilities (Entry, Listbox/Treeview, Toplevel, Scale, Checkbutton).

**4. Maturity and stability.**  
Tkinter has been part of Python since 1994 and is backed by the Tk toolkit, which has even longer history. There are no licensing concerns or deprecation risks.

Python's official documentation describes it as:

> "The tkinter package ('Tk interface') is the standard Python interface to the Tcl/Tk GUI toolkit. Both Tk and tkinter are available on most Unix platforms, including macOS, as well as on Windows systems."

— [Python tkinter documentation](https://docs.python.org/3/library/tkinter.html)

**Security considerations for the GUI:**
- Decrypted credential values are displayed in read-only `Entry` widgets and never written to disk or transmitted.
- Clipboard contents (copied passwords) are auto-cleared after 30 seconds using `widget.after(30000, clear_clipboard)`.
- The master password entry field uses `show='*'` to prevent shoulder-surfing.
- No sensitive data (passwords, VaultKey, session token) is written to log files.

---

## 8. Technology Stack Justification Summary

| Component | Technology | Key Justification |
|-----------|-----------|------------------|
| Key Derivation Function | Argon2id (`argon2-cffi`) | RFC 9106 mandated; PHC winner; memory-hard against GPU attacks |
| KDF parameters | t=3, m=64MB, p=4 | RFC 9106 §4 second recommended option; fits lab hardware |
| Authenticated encryption | PyNaCl `SecretBox` (XSalsa20-Poly1305) | Constant-time MAC; no lookup tables; misuse-resistant API |
| Symmetric key size | 256 bits | NIST SP 800-57 recommendation for 128-bit security level |
| Nonce generation | `nacl.utils.random(24)` | OS CSPRNG; 192-bit nonce eliminates collision risk |
| Auth separation | Separate salts for KEK and AuthHash | Cryptographic independence between auth and encryption paths |
| Database engine | SQLite3 (stdlib) | Zero-config; ACID; no extra dependencies; fits 10-user load |
| Write concurrency | `threading.Lock` | Prevents `database is locked`; no deadlock risk at scale |
| Schema isolation | Per-field encryption with per-field nonces | Prevents cross-field XOR attacks; field boundaries not exploitable |
| Transport security | TLS (Python `ssl` stdlib) | MITM prevention; no external dependency; self-signed fits lab |
| GUI framework | Tkinter (stdlib) | Standard library; cross-platform; no install friction |

---

## 9. Testing Strategy

### Unit Tests

Every function in `crypto.py` and every public method in `DatabaseManager` has a corresponding unit test in `tests/`. Test coverage requirements for Phase 1 are 70–80% of all lines. Tests are written with `pytest` and use fixtures for setup and teardown (in-memory SQLite databases for database tests, fixed test keys for crypto tests).

**Naming convention:** `test_<function>_<scenario>`

**Crypto test examples:**
- `test_derive_kek_returns_32_bytes` — Output length matches `KEY_LENGTH`
- `test_derive_kek_same_inputs_same_output` — Deterministic given same password + salt
- `test_derive_kek_different_salt_different_output` — Salt provides uniqueness
- `test_encrypt_field_returns_ciphertext_and_nonce` — Return type correct
- `test_encrypt_field_produces_different_ciphertext_each_call` — Non-deterministic due to fresh nonce
- `test_decrypt_field_recovers_plaintext` — Round-trip correctness
- `test_decrypt_field_wrong_key_raises_decryption_error` — Security property
- `test_decrypt_field_tampered_ciphertext_raises_decryption_error` — MAC enforcement
- `test_wrap_and_unwrap_vault_key_round_trip` — Envelope correctness
- `test_unwrap_vault_key_wrong_kek_raises_decryption_error` — Wrong password rejected

**Database test examples:**
- `test_create_user_returns_user_id` — Insert succeeds
- `test_create_user_duplicate_raises_user_exists_error` — UNIQUE enforced
- `test_get_user_by_username_not_found_returns_none` — Missing user handled
- `test_create_secret_and_retrieve_by_user` — Write then read
- `test_delete_user_cascades_to_secrets` — Cascade verified
- `test_delete_expired_sessions_removes_only_expired` — Time-based filtering
- `test_write_lock_prevents_concurrent_corruption` — Thread safety (two threads writing simultaneously)

### Integration Tests

Integration tests exercise complete workflows against an in-memory test database:

1. `test_registration_flow` — Register → verify `users` row created → verify no plaintext present in any column
2. `test_login_flow` — Registration → Login → verify session token returned → verify VaultKey recoverable
3. `test_secret_lifecycle` — Create → retrieve → update → delete → verify absent after delete
4. `test_session_expiry` — Create session with past `expires_at` → verify request correctly rejected
5. `test_concurrent_login_revokes_old_session` — Login twice → first session token rejected
6. `test_password_change_preserves_secrets` — Change password → re-derive new KEK → verify all secrets still decryptable

### Security Tests

- **Database breach simulation:** Dump raw SQLite file → grep all TEXT columns for known plaintext → verify zero matches
- **Wrong password:** Provide incorrect password at login → verify `DecryptionError` is raised and no partial plaintext is returned
- **Tampered ciphertext:** Flip one bit in `password_encrypted` → verify Poly1305 MAC verification fails and `DecryptionError` is raised before any output is produced

---

*End of Project Book — Phase 1*

---

### References

1. Bitwarden, Inc. — [Bitwarden Security Whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/)
2. AgileBits Inc. — [1Password Security Design White Paper](https://1password.com/files/1Password-White-Paper.pdf)
3. Birgit Pfitzmann-Winter, Alex Biryukov, Daniel Dinu, Dmitry Khovratovich, Simon Josefsson — [RFC 9106: Argon2 Memory-Hard Function](https://www.rfc-editor.org/rfc/rfc9106) — IETF, September 2021
4. OWASP — [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
5. Daniel J. Bernstein, Tanja Lange, Peter Schwabe — [Cryptography in NaCl](https://nacl.cr.yp.to/)
6. Python Software Foundation — [threading — Thread-based parallelism](https://docs.python.org/3/library/threading.html)
7. Python Software Foundation — [tkinter — Python interface to Tcl/Tk](https://docs.python.org/3/library/tkinter.html)
8. D. Richard Hipp — [SQLite Transactional Guarantees](https://www.sqlite.org/transactional.html)
