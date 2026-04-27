# SurfCrypt - Base Implementation Plan

**Objective:** Build a secure desktop application providing a password manager and basic URL analyzer.
**Core Technologies:** Python, Tkinter (GUI), SQLite (Database), PyNaCl/Argon2id (Cryptography), standard TCP Socket communication.

---

## Stage 1: Environment & Cryptographic Foundations

**Task 1.1: Environment Setup**
- Create `requirements.txt` with `argon2-cffi`, `PyNaCl`, `pytest`.
- Initialize virtual environment.
- Create structured project directories: `client/`, `server/`, `common/`.

**Task 1.2: Implement `crypto.py` (Envelope Core)**
- In `common/cryptography/crypto.py`, define `derive_kek(master_password, salt)`: Hash password via Argon2id to generate Key Encryption Key.
- Define `derive_auth_hash(master_password, salt)`: Hash password via Argon2id (separate salt) to produce the authentication hash sent to the server.
- Define `generate_vault_key()`: Output cryptographically secure 256-bit PyNaCl random bytes.
- Define `wrap_vault_key(vault_key, kek)` (returns wrapped_key, nonce) and `unwrap_vault_key(wrapped_key, kek, nonce)`: Encrypt/decrypt VaultKey using KEK via PyNaCl `SecretBox`.
- Define `encrypt_field(plaintext, vault_key)` (returns ciphertext, nonce) and `decrypt_field(ciphertext, vault_key, nonce)`: Reusable SecretBox wrappers for securing individual credential fields.

## Stage 2: Database Layer

**Task 2.1: Define Schema Definition**
- In `server/schema.sql`, construct tables:
  - `users`: id, username, auth_hash, wrapped_vault_key, kek_salt, auth_salt, nonce_wvk. (Two separate salts: `kek_salt` for KEK derivation, `auth_salt` for auth hash derivation.)
  - `secrets`: id, user_id, name_encrypted, url_encrypted, username_encrypted, password_encrypted, notes_encrypted, plus corresponding nonces.
  - `sessions`: id, user_id, session_token, expires_at.
  - `url_history`: id, url, rating, recommendation, is_shortened, expanded_url, analysis_data.

**Task 2.2: Implement `DatabaseManager` Class**
- In `server/database.py`, build class to encapsulate SQLite operations.
- `init_db()`: Execute schema creation if tables don't exist.
- `create_user(...)`: Insert row. Use parameterized queries everywhere.
- `get_user_by_username(username)`: Return auth hashes and keys.
- `add_secret(...)`, `get_secrets_for_user(...)`, `update_secret(...)`, `delete_secret(...)`: CRUD operations for payloads.
- `cache_url_analysis(...)`, `get_url_analysis(...)`: Check cached heuristic verdicts.

## Stage 3: Server Architecture

**Task 3.1: Implement `SessionServer` Class**
- In `server/server.py`, establish TCP socket server via Python `socket` and `ssl` modules, with optional TLS wrapping.
- Build `listen()` loop. `accept()` incoming connections. Spawn `threading.Thread(target=handle_client, args=(client_socket, addr))` per connection.
- Define raw packet protocol: Receive 4-byte big-endian length prefix, then JSON payload `{"action": "...", "data": {...}}`.

**Task 3.2: Implement Request Dispatcher & Action Handlers**
- Parse JSON, map string `action` to specific handler functions. Validate session token for all authenticated actions.
- `handle_register`: Store client-derived auth data (auth_hash, wrapped_vault_key, kek_salt, auth_salt, nonce_wvk). Client performs all derivation; server only stores.
- `handle_get_auth_salt` *(login step 1)*: Return stored auth_salt for username; return a random decoy if user not found (prevents username enumeration).
- `handle_login` *(login step 2)*: Receive username + client-derived auth_hash. Compare to stored value (constant-time). On success: create session, invalidate other sessions, return session_token, wrapped_vault_key, kek_salt, nonce_wvk. Rate-limit: 5 failures → 10-min lockout.
- `handle_sync_secrets`: Fetch all encrypted rows for authenticated user; return JSON array.
- `handle_save_secret`: Insert new encrypted secret to DB; return secret id.
- `handle_update_secret`: Verify secret ownership; update all encrypted fields.
- `handle_delete_secret`: Verify secret ownership; delete secret.

## Stage 4: Client Network & Identity Workflows

**Task 4.1: Implement `NetworkClient` Class**
- In `client/network.py`, wrap socket operations.
- `send_request(action, data, session_token=None)`: Open socket, serialize payload to JSON, send, await response, decode JSON response, close socket. Return dictionary.

**Task 4.2: Implement `IdentityManager` Class**
- Encapsulate auth workflows client-side.
- `register(username, password)`: Generate salt & VaultKey. Derive KEK. Wrap VaultKey. Send hashes & wrapped objects to server via `NetworkClient`.
- `login(username, password)`: Request auth variables from server. Derive KEK locally from password input. Unwrap VaultKey successfully. Store resulting plaintext VaultKey as an instance variable in memory for the duration of the app run.

## Stage 5: GUI Application (Tkinter)

**Task 5.1: Scaffold `MainApplication` Class**
- In `client/gui.py`, establish root Tkinter window (`tk.Tk()`).
- Implement `FrameRouter` logic: Easily switch active view between `LoginFrame` and `DashboardFrame`.

**Task 5.2: Build `LoginFrame`**
- Create string variables and Entry widgets for username and password. 
- Build "Login" and "Register" buttons. Bind commands to `IdentityManager` logic.
- Upon valid identity confirmation, trigger `FrameRouter` to shift to `DashboardFrame`. Catch/display errors on failure.

**Task 5.3: Build `DashboardFrame` (Vault)**
- Implement `ttk.Treeview` layout to list passwords in a table structure.
- `refresh_vault()`: Send `sync_secrets` request. Iterate through returned JSON array. Decrypt each field via `decrypt_symmetric(encoded_field, VaultKey)`. Insert plaintext into `Treeview`.

**Task 5.4: Build `SecretModal` Class (Add/Edit)**
- `tk.Toplevel` modal popup rendering Entry fields for Name, URL, Username, Password, Notes.
- Include "Generate Password" button utilizing `secrets` module to fill Password field with high-entropy string.
- `save_action()`: Take raw string inputs. Run `encrypt_symmetric()` iteratively on each field. Dispatch payload to Server. Call `refresh_vault()`.

## Stage 6: URL Analyzer Subsystem

**Task 6.1: Implement `UrlAnalyzer` Engine**
- In `client/analyzer.py`, define basic string parsing.
- Evaluate formatting (missing HTTP).
- Evaluate URL array against local imported `malicious_domains.txt` file (loaded into memory script list).
- Evaluate regex logic for excess subdomains or raw IP navigation. Calculate arbitrary risk rating based on strike count.

**Task 6.2: Build Analyzer GUI**
- Construct `Tkinter` sub-frame within or accessible from Dashboard.
- Provide input text box. Execute `UrlAnalyzer` engine locally.
- Dispatch analytical verdict to Server to cache in SQLite `url_history`. Update user UI Label with "Safe", "Warning", or "Danger".
