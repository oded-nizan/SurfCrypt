# Zero-Knowledge Proof (SRP-6a) Implementation Plan

## 1. Overview
This plan outlines the steps and architecture required to implement the Secure Remote Password (SRP-6a) protocol into SurfCrypt. This upgrade transitions the authentication model from a stateless, 1-step hashed request to a stateful, multi-step Zero-Knowledge Proof handshake.

**Critical Assumption:** This implementation assumes a "Clean Start" database purge. No backwards compatibility or data migration is required for legacy Argon2 `auth_hash` users.

---

## 2. File Changes & Context

The following files require modification or creation. This context is intended to guide an LLM agent during implementation.

### 2.1 Dependencies
* **File:** `requirements.txt`
* **Role:** Add the `srp` package (standard Python library for SRP-6a).
* **Context:** Utilize this library to handle the modular arithmetic and hashing underlying SRP.

### 2.2 Shared Configuration (NEW)
* **File:** `src/common/srp_config.py`
* **Role:** The ultimate source of truth for SRP parameters and encoding.
* **Context:** 
  * The Client and Server **must** use the exact same Prime (`N`) and Generator (`g`). This file enforces that.
  * Define explicit formatting wrappers here (e.g., `srp_to_hex()`, `hex_to_srp()`). All SRP numbers must be converted to Hex strings before network transmission to prevent Endianness/padding bugs.

### 2.3 Server-Side State Management (NEW)
* **File:** `src/server/handshake_manager.py`
* **Role:** Manages the state of pending multi-step login handshakes.
* **Context:** 
  * SRP requires the server to remember Step 1 (the generated ephemeral `B` value and session state) while waiting for Step 2.
  * Store states in a dictionary keyed by a secure, random `handshake_id`.
  * **Must** include an active cleanup mechanism (TTL of ~60 seconds) to purge abandoned handshakes and prevent memory exhaustion (DoS).

### 2.4 Database Schema
* **Files:** `src/server/user_schema.sql`, `src/server/user_db.py`
* **Role:** Store SRP verification parameters.
* **Context:** 
  * Replace the `auth_hash` column with `verifier` (a long hex string).
  * Replace `auth_salt` with `srp_salt` (hex string).
  * Update `user_db.py` CRUD operations to reflect these new column names.

### 2.5 Client Identity Manager
* **File:** `src/client/identity.py`
* **Role:** Client-side authentication logic.
* **Context:**
  * **Register:** Client generates `salt` and `verifier` locally using `srp.create_salted_verification_key(username, password)`. Sends these to the server instead of an `auth_hash`.
  * **Login:** Refactored into a multi-phase flow:
      1. Start `srp.User`, generate `A`. Send `{username, A}` to server.
      2. Receive `{salt, B, handshake_id}` from server.
      3. Compute proof `M1`. Send `{handshake_id, M1}` to server.
      4. Receive `{M2, session_token}`. Validate `M2` (to prove the server is authentic) before saving the token.
  * **Change Password:** Requires completing an SRP login to verify identity, then submitting a freshly generated `verifier` and `srp_salt`.

### 2.6 Server API & Routing
* **File:** `src/server/server.py`
* **Role:** Expose new network routes.
* **Context:**
  * Replace the single `login` route with `login_step1` and `login_step2`.
  * **`login_step1`**: Input `{username, A}`. Validates user exists. Instantiates `srp.Verifier`. Generates `B`. Saves to `HandshakeManager`. Returns `{srp_salt, B, handshake_id}`.
  * **`login_step2`**: Input `{handshake_id, M1}`. Retrieves state. Verifies `M1`. Generates `M2`. Returns `{M2, session_token}`.

---

## 3. Step-by-Step Implementation Plan

1. **Environment Prep:** Add `srp` to `requirements.txt`. Purge the local SQLite database.
2. **Schema Update:** Modify `user_schema.sql` and update all database queries in `user_db.py` to target `verifier` instead of `auth_hash`.
3. **Shared Config:** Create `srp_config.py` with standard Group parameters (e.g., 2048-bit) and explicit Hex encoding/decoding functions.
4. **State Management:** Implement `handshake_manager.py` with automated TTL cleanup to prevent stale state buildup.
5. **Registration Flow:** Rewrite `IdentityManager.register` and `Server._handle_register` to exchange the new SRP values. Test to ensure database writes succeed.
6. **Login Handshake - Step 1:** 
   - Client generates `A` and sends request.
   - Server initializes `srp.Verifier`, generates `B`, stores state, and returns values.
7. **Login Handshake - Step 2:**
   - Client processes `B`, computes `M1`, and sends it.
   - Server validates `M1`, generates `M2` and a standard `session_token`.
8. **Client Validation:** Client receives `M2`, verifies it against the local SRP state, and finalizes login.
9. **Refactor Envelope Crypto:** Ensure the Envelope Encryption keys (`KEK` and `VaultKey`) in `crypto.py` remain untouched and separate from the SRP process. The `KEK` should still be derived via Argon2 to maintain the decoupled architecture.

---

## 4. Crucial Checklist & Pitfalls

> **WARNING:** The following bugs are common in ZKP implementations. Pay strict attention to these guidelines.

- [ ] **Formatting & Endianness:** Ensure ALL large integers are converted to/from Hex strings explicitly using the wrappers in `srp_config.py` before touching the network dictionary. **Never transmit raw byte strings of BigInts.**
- [ ] **Zero-Value Vulnerabilities:** The server MUST abort if the client sends an `A` value where `A % N == 0`. The client MUST abort if the server sends a `B` value where `B % N == 0`. Verify that the `srp` library handles this automatically; if not, add explicit guards.
- [ ] **State Exhaustion (DoS):** Do not skip the TTL cleanup in `HandshakeManager`. Without it, a malicious user can spam Step 1 requests and crash the server out of memory.
- [ ] **Secure Handshake IDs:** Use `uuid.uuid4().hex` for `handshake_id`. Do NOT use the `username` as the key in the `HandshakeManager`, as this introduces race conditions if a user attempts to log in from two clients simultaneously.
- [ ] **Separation of Concerns:** Do not attempt to use the SRP session key as the `KEK` for the vault. Continue using the existing Argon2 `KEK` derivation in `crypto.py` for Vault Envelope Encryption. This isolates the authentication protocol from the encryption protocol.
