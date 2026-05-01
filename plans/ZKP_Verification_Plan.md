# SRP-6a Zero-Knowledge Proof Verification & Test Plan

This document defines the verification requirements for the successful implementation of the SRP-6a authentication protocol in SurfCrypt. It provides checklists and testing strategies to ensure the implementation is secure, robust, and correctly integrated.

## 1. Pre-Flight Checklist (Manual Verification)

Before running automated tests, verify the following architectural rules have been followed:

- [ ] **Dependencies:** `srp` library is installed and listed in `requirements.txt`.
- [ ] **Schema Migration:** `user_schema.sql` has been updated and the local SQLite database (`surfcrypt.db`) has been deleted to allow a clean initialization.
- [ ] **Shared Config:** `src/common/srp_config.py` exists and contains the hex formatting utility functions.
- [ ] **State Manager:** `src/server/handshake_manager.py` is implemented and includes a background thread or periodic check to clear expired handshakes.
- [ ] **Vault Crypto Isolation:** Verified that `derive_kek` in `src/common/crypto.py` is STILL using Argon2 and has NOT been modified to use the SRP session key.

## 2. Automated Testing Strategy

A dedicated test file `tests/test_srp_auth.py` has been created. It covers the following testing tiers:

### Tier 1: Configuration & Formatting Tests (Unit)
*   **Goal:** Ensure big integers do not cause network serialization crashes.
*   **Checks:** 
    *   Verify `srp_to_hex()` and `hex_to_srp()` successfully round-trip large integers.
    *   Verify leading zeros are handled correctly during encoding/decoding.

### Tier 2: State Management Tests (Unit)
*   **Goal:** Ensure the server is not vulnerable to State Exhaustion (DoS).
*   **Checks:**
    *   Verify `HandshakeManager` stores a state and retrieves it.
    *   Verify `HandshakeManager` successfully deletes a state after the TTL expires.
    *   Verify `HandshakeManager` rejects invalid or non-existent `handshake_id`s.

### Tier 3: Authentication Flow Tests (Integration)
*   **Goal:** Validate the full multi-step network flow.
*   **Checks:**
    *   **Registration:** Client can register, and DB stores `verifier` and `srp_salt` instead of `auth_hash`.
    *   **Successful Login:** Step 1 and Step 2 complete successfully, resulting in a valid `session_token`.
    *   **Failed Login (Wrong Password):** Step 2 correctly rejects the invalid proof `M1`.
    *   **Failed Login (Wrong User):** Step 1 correctly aborts or returns dummy data if the user does not exist (to prevent user enumeration).

## 3. Security & Edge Case Checklist (Red Team)

Once the tests pass, perform these manual security validations:

- [ ] **Replay Attack Check:** Capture a successful Step 2 request (`M1`). Try to send the exact same `M1` with a new Step 1 handshake. The server **must** reject it because the ephemeral `B` value has changed.
- [ ] **Zero-Value Check:** Modify the client code temporarily to send `A = 0` during Step 1. The server **must** throw an error and abort the handshake.
- [ ] **Concurrency Check:** Open two client instances. Attempt to log into the same account simultaneously. Both should succeed or one should fail gracefully; neither should cause the server to cross-wire the handshakes (proving `handshake_id` is working, not relying on `username` as a state key).
- [ ] **Partial Handshake Check:** Run Step 1 from a client, then close the client. Wait 60 seconds. Verify the server logs indicate the handshake was cleaned up.

## 4. Acceptance Criteria

The SRP implementation is considered "Production Ready" when:
1.  All tests in `test_srp_auth.py` pass.
2.  The existing `test_crypto.py` passes (proving Envelope Encryption was not broken).
3.  A user can register, log out, log back in, and change their password via the GUI without any application crashes.
