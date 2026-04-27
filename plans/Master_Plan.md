# SurfCrypt - Master Plan

**Project Type:** Secure Password Manager + URL Analyzer  
**Target Users:** Non-technical home users seeking web security  
**Platform:** Desktop application (Windows primary, cross-platform compatible)  
**Language:** Python 3.10+   
**Deployment:** School lab environment (~10 concurrent users max)

## Project Objective

Build secure desktop application providing:
1. **Password Manager** - Store/generate/manage credentials with zero-knowledge encryption
2. **URL Analyzer** - Check URLs for threats, shortened links, malware, blacklists
3. **Social Sharing** - Securely share credentials between trusted users
4. **AI Analysis** (Bonus) - Analyze password health, recommend security improvements

**Core Security Principle:** Even with database breach, user secrets remain encrypted and inaccessible.

## Architecture Overview

### System Components

**Client (Desktop App):**
- TKinter GUI
- Handles all encryption/decryption locally
- Communicates with server via TLS-encrypted JSON
- No plaintext secrets ever leave client

**Server:**
- Python TCP server with TLS encryption (ssl module)
- Handles authentication, session management
- Routes requests, enforces access control
- Stores only encrypted data
- Single server instance on one lab computer

**Database:**
- SQLite3 
- Stores: encrypted secrets, user auth data, URL analysis results
- Never contains plaintext passwords or decryption keys

**Network:**
- TLS 1.3 over TCP for all client-server communication
- Self-signed certificate (acceptable for lab environment)
- Clients connect via IP address in config file

## Developer Guidelines

### Work Environment

**Solo Development:**
- Developer works independently most of the time
- PM reviews code, tests features, provides feedback

### Code Documentation

**In-Code Comments:**
- Use ONLY when necessary (complex logic, non-obvious decisions)
- Keep concise, sacrifice grammar for brevity
- Example: `# Re-derive KEK to unwrap VaultKey` not `# We need to re-derive the Key Encryption Key from the master password in order to unwrap the VaultKey`

**Project Book Documentation:**
- Detailed, comprehensive explanations of every component
- Every class, method, variable documented
- Reader should have ZERO questions after reading
- Include: purpose, parameters, return values, algorithm explanations

**Programmer Notes (programmer_notes.md):**
- Design decisions and rationale
- Open questions for PM review
- Alternative approaches considered
- Technical considerations
- Example: "Considered using AES-GCM but chose PyNaCl SecretBox because: 1) simpler API, 2) includes nonce handling, 3) well-tested library"

### Testing Requirements

**Unit Tests:**
- EVERY method/function must have unit test
- Test normal cases, edge cases, error cases
- Use pytest fixtures for setup/teardown
- Naming: `test_<function_name>_<scenario>`
- Example: `test_encrypt_secret_with_valid_key()`, `test_encrypt_secret_with_invalid_key()`

**Integration Tests:**
- Test complete workflows end-to-end
- Example: register → login → save secret → retrieve secret → verify decryption
- Test multi-device scenarios
- Test session timeout behavior

**Documentation of Tests:**
- Each test documented in project book
- Describe: what is tested, expected result, actual result
- If bugs found, document resolution

---

## Cryptography Model (Envelope Encryption)

### Key Components

**VaultKey (256-bit random):**
- Single symmetric key encrypts all user's secrets
- Generated once during registration
- Never stored in plaintext anywhere
- Wrapped/unwrapped using KEK

**KEK (Key Encryption Key):**
- Derived from master password using Argon2id
- Used only to encrypt/decrypt VaultKey
- Never stored, re-derived on each login
- Allows password changes without re-encrypting all secrets

**Auth Hash:**
- Separate hash of master password for authentication
- Sent to server for login verification
- Derived with different salt than KEK

### Registration Flow

1. User enters username + master password
2. Client generates random VaultKey (256-bit)
3. Client generates random salt
4. Client derives KEK = Argon2id(master_password, salt, params)
5. Client wraps: WrappedVaultKey, nonce_wvk = AEAD_Encrypt(KEK, VaultKey)
6. Client derives AuthHash = Argon2id(master_password, auth_salt, params)
7. Client sends to server: username, AuthHash, WrappedVaultKey, salts, params, nonces
8. Server stores in database
9. Client keeps VaultKey in memory for session

**Server Never Sees:** Master password, KEK, VaultKey

### Login Flow

1. User enters username + master password
2. Client sends username to server; server returns `auth_salt` (random decoy if user not found, prevents enumeration)
3. Client derives `auth_hash` = Argon2id(master_password, auth_salt)
4. Client sends username + `auth_hash` to server
5. Server compares `auth_hash` with stored value (constant-time); 5 failed attempts triggers 10-min lockout
6. If match: server creates session, invalidates other sessions, returns `session_token`, `wrapped_vault_key`, `kek_salt`, `nonce_wvk`
7. Client derives KEK = Argon2id(master_password, kek_salt)
8. Client unwraps: VaultKey = AEAD_Decrypt(KEK, wrapped_vault_key, nonce_wvk)
9. Client stores VaultKey and session_token in memory; clears master password

### Secret Storage

**Encrypting Secret:**
1. User enters secret data (name, URL, username, password, notes)
2. Client encrypts each field: field_encrypted, unique_nonce = AEAD_Encrypt(VaultKey, field_plaintext)
3. Client sends encrypted blobs + nonces to server
4. Server stores in database with user_id association

**Retrieving Secret:**
1. Client requests secrets from server (with session token)
2. Server returns encrypted blobs + nonces
3. Client decrypts: field_plaintext = AEAD_Decrypt(VaultKey, field_encrypted, nonce)
4. Client displays in GUI

### Multi-Device Sync

**How It Works:**
- Same master password on any device → derives same KEK
- Same KEK → unwraps same VaultKey
- Same VaultKey → decrypts all secrets
- Server just stores/syncs encrypted data

**New Device Login:**
1. User logs in on Device B with same credentials
2. Device B fetches WrappedVaultKey from server
3. Device B derives KEK from master password
4. Device B unwraps VaultKey
5. Device B can now decrypt all secrets

### Password Change

**Critical Feature - Why Envelope Model:**
1. User enters old password + new password
2. Client derives old_KEK, unwraps VaultKey
3. Client derives new_KEK from new password
4. Client re-wraps: new_WrappedVaultKey = AEAD_Encrypt(new_KEK, VaultKey, new_nonce)
5. Client sends new_WrappedVaultKey to server
6. **All secrets remain unchanged** (still encrypted with same VaultKey)

### Encryption Algorithms

**AEAD Encryption:** PyNaCl SecretBox (XSalsa20-Poly1305)
- Authenticated encryption (prevents tampering)
- Unique nonce per encryption operation
- 256-bit keys
- **Why not AES-256 directly?** PyNaCl provides simpler API, automatic nonce handling, and is specifically designed for this use case. Performance and security are equivalent to AES-256-GCM.

**Key Derivation:** Argon2id (argon2-cffi)
- Memory-hard, resistant to GPU/ASIC attacks
- Parameters: time_cost=3, memory_cost=65536, parallelism=4
- Separate salts for AuthHash vs KEK

**Random Generation:** PyNaCl random utilities
- Cryptographically secure PRNG
- Used for: VaultKey, salts, nonces

---

## Communication Protocol

### Transport Layer

**TLS over TCP:**
- Python ssl module wraps sockets
- Self-signed certificate on server
- Client validates certificate (pinned or trusted)
- Prevents MITM attacks

**Message Format:**
- JSON-encoded messages
- Length-prefixed: `[4-byte length][JSON payload]`
- All messages encrypted by TLS layer

### Message Structure

**Client → Server:**
```json
{
  "action": "register|login|save_secret|get_secrets|analyze_url|...",
  "session_token": "abc123...",  // omitted for register/login
  "data": { /* action-specific payload */ }
}
```

**Server → Client:**
```json
{
  "status": "success|error",
  "message": "...",  // user-facing message (generic for security)
  "data": { /* response payload */ }
}
```

### Session Management

**Login Success:**
- Server generates random session token (256-bit)
- Stores: user_id, token, created_at, expires_at
- Returns token to client
- Client includes token in all subsequent requests

**Session Expiry:**
- 15 minutes of inactivity
- Server checks expiry on every request
- Server extends expiry on each valid request
- Client tracks activity, clears memory on timeout

**Logout:**
- Client sends logout request
- Server deletes session from database
- Client clears VaultKey, session token from memory

**Concurrent Logins:**
- New login invalidates previous session
- Only one active session per user
- Old device gets "session expired" error

---

## Database Schema

### Users Table
```
id: SERIAL PRIMARY KEY
username: VARCHAR(255) UNIQUE NOT NULL
auth_hash: VARCHAR(255) NOT NULL
wrapped_vault_key: BYTEA NOT NULL
kdf_salt: BYTEA NOT NULL
nonce_wvk: BYTEA NOT NULL
created_at: TIMESTAMP DEFAULT NOW()
```

### Secrets Table
```
id: SERIAL PRIMARY KEY
user_id: INTEGER REFERENCES users(id) ON DELETE CASCADE
name_encrypted: BYTEA NOT NULL
url_encrypted: BYTEA NOT NULL
username_encrypted: BYTEA NOT NULL
password_encrypted: BYTEA NOT NULL
notes_encrypted: BYTEA NOT NULL
nonce_name: BYTEA NOT NULL
nonce_url: BYTEA NOT NULL
nonce_username: BYTEA NOT NULL
nonce_password: BYTEA NOT NULL
nonce_notes: BYTEA NOT NULL
created_at: TIMESTAMP DEFAULT NOW()
updated_at: TIMESTAMP DEFAULT NOW()

NOTE: folder field added in Phase 2
```

### URL History Table
```
id: SERIAL PRIMARY KEY
url: TEXT NOT NULL
rating: INTEGER CHECK(rating BETWEEN 1 AND 5)
recommendation: VARCHAR(50) NOT NULL  // 'safe', 'warning', 'danger'
is_shortened: BOOLEAN DEFAULT FALSE
expanded_url: TEXT
analysis_data: JSONB NOT NULL  // {headers, redirects, blacklists, virustotal, etc}
analyzed_at: TIMESTAMP DEFAULT NOW()

INDEX idx_url ON url_history(url)  // fast lookup
```

### Sessions Table
```
id: SERIAL PRIMARY KEY
user_id: INTEGER REFERENCES users(id) ON DELETE CASCADE
session_token: VARCHAR(255) UNIQUE NOT NULL
created_at: TIMESTAMP DEFAULT NOW()
expires_at: TIMESTAMP NOT NULL

INDEX idx_session_token ON sessions(session_token)
INDEX idx_expires_at ON sessions(expires_at)
```

---

## Password Manager Features

### Secret Management

**Fields per Secret:**
- Name (e.g., "Gmail")
- URL (e.g., "https://gmail.com")
- Username (e.g., "user@example.com")
- Password (encrypted)
- Notes (optional, encrypted)

**Operations:**
- Create new secret
- View secret (decrypt on-demand)
- Edit secret (re-encrypt with new nonces)
- Delete secret
- Search secrets (by name, URL, username - client-side after decryption)
- Copy username/password to clipboard (auto-clear after 30 seconds)
- Secrets displayed in flat list (sorted by name or creation date)

**Note:** Folder organization added in Phase 2

### Password Generator

**Parameters:**
- Length: 6-32 characters (default: 16, warn if <10)
- Character types: uppercase, lowercase, numbers, symbols
- Option: exclude ambiguous chars (0/O, 1/l/I)
- Default: all types included, 16 chars, ambiguous included

**UI:**
- Generate button produces random password
- Customization sliders/checkboxes
- Preview field shows generated password
- Copy button
- Auto-fill into password field if triggered from secret creation

---

## URL Analyzer Features

### Analysis (Offline Only)

**Capabilities:**
- URL structure validation (malformed URLs, missing protocol)
- Shortened URL detection (bit.ly, tinyurl, goo.gl, t.co patterns)
- Attempt to expand shortened URLs (HTTP HEAD request)
- Local blacklist lookup (bundled PhishTank/URLhaus CSV exports)
- Basic heuristics (suspicious TLDs, excessive subdomains, IP-based URLs)

**Phase 2 Additions:**
- VirusTotal API integration
- HTTP header inspection
- Redirect chain following
- Download trigger detection

### Rating System

**Output:**
- Rating: 1-5 (1=dangerous, 5=safe)
- Recommendation: "Safe to visit" | "Exercise caution" | "Do not visit"
- Confidence level: based on available data

**Advanced Mode Toggle:**
- Simple mode: rating + recommendation only
- Advanced mode: full analysis details
  - HTTP headers
  - Redirect chain
  - Blacklist matches
  - VirusTotal scan results
  - Download triggers
  - SSL certificate info

### URL History Database

**Purpose:**
- Share analysis results across all users
- Avoid re-analyzing same URLs
- Build reputation database over time

**Storage:**
- Global (all users benefit)
- Indexed by URL for fast lookup
- Analysis data stored as JSON blob

**Workflow:**
1. User pastes URL
2. Client sends to server
3. Server checks if URL exists in history
4. If found: return cached analysis
5. If not: perform analysis, store result, return to user

---

## GUI Structure (TKinter)

### Screens

**1. Login/Register Screen**
- Tab switcher: Login | Register
- Fields: username, master password
- Show/hide password toggle
- Login/Register button
- Error messages (generic for security)

**2. Main Dashboard**
- Top bar: search box, add secret button, password generator button, URL analyzer button, settings button
- Center panel: secret list (table/list view with columns: name, username, URL)
- Bottom panel: selected secret details (read-only unless editing)
- Buttons: edit, delete, copy username, copy password

**3. Add/Edit Secret Modal**
- Input fields: name, URL, username, password, notes
- Generate password button (opens generator in modal)
- Save/Cancel buttons

**4. Password Generator Modal**
- Length slider (6-32)
- Checkboxes: uppercase, lowercase, numbers, symbols, exclude ambiguous
- Generated password display
- Generate button, copy button, use in secret button

**5. URL Analyzer Screen**
- URL input field
- Analyze button
- Results panel: rating (1-5 stars), recommendation (colored text)
- Advanced mode toggle
- Advanced details panel (collapsible): shows all analysis data
- History list: previously analyzed URLs (bottom section)

**6. Settings Screen**
- Change master password
- Session timeout display (read-only, shows 15min)
- Dark/light mode toggle
- Logout button
- About section (app version, description)

**Phase 2 Additions:**
- Folder tree sidebar
- Server GUI window

### Design Guidelines

- Dark mode default (professional dark gray/blue palette)
- Clean, modern, minimal design
- Consistent spacing, alignment
- Icons for common actions (Material Design icons or similar)
- Tooltips for clarity
- Keyboard shortcuts: Ctrl+N (new secret), Ctrl+F (search), Ctrl+G (generate password)

## Phase Breakdown

### Phase 1: Core MVP

**Goal:** Functional password manager + basic URL analyzer

**Deliverables:**
- User registration/login with envelope encryption
- Session management (15min timeout)
- Password manager CRUD operations (flat list, no folders yet)
- Password generator with customization
- URL analyzer (offline checks only - structure validation, shortened URL detection, local blacklist)
- URL history database
- TLS-encrypted client-server communication
- SQLite database with schema
- **Complete, detailed documentation per school requirements**
- **Unit tests for EVERY method/function**
- **Integration tests for all user workflows**
- Manual testing completed

**Documentation Priority:**
- Every class, method, variable documented in project book
- Code comments only when necessary (concise, no grammar fluff)
- Detailed explanations in project book
- Programmer notes in separate programmer_notes.md file
- Zero questions left after reading documentation

**Critical Path:**
1. Database setup + schema (simplified - no folders table)
2. Cryptography module (Argon2id + PyNaCl) - fully documented + tested
3. Server skeleton (TLS, message handling) - fully documented + tested
4. Client skeleton (GUI framework) - fully documented + tested
5. Authentication flow (register + login) - fully documented + tested
6. Secret storage flow (save + retrieve) - fully documented + tested
7. GUI screens (login, dashboard, secret list view, secret detail)
8. Password generator - fully documented + tested
9. URL analyzer (offline only) - fully documented + tested
10. Testing + bug fixes
11. Documentation writing (comprehensive)

### Phase 2: Enhancement & Organization

**Goal:** Add organizational features, expand URL analyzer, improve operations

**Deliverables:**
- **Folder system** (hierarchical organization, drag-and-drop)
- **Enhanced URL analyzer** (VirusTotal API integration, more blacklists)
- **Server GUI** (simple PyQt6 window showing: active sessions, connection log, start/stop server button, basic stats)
- **Log file management** (rotation, compression, audit trail)
- Import secrets from file (CSV/JSON)
- Export secrets (encrypted backup)
- Search functionality (filter by name, URL)
- Clipboard auto-clear for copied passwords
- Improved error handling + user feedback
- Performance optimization
- Additional unit/integration tests
- Documentation updates

### Phase 3: Social Sharing

**Goal:** Secure secret sharing between users

**Deliverables:**
- User discovery (search by username)
- Share secret with user (asymmetric encryption)
- Shared secrets view (separate section in GUI)
- **Shared secrets are read-only for recipients** (only owner can edit)
- Revoke sharing (remove recipient access)
- Shared secret indicators in vault (badge/icon)
- Documentation updates
- Additional tests

**Crypto Approach:**
- Each user has public/private key pair (generated from master password)
- Sharing: re-encrypt secret with recipient's public key
- Recipient decrypts with their private key
- Database tracks owner_id vs shared_with_id for access control

### Phase 4: AI Analysis (Bonus)

**Goal:** Intelligent password health assessment

**Deliverables:**
- Local AI model (small, packaged with app)
- Password strength analysis
- Reused password detection
- Password age tracking
- Breach detection (haveibeenpwned integration)
- Recommendations panel
- Manual trigger (user-initiated analysis)

**Privacy:** All analysis client-side, no data sent externally

## Technology Stack

### Core Dependencies

**Server:**
- Python 3.10+
- SQLite3
- argon2-cffi (password hashing)
- PyNaCl (encryption)

**Client:**
- Python 3.10+
- TKinter (GUI framework)
- argon2-cffi (password hashing)
- PyNaCl (encryption)
- requests (HTTP for URL analysis)

**Development:**
- pytest (unit testing)
- pytest-cov (coverage reporting)
- black (code formatting)
- pylint (linting)

**requirements.txt:**
```
argon2-cffi==23.1.0
PyNaCl==1.5.0
requests==2.31.0
python-dotenv==1.0.0
pytest==7.4.3
pytest-cov==4.1.0
```

### Development Environment

**Setup Steps:**
1. Install Python 3.10+
2. Create virtual environment
3. Install dependencies: `pip install -r requirements.txt`
4. Set environment variables (DB password, API keys)
5. Initialize database schema
6. Generate self-signed TLS certificate
7. Configure client/server IP addresses

## Configuration Files

### Server config.ini
```ini
[Server]
host = 0.0.0.0
port = 8443
cert = ./certs/server.crt
key = ./certs/server.key

[Security]
max_login_attempts = 5
lockout_minutes = 10
session_timeout_minutes = 15

[Logging]
log_file = ./logs/server.log
log_level = INFO
max_log_size_mb = 10
backup_count = 5
```

### Client config.ini
```ini
[Server]
ip = 192.168.1.100  # lab server IP
port = 8443

[Security]
tls_verify = true
cert_path = ./certs/server.crt
session_timeout_minutes = 15

[APIs]
virustotal_key = ${VIRUSTOTAL_API_KEY}  # from environment variable

[UI]
theme = dark
auto_clear_clipboard_seconds = 30
```

## Security Measures

### Authentication
- Argon2id with high cost parameters (memory-hard)
- Separate salts for auth vs encryption
- No plaintext passwords stored anywhere
- Rate limiting: 5 failed login attempts → 10min lockout
- Generic error messages (no username enumeration)

### Encryption
- 256-bit symmetric encryption (XSalsa20-Poly1305 via PyNaCl)
- Authenticated encryption (prevents tampering)
- Unique nonces per encryption operation
- Zero-knowledge: server never has decryption keys

### Session Management
- Cryptographically random session tokens
- 15-minute inactivity timeout
- One session per user (new login invalidates old)
- Token included in every request, verified server-side

### Transport Security
- TLS 1.3 over TCP
- Self-signed certificate (acceptable for closed network)
- Certificate pinning on client (prevents MITM)

### Database Security
- Prepared statements (prevent SQL injection)
- No plaintext secrets stored
- Foreign key constraints + cascading deletes
- Regular backups (encrypted)

### Application Security
- Input validation on all user inputs
- Output sanitization (prevent XSS in GUI)
- Memory clearing on logout/timeout
- No sensitive data in logs
- Clipboard auto-clear after 30 seconds

### Error Handling
- Generic error messages to users (no info leakage)
- Detailed logs server-side (access-controlled)
- No stack traces exposed to users
- Graceful degradation (offline mode for URL analyzer if APIs fail)

## Testing Strategy

### Unit Tests
- Cryptography functions (encrypt, decrypt, key derivation)
- Password generator (length, character types, randomness)
- URL parser (validation, shortened URL detection)
- Database operations (CRUD on secrets, users, sessions)
- Coverage target: 70-80% for Phase 1

### Integration Tests
- Full authentication flow (register → login → fetch secrets)
- Secret lifecycle (create → retrieve → update → delete)
- Session expiry (timeout handling)
- Multi-device sync (same user, different devices)

### Manual Testing
- GUI usability (all screens, workflows)
- Edge cases (long passwords, special chars, malformed URLs)
- Security scenarios (session timeout, concurrent logins, failed auth)
- Performance (10 concurrent users, 1000+ secrets)

### Security Testing
- MITM attempt (verify TLS protection)
- SQL injection attempts (verify prepared statements)
- Session hijacking attempts (verify token security)
- Database breach simulation (verify encryption holds)

## Logging & Monitoring

### Server Logs

**Auth Log (auth.log):**
- Timestamp
- Event type (register, login_success, login_fail, logout)
- Username
- IP address
- Result

**Application Log (server.log):**
- Timestamp
- Log level (INFO, WARNING, ERROR)
- Module
- Message
- Stack trace (for errors)

**Rotation:**
- Max file size: 10MB
- Keep 5 old files
- Compress old logs

### Client Logs

**Error Log (client.log):**
- Timestamp
- Error type
- User action that triggered error
- No sensitive data (no passwords, secrets)

## Error Handling

### User-Facing Errors (Generic)
- "Login failed. Please check your credentials."
- "Session expired. Please log in again."
- "Unable to connect to server. Please check your network."
- "An error occurred. Please try again."

### Server-Side Errors (Detailed in Logs)
- "Failed login attempt for user 'alice' from 192.168.1.50"
- "Database connection timeout after 30 seconds"
- "Invalid session token: abc123..."
- "SQL error: unique constraint violation on users.username"

## Deployment Guide

### Server Setup
1. Run schema initialization script
2. Generate TLS certificate: `openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes`
3. Start server: `python server.py`

### Client Setup
1. Install Python + dependencies
2. Copy server certificate to client
3. Configure client.ini with server IP
4. Set environment variables (VIRUSTOTAL_API_KEY if using)
5. Start client: `python client.py`

### Multi-Client Lab Setup
1. One computer runs server continuously
2. All other computers run client
3. All clients configure same server IP
4. Network: ensure port 8443 accessible on local network

## Git Workflow

**Branches:**
- `main` - production-ready, tested code only
- `develop` - integration branch
- `feature/feature-name` - individual feature development

**Process:**
1. Developer creates feature branch from develop
2. Developer commits code + unit tests
3. Developer creates pull request to develop
4. You review code, request changes if needed
5. You merge to develop
6. You test integrated features
7. When stable, merge develop → main
8. Tag releases: v1.0-phase1, v1.1-phase2, etc.

## Documentation Requirements (Per School)

### Project Portfolio Sections

**1. Introduction**
- Project initiation and rationale
- Target users and use cases
- Goals and objectives
- Comparison with existing solutions (LastPass, 1Password)
- Technology overview
- Project scope
- Development schedule (planned vs actual)
- Risk management

**2. Domain Knowledge**
- Detailed capability descriptions:
  - User registration
  - User authentication
  - Save secret
  - Retrieve secrets
  - Generate password
  - Analyze URL
  - Share secret (Phase 3)
  - AI analysis (Phase 4)

**3. Structure and Architecture**
- System architecture diagram (client-server-database)
- Hardware/network description
- Technology stack
- Data flow diagrams (per capability)
- Encryption algorithms and justification
- Communication protocol specification
- Screen mockups and flow diagram
- Database schema with field details
- Vulnerability review and mitigations

**4. Project Implementation**
- Module/class descriptions
- Key algorithms with code snippets
- Testing document (planned tests, results, resolutions)

**5. User Guide**
- Installation instructions
- System requirements
- File tree
- User workflows with screenshots
- Administrator guide (server setup)

**6. Personal Reflection**
- Challenges and solutions
- Learning outcomes
- Future improvements
- Acknowledgments

**7. Bibliography**
- APA format citations
- Documentation sources
- Research papers on cryptography

**8. Appendices**
- Full code printout with comments
- Additional technical details

## Risk Management

### Identified Risks

**Risk 1: Database Breach**
- **Mitigation:** Envelope encryption, zero-knowledge design
- **Result:** Even with DB access, attacker cannot decrypt secrets

**Risk 2: MITM Attack**
- **Mitigation:** TLS encryption, certificate pinning
- **Result:** All traffic encrypted, tampering detected

**Risk 3: Password Cracking**
- **Mitigation:** Argon2id with high parameters, strong password requirements
- **Result:** Computationally infeasible to brute-force

**Risk 4: Session Hijacking**
- **Mitigation:** Random session tokens, short timeout, one session per user
- **Result:** Limited window for attack, tokens rotate frequently

**Risk 5: SQL Injection**
- **Mitigation:** Prepared statements, input validation
- **Result:** No SQL command injection possible

**Risk 6: Malicious URL Analyzer Results**
- **Mitigation:** Multiple data sources, blacklist verification
- **Result:** False positives minimized, reputation-based scoring

**Risk 7: Developer Dependency on PM**
- **Mitigation:** Clear specifications, regular check-ins, feature branches
- **Result:** Parallel work possible, blockers identified early

**Risk 8: Timeline Overrun**
- **Mitigation:** Phase-based approach, MVP focus, defer advanced features
- **Result:** Phase 1 MVP guaranteed, extras added if time permits

## Success Criteria

### Phase 1 (Must Complete)
✅ User can register with username + password  
✅ User can login from any device with same credentials  
✅ User can save secrets (name, URL, username, password, notes)  
✅ User can retrieve and view all secrets  
✅ User can organize secrets in folders  
✅ User can generate strong passwords with customization  
✅ User can analyze URLs for threats  
✅ URL analyzer provides rating (1-5) and recommendation  
✅ All communication TLS-encrypted  
✅ All secrets encrypted with zero-knowledge model  
✅ Database breach does not expose secrets  
✅ Session timeout after 15min inactivity  
✅ Complete documentation per school requirements  
✅ Unit tests cover 70%+ of critical code  
✅ Manual testing completed, no critical bugs  

### Phase 2-4 (If Time Permits)
✅ Secret sharing between users  
✅ AI password health analysis  
✅ Import/export functionality  
✅ Advanced search and filters  

### Quality Metrics
✅ Code follows PEP 8 style guide  
✅ All functions have docstrings  
✅ No hardcoded secrets or credentials  
✅ Logs rotate properly, no sensitive data logged  
✅ GUI responsive, no freezing on operations  
✅ Server handles 10 concurrent users without degradation  

## Next Steps

1. Developer reads and understands this master plan
2. Developer sets up development environment
3. PM reviews and approves Phase 1 detailed specification
4. Developer begins implementation following feature branch workflow
5. Regular check-ins (2-3x per week) to review progress
6. PM tests each completed feature
7. Iterate until Phase 1 complete
8. Documentation writing begins after Phase 1 implementation
9. Evaluate timeline, proceed to Phase 2-4 as time allows
