# SurfCrypt
SurfCrypt is a zero-knowledge password manager and security toolkit designed with the Envelope Encryption model. It ensures that no plaintext passwords, secret data, or unencrypted keys are ever transmitted to or stored on the server.

## Features
- **Zero-Knowledge Architecture:** Cryptographic operations (key derivation, encryption/decryption) happen entirely client-side using `argon2-cffi` and `PyNaCl` (libsodium).
- **Network Security:** All client-server communication is protected via TLS.
- **URL Threat Analyzer:** Built-in heuristics engine to protect against malicious domains, phishing, and URL shorteners.
- **Secure Password Generation:** Integrated local password generator.

## Requirements
- Python 3.10+
- Dependencies: `pip install -r requirements.txt`

## Configuration
The project uses a `.env` file at the root of the repository for configuration. You should create a `.env` file containing the following variables:

```env
# Server Binding
SURFCRYPT_HOST=0.0.0.0
SURFCRYPT_PORT=8443

# TLS Certificates (Optional: Server auto-generates if missing)
SURFCRYPT_CERT=C:\Absolute\Path\To\resources\server.crt
SURFCRYPT_KEY=C:\Absolute\Path\To\resources\server.key

# Database Location
SURFCRYPT_DB=C:\Absolute\Path\To\data\surfcrypt.db
```

## Running the Application
Always run the application as a module from the `src` directory or project root.

**Start the Server:**
```bash
python -m server
```

**Start the Client GUI:**
```bash
python -m client
```
