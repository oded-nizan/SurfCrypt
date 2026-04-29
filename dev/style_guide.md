# SurfCrypt Python Style Guide

This guide defines the coding conventions for the SurfCrypt project. All Python files must conform to **PEP 8** as the baseline, with the project-specific rules below taking precedence where they differ. The canonical references are `common/crypto.py`, `client/identity.py`, and `common/analyzer.py`.

---

## 1. File Header

Every file opens with a triple-quoted string describing the module's purpose. This is not a docstring — it is a plain header read by humans, not tooling.

**Format:** `filename.py [verb] [purpose]. [Optional second sentence of key context.]`

```python
"""
analyzer.py is the URL threat analysis engine for SurfCrypt. Its main goal is to
evaluate a raw URL and return a security verdict (1-5 rating plus Safe/Warning/Danger).
"""
```

Keep it to 1–3 sentences. No trailing period.

---

## 2. Import Sections

Imports are split into exactly three ordered sections, each preceded by its own comment header:

1. `# Imports - Default Libraries` — Python standard library only
2. `# Imports - External Libraries` — third-party pip packages
3. `# Imports - Internal Modules` — project-local modules

One blank line separates each section. If a section is empty, **keep the header**.

```python
# Imports - Default Libraries
import base64
import secrets
from pathlib import Path

# Imports - External Libraries
import requests
from argon2 import Type

# Imports - Internal Modules
from client.network import NetworkClient, NetworkError, ServerError
from common.crypto import (
    generate_vault_key,
    derive_kek,
    DecryptionError,
)
```

**Rules:**
- Use bare `import x` for top-level module imports.
- Use `from x import y` for specific names from standard or external packages.
- Use parenthesized multi-line `from x import (...)` when importing more than one name from an internal module — one name per line.
- Within each section, sort imports alphabetically by module name.
- Never use wildcard imports (`from x import *`).

---

## 3. Constants

Constants are grouped under `# Constants - <Category>` headers. One blank line between categories.

```python
# Constants - Paths
_RESOURCES = Path(__file__).resolve().parent.parent.parent / 'resources'
BLACKLIST_PATH = _RESOURCES / 'malicious_domains.txt'

# Constants - Network
REQUEST_TIMEOUT = 5
USER_AGENT = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/124.0.0.0 Safari/537.36'
)

# Constants - Scoring
BASE_RATING = 5
MIN_RATING = 1
MAX_SUBDOMAIN_COUNT = 3  # More than this triggers excess-subdomain penalty
```

**Naming:**
- Public constants: `UPPER_SNAKE_CASE`
- Private module-level helpers: `_UPPER_SNAKE_CASE`

**Inline comments** on constants use two spaces before `#`:
```python
KDF_MEMORY_COST = 65536  # 64 MB
```

**Multi-line collections** always use a trailing comma on the last item:
```python
DOWNLOAD_CONTENT_TYPES = {
    'application/octet-stream',
    'application/x-msdownload',
    'application/zip',
    'application/vnd.android.package-archive',
}
```

Long strings are split across lines using implicit concatenation inside parentheses — one logical segment per line.

---

## 4. Docstrings

Docstrings are **concise one-line descriptions** of what a function, method, or class does. They are not API documentation — argument types, return values, and error behavior belong in `project_book.md`.

```python
def derive_kek(master_password, salt):
    """Hash password via Argon2id to generate Key Encryption Key"""
```

```python
def analyze(self, url: str) -> dict:
    """Perform full threat analysis on a URL; return verdict dictionary"""
```

```python
class IdentityManager:
    """Manages user identity, session state, and the Envelope Encryption auth workflows"""
```

Multi-line docstrings are acceptable when a single line would be genuinely unclear — lead with a summary, then add one or two sentences of context after a blank line:

```python
def login(self, username, password):
    """
    Authenticate an existing user. Fetch auth_salt from server then derive auth_hash locally,
    send for verification. On success, derive KEK and unwrap VaultKey entirely on the client.
    Stores session_token and vault_key in memory on success
    """
```

**Rules:**
- No trailing period.
- No parameter lists, return type descriptions, or exception tables — those go in the project book.
- Prefer imperative phrasing (`Generate ...`, `Return ...`, `Check ...`).
- Inline examples after a semicolon are encouraged where they aid clarity: `"""Count subdomains; e.g. a.b.c.example.com → 3 subdomains"""`

---

## 5. Custom Exceptions

Exceptions are grouped under `# Custom Exceptions`. Two blank lines between classes.

```python
# Custom Exceptions
class CryptoError(Exception):
    """Base exception for cryptographic operations"""
    pass


class DecryptionError(CryptoError):
    """Raised when decryption fails (wrong key or tampered data)"""
    pass
```

Always define a module-level base exception and have specific exceptions inherit from it. Docstring wording:
- Base: `"""Base exception for <domain> operations"""`
- Specific: `"""Raised when <condition>"""`

---

## 6. Module-Level Functions

Private helpers are prefixed with `_` and grouped under `# Internal Functions - <Category>` section headers. There is **no blank line** between the section header and the first function. Two blank lines between functions.

```python
# Internal Functions - Salt/Nonce
def generate_nonce():
    """Generate random 16 byte nonce for encryption"""
    return nacl.utils.random(NONCE_LENGTH)


def generate_salt():
    """Generate random salt for kdf"""
    return nacl.utils.random(SALT_LENGTH)
```

Type hints are used selectively on public-facing method signatures where they add clarity. They are not required on private helpers.

---

## 7. Inline Comments

Inline comments label logical phases within a function body. Use a dash to separate a phase label from a clarifying detail:

```python
# Normalize - prepend scheme if missing
# Active network resolution - follow redirects to find true destination
# Rule A: Immediate Danger - override rating to minimum
```

Plain statements are fine for single-line clarifications:

```python
# Registrable domain = last 2 labels; everything before is subdomains
# SecretBox.encrypt returns nonce + ciphertext, extract just ciphertext
```

Comments explain *what* and *why* — not what the code already makes obvious.

---

## 8. Exception Handling

Catch specific exceptions before broad ones. Always name the broad fallback `Exception as e`.

```python
except nacl.exceptions.CryptoError as e:
    raise DecryptionError('Failed to unwrap VaultKey - wrong password or tampered data') from e
except Exception as e:
    raise DecryptionError(f'Failed to unwrap VaultKey: {e}') from e
```

Use `from e` when re-raising a caught exception as a different type to preserve the traceback chain. Omit it when logging and returning a fallback value.

Use f-strings for all exception messages.

**Graceful degradation** — if a non-critical resource fails to load, print a warning and continue with a safe default rather than crashing:
```python
except FileNotFoundError:
    print(f'Warning: {label} not found at {path}. Proceeding with empty set.')
    return set()
```

**Sensitive data cleanup** — use `del` in `finally` blocks to remove passwords and key material from scope entirely after use:
```python
finally:
    del password
    del new_password
```

---

## 9. Classes

Classes are preceded by a `# <Role> Class` section header (e.g., `# Main Class`, `# Authenticator Class`). No blank line between this header and the `class` definition.

```python
# Authenticator Class
class IdentityManager:
    """Manages user identity, session state, and the Envelope Encryption auth workflows"""

    def __init__(self, network_client=None):
        """Initialize IdentityManager with an optional injected NetworkClient"""
        ...
```

Use `@property` for computed state that reads as an attribute:
```python
@property
def is_authenticated(self):
    """True if a session is active with a loaded VaultKey"""
    return self.session_token is not None and self.vault_key is not None
```

Private instance variables use `_underscore_prefix`. One blank line between methods.

---

## 10. Naming Conventions

| Thing | Convention | Example |
|---|---|---|
| Variables | `snake_case` | `wrapped_vault_key`, `auth_salt` |
| Functions | `snake_case` | `derive_kek`, `generate_nonce` |
| Private helpers | `_snake_case` | `_extract_domain`, `_load_blacklist` |
| Classes | `PascalCase` | `UrlAnalyzer`, `IdentityManager` |
| Constants | `UPPER_SNAKE_CASE` | `KDF_MEMORY_COST`, `BASE_RATING` |
| Private constants | `_UPPER_SNAKE_CASE` | `_RESOURCES` |

Use full, descriptive names. Abbreviations are acceptable only for established domain terms (`kek`, `kdf`, `nonce`, `wvk`).

---

## 11. Strings

Single quotes everywhere. f-strings for any interpolation. Triple-quoted strings reserved for the file header only.

```python
# Correct
return 'Safe'
raise CryptoError(f'Failed to wrap VaultKey: {e}') from e

# Incorrect
return "Safe"
```

---

## 12. Multi-Line Calls and Collections

Each argument or item on its own line, trailing comma after the last, closing delimiter on its own line:

```python
response = requests.get(
    url,
    stream=True,
    allow_redirects=True,
    timeout=REQUEST_TIMEOUT,
    headers={'User-Agent': USER_AGENT},
)
```

Build complex payloads as a named variable before passing — never construct them inline at the call site:

```python
payload = {
    'username': username,
    'auth_hash': auth_hash,
    'wrapped_vault_key': wrapped_vault_key.hex(),
}
self.network.send_request('register', payload)
```

---

## 13. File Structure

Every file follows this top-to-bottom order. Two blank lines between every top-level block.

```
[File header — triple-quoted string]

# Imports - Default Libraries
# Imports - External Libraries
# Imports - Internal Modules

# Constants - <Category>

# Custom Exceptions

# Internal Functions - <Category>

# <Role> Class
```

---

## 14. File Skeleton

The project source lives under `/src`, which contains `/client`, `/server`, and `/common`. Use this as the starting point for any new module:

```python
"""
filename.py [verb] [purpose]. [Optional second sentence.]
"""

# Imports - Default Libraries

# Imports - External Libraries

# Imports - Internal Modules


# Constants - General


# Custom Exceptions
class ModuleError(Exception):
    """Base exception for <module> operations"""
    pass


# Internal Functions - <Category>
def _helper():
    """One-line description"""
    pass


# Main Class
class ClassName:
    """One-line description"""

    def __init__(self):
        """Initialize ClassName"""
        pass
```

---

## 15. AI Context Reference

The following condensed rule set is intended to be included in context when an AI model writes code for this project:

```
SurfCrypt Python coding rules — follow exactly:

BASE: PEP 8, with the rules below taking precedence where they conflict.

STRUCTURE: File opens with a triple-quoted header string (not a docstring). Sections top-to-bottom:
  1. Imports — three headers always present in order, even if empty:
       # Imports - Default Libraries / # Imports - External Libraries / # Imports - Internal Modules
  2. # Constants - <Category> groups
  3. # Custom Exceptions
  4. # Internal Functions - <Category>  (all helpers prefixed _)
  5. # <Role> Class  (no blank line between header and class def)

DOCSTRINGS: Concise one-liners. No argument/return/exception tables — those are in project_book.md.
  Imperative or descriptive phrasing. No trailing period.
  Multi-line only when a single line is genuinely unclear.

INLINE COMMENTS: Use # Phase - Detail pattern to label logical blocks inside functions.
  Comments explain what and why, not what the code already makes obvious.

STRINGS: Single quotes always. f-strings for interpolation. Triple-quotes for the file header only.

IMPORTS: Alphabetical within each section.
  Parenthesised multi-line form for multiple names from a single internal module.
  No wildcard imports.

COLLECTIONS & CALLS: Trailing comma on last item in all multi-line collections and function calls.
  Build complex payloads as a named variable — never inline at the call site.

EXCEPTIONS: Specific before broad. `from e` when re-raising as a new type. f-strings for messages.
  Graceful degradation: print warning, return safe default — do not crash on non-critical failures.

SENSITIVE DATA: `del password` (and any key material) in finally blocks.

NAMING: snake_case variables/functions, _prefix private helpers, PascalCase classes,
  UPPER_SNAKE_CASE constants, _UPPER_SNAKE_CASE private constants.
  Full descriptive names; abbreviations only for established domain terms (kek, nonce, wvk).
```