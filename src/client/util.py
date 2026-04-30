"""
util.py provides client-side utility functions for decryption and session management.
"""


# Imports - Internal Modules
from common.crypto import decrypt_field


# Constants - Session
_SESSION_ERROR_KEYWORDS = (
    'session',
    'unauthorized',
    'invalid token',
    'expired',
)


# Internal Functions - Decryption
def _decrypt_secret_row(row, vault_key):
    """
    Decrypt all five credential fields from a server row dict.
    Expects hex-encoded ciphertext and nonce keys per field.
    Returns a plaintext dict with keys: name, url, username, password, notes
    """
    fields = ('name', 'url', 'username', 'password', 'notes')
    result = {}
    for field in fields:
        raw_cipher = bytes.fromhex(row[f'{field}_encrypted'])
        raw_nonce = bytes.fromhex(row[f'nonce_{field}'])
        result[field] = decrypt_field(raw_cipher, vault_key, raw_nonce)
    return result

def _is_session_error(error_str):
    """Return True if the error string suggests a server side session rejection"""
    lowered = error_str.lower()
    return any(kw in lowered for kw in _SESSION_ERROR_KEYWORDS)
