"""
util.py provides client-side utility functions for decryption and session management.
"""


# Imports - Internal Modules
from common.crypto import decrypt_field, encrypt_field


# Constants - Session
_SESSION_ERROR_KEYWORDS = (
    'session',
    'unauthorized',
    'invalid token',
    'expired',
)


# Internal Functions - Decryption
def _decrypt_secret_row(row, vault_key):
    """Decrypt all five credential fields from a server row dict"""
    fields = ('name', 'url', 'username', 'password', 'notes')
    result = {}
    for field in fields:
        # Field - decode hex and decrypt ciphertext
        raw_cipher = bytes.fromhex(row[f'{field}_encrypted'])
        raw_nonce = bytes.fromhex(row[f'nonce_{field}'])
        result[field] = decrypt_field(raw_cipher, vault_key, raw_nonce)
    return result


def _is_session_error(error_str):
    """Return True if the error string suggests a server-side session rejection"""
    lowered = error_str.lower()
    return any(kw in lowered for kw in _SESSION_ERROR_KEYWORDS)


# GUI and UI Utility Functions
def _encrypt_secret_row(plaintext_dict, vault_key):
    """Encrypt all five credential fields for a server payload dict"""
    fields = ('name', 'url', 'username', 'password', 'notes')
    payload = {}
    for field in fields:
        # Field - encrypt plaintext and encode to hex
        plaintext = plaintext_dict.get(field, '')
        cipher_bytes, field_nonce = encrypt_field(plaintext, vault_key)
        payload[f'{field}_encrypted'] = cipher_bytes.hex()
        payload[f'nonce_{field}'] = field_nonce.hex()
    return payload


def build_detail_string(result):
    """Convert analysis result to readable multiline string"""
    lines = []
    analysis_data = result.get('analysis_data', {})

    # Checks - append descriptive lines for flagged behavior
    if analysis_data.get('blacklisted_original') or analysis_data.get('blacklisted_final'):
        lines.append('Domain is on the known malicious domains blacklist')
    if result.get('is_shortened'):
        lines.append('URL shortener detected - destination may be obfuscated')
    if analysis_data.get('redirected'):
        lines.append('URL redirected to a different destination')
    if analysis_data.get('excess_subdomains'):
        lines.append('Excessive subdomains detected (potential phishing)')
    if analysis_data.get('raw_ip'):
        lines.append('Raw IP address used instead of domain name')
    if analysis_data.get('executable_extension'):
        lines.append('Link points to an executable file (High Risk)')
    if analysis_data.get('triggers_download'):
        lines.append('Link triggers an automatic file download')
    if analysis_data.get('network_error'):
        lines.append('Offline analysis only (network unreachable)')

    return '\n'.join(lines)


def secure_copy(root_widget, text, delay_ms=30000):
    """Copy text to clipboard and clear it after a delay"""
    root_widget.clipboard_clear()
    root_widget.clipboard_append(text)
    root_widget.after(delay_ms, root_widget.clipboard_clear)


def center_window(window, master):
    """Center a Toplevel window relative to its master"""
    window.update_idletasks()
    px = master.winfo_rootx() + master.winfo_width() // 2
    py = master.winfo_rooty() + master.winfo_height() // 2
    w, h = window.winfo_width(), window.winfo_height()
    window.geometry(f'+{px - w // 2}+{py - h // 2}')


def get_searchable_text(plaintext_dict):
    """Combine secret fields into a single lowercase searchable string"""
    return ' '.join([
        plaintext_dict.get('name', ''),
        plaintext_dict.get('url', ''),
        plaintext_dict.get('username', ''),
        plaintext_dict.get('notes', ''),
    ]).lower()
