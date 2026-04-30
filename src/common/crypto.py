"""
crypto.py is a file binding all cryptography-related functions. It's main goal is to implement the Envelope
Encryption Model
"""

# Imports - Default Libraries
import base64
import datetime
import os
import secrets
import string

# Imports - External Libraries
import argon2.low_level
from argon2 import Type

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import nacl.exceptions
import nacl.public
import nacl.secret
import nacl.utils

# Constants - General Cryptography
SALT_LENGTH = 16
NONCE_LENGTH = nacl.secret.SecretBox.NONCE_SIZE
KEY_LENGTH = nacl.secret.SecretBox.KEY_SIZE
SESSION_TOKEN_BYTES = 32

# Constants - Password Generator
DEFAULT_PASSWORD_LENGTH = 16
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128


# Constants - KDF
KDF_TIME_COST = 3
KDF_MEMORY_COST = 65536  # 64 MB
KDF_PARALLELISM = 4


# Custom Exceptions
class CryptoError(Exception):
    """Base exception for cryptographic operations"""
    pass


class DecryptionError(CryptoError):
    """Raised when decryption fails (wrong key or tampered data)"""
    pass


class KeyDerivationError(CryptoError):
    """Raised when key derivation fails"""
    pass


# Internal Functions - Salt/Nonce
def generate_nonce():
    """Generate random 16 byte nonce for encryption"""
    return nacl.utils.random(NONCE_LENGTH)


def generate_salt():
    """Generate random salt for kdf"""
    return nacl.utils.random(SALT_LENGTH)


def generate_session_token():
    """Generate cryptographically secure random session token; returns hex string"""
    return nacl.utils.random(SESSION_TOKEN_BYTES).hex()


# Internal Functions - KDF
def derive_kek(master_password, salt):
    """Hash password via Argon2id to generate Key Encryption Key"""
    try:
        kek = argon2.low_level.hash_secret_raw(
            secret=master_password.encode('utf-8'),
            salt=salt,
            time_cost=KDF_TIME_COST,
            memory_cost=KDF_MEMORY_COST,
            parallelism=KDF_PARALLELISM,
            hash_len=KEY_LENGTH,
            type=Type.ID  # Argon2id variant
        )
        return kek
    except Exception as e:
        raise KeyDerivationError(f'Failed to derive KEK: {e}') from e


def derive_auth_hash(master_password, salt):
    """Hash password via Argon2id to derive hash for authentication"""
    try:
        auth_hash_raw = argon2.low_level.hash_secret_raw(
            secret=master_password.encode('utf-8'),
            salt=salt,
            time_cost=KDF_TIME_COST,
            memory_cost=KDF_MEMORY_COST,
            parallelism=KDF_PARALLELISM,
            hash_len=KEY_LENGTH,
            type=Type.ID  # Argon2id variant
        )
        # Store in database a base 64 string
        return base64.b64encode(auth_hash_raw).decode('ascii')
    except Exception as e:
        raise KeyDerivationError(f'Failed to derive auth hash: {e}') from e


def generate_vault_key():
    """Output cryptographically secure 32 byte PyNaCl random bytes as vault key"""
    return nacl.utils.random(KEY_LENGTH)


# Internal Functions - Wrapping
def wrap_vault_key(vault_key, kek):
    """Encrypt VaultKey using KEK via PyNaCl SecretBox"""
    try:
        box = nacl.secret.SecretBox(kek)
        nonce = generate_nonce()
        wrapped = box.encrypt(vault_key, nonce)
        # SecretBox.encrypt returns nonce + ciphertext, extract just ciphertext
        ciphertext = wrapped.ciphertext
        return ciphertext, nonce
    except Exception as e:
        raise CryptoError(f'Failed to wrap VaultKey: {e}') from e


def unwrap_vault_key(wrapped_vault_key, kek, nonce):
    """Decrypt VaultKey using KEK via PyNaCl SecretBox"""
    try:
        box = nacl.secret.SecretBox(kek)
        vault_key = box.decrypt(wrapped_vault_key, nonce)
        return vault_key

    except nacl.exceptions.CryptoError as e:
        raise DecryptionError('Failed to unwrap VaultKey - wrong password or tampered data') from e
    except Exception as e:
        raise DecryptionError(f'Failed to unwrap VaultKey: {e}') from e


# Internal Functions - Encryption
def encrypt_field(plaintext, vault_key):
    """Encrypt a credential using PyNaCl SecretBox and VaultKey"""
    try:
        box = nacl.secret.SecretBox(vault_key)
        nonce = generate_nonce()
        encrypted = box.encrypt(plaintext.encode('utf-8'), nonce)
        ciphertext = encrypted.ciphertext
        return ciphertext, nonce
    except Exception as e:
        raise CryptoError(f'Failed to encrypt field: {e}') from e


def decrypt_field(ciphertext, vault_key, nonce):
    """Decrypt a credential using PyNaCl SecretBox and VaultKey"""
    try:
        box = nacl.secret.SecretBox(vault_key)
        decrypted = box.decrypt(ciphertext, nonce)
        return decrypted.decode('utf-8')
    except nacl.exceptions.CryptoError as e:
        raise DecryptionError('Failed to decrypt field - tampered data or wrong key') from e
    except UnicodeDecodeError as e:
        raise DecryptionError('Failed to decode decrypted data as UTF-8') from e
    except Exception as e:
        raise DecryptionError(f'Failed to decrypt field: {e}') from e


# Internal Functions - Password Generation
def generate_password(length=DEFAULT_PASSWORD_LENGTH, uppercase=True, lowercase=True,
                      digits=True, symbols=True):
    """Generate a cryptographically secure random password using the secrets module"""
    length = max(MIN_PASSWORD_LENGTH, min(length, MAX_PASSWORD_LENGTH))

    alphabet = ''
    required = []

    if uppercase:
        alphabet += string.ascii_uppercase
        required.append(secrets.choice(string.ascii_uppercase))
    if lowercase:
        alphabet += string.ascii_lowercase
        required.append(secrets.choice(string.ascii_lowercase))
    if digits:
        alphabet += string.digits
        required.append(secrets.choice(string.digits))
    if symbols:
        alphabet += string.punctuation
        required.append(secrets.choice(string.punctuation))

    if not alphabet:
        alphabet = string.ascii_letters + string.digits
        required = [secrets.choice(alphabet)]

    # Fill remaining length from full alphabet
    remaining = length - len(required)
    password_chars = required + [secrets.choice(alphabet) for _ in range(remaining)]

    # Fisher-Yates shuffle to prevent predictable positions for required chars
    result = list(password_chars)
    for i in range(len(result) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        result[i], result[j] = result[j], result[i]

    return ''.join(result)


def generate_self_signed_cert(cert_path, key_path):
    """Generates a secure self-signed TLS certificate and private key for local demo use"""
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"surfcrypt-server")])
    now = datetime.datetime.now(datetime.timezone.utc)
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now
    ).not_valid_after(
        now + datetime.timedelta(days=365)
    ).sign(key, hashes.SHA256())

    with open(key_path, 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
