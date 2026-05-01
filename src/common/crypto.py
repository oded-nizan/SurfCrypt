"""
crypto.py contains all cryptographic primitives and security-related utilities.
"""

# Imports - Default Libraries
import base64
import datetime
import os
import secrets
import string

# Imports - External Libraries
import argon2.low_level
import nacl.exceptions
import nacl.public
import nacl.secret
import nacl.utils
from argon2 import Type
from cryptography import x509
from cryptography.hazmat.primitives import (
    hashes,
    serialization,
)
from cryptography.hazmat.primitives.asymmetric import rsa

# Imports - Internal Modules

# Constants - General Cryptography
SALT_LENGTH = 16
NONCE_LENGTH = nacl.secret.SecretBox.NONCE_SIZE
KEY_LENGTH = nacl.secret.SecretBox.KEY_SIZE
SESSION_TOKEN_BYTES = 32


# Constants - Password Generation
DEFAULT_PASSWORD_LENGTH = 16
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128


# Constants - Key Derivation (KDF)
KDF_TIME_COST = 3
KDF_MEMORY_COST = 65536
KDF_PARALLELISM = 4


# Custom Exceptions
class CryptoError(Exception):
    """Base exception for cryptographic operations"""


class DecryptionError(CryptoError):
    """Raised when decryption fails due to wrong key or tampered data"""


class KeyDerivationError(CryptoError):
    """Raised when key derivation fails"""


# Functions - Randomness
def generate_nonce():
    """Generate a random 16-byte nonce for encryption"""
    return nacl.utils.random(NONCE_LENGTH)


def generate_salt():
    """Generate a random salt for key derivation"""
    return nacl.utils.random(SALT_LENGTH)


def generate_session_token():
    """Generate a secure random session token string"""
    return nacl.utils.random(SESSION_TOKEN_BYTES).hex()


def generate_vault_key():
    """Generate a random 32-byte vault key"""
    return nacl.utils.random(KEY_LENGTH)


# Functions - Key Derivation
def derive_kek(master_password, salt):
    """Derive a Key Encryption Key (KEK) using Argon2id"""
    try:
        # Hashing - generate raw KEK from password and salt
        kek = argon2.low_level.hash_secret_raw(
            secret=master_password.encode('utf-8'),
            salt=salt,
            time_cost=KDF_TIME_COST,
            memory_cost=KDF_MEMORY_COST,
            parallelism=KDF_PARALLELISM,
            hash_len=KEY_LENGTH,
            type=Type.ID
        )
        return kek
    except Exception as e:
        raise KeyDerivationError(f'Failed to derive KEK: {e}') from e
    finally:
        # Security - wipe sensitive master password
        del master_password


def derive_auth_hash(master_password, salt):
    """Derive an authentication hash string using Argon2id"""
    try:
        # Hashing - generate raw auth hash and encode to base64
        auth_hash_raw = argon2.low_level.hash_secret_raw(
            secret=master_password.encode('utf-8'),
            salt=salt,
            time_cost=KDF_TIME_COST,
            memory_cost=KDF_MEMORY_COST,
            parallelism=KDF_PARALLELISM,
            hash_len=KEY_LENGTH,
            type=Type.ID
        )
        return base64.b64encode(auth_hash_raw).decode('ascii')
    except Exception as e:
        raise KeyDerivationError(f'Failed to derive auth hash: {e}') from e
    finally:
        # Security - wipe sensitive master password
        del master_password


# Functions - Envelope Encryption
def wrap_vault_key(vault_key, kek):
    """Encrypt a vault key using a KEK"""
    try:
        # Wrapping - encrypt vault key with KEK in SecretBox
        box = nacl.secret.SecretBox(kek)
        nonce = generate_nonce()
        wrapped = box.encrypt(vault_key, nonce)
        return wrapped.ciphertext, nonce
    except Exception as e:
        raise CryptoError(f'Failed to wrap VaultKey: {e}') from e
    finally:
        # Security - wipe sensitive keys
        del vault_key
        del kek


def unwrap_vault_key(wrapped_vault_key, kek, nonce):
    """Decrypt a vault key using a KEK"""
    try:
        # Unwrapping - decrypt ciphertext back to raw vault key
        box = nacl.secret.SecretBox(kek)
        vault_key = box.decrypt(wrapped_vault_key, nonce)
        return vault_key
    except nacl.exceptions.CryptoError as e:
        raise DecryptionError('Failed to unwrap VaultKey: Invalid key or data') from e
    except Exception as e:
        raise DecryptionError(f'Failed to unwrap VaultKey: {e}') from e
    finally:
        # Security - wipe sensitive KEK
        del kek


# Functions - Field Encryption
def encrypt_field(plaintext, vault_key):
    """Encrypt a single plaintext field using the vault key"""
    try:
        # Encryption - process string field into ciphertext
        box = nacl.secret.SecretBox(vault_key)
        nonce = generate_nonce()
        encrypted = box.encrypt(plaintext.encode('utf-8'), nonce)
        return encrypted.ciphertext, nonce
    except Exception as e:
        raise CryptoError(f'Failed to encrypt field: {e}') from e
    finally:
        # Security - wipe sensitive plaintext
        del plaintext


def decrypt_field(ciphertext, vault_key, nonce):
    """Decrypt a single ciphertext field using the vault key"""
    try:
        # Decryption - process ciphertext back into UTF-8 string
        box = nacl.secret.SecretBox(vault_key)
        decrypted = box.decrypt(ciphertext, nonce)
        return decrypted.decode('utf-8')
    except nacl.exceptions.CryptoError as e:
        raise DecryptionError('Failed to decrypt field: Invalid key or data') from e
    except UnicodeDecodeError as e:
        raise DecryptionError('Failed to decode decrypted data as UTF-8') from e
    except Exception as e:
        raise DecryptionError(f'Failed to decrypt field: {e}') from e


# Functions - Utilities
def generate_password(length=DEFAULT_PASSWORD_LENGTH, uppercase=True, lowercase=True,
                      digits=True, symbols=True):
    """Generate a cryptographically secure random password"""
    length = max(MIN_PASSWORD_LENGTH, min(length, MAX_PASSWORD_LENGTH))
    alphabet = ''
    required = []

    # Building - construct alphabet and ensure required characters
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

    # Filling - complete password and shuffle positions
    remaining = length - len(required)
    password_chars = required + [secrets.choice(alphabet) for _ in range(remaining)]
    result = list(password_chars)
    for i in range(len(result) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        result[i], result[j] = result[j], result[i]

    return ''.join(result)


def generate_self_signed_cert(cert_path, key_path):
    """Generate a self-signed TLS certificate and private key"""
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    os.makedirs(os.path.dirname(key_path), exist_ok=True)

    # Keygen - generate 4096-bit RSA key
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'surfcrypt-server')])
    now = datetime.datetime.now(datetime.timezone.utc)

    # Certification - build and sign the certificate
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

    # Saving - write PEM files to disk
    with open(key_path, 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
