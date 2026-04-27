"""identity.py contains all client-side authentication and session state and handles registration, login, and logout
using the Envelope Encryption model. No plaintext passwords are ever transmitted to the server"""

# Imports - Internal Modules
from client.network import NetworkClient, NetworkError, ServerError
from common.crypto import (
    generate_vault_key,
    generate_salt,
    derive_kek,
    derive_auth_hash,
    wrap_vault_key,
    unwrap_vault_key,
    DecryptionError,
    KeyDerivationError,
)


# Custom Exceptions
class AuthenticationError(Exception):
    """Raised when registration, login, or session validation fails"""
    pass


# Authenticator Class
class IdentityManager:
    """Manages user identity, session state, and the Envelope Encryption auth workflows"""

    def __init__(self, network_client=None):
        self.network = network_client or NetworkClient()
        self.session_token = None
        self.vault_key = None
        self.username = None

    @property
    def is_authenticated(self):
        """True if a session is active with a loaded VaultKey"""
        return self.session_token is not None and self.vault_key is not None

    def register(self, username, password):
        """
        Register a new user account.
        Generates all cryptographic material client-side, then sends only derived values to the server.
        Returns True on success; raises AuthenticationError on failure
        """
        try:
            vault_key = generate_vault_key()
            kek_salt = generate_salt()
            auth_salt = generate_salt()

            kek = derive_kek(password, kek_salt)
            auth_hash = derive_auth_hash(password, auth_salt)
            wrapped_vault_key, nonce_wvk = wrap_vault_key(vault_key, kek)

        except (KeyDerivationError, Exception) as e:
            raise AuthenticationError(f'Failed to generate registration credentials: {e}') from e

        payload = {
            'username': username,
            'auth_hash': auth_hash,
            'wrapped_vault_key': wrapped_vault_key.hex(),
            'kek_salt': kek_salt.hex(),
            'auth_salt': auth_salt.hex(),
            'nonce_wvk': nonce_wvk.hex(),
        }

        try:
            self.network.send_request('register', payload)
        except ServerError as e:
            raise AuthenticationError(f'Registration rejected by server: {e}') from e
        except NetworkError as e:
            raise AuthenticationError(f'Network error during registration: {e}') from e

        return True

    def login(self, username, password):
        """
        Authenticate an existing user. Fetch auth_salt from server than derive auth_hash locally,
        send for verification. On success, derive KEK and unwrap VaultKey entirely on the client.
        Stores session_token and vault_key in memory on success
        """
        try:
            salt_response = self.network.send_request('get_auth_salt', {'username': username})
        except ServerError as e:
            raise AuthenticationError(f'Failed to fetch auth salt: {e}') from e
        except NetworkError as e:
            raise AuthenticationError(f'Network error during login: {e}') from e

        try:
            auth_salt = bytes.fromhex(salt_response['data']['auth_salt'])
        except (KeyError, ValueError) as e:
            raise AuthenticationError(f'Invalid server response format: {e}') from e

        try:
            auth_hash = derive_auth_hash(password, auth_salt)
        except KeyDerivationError as e:
            raise AuthenticationError(f'Key derivation failed: {e}') from e

        try:
            login_response = self.network.send_request('login', {
                'username': username,
                'auth_hash': auth_hash,
            })
        except ServerError as e:
            raise AuthenticationError(f'Login rejected by server: {e}') from e
        except NetworkError as e:
            raise AuthenticationError(f'Network error during login: {e}') from e

        try:
            response_data = login_response['data']
            kek = derive_kek(password, bytes.fromhex(response_data['kek_salt']))
            vault_key = unwrap_vault_key(
                bytes.fromhex(response_data['wrapped_vault_key']),
                kek,
                bytes.fromhex(response_data['nonce_wvk']),
            )
        except (KeyError, ValueError) as e:
            raise AuthenticationError(f'Invalid server response format: {e}') from e
        except KeyDerivationError as e:
            raise AuthenticationError(f'Key derivation failed: {e}') from e
        except DecryptionError as e:
            # Tampered or corrupted wrapped key - should not normally occur post-auth
            raise AuthenticationError(f'Failed to unwrap VaultKey: {e}') from e
        finally:
            password = None  # noqa: F841

        self.session_token = response_data['session_token']
        self.vault_key = vault_key
        self.username = username

        return True

    def logout(self):
        """Send logout to server then clear all session state from memory"""
        if self.session_token:
            try:
                self.network.send_request('logout', {}, self.session_token)
            except Exception:
                pass  # Best-effort; clear local state regardless
        self.session_token = None
        self.vault_key = None
        self.username = None

    def change_password(self, old_password, new_password):
        """
        Re-key the envelope: derive new KEK/auth material from new password,
        re-wrap VaultKey, and send updated credentials to server.
        Requires current session and vault_key in memory.
        """
        if not self.is_authenticated:
            raise AuthenticationError('Must be logged in to change password')

        try:
            # Fetch current auth_salt to derive old auth_hash for verification
            salt_response = self.network.send_request(
                'get_auth_salt', {'username': self.username}, self.session_token
            )
            old_auth_salt = bytes.fromhex(salt_response['data']['auth_salt'])
            old_auth_hash = derive_auth_hash(old_password, old_auth_salt)

            # Generate new salts and derive new keys
            new_kek_salt = generate_salt()
            new_auth_salt = generate_salt()
            new_kek = derive_kek(new_password, new_kek_salt)
            new_auth_hash = derive_auth_hash(new_password, new_auth_salt)
            new_wrapped_vault_key, new_nonce_wvk = wrap_vault_key(self.vault_key, new_kek)

            payload = {
                'old_auth_hash': old_auth_hash,
                'new_auth_hash': new_auth_hash,
                'new_wrapped_vault_key': new_wrapped_vault_key.hex(),
                'new_kek_salt': new_kek_salt.hex(),
                'new_auth_salt': new_auth_salt.hex(),
                'new_nonce_wvk': new_nonce_wvk.hex(),
                'session_token': self.session_token,
            }
            self.network.send_request('change_password', payload, self.session_token)

        except ServerError as e:
            raise AuthenticationError(f'Password change rejected: {e}') from e
        except NetworkError as e:
            raise AuthenticationError(f'Network error during password change: {e}') from e
        except (KeyDerivationError, Exception) as e:
            raise AuthenticationError(f'Failed to change password: {e}') from e
        finally:
            old_password = None  # noqa: F841
            new_password = None  # noqa: F841

        return True
