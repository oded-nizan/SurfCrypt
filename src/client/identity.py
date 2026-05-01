"""
identity.py manages client-side authentication and session state.
"""

# Imports - Default Libraries

# Imports - External Libraries

# Imports - Internal Modules
from client.network import (
    NetworkClient,
    NetworkError,
    ServerError,
)
from common.crypto import (
    DecryptionError,
    KeyDerivationError,
    derive_auth_hash,
    derive_kek,
    generate_salt,
    generate_vault_key,
    unwrap_vault_key,
    wrap_vault_key,
)


# Custom Exceptions
class AuthenticationError(Exception):
    """Raised when registration, login, or session validation fails"""


# Main Identity Manager
class IdentityManager:
    """Manages user identity, session state, and encryption workflows"""

    def __init__(self, network_client=None):
        """Initialize IdentityManager with network client dependency"""
        self._network = network_client or NetworkClient()
        self._session_token = None
        self._vault_key = None
        self._username = None

    @property
    def is_authenticated(self):
        """Check if a session is active with a loaded vault key"""
        return self._session_token is not None and self._vault_key is not None

    @property
    def session_token(self):
        """Expose current active session token"""
        return self._session_token

    @property
    def vault_key(self):
        """Expose current active vault key"""
        return self._vault_key

    @property
    def username(self):
        """Expose current active username"""
        return self._username

    def register(self, username, password):
        """
        Register a new user account with the server.

        Generates a unique VaultKey and wraps it using a KEK derived from the
        user's password. Sends the wrapped key and public salts to the server
        """
        try:
            # Material - create salts and initial vault key
            vault_key = generate_vault_key()
            kek_salt = generate_salt()
            auth_salt = generate_salt()

            # Keys - derive KEK and auth hash
            kek = derive_kek(password, kek_salt)
            auth_hash = derive_auth_hash(password, auth_salt)
            wrapped_vault_key, nonce_wvk = wrap_vault_key(vault_key, kek)
        except (KeyDerivationError, Exception) as e:
            raise AuthenticationError(f'Failed to generate registration material: {e}') from e

        # Payload - build registration data package
        payload = {
            'username': username,
            'auth_hash': auth_hash,
            'wrapped_vault_key': wrapped_vault_key.hex(),
            'kek_salt': kek_salt.hex(),
            'auth_salt': auth_salt.hex(),
            'nonce_wvk': nonce_wvk.hex(),
        }

        try:
            # Network - dispatch registration request
            self._network.send_request('register', payload)
        except ServerError as e:
            raise AuthenticationError(f'Registration rejected: {e}') from e
        except NetworkError as e:
            raise AuthenticationError(f'Network error: {e}') from e
        finally:
            # Cleanup - wipe password from local scope
            del password

        return True

    def login(self, username, password):
        """
        Authenticate user and unwrap the vault key.

        Fetches the user's salts from the server, derives the authentication
        hash locally for verification, and on success, unwraps the VaultKey
        into memory using a freshly derived KEK
        """
        try:
            # Salt - fetch auth salt from server
            salt_response = self._network.send_request('get_auth_salt', {'username': username})
            auth_salt = bytes.fromhex(salt_response['data']['auth_salt'])
        except (ServerError, NetworkError, KeyError, ValueError) as e:
            raise AuthenticationError(f'Auth salt fetch failed: {e}') from e

        try:
            # Auth - derive hash and send login request
            auth_hash = derive_auth_hash(password, auth_salt)
            payload = {'username': username, 'auth_hash': auth_hash}
            login_response = self._network.send_request('login', payload)
            response_data = login_response['data']

            # Key - derive KEK and unwrap vault key
            kek = derive_kek(password, bytes.fromhex(response_data['kek_salt']))
            vault_key = unwrap_vault_key(
                bytes.fromhex(response_data['wrapped_vault_key']),
                kek,
                bytes.fromhex(response_data['nonce_wvk']),
            )
        except (ServerError, NetworkError, KeyError, ValueError, KeyDerivationError, DecryptionError) as e:
            raise AuthenticationError(f'Login failed: {e}') from e
        finally:
            # Cleanup - wipe password from local scope
            del password

        # Session - store identity state in memory
        self._session_token = response_data['session_token']
        self._vault_key = vault_key
        self._username = username

        return True

    def logout(self):
        """Terminate server session and clear memory state"""
        if self._session_token:
            try:
                self._network.send_request('logout', {}, self._session_token)
            except Exception:
                pass
        self._session_token = None
        self._vault_key = None
        self._username = None

    def change_password(self, old_password, new_password):
        """Re-key the vault envelope with a new master password"""
        if not self.is_authenticated:
            raise AuthenticationError('Authentication required')

        try:
            # Verification - confirm old password with server
            salt_response = self._network.send_request(
                'get_auth_salt', {'username': self._username}, self._session_token
            )
            old_auth_salt = bytes.fromhex(salt_response['data']['auth_salt'])
            old_auth_hash = derive_auth_hash(old_password, old_auth_salt)

            # Re-keying - generate new material and re-wrap vault key
            new_kek_salt = generate_salt()
            new_auth_salt = generate_salt()
            new_kek = derive_kek(new_password, new_kek_salt)
            new_auth_hash = derive_auth_hash(new_password, new_auth_salt)
            new_wrapped_vault_key, new_nonce_wvk = wrap_vault_key(self._vault_key, new_kek)

            payload = {
                'old_auth_hash': old_auth_hash,
                'new_auth_hash': new_auth_hash,
                'new_wrapped_vault_key': new_wrapped_vault_key.hex(),
                'new_kek_salt': new_kek_salt.hex(),
                'new_auth_salt': new_auth_salt.hex(),
                'new_nonce_wvk': new_nonce_wvk.hex(),
                'session_token': self._session_token,
            }
            # Update - sync new credentials to server
            self._network.send_request('change_password', payload, self._session_token)
        except (ServerError, NetworkError, KeyDerivationError, Exception) as e:
            raise AuthenticationError(f'Password change failed: {e}') from e
        finally:
            # Cleanup - wipe sensitive passwords from memory
            del old_password
            del new_password

        return True
