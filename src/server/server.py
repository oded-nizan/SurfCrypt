"""
server.py provides the TCP/TLS network listener, request dispatching, and session management.
"""

# Imports - Default Libraries
import hmac
import os
import socket
import ssl
import threading
from datetime import (
    UTC,
    datetime,
    timedelta,
)

# Imports - Internal Modules
from common.crypto import generate_salt, generate_session_token

from common.protocol import recv_message, send_message

from server.analyzer_handler import (
    handle_cache_url_analysis,
    handle_get_url_analysis,
)

from server.user_db import DatabaseError, UserExistsError


# Constants - Server
DEFAULT_HOST = os.getenv('SURFCRYPT_HOST', '0.0.0.0')
DEFAULT_PORT = int(os.getenv('SURFCRYPT_PORT', 8443))


# Constants - Security
SESSION_TIMEOUT_MINUTES = 15
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 10


# Constants - Response Status
STATUS_SUCCESS = 'success'
STATUS_ERROR = 'error'


# Custom Exceptions
class ServerError(Exception):
    """Base exception for server-side errors"""
    pass


class AuthenticationError(ServerError):
    """Raised on authentication or lockout failure"""
    pass


class SessionError(ServerError):
    """Raised on missing, invalid, or expired session"""
    pass


# Server Class
class SessionServer:
    """TCP/TLS server. Accepts connections, dispatches requests, manages sessions"""

    def __init__(self, db_manager, cache_db_manager, host=DEFAULT_HOST, port=DEFAULT_PORT, cert_path=None, key_path=None):
        """Initialize SessionServer with databases and network settings"""
        self.db = db_manager
        self.cache_db = cache_db_manager
        self.host = host
        self.port = port
        self._ssl_context = self._create_ssl_context(cert_path, key_path)
        self._server_socket = None
        self._running = False
        self._login_attempts = {}  # In-memory rate limiting: {username: {'fails': int, 'lockout_until': datetime|None}}
        self._attempts_lock = threading.Lock()

    # Setup
    @staticmethod
    def _create_ssl_context(cert_path, key_path):
        """Create TLS server context; returns ssl.SSLContext or None if paths not provided"""
        if not cert_path or not key_path:
            return None
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context

    # Lifecycle
    def start_server(self):
        """
        Initialise DBs, bind socket, and enter the accept loop.

        This is a blocking call that sets up the database schemas, binds the
        listening socket to the configured host/port, and begins accepting
        new client connections
        """
        # Setup - initialize resources and bind socket
        self.db.init_db()
        self.cache_db.init_db()
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(5)
        self._running = True
        # logger.info(f'Server listening on {self.host}:{self.port} {'(TLS)' if self._ssl_context else '(plaintext)'}')
        self._listen()

    def start_server_async(self):
        """Non-blocking variant of start; runs accept loop in a daemon thread"""
        # Setup - initialize resources and bind socket
        self.db.init_db()
        self.cache_db.init_db()
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(5)
        self._running = True

        # Threading - launch the listener thread
        server_thread = threading.Thread(target=self._listen, daemon=True)
        server_thread.start()

    @property
    def bound_port(self):
        """Return the actual bound port (useful when port=0 is requested)"""
        if self._server_socket:
            return self._server_socket.getsockname()[1]
        return None

    def stop_server(self):
        """Stop the accept loop and close the listening socket"""
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except OSError:
                pass
            finally:
                self._server_socket = None
        # logger.info('Server stopped')

    # Connection Handling
    def _listen(self):
        """Main accept loop; spawn a daemon thread per client connection"""
        while self._running:
            try:
                client_socket, addr = self._server_socket.accept()
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, addr),
                    daemon=True,
                )
                client_thread.start()
            except OSError:
                break

    def _handle_client(self, client_socket, addr):
        """Handle a single client connection; wrap with TLS if configured"""
        # logger.info(f'Connection from {addr}')
        try:
            # TLS - wrap socket if context is available
            if self._ssl_context:
                client_socket = self._ssl_context.wrap_socket(client_socket, server_side=True)
            while True:
                # Communication - receive request and dispatch
                request = recv_message(client_socket)
                if request is None:
                    break
                response = self._dispatch(request)
                send_message(client_socket, response)
        except ssl.SSLError:
            # logger.warning(f'TLS error from {addr}')
            pass
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception:
            # logger.error(f'Unexpected error handling {addr}')
            pass
        finally:
            try:
                client_socket.close()
            except Exception:
                pass
            # logger.info(f'Connection closed: {addr}')

    # Response Helpers
    @staticmethod
    def _success(data=None):
        """Build a success response dict"""
        return {'status': STATUS_SUCCESS, 'data': data or {}}

    @staticmethod
    def _error(message='An error occurred'):
        """Build an error response dict"""
        return {'status': STATUS_ERROR, 'message': message}

    # Binary Encoding Helpers
    @staticmethod
    def _encode_bytes(b):
        """Encode bytes to hex string for JSON transport"""
        return b.hex() if isinstance(b, (bytes, bytearray)) else b

    @staticmethod
    def _decode_bytes(s):
        """Decode hex string to bytes; returns None if s is falsy"""
        return bytes.fromhex(s) if s else None

    # Session Helpers
    def _validate_session(self, request):
        """Validate session token; extend expiry on success; return user_id"""
        token = request.get('session_token')
        if not token:
            raise SessionError('Missing session token')
        session = self.db.get_session(token)
        if not session:
            raise SessionError('Invalid session')
        expires_at = datetime.strptime(session['expires_at'], '%Y-%m-%d %H:%M:%S')
        if datetime.now(UTC).replace(tzinfo=None) > expires_at:
            self.db.delete_session(token)
            raise SessionError('Session expired')
        new_expiry = datetime.now(UTC).replace(tzinfo=None) + timedelta(minutes=SESSION_TIMEOUT_MINUTES)
        self.db.update_session_expiry(token, new_expiry)
        return session['user_id']

    # Rate Limiting
    def _check_lockout(self, username):
        """Raise AuthenticationError if username is currently locked out"""
        with self._attempts_lock:
            record = self._login_attempts.get(username)
            if not record:
                return
            lockout_until = record.get('lockout_until')
            if lockout_until and datetime.now(UTC).replace(tzinfo=None) < lockout_until:
                raise AuthenticationError('Account temporarily locked. Try again later.')

    def _record_failed_login(self, username):
        """Increment fail counter; apply lockout if limit reached"""
        with self._attempts_lock:
            record = self._login_attempts.setdefault(username, {'fails': 0, 'lockout_until': None})
            record['fails'] += 1
            if record['fails'] >= MAX_LOGIN_ATTEMPTS:
                record['lockout_until'] = datetime.now(UTC).replace(tzinfo=None) + timedelta(minutes=LOCKOUT_MINUTES)
                record['fails'] = 0

    def _clear_failed_logins(self, username):
        """Reset fail counter after successful login"""
        with self._attempts_lock:
            self._login_attempts.pop(username, None)

    # Dispatcher - Routes to handlers
    def _dispatch(self, request):
        """
        Route request to the appropriate handler and return response.

        Separates unauthenticated actions (registration/login) from session-guarded
        actions. Performs session validation and token extension for all
        authenticated routes before dispatching to specific handlers
        """
        action = request.get('action')
        data = request.get('data', {})

        if not isinstance(data, dict):
            return self._error('Invalid request format')

        # Unauthenticated actions
        if action == 'register':
            return self._handle_register(data)
        if action == 'get_auth_salt':
            return self._handle_get_auth_salt(data)
        if action == 'login':
            return self._handle_login(data)

        # Authenticated actions - validate session first
        try:
            user_id = self._validate_session(request)
        except SessionError as e:
            return self._error(str(e))

        if action == 'sync_secrets':
            return self._handle_sync_secrets(user_id)
        if action == 'save_secret':
            return self._handle_save_secret(data, user_id)
        if action == 'update_secret':
            return self._handle_update_secret(data, user_id)
        if action == 'delete_secret':
            return self._handle_delete_secret(data, user_id)
        if action == 'get_url_analysis':
            return handle_get_url_analysis(self.cache_db, data, self._success, self._error)
        if action == 'cache_url_analysis':
            return handle_cache_url_analysis(self.cache_db, data, self._success, self._error)
        if action == 'logout':
            return self._handle_logout(request)
        if action == 'change_password':
            return self._handle_change_password(data, user_id)

        return self._error('Unknown action')

    # Handlers - Auth
    def _handle_register(self, data):
        """Store client-derived auth credentials and wrapped vault key"""
        try:
            # Input - extract and decode registration material
            username = data['username']
            auth_hash = data['auth_hash']
            wrapped_vault_key = self._decode_bytes(data['wrapped_vault_key'])
            kek_salt = self._decode_bytes(data['kek_salt'])
            auth_salt = self._decode_bytes(data['auth_salt'])
            nonce_wvk = self._decode_bytes(data['nonce_wvk'])
        except (KeyError, ValueError):
            return self._error('Invalid request data')

        try:
            # Database - create user record
            user_id = self.db.create_user(
                username,
                auth_hash,
                wrapped_vault_key,
                kek_salt,
                auth_salt,
                nonce_wvk,
            )
            return self._success({'user_id': user_id})
        except UserExistsError:
            return self._error('Username already exists')
        except DatabaseError:
            return self._error('Registration failed')

    def _handle_get_auth_salt(self, data):
        """Return auth_salt for username; return random decoy if user not found"""
        username = data.get('username', '')
        auth_salt_raw = self.db.get_user_auth_salt(username)
        if auth_salt_raw:
            auth_salt = self._encode_bytes(auth_salt_raw)
        else:
            # Decoy - same length as a real salt to prevent enumeration
            auth_salt = self._encode_bytes(generate_salt())
        return self._success({'auth_salt': auth_salt})

    def _handle_login(self, data):
        """Verify auth_hash, create session, and return vault data"""
        try:
            # Input - extract login credentials
            username = data['username']
            auth_hash_client = data['auth_hash']
        except KeyError:
            return self._error('Invalid request data')

        try:
            # Rate Limiting - check if user is locked out
            self._check_lockout(username)

            # Verification - check credentials
            auth_data = self.db.get_user_auth_data(username)
            auth_ok = auth_data and hmac.compare_digest(auth_data['auth_hash'], auth_hash_client)

            if not auth_ok:
                self._record_failed_login(username)
                return self._error('Invalid credentials')

            # Session - create new session and invalidate others
            self._clear_failed_logins(username)
            user_id = auth_data['id']
            session_token = generate_session_token()
            expires_at = datetime.now(UTC).replace(tzinfo=None) + timedelta(minutes=SESSION_TIMEOUT_MINUTES)

            self.db.create_session(
                user_id,
                session_token,
                expires_at,
            )
            self.db.delete_other_sessions(
                user_id,
                session_token,
            )

            # Retrieval - fetch sensitive vault data post-auth
            vault_data = self.db.get_user_vault_data(user_id)

            return self._success({
                'session_token': session_token,
                'wrapped_vault_key': self._encode_bytes(vault_data['wrapped_vault_key']),
                'kek_salt': self._encode_bytes(vault_data['kek_salt']),
                'nonce_wvk': self._encode_bytes(vault_data['nonce_wvk']),
            })
        except AuthenticationError as e:
            return self._error(str(e))
        finally:
            # Cleanup - explicitly clear sensitive material
            if 'auth_hash_client' in locals():
                del auth_hash_client

    def _handle_logout(self, request):
        """Delete the session from the database on explicit logout"""
        token = request.get('session_token')
        if token:
            self.db.delete_session(token)
        return self._success()

    def _handle_change_password(self, data, user_id):
        """Verify old auth_hash then update all auth material"""
        try:
            # Input - extract and decode change material
            old_auth_hash = data['old_auth_hash']
            new_auth_hash = data['new_auth_hash']
            new_wrapped_vault_key = self._decode_bytes(data['new_wrapped_vault_key'])
            new_kek_salt = self._decode_bytes(data['new_kek_salt'])
            new_auth_salt = self._decode_bytes(data['new_auth_salt'])
            new_nonce_wvk = self._decode_bytes(data['new_nonce_wvk'])
        except (KeyError, ValueError):
            return self._error('Invalid request data')

        try:
            # Verification - check old credentials
            user = self.db.get_user_by_id(user_id)
            if not user or not hmac.compare_digest(user['auth_hash'], old_auth_hash):
                return self._error('Invalid current password')

            # Update - store new credentials and invalidate other sessions
            self.db.update_user_credentials(
                user_id,
                new_auth_hash,
                new_wrapped_vault_key,
                new_kek_salt,
                new_auth_salt,
                new_nonce_wvk,
            )
            token = data.get('session_token')
            if token:
                self.db.delete_other_sessions(user_id, token)
            return self._success()
        except DatabaseError:
            return self._error('Failed to update password')
        finally:
            # Cleanup - explicitly clear sensitive material
            if 'old_auth_hash' in locals():
                del old_auth_hash
            if 'new_auth_hash' in locals():
                del new_auth_hash

    # Handlers - Secrets
    def _handle_sync_secrets(self, user_id):
        """Return all encrypted secrets for the authenticated user"""
        secrets = self.db.get_secrets_by_user(user_id)
        encoded = []
        for secret in secrets:
            encoded.append({
                'id': secret['id'],
                'name_encrypted': self._encode_bytes(secret['name_encrypted']),
                'url_encrypted': self._encode_bytes(secret['url_encrypted']),
                'username_encrypted': self._encode_bytes(secret['username_encrypted']),
                'password_encrypted': self._encode_bytes(secret['password_encrypted']),
                'notes_encrypted': self._encode_bytes(secret['notes_encrypted']),
                'nonce_name': self._encode_bytes(secret['nonce_name']),
                'nonce_url': self._encode_bytes(secret['nonce_url']),
                'nonce_username': self._encode_bytes(secret['nonce_username']),
                'nonce_password': self._encode_bytes(secret['nonce_password']),
                'nonce_notes': self._encode_bytes(secret['nonce_notes']),
                'created_at': secret['created_at'],
                'updated_at': secret['updated_at'],
            })
        return self._success({'secrets': encoded})

    def _handle_save_secret(self, data, user_id):
        """Insert new encrypted secret; return secret id"""
        try:
            encrypted_fields = {
                'name_encrypted': self._decode_bytes(data['name_encrypted']),
                'url_encrypted': self._decode_bytes(data['url_encrypted']),
                'username_encrypted': self._decode_bytes(data['username_encrypted']),
                'password_encrypted': self._decode_bytes(data['password_encrypted']),
                'notes_encrypted': self._decode_bytes(data['notes_encrypted']),
            }
            nonces = {
                'nonce_name': self._decode_bytes(data['nonce_name']),
                'nonce_url': self._decode_bytes(data['nonce_url']),
                'nonce_username': self._decode_bytes(data['nonce_username']),
                'nonce_password': self._decode_bytes(data['nonce_password']),
                'nonce_notes': self._decode_bytes(data['nonce_notes']),
            }
        except (KeyError, ValueError):
            return self._error('Invalid request data')

        try:
            secret_id = self.db.create_secret(
                user_id,
                encrypted_fields,
                nonces,
            )
            return self._success({'secret_id': secret_id})
        except DatabaseError:
            return self._error('Failed to save secret')

    def _handle_update_secret(self, data, user_id):
        """Update an existing encrypted secret owned by the authenticated user"""
        try:
            secret_id = data['secret_id']
        except KeyError:
            return self._error('Invalid request data')

        # Verify ownership; returns 'Permission denied' for both not-found and wrong owner
        owner_id = self.db.get_secret_owner(secret_id)
        if owner_id != user_id:
            return self._error('Permission denied')

        try:
            encrypted_fields = {
                'name_encrypted': self._decode_bytes(data['name_encrypted']),
                'url_encrypted': self._decode_bytes(data['url_encrypted']),
                'username_encrypted': self._decode_bytes(data['username_encrypted']),
                'password_encrypted': self._decode_bytes(data['password_encrypted']),
                'notes_encrypted': self._decode_bytes(data['notes_encrypted']),
            }
            nonces = {
                'nonce_name': self._decode_bytes(data['nonce_name']),
                'nonce_url': self._decode_bytes(data['nonce_url']),
                'nonce_username': self._decode_bytes(data['nonce_username']),
                'nonce_password': self._decode_bytes(data['nonce_password']),
                'nonce_notes': self._decode_bytes(data['nonce_notes']),
            }
        except (KeyError, ValueError):
            return self._error('Invalid request data')

        try:
            updated = self.db.update_secret(
                secret_id,
                encrypted_fields,
                nonces,
            )
            return self._success({'updated': updated})
        except DatabaseError:
            return self._error('Failed to update secret')

    def _handle_delete_secret(self, data, user_id):
        """Delete a secret owned by the authenticated user"""
        try:
            secret_id = data['secret_id']
        except KeyError:
            return self._error('Invalid request data')

        owner_id = self.db.get_secret_owner(secret_id)
        if owner_id != user_id:
            return self._error('Permission denied')

        try:
            deleted = self.db.delete_secret(secret_id)
            return self._success({'deleted': deleted})
        except DatabaseError:
            return self._error('Failed to delete secret')

    @property
    def ssl_context(self):
        return self._ssl_context
