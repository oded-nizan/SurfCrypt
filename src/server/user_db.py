"""
user_db.py manages the SQLite persistence layer for users, secrets, and sessions.
"""

# Imports - Default Libraries
import os
import sqlite3
import threading
from pathlib import Path

# Imports - External Libraries

# Imports - Internal Modules


# Constants - Persistence
DEFAULT_DB_PATH = os.getenv('SURFCRYPT_DB', './src/data/surfcrypt.db')


# Custom Exceptions
class DatabaseError(Exception):
    """Base exception for database operations"""


class UserExistsError(DatabaseError):
    """Raised when attempting to create a user with existing username"""


# Main Database Manager
class UserDatabaseManager:
    """Manage user and secret database operations including CRUD operations"""

    def __init__(self, db_path=DEFAULT_DB_PATH):
        """Initialize UserDatabaseManager with database path and write lock"""
        self._db_path = db_path
        self._conn = None
        self._write_lock = threading.Lock()

    @property
    def conn(self):
        """Expose the internal SQLite connection"""
        return self._conn

    def connect(self):
        """Establish the SQLite connection if it doesn't already exist"""
        if self._conn is None:
            # File system - ensure the data directory exists
            dir_path = os.path.dirname(self._db_path)
            if dir_path:
                os.makedirs(dir_path, exist_ok=True)
            self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row

    def init_db(self):
        """Execute schema creation if tables don't exist"""
        self.connect()
        schema_path = Path(__file__).parent / 'user_schema.sql'

        try:
            # Schema - load and execute SQL script
            with open(schema_path, 'r', encoding='utf-8') as f:
                schema_script = f.read()
            self._conn.executescript(schema_script)
            self._conn.commit()
            print('Successfully initialized the user database schema')
        except FileNotFoundError:
            print(f'Error: Could not find schema file at {schema_path}')
        except sqlite3.Error as e:
            print(f'SQLite Error: {e}')

    def disconnect(self):
        """Close database connection gracefully"""
        if self._conn:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass
            finally:
                self._conn = None

    def _execute_query(self, query, params=None, fetch=None):
        """Execute a query with parameterized statement"""
        if not self._conn:
            raise DatabaseError('No database connection')

        try:
            # Cursor - execute statement with optional parameters
            cursor = self._conn.cursor()
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)

            # Results - process based on fetch type
            if fetch == 'one':
                result = cursor.fetchone()
                return self._row_to_dict(result)
            if fetch == 'all':
                return [self._row_to_dict(row) for row in cursor.fetchall()]
            return None
        except sqlite3.Error as e:
            self._conn.rollback()
            raise DatabaseError(f'Query execution failed: {e}')

    @staticmethod
    def _row_to_dict(row):
        """Convert sqlite3.Row to dictionary"""
        return dict(row) if row else None

    def _commit(self):
        """Commit the current transaction"""
        if self._conn:
            self._conn.commit()

    def _rollback(self):
        """Rollback the current transaction"""
        if self._conn:
            self._conn.rollback()

    # User CRUD - Create
    def create_user(self, username, auth_hash, wrapped_vault_key, kek_salt, auth_salt, nonce_wvk):
        """Create a new user account; returns user id"""
        query = """
            INSERT INTO users (username, auth_hash, wrapped_vault_key, kek_salt, auth_salt, nonce_wvk)
            VALUES (?, ?, ?, ?, ?, ?)
        """
        try:
            with self._write_lock:
                # Execution - insert user row and commit
                cursor = self._conn.cursor()
                cursor.execute(
                    query,
                    (
                        username,
                        auth_hash,
                        wrapped_vault_key,
                        kek_salt,
                        auth_salt,
                        nonce_wvk,
                    ),
                )
                user_id = cursor.lastrowid
                self._commit()
                return user_id
        except sqlite3.IntegrityError:
            self._rollback()
            raise UserExistsError(f'Username already exists: {username}')
        except sqlite3.Error as e:
            self._rollback()
            raise DatabaseError(f'Failed to create user: {e}')

    # User CRUD - Read
    def get_user_by_username(self, username):
        """Retrieve user by username"""
        query = """
            SELECT id, username, auth_hash, wrapped_vault_key, kek_salt,
                   auth_salt, nonce_wvk, created_at
            FROM users WHERE username = ?
        """
        return self._execute_query(query, (username,), fetch='one')

    def get_user_by_id(self, user_id):
        """Retrieve user by ID"""
        query = """
            SELECT id, username, auth_hash, wrapped_vault_key, kek_salt,
                   auth_salt, nonce_wvk, created_at
            FROM users WHERE id = ?
        """
        return self._execute_query(query, (user_id,), fetch='one')

    def get_user_auth_salt(self, username):
        """Retrieve only the auth_salt for a username"""
        query = 'SELECT auth_salt FROM users WHERE username = ?'
        result = self._execute_query(query, (username,), fetch='one')
        return result['auth_salt'] if result else None

    def get_user_auth_data(self, username):
        """Retrieve ID and auth_hash for initial login verification"""
        query = 'SELECT id, auth_hash FROM users WHERE username = ?'
        return self._execute_query(query, (username,), fetch='one')

    def get_user_vault_data(self, user_id):
        """Retrieve sensitive vault keys and nonces after successful authentication"""
        query = 'SELECT wrapped_vault_key, kek_salt, nonce_wvk FROM users WHERE id = ?'
        return self._execute_query(query, (user_id,), fetch='one')

    # User CRUD - Update
    def update_user_credentials(self, user_id, auth_hash, wrapped_vault_key, kek_salt, auth_salt, nonce_wvk):
        """Update user's authentication credentials; returns success status"""
        query = """
            UPDATE users SET
                auth_hash = ?,
                wrapped_vault_key = ?,
                kek_salt = ?,
                auth_salt = ?,
                nonce_wvk = ?
            WHERE id = ?
        """
        try:
            with self._write_lock:
                # Execution - update credentials and commit
                cursor = self._conn.cursor()
                cursor.execute(
                    query,
                    (auth_hash, wrapped_vault_key, kek_salt, auth_salt, nonce_wvk, user_id),
                )
                updated = cursor.rowcount > 0
                self._commit()
                return updated
        except sqlite3.Error as e:
            self._rollback()
            raise DatabaseError(f'Failed to update user credentials: {e}')

    # User CRUD - Delete
    def delete_user(self, user_id):
        """Delete a user account permanently; returns success status"""
        query = 'DELETE FROM users WHERE id = ?'
        try:
            with self._write_lock:
                # Execution - delete user and commit
                cursor = self._conn.cursor()
                cursor.execute(query, (user_id,))
                deleted = cursor.rowcount > 0
                self._commit()
                return deleted
        except sqlite3.Error as e:
            self._rollback()
            raise DatabaseError(f'Failed to delete user: {e}')

    # Secret CRUD - Create
    def create_secret(self, user_id, encrypted_fields, nonces):
        """Create a new secret; return secret id"""
        query = """
            INSERT INTO secrets (
                user_id, name_encrypted, url_encrypted, username_encrypted,
                password_encrypted, notes_encrypted, nonce_name, nonce_url,
                nonce_username, nonce_password, nonce_notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        try:
            with self._write_lock:
                # Execution - insert secret and commit
                cursor = self._conn.cursor()
                cursor.execute(
                    query,
                    (
                        user_id,
                        encrypted_fields['name_encrypted'],
                        encrypted_fields['url_encrypted'],
                        encrypted_fields['username_encrypted'],
                        encrypted_fields['password_encrypted'],
                        encrypted_fields['notes_encrypted'],
                        nonces['nonce_name'],
                        nonces['nonce_url'],
                        nonces['nonce_username'],
                        nonces['nonce_password'],
                        nonces['nonce_notes'],
                    ),
                )
                secret_id = cursor.lastrowid
                self._commit()
                return secret_id
        except sqlite3.Error as e:
            self._rollback()
            raise DatabaseError(f'Failed to create secret: {e}')

    # Secret CRUD - Read
    def get_secrets_by_user(self, user_id):
        """Retrieve all secrets for a user"""
        query = """
            SELECT id, user_id, name_encrypted, url_encrypted, username_encrypted,
                   password_encrypted, notes_encrypted, nonce_name, nonce_url,
                   nonce_username, nonce_password, nonce_notes,
                   created_at, updated_at
            FROM secrets WHERE user_id = ?
            ORDER BY created_at DESC
        """
        return self._execute_query(query, (user_id,), fetch='all') or []

    def get_secrets_by_user_paginated(self, user_id, offset=0, limit=50):
        """Retrieve secrets for a user with pagination"""
        query = """
            SELECT id, user_id, name_encrypted, url_encrypted, username_encrypted,
                   password_encrypted, notes_encrypted, nonce_name, nonce_url,
                   nonce_username, nonce_password, nonce_notes,
                   created_at, updated_at
            FROM secrets WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        """
        return self._execute_query(query, (user_id, limit, offset), fetch='all') or []

    def count_secrets_by_user(self, user_id):
        """Count total secrets for a user"""
        query = 'SELECT COUNT(*) as count FROM secrets WHERE user_id = ?'
        result = self._execute_query(query, (user_id,), fetch='one')
        return result['count'] if result else 0

    def get_secret_by_id(self, secret_id):
        """Retrieve a secret by ID"""
        query = """
            SELECT id, user_id, name_encrypted, url_encrypted, username_encrypted,
                   password_encrypted, notes_encrypted, nonce_name, nonce_url,
                   nonce_username, nonce_password, nonce_notes,
                   created_at, updated_at
            FROM secrets WHERE id = ?
        """
        return self._execute_query(query, (secret_id,), fetch='one')

    def get_secret_owner(self, secret_id):
        """Get the owner user ID of a secret"""
        query = 'SELECT user_id FROM secrets WHERE id = ?'
        result = self._execute_query(query, (secret_id,), fetch='one')
        return result['user_id'] if result else None

    # Secret CRUD - Update
    def update_secret(self, secret_id, encrypted_fields, nonces):
        """Update a secret; returns success status"""
        query = """
            UPDATE secrets SET
                name_encrypted = ?,
                url_encrypted = ?,
                username_encrypted = ?,
                password_encrypted = ?,
                notes_encrypted = ?,
                nonce_name = ?,
                nonce_url = ?,
                nonce_username = ?,
                nonce_password = ?,
                nonce_notes = ?,
                updated_at = datetime('now')
            WHERE id = ?
        """
        try:
            with self._write_lock:
                # Execution - update secret and commit
                cursor = self._conn.cursor()
                cursor.execute(
                    query,
                    (
                        encrypted_fields['name_encrypted'],
                        encrypted_fields['url_encrypted'],
                        encrypted_fields['username_encrypted'],
                        encrypted_fields['password_encrypted'],
                        encrypted_fields['notes_encrypted'],
                        nonces['nonce_name'],
                        nonces['nonce_url'],
                        nonces['nonce_username'],
                        nonces['nonce_password'],
                        nonces['nonce_notes'],
                        secret_id,
                    ),
                )
                updated = cursor.rowcount > 0
                self._commit()
                return updated
        except sqlite3.Error as e:
            self._rollback()
            raise DatabaseError(f'Failed to update secret: {e}')

    # Secret CRUD - Delete
    def delete_secret(self, secret_id):
        """Delete a secret; returns success status"""
        query = 'DELETE FROM secrets WHERE id = ?'
        try:
            with self._write_lock:
                # Execution - delete secret and commit
                cursor = self._conn.cursor()
                cursor.execute(query, (secret_id,))
                deleted = cursor.rowcount > 0
                self._commit()
                return deleted
        except sqlite3.Error as e:
            self._rollback()
            raise DatabaseError(f'Failed to delete secret: {e}')

    # Session CRUD - Create
    def create_session(self, user_id, session_token, expires_at):
        """Create a new session; returns session id"""
        query = """
            INSERT INTO sessions (user_id, session_token, expires_at)
            VALUES (?, ?, ?)
        """
        try:
            with self._write_lock:
                # Execution - insert session and commit
                cursor = self._conn.cursor()
                cursor.execute(
                    query,
                    (
                        user_id,
                        session_token,
                        expires_at.strftime('%Y-%m-%d %H:%M:%S'),
                    ),
                )
                session_id = cursor.lastrowid
                self._commit()
                return session_id
        except sqlite3.Error as e:
            self._rollback()
            raise DatabaseError(f'Failed to create session: {e}')

    # Session CRUD - Read
    def get_session(self, session_token):
        """Retrieve a session by token"""
        query = """
            SELECT id, user_id, session_token, created_at, expires_at
            FROM sessions WHERE session_token = ?
        """
        return self._execute_query(query, (session_token,), fetch='one')

    # Session CRUD - Update
    def update_session_expiry(self, session_token, new_expires_at):
        """Update a session expiry"""
        query = """
            UPDATE sessions SET expires_at = ?
            WHERE session_token = ?
        """
        try:
            with self._write_lock:
                # Execution - update expiry and commit
                cursor = self._conn.cursor()
                cursor.execute(
                    query,
                    (new_expires_at.strftime('%Y-%m-%d %H:%M:%S'), session_token),
                )
                updated = cursor.rowcount > 0
                self._commit()
                return updated
        except sqlite3.Error as e:
            self._rollback()
            raise DatabaseError(f'Failed to update session: {e}')

    # Session CRUD - Delete
    def delete_session(self, session_token):
        """Delete a session by token"""
        query = 'DELETE FROM sessions WHERE session_token = ?'
        try:
            with self._write_lock:
                # Execution - delete session and commit
                cursor = self._conn.cursor()
                cursor.execute(query, (session_token,))
                deleted = cursor.rowcount > 0
                self._commit()
                return deleted
        except sqlite3.Error as e:
            self._rollback()
            raise DatabaseError(f'Failed to delete session: {e}')

    def delete_user_sessions(self, user_id):
        """Delete all sessions for a user"""
        query = 'DELETE FROM sessions WHERE user_id = ?'
        try:
            with self._write_lock:
                # Execution - delete user sessions and commit
                cursor = self._conn.cursor()
                cursor.execute(query, (user_id,))
                count = cursor.rowcount
                self._commit()
                return count
        except sqlite3.Error as e:
            self._rollback()
            raise DatabaseError(f'Failed to delete user sessions: {e}')

    def delete_other_sessions(self, user_id, keep_session_token):
        """Delete all sessions for a user EXCEPT the specified one"""
        query = 'DELETE FROM sessions WHERE user_id = ? AND session_token != ?'
        try:
            with self._write_lock:
                # Execution - delete other sessions and commit
                cursor = self._conn.cursor()
                cursor.execute(query, (user_id, keep_session_token))
                count = cursor.rowcount
                self._commit()
                return count
        except sqlite3.Error as e:
            self._rollback()
            raise DatabaseError(f'Failed to delete other sessions: {e}')

    def delete_expired_sessions(self):
        """Delete all expired sessions"""
        query = "DELETE FROM sessions WHERE expires_at < datetime('now')"
        try:
            with self._write_lock:
                # Execution - cleanup expired sessions and commit
                cursor = self._conn.cursor()
                cursor.execute(query)
                count = cursor.rowcount
                self._commit()
                return count
        except sqlite3.Error:
            self._rollback()
            return 0
