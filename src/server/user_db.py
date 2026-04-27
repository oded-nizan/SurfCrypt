"""
database.py is a file binding all database operations. Its main goal is to manage the database
"""

# Imports - Default Libraries
import sqlite3
import threading
import json
import os
from pathlib import Path

# Constants
DEFAULT_DB_PATH = os.getenv('SURFCRYPT_DB', './data/surfcrypt.db')


# Custom Exceptions
class DatabaseError(Exception):
    """Custom exception for database operations"""
    pass


class UserExistsError(DatabaseError):
    """Raised when attempting to create a user with existing username"""
    pass


# Database Class
class UserDatabaseManager:
    """Class to manage user and secret database operations including CRUD operations"""
    def __init__(self, db_path=DEFAULT_DB_PATH):
        self.db_path = db_path
        self.conn = None
        self._write_lock = threading.Lock()

    def connect(self):
        """Establish the SQLite connection if it doesn't already exist"""
        if self.conn is None:
            # Explicit OS interaction to ensure the data directory exists
            dir_path = os.path.dirname(self.db_path)
            if dir_path:
                os.makedirs(dir_path, exist_ok=True)
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row

    def init_db(self):
        """Execute schema creation if tables don't exist"""
        self.connect()
        schema_path = Path(__file__).parent / 'user_schema.sql'

        try:
            with open(schema_path, 'r') as file:
                schema_script = file.read()
            self.conn.executescript(schema_script)
            self.conn.commit()
            print('Successfully initialized the database schema')

        except FileNotFoundError:
            print(f'Error: Could not find the schema file at {schema_path}')
        except sqlite3.Error as e:
            print(f'SQLite Error: {e}')

    def disconnect(self):
        """Close database connection gracefully."""
        if self.conn:
            try:
                self.conn.close()
                # logger.info('Database connection closed')
            except sqlite3.Error as e:
                # logger.error(f'Error closing connection: {e}')
                pass
            finally:
                self.conn = None

    @staticmethod
    def _row_to_dict(row):
        """Convert sqlite3.row to dictionary"""
        return dict(row) if row else None

    def _execute_query(self, query, params=None, fetch=None):
        """Execute a query with parameterized statement"""
        if not self.conn:
            raise DatabaseError('No database connection')

        try:
            cursor = self.conn.cursor()
            if params:
                cursor.execute(query, params,)
            else:
                cursor.execute(query)

            if fetch == "one":
                result = cursor.fetchone()
                return self._row_to_dict(result)
            elif fetch == "all":
                return [self._row_to_dict(row) for row in cursor.fetchall()]
            else:
                return None
        except sqlite3.Error as e:
            self.conn.rollback()
            # logger.error(f'Query execution failed: {e}')
            raise DatabaseError(f'Query execution failed: {e}')

    def _commit(self) -> None:
        if self.conn:
            self.conn.commit()

    def _rollback(self) -> None:
        if self.conn:
            self.conn.rollback()

    # User CRUD
    # -Create
    def create_user(self, username, auth_hash, wrapped_vault_key, kek_salt, auth_salt, nonce_wvk):
        """Create a new user account; returns user id"""
        query = """
            INSERT INTO users (username, auth_hash, wrapped_vault_key, kek_salt, auth_salt, nonce_wvk)
            VALUES (?, ?, ?, ?, ?, ?)
        """
        try:
            with self._write_lock:
                cursor = self.conn.cursor()
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
                # logger.info(f'User created with ID: {user_id}')
                return user_id
        except sqlite3.IntegrityError:
            self._rollback()
            raise UserExistsError(f'Username already exists: {username}')
        except sqlite3.Error as e:
            self._rollback()
            # logger.error(f'Failed to create user: {e}')
            raise DatabaseError(f'Failed to create user: {e}')

    # -Retrive
    def get_user_by_username(self, username):
        """Retrieve user by username"""
        query = """
            SELECT id, username, auth_hash, wrapped_vault_key, kek_salt,
                   auth_salt, nonce_wvk, created_at
            FROM users WHERE username = ?
        """
        result = self._execute_query(query, (username,), fetch='one')
        return result

    def get_user_by_id(self, user_id):
        """Retrieve user by ID"""
        query = """
            SELECT id, username, auth_hash, wrapped_vault_key, kek_salt,
                   auth_salt, nonce_wvk, created_at
            FROM users WHERE id = ?
        """
        result = self._execute_query(query, (user_id,), fetch='one')
        return result

    def get_user_auth_salt(self, username):
        """Retrieve only the auth_salt for a username"""
        query = "SELECT auth_salt FROM users WHERE username = ?"
        result = self._execute_query(query, (username,), fetch='one')
        return result["auth_salt"] if result else None

    def get_user_auth_data(self, username):
        """Retrieve ID and auth_hash for initial login verification"""
        query = "SELECT id, auth_hash FROM users WHERE username = ?"
        result = self._execute_query(query, (username,), fetch='one')
        return result

    def get_user_vault_data(self, user_id):
        """Retrieve sensitive vault keys and nonces after successful authentication"""
        query = "SELECT wrapped_vault_key, kek_salt, nonce_wvk FROM users WHERE id = ?"
        return self._execute_query(query, (user_id,), fetch='one')

    # -Update
    def update_user_credentials(self, user_id, auth_hash, wrapped_vault_key, kek_salt, auth_salt, nonce_wvk):
        """Update user's authentication credentials (for password change); returns success status"""
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
                cursor = self.conn.cursor()
                cursor.execute(query, (auth_hash, wrapped_vault_key, kek_salt, auth_salt, nonce_wvk, user_id,),)
                updated = cursor.rowcount > 0
                self._commit()
                if updated:
                    # logger.info(f'Credentials updated for user {user_id}')
                    pass
                return updated
        except sqlite3.Error as e:
            self._rollback()
            # logger.error(f'Failed to update user credentials: {e}')
            raise DatabaseError(f'Failed to update user credentials: {e}')

    # -Delete
    def delete_user(self, user_id):
        """Delete a user account permanently; returns success status"""
        query = "DELETE FROM users WHERE id = ?"
        try:
            with self._write_lock:
                cursor = self.conn.cursor()
                cursor.execute(query, (user_id,),)
                deleted = cursor.rowcount > 0
                self._commit()
                if deleted:
                    # logger.info(f'User {user_id} deleted (cascade)')
                    pass
                return deleted
        except sqlite3.Error as e:
            self._rollback()
            # logger.error(f'Failed to delete user: {e}')
            raise DatabaseError(f'Failed to delete user: {e}')

    # Secret CRUD
    # -Create
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
                cursor = self.conn.cursor()
                cursor.execute(
                    query,
                    (
                        user_id,
                        encrypted_fields["name_encrypted"],
                        encrypted_fields["url_encrypted"],
                        encrypted_fields["username_encrypted"],
                        encrypted_fields["password_encrypted"],
                        encrypted_fields["notes_encrypted"],
                        nonces["nonce_name"],
                        nonces["nonce_url"],
                        nonces["nonce_username"],
                        nonces["nonce_password"],
                        nonces["nonce_notes"],
                    ),
                )
                secret_id = cursor.lastrowid
                self._commit()
                # logger.info(f'Secret created with ID: {secret_id}')
                return secret_id
        except sqlite3.Error as e:
            self._rollback()
            # logger.error(f'Failed to create secret: {e}')
            raise DatabaseError(f'Failed to create secret: {e}')

    # -Retrive
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
        result = self._execute_query(query, (user_id,), fetch='all') or []
        return result

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
        result = self._execute_query(query, (user_id, limit, offset), fetch='all') or []
        return result

    def count_secrets_by_user(self, user_id):
        """Count total secrets for a user"""
        query = "SELECT COUNT(*) as count FROM secrets WHERE user_id = ?"
        result = self._execute_query(query, (user_id,), fetch='one')
        return result["count"] if result else 0

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

    def get_secret_owner(self, secret_id: int):
        """Get the owner user ID of a secret"""
        query = "SELECT user_id FROM secrets WHERE id = ?"
        result = self._execute_query(query, (secret_id,), fetch='one')
        return result["user_id"] if result else None

    # -Update
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
                cursor = self.conn.cursor()
                cursor.execute(
                    query,
                    (
                        encrypted_fields["name_encrypted"],
                        encrypted_fields["url_encrypted"],
                        encrypted_fields["username_encrypted"],
                        encrypted_fields["password_encrypted"],
                        encrypted_fields["notes_encrypted"],
                        nonces["nonce_name"],
                        nonces["nonce_url"],
                        nonces["nonce_username"],
                        nonces["nonce_password"],
                        nonces["nonce_notes"],
                        secret_id,
                    ),
                )
                updated = cursor.rowcount > 0
                self._commit()
                return updated
        except sqlite3.Error as e:
            self._rollback()
            # logger.error(f'Failed to update secret: {e}')
            raise DatabaseError(f'Failed to update secret: {e}')

    # -Delete
    def delete_secret(self, secret_id):
        """Delete a secret; returns success status"""
        query = "DELETE FROM secrets WHERE id = ?"
        try:
            with self._write_lock:
                cursor = self.conn.cursor()
                cursor.execute(query, (secret_id,),)
                deleted = cursor.rowcount > 0
                self._commit()
                return deleted
        except sqlite3.Error as e:
            self._rollback()
            # logger.error(f'Failed to delete secret: {e}')
            raise DatabaseError(f'Failed to delete secret: {e}')

    # Session CRUD
    # -Create
    def create_session(self, user_id, session_token, expires_at):
        """Create a new session; returns session id"""
        query = """
            INSERT INTO sessions (user_id, session_token, expires_at)
            VALUES (?, ?, ?)
        """
        try:
            with self._write_lock:
                cursor = self.conn.cursor()
                cursor.execute(query, (user_id, session_token, expires_at.strftime('%Y-%m-%d %H:%M:%S'),),)
                session_id = cursor.lastrowid
                self._commit()
                # logger.info(f'Session created for user {user_id}')
                return session_id
        except sqlite3.Error as e:
            self._rollback()
            # logger.error(f'Failed to create session: {e}')
            raise DatabaseError(f'Failed to create session: {e}')

    # -Retrive
    def get_session(self, session_token):
        """Retrieve a session"""
        query = """
                    SELECT id, user_id, session_token, created_at, expires_at
                    FROM sessions WHERE session_token = ?
                """
        result = self._execute_query(query, (session_token,), fetch='one')
        return result

    # -Update
    def update_session_expiry(self, session_token, new_expires_at):
        """Update a session expiry"""
        query = """
                    UPDATE sessions SET expires_at = ?
                    WHERE session_token = ?
                """
        try:
            with self._write_lock:
                cursor = self.conn.cursor()
                cursor.execute(query, (new_expires_at.strftime('%Y-%m-%d %H:%M:%S'), session_token,),)
                updated = cursor.rowcount > 0
                self._commit()
                return updated
        except sqlite3.Error as e:
            self._rollback()
            # logger.error(f'Failed to update session: {e}')
            raise DatabaseError(f'Failed to update session: {e}')

    # -Delete
    def delete_session(self, session_token):
        """Delete a session"""
        query = "DELETE FROM sessions WHERE session_token = ?"
        try:
            with self._write_lock:
                cursor = self.conn.cursor()
                cursor.execute(query, (session_token,),)
                deleted = cursor.rowcount > 0
                self._commit()
                return deleted
        except sqlite3.Error as e:
            self._rollback()
            # logger.error(f'Failed to delete session: {e}')
            raise DatabaseError(f'Failed to delete session: {e}')

    def delete_user_sessions(self, user_id):
        """Delete all sessions for a user"""
        query = "DELETE FROM sessions WHERE user_id = ?"
        try:
            with self._write_lock:
                cursor = self.conn.cursor()
                cursor.execute(query, (user_id,),)
                count = cursor.rowcount
                self._commit()
                # logger.info(f'Deleted {count} sessions for user {user_id}')
                return count
        except sqlite3.Error as e:
            self._rollback()
            # logger.error(f'Failed to delete user sessions: {e}')
            raise DatabaseError(f'Failed to delete user sessions: {e}')

    def delete_other_sessions(self, user_id, keep_session_token):
        """Delete all sessions for a user EXCEPT the specified one"""
        query = "DELETE FROM sessions WHERE user_id = ? AND session_token != ?"
        try:
            with self._write_lock:
                cursor = self.conn.cursor()
                cursor.execute(query, (user_id, keep_session_token,),)
                count = cursor.rowcount
                self._commit()
                # logger.info(f'Deleted {count} other sessions for user {user_id}')
                return count
        except sqlite3.Error as e:
            self._rollback()
            # logger.error(f'Failed to delete other sessions: {e}')
            raise DatabaseError(f'Failed to delete other sessions: {e}')

    def delete_expired_sessions(self):
        """Delete all expired sessions"""
        query = "DELETE FROM sessions WHERE expires_at < datetime('now')"
        try:
            with self._write_lock:
                cursor = self.conn.cursor()
                cursor.execute(query,)
                count = cursor.rowcount
                self._commit()
                # logger.info(f'Cleaned up {count} expired sessions')
                return count
        except sqlite3.Error as e:
            self._rollback()
            # logger.error(f'Failed to cleanup sessions: {e}')
