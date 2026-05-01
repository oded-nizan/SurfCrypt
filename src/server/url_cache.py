"""
url_cache.py handles the initialization and management of the URL analysis cache database.
"""

# Imports - Default Libraries
import json
import os
import sqlite3
import threading
from pathlib import Path

# Imports - Internal Modules
from server.user_db import DatabaseError

# Constants - Persistence
DEFAULT_CACHE_DB_PATH = os.getenv('SURFCRYPT_CACHE_DB', './src/data/url_cache.db')


# Database Class
class CacheDatabaseManager:
    """Manage URL analysis cache database operations"""

    def __init__(self, db_path=DEFAULT_CACHE_DB_PATH):
        """Initialize CacheDatabaseManager with database path and write lock"""
        self.db_path = db_path
        self.conn = None
        self._write_lock = threading.Lock()

    def connect(self):
        """Establish the SQLite connection if it doesn't already exist"""
        if self.conn is None:
            # File system - ensure the data directory exists
            dir_path = os.path.dirname(self.db_path)
            if dir_path:
                os.makedirs(dir_path, exist_ok=True)
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row

    def init_db(self):
        """Execute schema creation if tables don't exist"""
        self.connect()
        schema_path = Path(__file__).parent / 'cache_schema.sql'

        try:
            # Schema - load and execute SQL script
            with open(schema_path, 'r', encoding='utf-8') as f:
                schema_script = f.read()
            self.conn.executescript(schema_script)
            self.conn.commit()
            print('Successfully initialized the cache database schema')
        except FileNotFoundError:
            print(f'Error: Could not find the schema file at {schema_path}')
        except sqlite3.Error as e:
            print(f'SQLite Error: {e}')

    def disconnect(self):
        """Close database connection gracefully"""
        if self.conn:
            try:
                self.conn.close()
            except sqlite3.Error:
                pass
            finally:
                self.conn = None

    @staticmethod
    def _row_to_dict(row):
        """Convert sqlite3.Row to dictionary"""
        return dict(row) if row else None

    def _execute_query(self, query, params=None, fetch=None):
        """Execute a query with parameterized statement"""
        if not self.conn:
            raise DatabaseError('No database connection')

        try:
            cursor = self.conn.cursor()
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)

            if fetch == 'one':
                result = cursor.fetchone()
                return self._row_to_dict(result)
            elif fetch == 'all':
                return [self._row_to_dict(row) for row in cursor.fetchall()]
            else:
                return None
        except sqlite3.Error as e:
            self.conn.rollback()
            raise DatabaseError(f'Query execution failed: {e}')

    def _commit(self):
        """Commit the current transaction"""
        if self.conn:
            self.conn.commit()

    def _rollback(self):
        """Rollback the current transaction"""
        if self.conn:
            self.conn.rollback()

    # URL CRUD
    # -Create
    def create_url_analysis(self, url, rating, recommendation, is_shortened, expanded_url, analysis_data):
        """Store URL analysis result; returns analysis id"""
        query = """
            INSERT INTO url_history (url, rating, recommendation, is_shortened,
                                     expanded_url, analysis_data)
            VALUES (?, ?, ?, ?, ?, ?)
        """
        try:
            with self._write_lock:
                cursor = self.conn.cursor()
                cursor.execute(
                    query,
                    (
                        url,
                        rating,
                        recommendation,
                        is_shortened,
                        expanded_url,
                        json.dumps(analysis_data) if isinstance(analysis_data, dict) else analysis_data,
                    ),
                )
                analysis_id = cursor.lastrowid
                self._commit()
                return analysis_id
        except sqlite3.Error as e:
            self._rollback()
            raise DatabaseError(f'Failed to store URL analysis: {e}')

    # -Retrieve
    def get_url_analysis(self, url):
        """Get cached URL analysis result by URL"""
        query = """
            SELECT id, url, rating, recommendation, is_shortened, expanded_url, analysis_data, analyzed_at
            FROM url_history WHERE url = ?
        """
        return self._execute_query(query, (url,), fetch='one')

    def get_url_analysis_by_id(self, analysis_id):
        """Get cached URL analysis result by id"""
        query = """
            SELECT id, url, rating, recommendation, is_shortened, expanded_url, analysis_data, analyzed_at
            FROM url_history WHERE id = ?
        """
        return self._execute_query(query, (analysis_id,), fetch='one')

    # -Update
    def update_url_analysis(self, analysis_id, rating, recommendation, expanded_url, analysis_data):
        """Update existing URL analysis; returns success status"""
        query = """
            UPDATE url_history SET 
                rating = ?, 
                recommendation = ?, 
                expanded_url = ?, 
                analysis_data = ?,
                analyzed_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """
        try:
            with self._write_lock:
                cursor = self.conn.cursor()
                cursor.execute(
                    query,
                    (
                        rating,
                        recommendation,
                        expanded_url,
                        json.dumps(analysis_data) if isinstance(analysis_data, dict) else analysis_data,
                        analysis_id,
                    ),
                )
                updated = cursor.rowcount > 0
                self._commit()
                return updated
        except sqlite3.Error as e:
            self._rollback()
            raise DatabaseError(f'Failed to update URL analysis: {e}')

    # -Delete
    def delete_url_analysis(self, analysis_id):
        """Delete specific analysis from cache; returns success status"""
        query = "DELETE FROM url_history WHERE id = ?"
        try:
            with self._write_lock:
                cursor = self.conn.cursor()
                cursor.execute(query, (analysis_id,))
                deleted = cursor.rowcount > 0
                self._commit()
                return deleted
        except sqlite3.Error as e:
            self._rollback()
            raise DatabaseError(f'Failed to delete URL analysis: {e}')

    def delete_old_cache(self, days=30):
        """Prune analysis entries older than specified days; returns count"""
        query = "DELETE FROM url_history WHERE analyzed_at < datetime('now', ?)"
        try:
            with self._write_lock:
                cursor = self.conn.cursor()
                cursor.execute(query, (f'-{days} days',))
                count = cursor.rowcount
                self._commit()
                return count
        except sqlite3.Error as e:
            self._rollback()
            raise DatabaseError(f'Failed to prune URL cache: {e}')
