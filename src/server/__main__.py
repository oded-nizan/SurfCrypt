"""
__main__.py is the primary entry point for starting the SurfCrypt server.
"""

# Imports - Default Libraries
import os
import sys
from pathlib import Path

# Path Configuration - ensure src is in path for internal module imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Imports - External Libraries
from dotenv import load_dotenv

# Imports - Internal Modules
from server.server import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    SessionServer,
)
from server.url_cache import CacheDatabaseManager
from server.user_db import UserDatabaseManager


# Internal Functions - Entry Point
def main():
    """Initialize and start the SurfCrypt session server"""
    load_dotenv()

    print('SurfCrypt Server')
    print(f'Binding to {DEFAULT_HOST}:{DEFAULT_PORT}')

    # Path resolution - locate TLS certificates
    project_root = Path(__file__).resolve().parent.parent.parent
    cert_path = os.getenv('SURFCRYPT_CERT', str(project_root / 'resources' / 'server.crt'))
    key_path = os.getenv('SURFCRYPT_KEY', str(project_root / 'resources' / 'server.key'))

    # Certificates - automatically generate self-signed certs if missing
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        print('TLS Certificates not found. Auto-generating secure self-signed certificates...')
        try:
            from common.crypto import generate_self_signed_cert
            generate_self_signed_cert(cert_path, key_path)
            print(f'Certificates generated at:\n- {cert_path}\n- {key_path}')
        except Exception as e:
            print(f'Failed to generate certificates: {e}')
            cert_path = None
            key_path = None

    # Database - initialize user and cache managers
    db = UserDatabaseManager()
    cache_db = CacheDatabaseManager()
    server = SessionServer(
        db,
        cache_db,
        host=DEFAULT_HOST,
        port=DEFAULT_PORT,
        cert_path=cert_path,
        key_path=key_path,
    )

    tls_mode = 'TLS' if server.ssl_context else 'plaintext'

    print(f'Transport: {tls_mode}')
    print('Press Ctrl+C to stop')
    print('-' * 40)

    try:
        # Execution - enter the server loop
        server.start_server()
    except KeyboardInterrupt:
        print('\nShutting down...')
        server.stop_server()
        db.disconnect()
        cache_db.disconnect()
        print('Server stopped.')


if __name__ == '__main__':
    main()
