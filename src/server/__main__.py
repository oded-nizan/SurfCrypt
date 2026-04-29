"""
SurfCrypt Server Entry Point
"""

# Imports - Default Libraries
import sys
import os
from pathlib import Path

# Ensure src is in path for internal module imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Imports - External Libraries
from dotenv import load_dotenv

# Imports - Internal Modules
from server.user_db import UserDatabaseManager
from server.url_cache import CacheDatabaseManager
from server.server import SessionServer, DEFAULT_HOST, DEFAULT_PORT


def main():
    load_dotenv() 

    print(f'SurfCrypt Server')
    print(f'Binding to {DEFAULT_HOST}:{DEFAULT_PORT}')

    # Path resolution for TLS certificates
    project_root = Path(__file__).resolve().parent.parent.parent
    cert_path = os.getenv('SURFCRYPT_CERT', str(project_root / 'resources' / 'server.crt'))
    key_path = os.getenv('SURFCRYPT_KEY', str(project_root / 'resources' / 'server.key'))

    # Automatically generate self-signed certs if they do not exist
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        print("TLS Certificates not found. Auto-generating secure self-signed certificates...")
        try:
            from common.crypto import generate_self_signed_cert
            generate_self_signed_cert(cert_path, key_path)
            print(f"Certificates generated at:\n- {cert_path}\n- {key_path}")
        except Exception as e:
            print(f"Failed to generate certificates: {e}")
            cert_path = None
            key_path = None

    db = UserDatabaseManager()
    cache_db = CacheDatabaseManager()
    server = SessionServer(db, cache_db, host=DEFAULT_HOST, port=DEFAULT_PORT, cert_path=cert_path, key_path=key_path)

    tls_mode = 'plaintext'
    if server.ssl_context:
        tls_mode = 'TLS'

    print(f'Transport: {tls_mode}')
    print(f'Press Ctrl+C to stop')
    print('-' * 40)

    try:
        server.start_server()
    except KeyboardInterrupt:
        print('\nShutting down...')
        server.stop_server()
        db.disconnect()
        cache_db.disconnect()
        print('Server stopped.')


if __name__ == '__main__':
    main()
