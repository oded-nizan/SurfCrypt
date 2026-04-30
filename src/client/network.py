"""
network.py handles all TCP/TLS socket communication with the server and Implements stateless per-request
connections with a 4-byte length-prefixed JSON protocol.
"""

# Imports - Default Libraries
import socket
import ssl

# Imports - Internal Modules
from common.protocol import (
    recv_message,
    send_message,
)


# Constants - Server
DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = 8443


# Custom Exceptions
class NetworkError(Exception):
    """Raised when a network/socket operation fails"""
    pass


class ServerError(Exception):
    """Raised when the server returns a non-success status"""
    pass


# Network Class
class NetworkClient:
    """Manages TCP/TLS connections to the server"""

    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT, cert_path=None, use_tls=True):
        self.host = host
        self.port = port
        self.cert_path = cert_path
        self.use_tls = use_tls

    def _build_ssl_context(self):
        """Build SSL context; loads pinned cert if provided, else disables hostname/cert checks for lab env"""
        if self.cert_path:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.load_verify_locations(self.cert_path)
            ctx.check_hostname = False
        else:
            # Lab environment fallback - no cert pinning
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def send_request(self, action, data, session_token=None):
        """
        Send a JSON request to the server and return the parsed response dict
        Packet structure: [4-byte big-endian length][UTF-8 JSON payload]
        """
        # Build JSON payload
        request = {'action': action, 'data': data}
        if session_token:
            request['session_token'] = session_token

        # Prevent reference before assignment error
        raw_sock = None
        response = None

        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(10)

            if self.use_tls:
                ctx = self._build_ssl_context()
                sock = ctx.wrap_socket(raw_sock, server_hostname=self.host)
                sock.connect((self.host, self.port))
            else:
                raw_sock.connect((self.host, self.port))
                sock = raw_sock

            send_message(sock, request)
            response = recv_message(sock)
            if response is None:
                raise NetworkError('Connection closed by server before response was received')

        except (socket.timeout, socket.error, ssl.SSLError, OSError) as e:
            raise NetworkError(f'Socket error during request "{action}": {e}') from e
        except (TypeError, ValueError) as e:
            # Captures both serialization errors and json.JSONDecodeError / UnicodeDecodeError
            raise NetworkError(f'Serialization or decode error: {e}') from e
        finally:
            if raw_sock:
                try:
                    raw_sock.close()
                except OSError:
                    pass

        if response.get('status') != 'success':
            message = response.get('message', 'Unknown server error')
            raise ServerError(message)

        return response
