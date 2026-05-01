"""
protocol.py is a common message framing logic for client-server communication.
"""

# Imports - Default Libraries
import json
import struct

# Constants - Protocol
MSG_LENGTH_PREFIX_SIZE = 4
MAX_PAYLOAD_SIZE = 10 * 1024 * 1024  # 10 MB limit to prevent out-of-memory attacks


# Internal Functions - Framing
def _recv_exact(sock, n):
    """Read exactly n bytes from socket; returns bytes or None on disconnect"""
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


# Internal Functions - Messaging
def recv_message(sock):
    """Read a length-prefixed JSON message; returns dict or None on disconnect"""
    # Header - read the payload length prefix
    raw_len = _recv_exact(sock, MSG_LENGTH_PREFIX_SIZE)
    if raw_len is None:
        return None
    length = struct.unpack('>I', raw_len)[0]

    # Security - validate payload size
    if length > MAX_PAYLOAD_SIZE:
        raise ValueError(f'Payload size {length} exceeds maximum: {MAX_PAYLOAD_SIZE}')

    # Payload - read and decode the JSON data
    payload = _recv_exact(sock, length)
    if payload is None:
        return None
    return json.loads(payload.decode('utf-8'))


def send_message(sock, data):
    """Send a dictionary as a length-prefixed JSON message"""
    # Serialization - encode data to JSON bytes
    payload = json.dumps(data).encode('utf-8')
    if len(payload) > MAX_PAYLOAD_SIZE:
        raise ValueError(f'Payload size {len(payload)} exceeds maximum: {MAX_PAYLOAD_SIZE}')

    # Transmission - send prefix and payload
    sock.sendall(struct.pack('>I', len(payload)) + payload)
