"""
protocol.py is a common message framing logic for client-server communication.
"""


# Imports - Default Libraries
import json
import struct


# Imports - External Libraries


# Imports - Internal Modules


# Constants - Protocol
MSG_LENGTH_PREFIX_SIZE = 4
MAX_PAYLOAD_SIZE = 10 * 1024 * 1024  # 10 MB limit to prevent out-of-memory attacks


# Internal Functions - Framing
def _recv_exact(sock, n):
    """Read exactly n bytes from socket; returns bytes or None on safe disconnect"""
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


# Internal Functions - Messaging
def recv_message(sock):
    """Read a length-prefixed JSON message; returns dict or None on safe disconnect"""
    raw_len = _recv_exact(sock, MSG_LENGTH_PREFIX_SIZE)
    if raw_len is None:
        return None
    length = struct.unpack('>I', raw_len)[0]
    
    if length > MAX_PAYLOAD_SIZE:
        raise ValueError(f'Payload size {length} bytes exceeds maximum allowed size of {MAX_PAYLOAD_SIZE} bytes')
        
    payload = _recv_exact(sock, length)
    if payload is None:
        return None
    return json.loads(payload.decode('utf-8'))


def send_message(sock, data):
    """Send a dict as a length-prefixed JSON message"""
    payload = json.dumps(data).encode('utf-8')
    if len(payload) > MAX_PAYLOAD_SIZE:
        raise ValueError(f'Payload size {len(payload)} exceeds maximum allowed size')
    sock.sendall(struct.pack('>I', len(payload)) + payload)
