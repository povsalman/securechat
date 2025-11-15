"""
Utility functions for SecureChat.
"""

import base64
import hashlib
import time
import secrets


def now_ms() -> int:
    """
    Get current Unix timestamp in milliseconds.
    
    Returns:
        Current timestamp in milliseconds
    """
    return int(time.time() * 1000)


def sha256_hex(data: bytes) -> str:
    """
    Compute SHA-256 hash and return as hex string.
    
    Args:
        data: Data to hash
    
    Returns:
        Hex-encoded SHA-256 hash
    """
    return hashlib.sha256(data).hexdigest()


def b64encode(data: bytes) -> str:
    """
    Base64 encode bytes to string.
    
    Args:
        data: Bytes to encode
    
    Returns:
        Base64-encoded string
    """
    return base64.b64encode(data).decode('ascii')


def b64decode(data: str) -> bytes:
    """
    Base64 decode string to bytes.
    
    Args:
        data: Base64-encoded string
    
    Returns:
        Decoded bytes
    """
    return base64.b64decode(data)


def generate_nonce(length: int = 16) -> bytes:
    """
    Generate a cryptographically secure random nonce.
    
    Args:
        length: Length in bytes (default: 16)
    
    Returns:
        Random bytes
    """
    return secrets.token_bytes(length)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison to prevent timing attacks.
    
    Args:
        a: First bytes object
        b: Second bytes object
    
    Returns:
        True if equal, False otherwise
    """
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0


# Test function
if __name__ == "__main__":
    print("[*] Testing utility functions")
    
    # Test timestamp
    ts = now_ms()
    print(f"\n[1] Current timestamp: {ts} ms")
    
    # Test SHA-256
    data = b"Hello, World!"
    hash_hex = sha256_hex(data)
    print(f"\n[2] SHA-256('{data.decode()}'): {hash_hex}")
    
    # Test base64
    encoded = b64encode(data)
    decoded = b64decode(encoded)
    print(f"\n[3] Base64 encode/decode:")
    print(f"    Original: {data}")
    print(f"    Encoded:  {encoded}")
    print(f"    Decoded:  {decoded}")
    assert data == decoded, "Base64 encode/decode failed!"
    
    # Test nonce generation
    nonce = generate_nonce(16)
    print(f"\n[4] Random nonce (16 bytes): {nonce.hex()}")
    
    # Test constant-time compare
    result1 = constant_time_compare(b"hello", b"hello")
    result2 = constant_time_compare(b"hello", b"world")
    print(f"\n[5] Constant-time compare:")
    print(f"    'hello' == 'hello': {result1}")
    print(f"    'hello' == 'world': {result2}")
    
    print("\n[✓] Utility functions test passed!")