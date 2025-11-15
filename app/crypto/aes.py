"""
AES-128 Encryption/Decryption with PKCS#7 Padding

This module implements AES-128 in ECB mode with PKCS#7 padding.
ECB is used per assignment specification (not recommended for production!).
"""

import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """
    Apply PKCS#7 padding to data.
    
    Args:
        data: Data to pad
        block_size: Block size in bytes (default: 16 for AES)
    
    Returns:
        Padded data
    """
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding


def pkcs7_unpad(data: bytes) -> bytes:
    """
    Remove PKCS#7 padding from data.
    
    Args:
        data: Padded data
    
    Returns:
        Unpadded data
    
    Raises:
        ValueError: If padding is invalid
    """
    if not data:
        raise ValueError("Cannot unpad empty data")
    
    padding_length = data[-1]
    
    if padding_length < 1 or padding_length > 16:
        raise ValueError(f"Invalid padding length: {padding_length}")
    
    # Verify all padding bytes are correct
    for i in range(padding_length):
        if data[-(i + 1)] != padding_length:
            raise ValueError("Invalid PKCS#7 padding")
    
    return data[:-padding_length]


def encrypt(plaintext: str, key: bytes) -> str:
    """
    Encrypt plaintext using AES-128 ECB mode with PKCS#7 padding.
    
    Args:
        plaintext: String to encrypt
        key: 16-byte AES key
    
    Returns:
        Base64-encoded ciphertext
    
    Raises:
        ValueError: If key length is not 16 bytes
    """
    if len(key) != 16:
        raise ValueError(f"AES-128 requires 16-byte key, got {len(key)} bytes")
    
    # Convert plaintext to bytes
    plaintext_bytes = plaintext.encode('utf-8')
    
    # Apply PKCS#7 padding
    padded_data = pkcs7_pad(plaintext_bytes)
    
    # Create AES cipher in ECB mode
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Encrypt
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return base64-encoded ciphertext
    return base64.b64encode(ciphertext).decode('ascii')


def decrypt(ciphertext_b64: str, key: bytes) -> str:
    """
    Decrypt base64-encoded ciphertext using AES-128 ECB mode.
    
    Args:
        ciphertext_b64: Base64-encoded ciphertext
        key: 16-byte AES key
    
    Returns:
        Decrypted plaintext string
    
    Raises:
        ValueError: If key length is not 16 bytes or decryption fails
    """
    if len(key) != 16:
        raise ValueError(f"AES-128 requires 16-byte key, got {len(key)} bytes")
    
    try:
        # Decode base64 ciphertext
        ciphertext = base64.b64decode(ciphertext_b64)
        
        # Create AES cipher in ECB mode
        cipher = Cipher(
            algorithms.AES(key),
            modes.ECB(),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove PKCS#7 padding
        plaintext_bytes = pkcs7_unpad(padded_plaintext)
        
        # Convert to string
        return plaintext_bytes.decode('utf-8')
    
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")


# Test function for development
if __name__ == "__main__":
    # Test AES encryption/decryption
    test_key = b'0123456789ABCDEF'  # 16 bytes
    test_message = "Hello, SecureChat!"
    
    print(f"Original: {test_message}")
    
    encrypted = encrypt(test_message, test_key)
    print(f"Encrypted (base64): {encrypted}")
    
    decrypted = decrypt(encrypted, test_key)
    print(f"Decrypted: {decrypted}")
    
    assert decrypted == test_message, "Encryption/Decryption test failed!"
    print("\n[✓] AES encryption/decryption test passed!")
