"""
RSA Digital Signatures

Implements RSA signing and verification using SHA-256 with PKCS#1 v1.5 padding.
"""

import base64
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


def load_private_key(key_path: str):
    """
    Load RSA private key from PEM file.
    
    Args:
        key_path: Path to private key file
    
    Returns:
        RSA private key object
    """
    with open(key_path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
        )


def sign_data(data: bytes, private_key) -> str:
    """
    Sign data using RSA private key.
    
    The signature is computed over SHA-256(data) using PKCS#1 v1.5 padding.
    
    Args:
        data: Data to sign (bytes)
        private_key: RSA private key object
    
    Returns:
        Base64-encoded signature
    """
    # Compute SHA-256 hash of data
    digest = hashlib.sha256(data).digest()
    
    # Sign the hash using RSA with PKCS#1 v1.5 padding
    signature = private_key.sign(
        digest,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    # Return base64-encoded signature
    return base64.b64encode(signature).decode('ascii')


def verify_signature(data: bytes, signature_b64: str, public_key) -> bool:
    """
    Verify RSA signature.
    
    Args:
        data: Original data (bytes)
        signature_b64: Base64-encoded signature
        public_key: RSA public key object (from certificate)
    
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        # Decode base64 signature
        signature = base64.b64decode(signature_b64)
        
        # Compute SHA-256 hash of data
        digest = hashlib.sha256(data).digest()
        
        # Verify signature
        public_key.verify(
            signature,
            digest,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        return True
    
    except InvalidSignature:
        return False
    except Exception:
        return False


def sign_message(seqno: int, timestamp: int, ciphertext: str, private_key) -> str:
    """
    Sign a chat message.
    
    Computes signature over: SHA-256(seqno || timestamp || ciphertext)
    
    Args:
        seqno: Sequence number
        timestamp: Unix timestamp in milliseconds
        ciphertext: Base64-encoded ciphertext
        private_key: RSA private key
    
    Returns:
        Base64-encoded signature
    """
    # Construct data to sign: seqno||timestamp||ciphertext
    data = f"{seqno}|{timestamp}|{ciphertext}".encode('utf-8')
    
    return sign_data(data, private_key)


def verify_message_signature(
    seqno: int,
    timestamp: int,
    ciphertext: str,
    signature: str,
    public_key
) -> bool:
    """
    Verify a chat message signature.
    
    Args:
        seqno: Sequence number
        timestamp: Unix timestamp in milliseconds
        ciphertext: Base64-encoded ciphertext
        signature: Base64-encoded signature
        public_key: RSA public key (from certificate)
    
    Returns:
        True if signature is valid, False otherwise
    """
    # Reconstruct data that was signed
    data = f"{seqno}|{timestamp}|{ciphertext}".encode('utf-8')
    
    return verify_signature(data, signature, public_key)


# Test function for development
if __name__ == "__main__":
    from cryptography.hazmat.primitives.asymmetric import rsa
    
    print("[*] Testing RSA Signature")
    
    # Generate test keypair
    print("\n[1] Generating test RSA keypair...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    # Test data
    test_data = b"Hello, SecureChat!"
    print(f"\n[2] Test data: {test_data}")
    
    # Sign
    signature = sign_data(test_data, private_key)
    print(f"\n[3] Signature (base64): {signature[:64]}...")
    
    # Verify
    is_valid = verify_signature(test_data, signature, public_key)
    print(f"\n[4] Signature verification: {is_valid}")
    
    # Test with modified data
    modified_data = b"Hello, SecureChat?"
    is_valid_modified = verify_signature(modified_data, signature, public_key)
    print(f"[5] Modified data verification: {is_valid_modified}")
    
    assert is_valid == True, "Signature verification failed!"
    assert is_valid_modified == False, "Modified data verification should fail!"
    
    # Test message signing
    print("\n[6] Testing message signing...")
    seqno = 1
    timestamp = 1234567890000
    ciphertext = "aGVsbG8gd29ybGQ="  # base64 encoded
    
    msg_sig = sign_message(seqno, timestamp, ciphertext, private_key)
    print(f"    Message signature: {msg_sig[:64]}...")
    
    msg_valid = verify_message_signature(seqno, timestamp, ciphertext, msg_sig, public_key)
    print(f"    Verification: {msg_valid}")
    
    assert msg_valid == True, "Message signature verification failed!"
    
    print("\n[✓] RSA signature test passed!")
