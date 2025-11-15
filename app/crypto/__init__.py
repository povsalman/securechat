"""
Cryptographic primitives for SecureChat.

This package provides implementations of:
- AES-128 encryption/decryption with PKCS#7 padding
- Diffie-Hellman key exchange
- RSA digital signatures
- X.509 certificate validation (PKI)
"""

from .aes import encrypt, decrypt
from .dh import generate_params, generate_keypair, compute_shared_secret, derive_aes_key
from .sign import sign_data, verify_signature
from .pki import validate_certificate, load_certificate, get_certificate_fingerprint

__all__ = [
    'encrypt',
    'decrypt',
    'generate_params',
    'generate_keypair',
    'compute_shared_secret',
    'derive_aes_key',
    'sign_data',
    'verify_signature',
    'validate_certificate',
    'load_certificate',
    'get_certificate_fingerprint',
]
