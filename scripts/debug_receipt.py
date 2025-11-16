#!/usr/bin/env python3
"""
Debug Receipt Signature

This script helps diagnose receipt signature verification issues.
"""

import json
import base64
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

def load_certificate(cert_path):
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def main():
    import sys
    if len(sys.argv) != 4:
        print("Usage: python debug_receipt.py <receipt.json> <transcript.txt> <cert.pem>")
        sys.exit(1)
    
    receipt_path = sys.argv[1]
    transcript_path = sys.argv[2]
    cert_path = sys.argv[3]
    
    # Load receipt
    with open(receipt_path, 'r') as f:
        receipt = json.load(f)
    
    print("\n" + "="*70)
    print("  RECEIPT SIGNATURE DEBUG")
    print("="*70)
    
    # Compute transcript hash
    print("\n[1] Computing transcript hash...")
    hasher = hashlib.sha256()
    with open(transcript_path, 'r') as f:
        content = f.read()
        hasher.update(content.encode('utf-8'))
    
    computed_hash = hasher.hexdigest()
    expected_hash = receipt['transcript_sha256']
    
    print(f"    Computed: {computed_hash}")
    print(f"    Expected: {expected_hash}")
    print(f"    Match: {computed_hash == expected_hash}")
    
    # Load certificate
    print("\n[2] Loading certificate...")
    cert = load_certificate(cert_path)
    public_key = cert.public_key()
    print(f"    Certificate CN: {cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value}")
    
    # Get signature
    signature_b64 = receipt['sig']
    signature_bytes = base64.b64decode(signature_b64)
    
    print(f"\n[3] Signature info...")
    print(f"    Signature length: {len(signature_bytes)} bytes")
    print(f"    First 20 bytes: {signature_bytes[:20].hex()}")
    
    # Try different verification methods
    print(f"\n[4] Trying different verification methods...")
    
    # Method 1: Sign hex string as bytes
    print("\n    Method 1: Signing hex string as UTF-8 bytes")
    try:
        data = computed_hash.encode('utf-8')
        digest = hashlib.sha256(data).digest()
        public_key.verify(signature_bytes, digest, padding.PKCS1v15(), hashes.SHA256())
        print("    ✓ SUCCESS - Signature verified!")
    except InvalidSignature:
        print("    ✗ FAILED - Invalid signature")
    
    # Method 2: Sign raw hash bytes
    print("\n    Method 2: Signing raw hash bytes")
    try:
        data = bytes.fromhex(computed_hash)
        digest = hashlib.sha256(data).digest()
        public_key.verify(signature_bytes, digest, padding.PKCS1v15(), hashes.SHA256())
        print("    ✓ SUCCESS - Signature verified!")
    except InvalidSignature:
        print("    ✗ FAILED - Invalid signature")
    
    # Method 3: Direct verification (no additional hash)
    print("\n    Method 3: Direct verification (hash bytes only)")
    try:
        data = bytes.fromhex(computed_hash)
        public_key.verify(signature_bytes, data, padding.PKCS1v15(), hashes.SHA256())
        print("    ✓ SUCCESS - Signature verified!")
    except InvalidSignature:
        print("    ✗ FAILED - Invalid signature")
    
    print("\n" + "="*70 + "\n")

if __name__ == "__main__":
    main()