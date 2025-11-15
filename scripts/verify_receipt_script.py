#!/usr/bin/env python3
"""
Offline Session Receipt Verification Tool

This script verifies the non-repudiation evidence by:
1. Validating each message signature in the transcript
2. Verifying the SessionReceipt signature over the transcript hash

Usage:
    python scripts/verify_receipt.py --transcript transcripts/session_123.txt --receipt transcripts/receipt_123.json --cert certs/client_cert.pem
"""

import argparse
import json
import hashlib
import base64
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


def load_certificate(cert_path: str):
    """Load X.509 certificate from PEM file."""
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def verify_message_signature(seqno: int, ts: int, ct: str, sig: str, public_key) -> bool:
    """
    Verify a single message signature.
    
    Args:
        seqno: Sequence number
        ts: Timestamp
        ct: Base64-encoded ciphertext
        sig: Base64-encoded signature
        public_key: RSA public key from certificate
    
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        # Reconstruct the data that was signed
        data = f"{seqno}|{ts}|{ct}".encode('utf-8')
        
        # Compute SHA-256 hash
        digest = hashlib.sha256(data).digest()
        
        # Decode signature
        signature_bytes = base64.b64decode(sig)
        
        # Verify signature
        public_key.verify(
            signature_bytes,
            digest,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"    [!] Error verifying message: {e}")
        return False


def compute_transcript_hash(transcript_path: str) -> str:
    """
    Compute SHA-256 hash of the entire transcript.
    
    Args:
        transcript_path: Path to transcript file
    
    Returns:
        Hex-encoded SHA-256 hash
    """
    hasher = hashlib.sha256()
    
    with open(transcript_path, 'r') as f:
        for line in f:
            hasher.update(line.encode('utf-8'))
    
    return hasher.hexdigest()


def verify_receipt_signature(transcript_hash: str, receipt_sig: str, public_key) -> bool:
    """
    Verify the SessionReceipt signature.
    
    Args:
        transcript_hash: Hex-encoded transcript hash
        receipt_sig: Base64-encoded receipt signature
        public_key: RSA public key from certificate
    
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        # Convert hex hash to bytes
        hash_bytes = bytes.fromhex(transcript_hash)
        
        # Compute the actual digest that was signed (extra SHA-256 layer)
        digest = hashlib.sha256(hash_bytes).digest()
        
        # Decode signature
        signature_bytes = base64.b64decode(receipt_sig)
        
        # Verify signature
        public_key.verify(
            signature_bytes,
            digest,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"    [!] Error verifying receipt: {e}")
        return False


def verify_session(transcript_path: str, receipt_path: str, cert_path: str):
    """
    Complete verification of session transcript and receipt.
    
    Args:
        transcript_path: Path to transcript file
        receipt_path: Path to receipt JSON file
        cert_path: Path to certificate used for signing
    """
    
    print("\n" + "="*70)
    print("  SESSION RECEIPT VERIFICATION")
    print("="*70)
    
    # Load certificate and extract public key
    print(f"\n[1] Loading certificate: {cert_path}")
    cert = load_certificate(cert_path)
    public_key = cert.public_key()
    cert_cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    print(f"    Certificate CN: {cert_cn}")
    print(f"    Valid from: {cert.not_valid_before_utc}")
    print(f"    Valid until: {cert.not_valid_after_utc}")
    
    # Load receipt
    print(f"\n[2] Loading receipt: {receipt_path}")
    with open(receipt_path, 'r') as f:
        receipt = json.load(f)
    
    print(f"    Peer: {receipt['peer']}")
    print(f"    First sequence: {receipt['first_seq']}")
    print(f"    Last sequence: {receipt['last_seq']}")
    print(f"    Transcript hash: {receipt['transcript_sha256']}")
    
    # Verify individual messages in transcript
    print(f"\n[3] Verifying individual message signatures...")
    message_count = 0
    valid_messages = 0
    
    with open(transcript_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            
            # Parse transcript line: seqno|ts|ct|sig|peer_cert_fingerprint
            parts = line.split('|')
            if len(parts) != 5:
                print(f"    [!] Line {line_num}: Invalid format")
                continue
            
            seqno, ts, ct, sig, fingerprint = parts
            message_count += 1
            
            if verify_message_signature(int(seqno), int(ts), ct, sig, public_key):
                valid_messages += 1
                print(f"    [✓] Message {seqno}: VALID")
            else:
                print(f"    [✗] Message {seqno}: INVALID SIGNATURE")
    
    print(f"\n    Summary: {valid_messages}/{message_count} messages have valid signatures")
    
    # Compute transcript hash
    print(f"\n[4] Computing transcript hash...")
    computed_hash = compute_transcript_hash(transcript_path)
    expected_hash = receipt['transcript_sha256']
    
    print(f"    Computed:  {computed_hash}")
    print(f"    Expected:  {expected_hash}")
    
    if computed_hash == expected_hash:
        print(f"    [✓] Transcript hash MATCHES")
    else:
        print(f"    [✗] Transcript hash MISMATCH - transcript may have been modified!")
    
    # Verify receipt signature
    print(f"\n[5] Verifying SessionReceipt signature...")
    receipt_valid = verify_receipt_signature(
        expected_hash,
        receipt['sig'],
        public_key
    )
    
    if receipt_valid:
        print(f"    [✓] Receipt signature VALID")
    else:
        print(f"    [✗] Receipt signature INVALID")
    
    # Final verdict
    print(f"\n" + "="*70)
    if valid_messages == message_count and computed_hash == expected_hash and receipt_valid:
        print("  VERIFICATION RESULT: ✓ ALL CHECKS PASSED")
        print("  Non-repudiation evidence is valid and authentic.")
    else:
        print("  VERIFICATION RESULT: ✗ VERIFICATION FAILED")
        print("  Evidence may have been tampered with or is invalid.")
    print("="*70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Verify session transcript and receipt for non-repudiation"
    )
    parser.add_argument(
        "--transcript",
        required=True,
        help="Path to transcript file"
    )
    parser.add_argument(
        "--receipt",
        required=True,
        help="Path to receipt JSON file"
    )
    parser.add_argument(
        "--cert",
        required=True,
        help="Path to certificate used for signing"
    )
    
    args = parser.parse_args()
    
    try:
        verify_session(args.transcript, args.receipt, args.cert)
    except FileNotFoundError as e:
        print(f"\n[ERROR] File not found: {e}")
    except Exception as e:
        print(f"\n[ERROR] Verification failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
