"""
X.509 Certificate Validation (PKI)

Implements certificate validation including:
- Signature verification (signed by trusted CA)
- Validity period checking
- Common Name (CN) validation
"""

import hashlib
from datetime import datetime
from typing import Optional
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature


def load_certificate(cert_path: str) -> x509.Certificate:
    """
    Load X.509 certificate from PEM file.
    
    Args:
        cert_path: Path to certificate file
    
    Returns:
        Certificate object
    """
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def get_certificate_fingerprint(cert: x509.Certificate) -> str:
    """
    Compute SHA-256 fingerprint of certificate.
    
    Args:
        cert: Certificate object
    
    Returns:
        Hex-encoded SHA-256 fingerprint
    """
    cert_bytes = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(cert_bytes).hexdigest()


def validate_certificate(
    cert: x509.Certificate,
    ca_cert: x509.Certificate,
    expected_cn: Optional[str] = None
) -> tuple[bool, str]:
    """
    Validate a certificate against a trusted CA.
    
    Checks:
    1. Certificate is signed by the CA
    2. Certificate is within its validity period
    3. Common Name matches expected value (if provided)
    
    Args:
        cert: Certificate to validate
        ca_cert: Trusted CA certificate
        expected_cn: Expected Common Name (optional)
    
    Returns:
        Tuple of (is_valid, error_message)
        is_valid: True if all checks pass
        error_message: Description of failure, or "OK" if valid
    """
    
    # Check 1: Verify signature (certificate is signed by CA)
    try:
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except InvalidSignature:
        return False, "BAD_CERT: Invalid signature (not signed by trusted CA)"
    except Exception as e:
        return False, f"BAD_CERT: Signature verification error: {e}"
    
    # Check 2: Verify validity period
    now = datetime.utcnow()
    
    if now < cert.not_valid_before:
        return False, f"BAD_CERT: Certificate not yet valid (valid from {cert.not_valid_before})"
    
    if now > cert.not_valid_after:
        return False, f"BAD_CERT: Certificate expired (expired on {cert.not_valid_after})"
    
    # Check 3: Verify Common Name (if expected_cn is provided)
    if expected_cn:
        try:
            cert_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            if cert_cn != expected_cn:
                return False, f"BAD_CERT: Common Name mismatch (expected '{expected_cn}', got '{cert_cn}')"
        except IndexError:
            return False, "BAD_CERT: Certificate has no Common Name"
    
    # All checks passed
    return True, "OK"


def get_common_name(cert: x509.Certificate) -> str:
    """
    Extract Common Name from certificate.
    
    Args:
        cert: Certificate object
    
    Returns:
        Common Name (CN) value
    """
    try:
        return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        return "UNKNOWN"


def get_certificate_info(cert: x509.Certificate) -> dict:
    """
    Extract certificate information for display.
    
    Args:
        cert: Certificate object
    
    Returns:
        Dictionary with certificate details
    """
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "common_name": get_common_name(cert),
        "serial_number": cert.serial_number,
        "not_valid_before": cert.not_valid_before,
        "not_valid_after": cert.not_valid_after,
        "fingerprint": get_certificate_fingerprint(cert),
    }


# Test function for development
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python -m app.crypto.pki <cert_path> <ca_cert_path> [expected_cn]")
        sys.exit(1)
    
    cert_path = sys.argv[1]
    ca_cert_path = sys.argv[2]
    expected_cn = sys.argv[3] if len(sys.argv) > 3 else None
    
    print(f"[*] Loading certificate: {cert_path}")
    cert = load_certificate(cert_path)
    
    print(f"[*] Loading CA certificate: {ca_cert_path}")
    ca_cert = load_certificate(ca_cert_path)
    
    print("\n[*] Certificate Information:")
    info = get_certificate_info(cert)
    for key, value in info.items():
        print(f"    {key}: {value}")
    
    print("\n[*] Validating certificate...")
    is_valid, message = validate_certificate(cert, ca_cert, expected_cn)
    
    if is_valid:
        print(f"[✓] Certificate is VALID: {message}")
    else:
        print(f"[✗] Certificate is INVALID: {message}")
    
    sys.exit(0 if is_valid else 1)
