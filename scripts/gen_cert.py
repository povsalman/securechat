#!/usr/bin/env python3
"""
Issue X.509 Certificates Signed by Root CA

This script generates RSA key pairs and issues certificates signed by
the root CA for servers and clients.

Usage:
    python scripts/gen_cert.py --cn server.local --out certs/server
    python scripts/gen_cert.py --cn client.local --out certs/client
"""

import argparse
import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def load_ca(ca_cert_path: str, ca_key_path: str):
    """Load CA certificate and private key."""
    
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )
    
    return ca_cert, ca_key


def issue_certificate(
    common_name: str,
    ca_cert: x509.Certificate,
    ca_key,
    country: str = "PK",
    state: str = "Islamabad",
    locality: str = "Islamabad",
    organization: str = "FAST-NUCES",
    validity_days: int = 365,
    is_server: bool = False
):
    """
    Issue a certificate signed by the CA.
    
    Args:
        common_name: Common Name (CN) for the certificate (e.g., server.local)
        ca_cert: CA certificate object
        ca_key: CA private key object
        country: Two-letter country code
        state: State or province
        locality: City
        organization: Organization name
        validity_days: Certificate validity period in days
        is_server: Whether this is a server certificate
    
    Returns:
        Tuple of (private_key, certificate)
    """
    
    print(f"[*] Generating RSA private key for '{common_name}'...")
    # Generate private key for the entity
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    print(f"[*] Creating certificate for '{common_name}'...")
    # Create certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # Build the certificate
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
    )
    
    # Add appropriate key usage based on certificate type
    if is_server:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=True,
        )
        # Add Subject Alternative Name for server
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(common_name),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
    else:
        # Client certificate
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True,
        )
    
    # Sign the certificate with CA's private key
    cert = builder.sign(ca_key, hashes.SHA256())
    
    print(f"[+] Certificate issued successfully!")
    print(f"    Issued to: {common_name}")
    print(f"    Issued by: {ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
    print(f"    Valid from: {cert.not_valid_before}")
    print(f"    Valid until: {cert.not_valid_after}")
    print(f"    Serial: {cert.serial_number}")
    
    return private_key, cert


def save_certificate_and_key(private_key, cert, output_prefix: str):
    """Save private key and certificate to files."""
    
    # Ensure output directory exists
    output_dir = os.path.dirname(output_prefix)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    
    # Save private key
    key_path = f"{output_prefix}_key.pem"
    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    print(f"[+] Private key saved to: {key_path}")
    
    # Save certificate
    cert_path = f"{output_prefix}_cert.pem"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[+] Certificate saved to: {cert_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Issue certificates signed by Root CA"
    )
    parser.add_argument(
        "--cn",
        required=True,
        help="Common Name (CN) for the certificate (e.g., server.local, client.local)"
    )
    parser.add_argument(
        "--out",
        required=True,
        help="Output prefix for certificate and key files (e.g., certs/server)"
    )
    parser.add_argument(
        "--server",
        action="store_true",
        help="Generate server certificate (includes SAN extension)"
    )
    parser.add_argument(
        "--days",
        type=int,
        default=365,
        help="Validity period in days (default: 365)"
    )
    parser.add_argument(
        "--ca-cert",
        default="certs/ca_cert.pem",
        help="Path to CA certificate"
    )
    parser.add_argument(
        "--ca-key",
        default="certs/ca_key.pem",
        help="Path to CA private key"
    )
    
    args = parser.parse_args()
    
    # Import ipaddress here to avoid issues if not needed
    if args.server:
        import ipaddress
        globals()['ipaddress'] = ipaddress
    
    # Load CA
    print(f"[*] Loading CA certificate and key...")
    ca_cert, ca_key = load_ca(args.ca_cert, args.ca_key)
    
    # Issue certificate
    private_key, cert = issue_certificate(
        common_name=args.cn,
        ca_cert=ca_cert,
        ca_key=ca_key,
        validity_days=args.days,
        is_server=args.server
    )
    
    # Save to files
    save_certificate_and_key(private_key, cert, args.out)
    
    print(f"\n[✓] Certificate issued and saved successfully!")


if __name__ == "__main__":
    main()