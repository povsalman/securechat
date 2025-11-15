#!/usr/bin/env python3
"""
Generate Root Certificate Authority (CA)

This script creates a self-signed root CA certificate that will be used
to sign and validate client/server certificates.

Usage:
    python scripts/gen_ca.py --name "FAST-NU Root CA" --days 3650
"""

import argparse
import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_root_ca(
    common_name: str,
    country: str = "PK",
    state: str = "Islamabad",
    locality: str = "Islamabad",
    organization: str = "FAST-NUCES",
    validity_days: int = 3650,
    output_dir: str = "certs"
):
    """
    Generate a self-signed root CA certificate.
    
    Args:
        common_name: Common Name (CN) for the CA
        country: Two-letter country code
        state: State or province
        locality: City
        organization: Organization name
        validity_days: Certificate validity period in days
        output_dir: Directory to save certificate and key
    """
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"[*] Generating RSA private key (2048 bits)...")
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    print(f"[*] Creating self-signed certificate for '{common_name}'...")
    # Create certificate subject and issuer (same for self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # Build the certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    
    # Save private key
    key_path = os.path.join(output_dir, "ca_key.pem")
    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    print(f"[+] CA private key saved to: {key_path}")
    
    # Save certificate
    cert_path = os.path.join(output_dir, "ca_cert.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[+] CA certificate saved to: {cert_path}")
    
    print(f"\n[✓] Root CA created successfully!")
    print(f"    Valid from: {cert.not_valid_before}")
    print(f"    Valid until: {cert.not_valid_after}")
    print(f"    Serial: {cert.serial_number}")
    
    return private_key, cert


def main():
    parser = argparse.ArgumentParser(
        description="Generate a self-signed Root Certificate Authority"
    )
    parser.add_argument(
        "--name",
        default="FAST-NU Root CA",
        help="Common Name (CN) for the CA certificate"
    )
    parser.add_argument(
        "--days",
        type=int,
        default=3650,
        help="Validity period in days (default: 3650 = 10 years)"
    )
    parser.add_argument(
        "--output",
        default="certs",
        help="Output directory for certificates (default: certs)"
    )
    
    args = parser.parse_args()
    
    generate_root_ca(
        common_name=args.name,
        validity_days=args.days,
        output_dir=args.output
    )


if __name__ == "__main__":
    main()
