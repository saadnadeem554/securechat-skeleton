# scripts/gen_ca.py

import os
import argparse
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# --- Configuration ---
CERT_DIR = "certs"
CA_KEY_FILE = os.path.join(CERT_DIR, "root_ca_key.pem")
CA_CERT_FILE = os.path.join(CERT_DIR, "root_ca_cert.pem")
CA_EXPIRY_DAYS = 3650 # 10 years

def create_ca(ca_name):
    """Generates the Root CA keypair and a self-signed certificate."""
    print(f"[*] Ensuring directory {CERT_DIR} exists...")
    os.makedirs(CERT_DIR, exist_ok=True)

    # 1. Generate RSA Private Key for the CA
    print("[*] Generating Root CA RSA Private Key...")
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # 2. Build the self-signed X.509 Certificate
    print(f"[*] Building self-signed Root CA Certificate with CN: {ca_name}...")
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST-NUCES IS Dept"),
        x509.NameAttribute(NameOID.COMMON_NAME, ca_name),
    ])

    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=CA_EXPIRY_DAYS)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).sign(ca_key, hashes.SHA256(), default_backend())

    # 3. Write key and certificate to disk
    print(f"[*] Writing CA Private Key to {CA_KEY_FILE}...")
    with open(CA_KEY_FILE, "wb") as f:
        f.write(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    print(f"[*] Writing CA Certificate to {CA_CERT_FILE}...")
    with open(CA_CERT_FILE, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    print("\n[SUCCESS] Root CA Setup Complete.")
    print(f"CA Certificate: {CA_CERT_FILE}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create the Root Certificate Authority key and self-signed certificate.")
    parser.add_argument("--name", required=True, help="The Common Name (CN) for the Root CA certificate.")
    args = parser.parse_args()
    create_ca(args.name)