# scripts/gen_cert.py

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
CERT_EXPIRY_DAYS = 365

def load_ca_data():
    """Loads the CA key and certificate."""
    try:
        with open(CA_KEY_FILE, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        with open(CA_CERT_FILE, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        return ca_key, ca_cert
    except FileNotFoundError:
        print(f"[ERROR] CA files not found. Ensure '{CA_KEY_FILE}' and '{CA_CERT_FILE}' exist.")
        print("Please run 'python scripts/gen_ca.py --name \"CA Name\"' first.")
        exit(1)

def generate_signed_cert(ca_key, ca_cert, common_name, output_base):
    """Generates an entity keypair and a CA-signed certificate."""
    
    entity_name = os.path.basename(output_base).capitalize()
    
    # 1. Generate RSA Private Key for the entity
    print(f"[*] Generating {entity_name} RSA Private Key (CN: {common_name})...")
    entity_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # 2. Create the Certificate Subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name), # Used for CN match check
    ])
    
    # 3. Issue the certificate, signed by the CA
    print(f"[*] Signing {entity_name} Certificate with Root CA...")
    entity_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject # Issuer is the Root CA
    ).public_key(
        entity_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=CERT_EXPIRY_DAYS)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False
    ).sign(ca_key, hashes.SHA256(), default_backend())

    # 4. Write keypair and certificate to disk
    key_file = output_base + "_key.pem"
    cert_file = output_base + "_cert.pem"

    with open(key_file, "wb") as f:
        f.write(entity_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open(cert_file, "wb") as f:
        f.write(entity_cert.public_bytes(serialization.Encoding.PEM))

    print(f"  -> Private Key written to: {key_file}")
    print(f"  -> Certificate written to: {cert_file}")
    print(f"[SUCCESS] {entity_name} Certificate Issued.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Issue an RSA X.509 certificate signed by the Root CA.")
    parser.add_argument("--cn", required=True, help="The Common Name (CN) for the certificate, used for hostname/identity match.")
    parser.add_argument("--out", required=True, help="Base path and filename for the output key/cert (e.g., certs/server).")
    args = parser.parse_args()
    
    ca_key, ca_cert = load_ca_data()
    generate_signed_cert(ca_key, ca_cert, args.cn, args.out)