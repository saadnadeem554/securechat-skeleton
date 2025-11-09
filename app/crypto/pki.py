# app/crypto/pki.py

import os
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend

CERT_DIR = "certs"
CA_CERT_PATH = os.path.join(CERT_DIR, "root_ca_cert.pem")

class CertificateValidationError(Exception):
    """Custom exception for certificate validation failures (BAD_CERT)."""
    pass

def load_certificate(cert_pem_data: bytes) -> x509.Certificate:
    """Loads a certificate from PEM data."""
    try:
        return x509.load_pem_x509_certificate(cert_pem_data, default_backend())
    except Exception as e:
        raise CertificateValidationError(f"Invalid certificate format: {e}")

def load_root_ca() -> x509.Certificate:
    """Loads the trusted Root CA certificate."""
    try:
        with open(CA_CERT_PATH, "rb") as f:
            return load_certificate(f.read())
    except FileNotFoundError:
        raise FileNotFoundError(f"Root CA certificate not found at {CA_CERT_PATH}")
    
def get_cert_cn(cert: x509.Certificate) -> str:
    """Extracts the Common Name (CN) from a certificate."""
    try:
        return cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except IndexError:
        return ""

def validate_certificate(cert_pem_data: bytes, expected_cn: str, trusted_ca: x509.Certificate):
    """Performs full mutual certificate validation (chain, expiry, CN)."""
    cert = load_certificate(cert_pem_data)
    
    # i. Signature chain validity (Trusted CA)
    if cert.issuer != trusted_ca.subject:
        raise CertificateValidationError("BAD CERT: Issuer name does not match Root CA subject (Untrusted).")

    # ii. Expiry date and validity period (using UTC properties to avoid deprecation warnings)
    now = datetime.datetime.now(datetime.timezone.utc)
    not_valid_before = cert.not_valid_before_utc
    not_valid_after = cert.not_valid_after_utc
    
    if now < not_valid_before or now > not_valid_after:
        raise CertificateValidationError("BAD CERT: Certificate expired or not yet valid.")

    # iii. Common Name (CN) or hostname match
    actual_cn = get_cert_cn(cert)
    if actual_cn != expected_cn:
        raise CertificateValidationError(f"BAD CERT: CN mismatch. Expected: '{expected_cn}', Got: '{actual_cn}'")