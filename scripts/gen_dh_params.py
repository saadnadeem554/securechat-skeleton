# scripts/gen_dh_params.py

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os

CERT_DIR = "certs"
DH_PARAMS_FILE = os.path.join(CERT_DIR, "dh_params.pem")

def generate_and_save_dh_parameters(key_size: int = 1024):
    """Generates 1024-bit DH parameters and saves them to a PEM file."""
    
    if not os.path.exists(CERT_DIR):
        os.makedirs(CERT_DIR)

    if os.path.exists(DH_PARAMS_FILE):
        print(f"[*] DH parameters already exist at {DH_PARAMS_FILE}. Skipping generation.")
        return

    print(f"[*] Generating {key_size}-bit DH parameters (this may take a moment)...")
    
    # Generate the parameters using a known-good key size (1024-bit)
    parameters = dh.generate_parameters(
        generator=2, 
        key_size=key_size, 
        backend=default_backend()
    )

    # Serialize parameters to the PEM format recognized by the library
    pem = parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3
    )
    
    with open(DH_PARAMS_FILE, "wb") as f:
        f.write(pem)
        
    print(f"[SUCCESS] DH parameters saved to: {DH_PARAMS_FILE}")
    print("Run this file BEFORE running client/server.")

if __name__ == '__main__':
    generate_and_save_dh_parameters()