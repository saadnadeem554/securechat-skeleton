# app/crypto/dh.py

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from common.utils import sha256
import os

CERT_DIR = "certs"
DH_PARAMS_FILE = os.path.join(CERT_DIR, "dh_params.pem")

# --- Load Parameters (CRITICAL: Ensures client and server use the same p and g) ---
def load_dh_parameters():
    """Loads the pre-generated DH parameters from the file."""
    try:
        with open(DH_PARAMS_FILE, "rb") as f:
            # Use load_pem_parameters to deserialize the PEM file
            return serialization.load_pem_parameters(f.read(), backend=default_backend())
    except FileNotFoundError:
        print(f"[ERROR] DH parameters not found at {DH_PARAMS_FILE}.")
        print("Please run 'python scripts/gen_dh_params.py' once before starting the server/client.")
        exit(1)

# Load parameters globally on import
DH_PARAMETERS = load_dh_parameters() 

# --- Core DH Functions ---
def get_dh_params_object() -> dh.DHParameters:
    """Retrieves the globally loaded DHParameters object."""
    return DH_PARAMETERS

def get_dh_params() -> tuple[int, int]:
    """Extracts p and g as integers from the global parameters."""
    p = DH_PARAMETERS.parameter_numbers().p
    g = DH_PARAMETERS.parameter_numbers().g
    return p, g

def generate_dh_keypair_from_params(parameters: dh.DHParameters):
    """Generates a Diffie-Hellman private and public key using the provided parameters object."""
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_secret_int(private_key, peer_public_int: int, parameters: dh.DHParameters) -> bytes:
    """
    Computes the shared secret (Ks) using a local private key and a peer's 
    public key provided as an integer (A or B), using the provided parameters object.
    """
    # 1. Reconstruct the peer's public key numbers object
    peer_public_numbers = dh.DHPublicNumbers(
        peer_public_int,
        parameters.parameter_numbers()
    )
    
    # 2. FIX: Convert numbers to public key object using .public_key() method
    peer_public_key = peer_public_numbers.public_key(default_backend())
    
    # 3. Compute the shared secret Ks
    return private_key.exchange(peer_public_key)

def kdf_derive_aes_key(shared_secret: bytes) -> bytes:
    """
    Derives the 16-byte AES-128 key K from the DH shared secret Ks.
    K = Trunc16(SHA256(big-endian(Ks)))
    """
    full_hash = sha256(shared_secret) # 32 bytes
    aes_key = full_hash[:16]
    
    return aes_key