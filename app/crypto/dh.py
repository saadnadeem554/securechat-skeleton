"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation.""" 


from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from common.utils import sha256

# Standard 2048-bit DH parameters for the exchange
DH_PARAMETERS = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

def generate_dh_keypair():
    """Generates a Diffie-Hellman private and public key."""
    private_key = DH_PARAMETERS.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_secret(private_key: dh.DHPrivateNumbers, peer_public_key: dh.DHPublicNumbers) -> bytes:
    """Computes the DH shared secret (Ks)."""
    return private_key.exchange(peer_public_key)

def kdf_derive_aes_key(shared_secret: bytes) -> bytes:
    """
    Derives the 16-byte AES-128 key K from the DH shared secret Ks.
    K = Trunc16(SHA256(big-endian(Ks)))
    """
    ks_bytes = shared_secret
    
    # 1. Compute SHA256(Ks)
    full_hash = sha256(ks_bytes) # 32 bytes
    
    # 2. Truncate to 16 bytes for AES-128 key
    aes_key = full_hash[:16]
    
    return aes_key

def serialize_public_key(public_key) -> bytes:
    """Serializes a DH public key for transmission."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pem_data: bytes):
    """Deserializes a DH public key received from the peer."""
    return serialization.load_pem_public_key(pem_data, backend=default_backend())

def derive_aes_key_from_exchange(private_key, peer_public_pem: bytes) -> bytes:
    """Helper to handle the full KDF process from a received PEM public key."""
    peer_public_key = deserialize_public_key(peer_public_pem)
    shared_secret = derive_shared_secret(private_key, peer_public_key)
    return kdf_derive_aes_key(shared_secret)
