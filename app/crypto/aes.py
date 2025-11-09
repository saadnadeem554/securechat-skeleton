
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

KEY_SIZE = 16 # AES-128 (16 bytes)

class AESCipher:
    def __init__(self, key: bytes):
        if len(key) != KEY_SIZE:
            raise ValueError(f"AES key must be {KEY_SIZE} bytes.")
        self.key = key
        # Using ECB as per assignment's 'no modes' constraint.
        self.cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=default_backend())

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypts data using AES-128-ECB with PKCS#7 padding."""
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        encryptor = self.cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypts data using AES-128-ECB and removes PKCS#7 padding."""
        decryptor = self.cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        return plaintext
