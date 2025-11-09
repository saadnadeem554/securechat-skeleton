# app/common/protocol.py

import json
from typing import Optional

class MessageType:
    HELLO = "hello"
    SERVER_HELLO = "server hello"
    DH_CLIENT = "dh client"
    DH_SERVER = "dh server"
    REGISTER = "register"
    LOGIN = "login"
    SUCCESS = "success"
    FAILURE = "failure"
    BAD_CERT = "BAD CERT"

class BaseMessage:
    def to_dict(self):
        # Filter out None values to keep the message clean
        return {k: v for k, v in self.__dict__.items() if v is not None}

class HelloMessage(BaseMessage):
    """Format for client hello (Certificate Exchange)."""
    def __init__(self, cert: str, nonce: str):
        self.type = MessageType.HELLO
        self.cert = cert       # Base64 PEM certificate
        self.nonce = nonce     # Base64 nonce

class ServerHelloMessage(BaseMessage):
    """Format for server hello (Certificate Exchange)."""
    def __init__(self, cert: str, nonce: str):
        self.type = MessageType.SERVER_HELLO
        self.cert = cert
        self.nonce = nonce

class KeyAgreementMessage(BaseMessage):
    """Format for the integer-based DH Key Agreement."""
    def __init__(self, type: str, g: int, p: int, A: Optional[int] = None, B: Optional[int] = None):
        self.type = type
        self.g = g  # Generator
        self.p = p  # Prime Modulus
        self.A = A
        self.B = B

class AuthData(BaseMessage):
    """The plaintext data for registration/login (Encrypted inside the payload)."""
    def __init__(self, email: str, username: str, password: str):
        self.email = email
        self.username = username
        self.password = password

    def to_json_bytes(self) -> bytes:
        return json.dumps(self.to_dict()).encode('utf-8')

class EncryptedMessage(BaseMessage):
    """The final transmitted message for registration/login."""
    def __init__(self, type: str, encrypted_payload: str):
        self.type = type
        self.payload = encrypted_payload # Base64 encoded ciphertext