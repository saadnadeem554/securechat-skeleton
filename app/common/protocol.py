"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt.""" 


# common/protocol.py

import json

class MessageType:
    HELLO = "hello"
    SERVER_HELLO = "server hello"
    REGISTER = "register"
    LOGIN = "login"
    SUCCESS = "success"
    FAILURE = "failure"
    BAD_CERT = "BAD CERT"

class BaseMessage:
    def to_dict(self):
        # A utility method to turn the object into a transmittable dictionary
        return self.__dict__

class HelloMessage(BaseMessage):
    """Format for client hello."""
    def __init__(self, cert: str, nonce: str, dh_pub: str):
        self.type = MessageType.HELLO
        self.cert = cert       # Base64 PEM certificate
        self.nonce = nonce     # Base64 nonce
        self.dh_pub = dh_pub   # Base64 DH public key

class ServerHelloMessage(BaseMessage):
    """Format for server hello."""
    def __init__(self, cert: str, nonce: str, dh_pub: str):
        self.type = MessageType.SERVER_HELLO
        self.cert = cert
        self.nonce = nonce
        self.dh_pub = dh_pub

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