"""Server skeleton — plain TCP; no TLS. See assignment spec."""

# --- Server-Side Authentication Logic ---

import socket
import json
import secrets
from common.utils import b64_decode, b64_encode
from crypto.pki import validate_certificate, load_root_ca, CertificateValidationError
from crypto.dh import generate_dh_keypair, serialize_public_key, derive_aes_key_from_exchange
from crypto.aes import AESCipher
from common.protocol import HelloMessage, ServerHelloMessage, AuthData, EncryptedMessage, MessageType
from app.storage.db1 import UserStorage

SERVER_CN = "server.local"
TRUSTED_CA = load_root_ca()
USER_DB = UserStorage()

def handle_control_plane(client_socket, server_cert_pem: bytes, server_priv_key):
    # 1. Receive Client Hello (assumed already received)
    client_hello_data = json.loads(client_socket.recv(4096).decode())
    
    # --- Phase 1: Mutual Certificate Validation ---
    try:
        # i, ii, iii. Validate client certificate (Chain, Expiry, CN)
        client_cert_pem = b64_decode(client_hello_data["client cert"])
        validate_certificate(client_cert_pem, "client.local", TRUSTED_CA) 
        
    except CertificateValidationError as e:
        print(f"Client certificate failed validation: {e}")
        client_socket.sendall(MessageType.BAD_CERT.encode())
        return

    # --- Phase 2: Temporary DH Exchange and Key Derivation ---
    server_dh_priv, server_dh_pub = generate_dh_keypair()
    server_dh_pub_pem_b64 = b64_encode(serialize_public_key(server_dh_pub))
    
    # Send Server Hello
    server_hello = ServerHelloMessage(
        cert=b64_encode(server_cert_pem), 
        nonce=b64_encode(secrets.token_bytes(16)), 
        dh_pub=server_dh_pub_pem_b64
    )
    client_socket.sendall(json.dumps(server_hello.to_dict()).encode())
    
    # Derive AES Key K
    client_dh_pub_pem = b64_decode(client_hello_data["dh_pub"])
    aes_key = derive_aes_key_from_exchange(server_dh_priv, client_dh_pub_pem)
    cipher = AESCipher(aes_key)

    # --- Phase 3: Handle Encrypted Credentials ---
    encrypted_msg = json.loads(client_socket.recv(4096).decode())
    
    # Decrypt payload
    ciphertext = b64_decode(encrypted_msg["payload"])
    try:
        decrypted_data = cipher.decrypt(ciphertext)
        auth_data_dict = json.loads(decrypted_data.decode())
    except Exception as e:
        print(f"Decryption failed or JSON malformed: {e}. Aborting.")
        client_socket.sendall(MessageType.FAILURE.encode())
        return

    auth_type = encrypted_msg["type"]
    username = auth_data_dict.get('username')
    password = auth_data_dict.get('password')
    email = auth_data_dict.get('email')

    if auth_type == MessageType.REGISTER:
        success = USER_DB.register_user(email, username, password)
    elif auth_type == MessageType.LOGIN:
        success = USER_DB.login_user(username, password)
    else:
        success = False

    # Send final authentication result
    response = MessageType.SUCCESS if success else MessageType.FAILURE
    client_socket.sendall(response.encode())
    
    if success:
        print(f"[SUCCESS] {username} authenticated. Proceeding to Session Key Agreement...")
        # Return success/key for next phase
    else:
        print(f"[FAILURE] Authentication failed for {username}.")