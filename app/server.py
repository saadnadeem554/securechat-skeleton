# app/server.py

import socket
import os
import json
import secrets
from common.utils import b64_decode, b64_encode
from crypto.pki import validate_certificate, load_root_ca, CertificateValidationError
from crypto.dh import generate_dh_keypair_from_params, derive_shared_secret_int, kdf_derive_aes_key, get_dh_params_object, load_dh_parameters # UPDATED IMPORTS
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from crypto.aes import AESCipher
from common.protocol import HelloMessage, ServerHelloMessage, AuthData, EncryptedMessage, MessageType, KeyAgreementMessage
from storage.db import UserStorage

HOST = '127.0.0.1'
PORT = 8080
CERT_DIR = "certs"
TRUSTED_CA = load_root_ca()

# Load parameters globally on server start, ensuring it halts if file is missing.
DH_PARAMETERS = load_dh_parameters() 
USER_DB = UserStorage()


def perform_key_exchange(conn) -> bytes | None:
    """Handles the DH Key Exchange: loads (p, g), receives A, generates B, computes K."""
    print("[SERVER] 4. --- Starting DH Key Exchange (Receiving Params) ---")
    
    # 1. Server waits for DH Client message (g, p, A)
    raw_client_dh = conn.recv(4096).decode()
    if not raw_client_dh: return None
        
    client_dh_data = json.loads(raw_client_dh)
    
    if client_dh_data.get('type') != MessageType.DH_CLIENT:
        print("[SERVER] ❌ Expected DH CLIENT, received unexpected message.")
        return None

    # Extract p, g, and A from the client message
    p = client_dh_data.get('p')
    g = client_dh_data.get('g')
    client_public_key_A = client_dh_data.get('A')
    
    # Get the globally loaded and validated parameters object
    server_dh_params = get_dh_params_object()
    
    # 2. Server generates its ephemeral DH keypair based on the global parameters
    server_dh_priv, server_dh_pub = generate_dh_keypair_from_params(server_dh_params)
    
    # 3. Server computes its public key B = g^b mod p
    server_public_key_B = server_dh_pub.public_numbers().y
    
    # 4. Server sends DH Server message (B)
    server_dh_msg = KeyAgreementMessage(
        type=MessageType.DH_SERVER, 
        g=p, p=g, B=server_public_key_B
    )
    conn.sendall(json.dumps(server_dh_msg.to_dict()).encode())
    print("[SERVER] 5. Sent DH SERVER message (B).")

    # 5. Derive the final key K
    shared_secret = derive_shared_secret_int(server_dh_priv, client_public_key_A, server_dh_params)
    K = kdf_derive_aes_key(shared_secret)
    
    print("[SERVER] 6. Derived shared key **K** (for credential protection).")
    return K


def handle_control_plane(client_socket, server_cert_pem: bytes):
    """Handles mutual authentication, DH key exchange, and credential validation."""
    
    print(f"\n[SERVER] --- Starting Control Plane with {client_socket.getpeername()} ---")

    # 1. Receive Client Hello (Certificate Exchange)
    client_hello_data = json.loads(client_socket.recv(4096).decode())
    print("[SERVER] 1. Received HELLO from Client.")
    
    # --- Phase 1: Mutual Certificate Validation ---
    try:
        client_cert_pem = b64_decode(client_hello_data["cert"])
        print("[SERVER] 2. Validating Client Certificate...")
        validate_certificate(client_cert_pem, "client.local", TRUSTED_CA) 
        print("[SERVER] ✅ Client Certificate is VALID and TRUSTED.")
        
    except CertificateValidationError:
        client_socket.sendall(MessageType.BAD_CERT.encode())
        return False
    
    # Send Server Hello after validation
    server_hello = ServerHelloMessage(
        cert=b64_encode(server_cert_pem), 
        nonce=b64_encode(secrets.token_bytes(16))
    )
    client_socket.sendall(json.dumps(server_hello.to_dict()).encode())
    print("[SERVER] 3. Sent SERVER HELLO.")


    # --- Phase 2: DH Key Exchange for K (Credential Protection) ---
    K = perform_key_exchange(client_socket)
    if not K:
        return False

    cipher = AESCipher(K)

    # --- Phase 3: Handle Encrypted Credentials ---
    encrypted_msg = json.loads(client_socket.recv(4096).decode())
    auth_type = encrypted_msg["type"]
    print(f"[SERVER] 7. Received ENCRYPTED {auth_type.upper()} message.")
    
    # Decrypt payload using K
    ciphertext = b64_decode(encrypted_msg["payload"])
    try:
        decrypted_data = cipher.decrypt(ciphertext)
        auth_data_dict = json.loads(decrypted_data.decode())
        username = auth_data_dict.get('username')
        password = auth_data_dict.get('password')
        email = auth_data_dict.get('email')
        print(f"[SERVER] 8. Successfully Decrypted payload for user: {username}.")
    except Exception:
        client_socket.sendall(MessageType.FAILURE.encode())
        return False

    # Phase 4: Database Verification/Registration
    success = False
    if auth_type == MessageType.REGISTER:
        success = USER_DB.register_user(email, username, password)
        print(f"[SERVER] 9. Registration attempt result: {'SUCCESS' if success else 'FAILURE (User Exists)'}")
    elif auth_type == MessageType.LOGIN:
        success = USER_DB.login_user(username, password)
        print(f"[SERVER] 9. Login attempt result: {'SUCCESS' if success else 'FAILURE (Invalid Credentials)'}")

    # Send final authentication result
    response = MessageType.SUCCESS if success else MessageType.FAILURE
    client_socket.sendall(response.encode())
    
    if success:
        print(f"[SERVER] ✅ Authentication Complete. Sent {MessageType.SUCCESS}.")
        return K # Return the key K
    else:
        print(f"[SERVER] ❌ Authentication Failed. Sent {MessageType.FAILURE}.")
        return False


def load_server_assets():
    """Loads the server's certificate and private key."""
    try:
        with open(os.path.join(CERT_DIR, "server_cert.pem"), "rb") as f:
            server_cert_pem = f.read()
        return server_cert_pem
    except FileNotFoundError as e:
        print(f"[SERVER] ❌ Error loading assets: {e}")
        exit(1)

def main():
    server_cert_pem = load_server_assets()
    if not USER_DB.conn: return
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((HOST, PORT))
            s.listen(5)
            print(f"[SERVER] 🟢 Listening on {HOST}:{PORT}")
            
            while True:
                conn, addr = s.accept()
                
                auth_result = handle_control_plane(conn, server_cert_pem)
                
                if auth_result:
                    print(f"[SERVER] Client {addr} authenticated. Credentials validated.")
                
                conn.close()
                    
        except KeyboardInterrupt:
            print("\n[SERVER] Server shutting down...")
        finally:
            USER_DB.close()
            s.close()

if __name__ == '__main__':
    main()