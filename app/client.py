# app/client.py

import socket
import os
import argparse
import json
import secrets
from common.utils import b64_decode, b64_encode
from crypto.pki import validate_certificate, load_root_ca, CertificateValidationError
from crypto.dh import get_dh_params, generate_dh_keypair_from_params, derive_shared_secret_int, kdf_derive_aes_key, get_dh_params_object # UPDATED IMPORTS
from crypto.aes import AESCipher
from common.protocol import HelloMessage, ServerHelloMessage, AuthData, EncryptedMessage, MessageType, KeyAgreementMessage

HOST = '127.0.0.1'
PORT = 8080
CERT_DIR = "certs"
TRUSTED_CA = load_root_ca()


def perform_key_exchange(s: socket.socket) -> bytes | None:
    """Handles the DH Key Exchange: loads (p, g), sends A, receives B, computes K."""
    print("[CLIENT] 3. --- Starting DH Key Exchange (Loading Fixed Params) ---")

    # 1. Load the single, globally-validated parameters object
    parameters = get_dh_params_object()
    p, g = get_dh_params()
    
    # 2. Client generates its ephemeral DH keypair using the loaded parameters
    client_dh_priv, client_dh_pub = generate_dh_keypair_from_params(parameters)
    
    # 3. Client computes its public key A = g^a mod p
    client_public_key_A = client_dh_pub.public_numbers().y
    
    # 4. Client sends DH Client message (g, p, A)
    client_dh_msg = KeyAgreementMessage(
        type=MessageType.DH_CLIENT,
        g=g, p=p, A=client_public_key_A
    )
    s.sendall(json.dumps(client_dh_msg.to_dict()).encode())
    print("[CLIENT] 4. Sent DH CLIENT message (g, p, A).")

    # 5. Client waits for DH Server message (B)
    raw_server_dh = s.recv(4096).decode()
    if not raw_server_dh: return None
        
    server_dh_data = json.loads(raw_server_dh)
    
    if server_dh_data.get('type') != MessageType.DH_SERVER:
        print("[CLIENT] ❌ Expected DH SERVER, received unexpected message.")
        return None
        
    server_public_key_B = server_dh_data.get('B')
    print("[CLIENT] 5. Received DH SERVER message (B).")

    # 6. Derive the final key K
    shared_secret = derive_shared_secret_int(client_dh_priv, server_public_key_B, parameters)
    K = kdf_derive_aes_key(shared_secret)
    
    print("[CLIENT] 6. Derived shared key **K**.")
    return K


def perform_authentication(server_socket, client_cert_pem: bytes, username, password, email=None, is_register=False):
    """Performs the full authentication flow against the server."""
    
    auth_type_str = "REGISTER" if is_register else "LOGIN"
    print(f"\n[CLIENT] --- Starting Control Plane for {auth_type_str} ({username}) ---")

    # --- Phase 1: Client Hello and Server Certificate Validation ---
    hello_msg = HelloMessage(
        cert=b64_encode(client_cert_pem), 
        nonce=b64_encode(secrets.token_bytes(16))
    )
    server_socket.sendall(json.dumps(hello_msg.to_dict()).encode())
    print("[CLIENT] 1. Sending HELLO (Certificate).")
    
    raw_server_hello = server_socket.recv(4096)
    if raw_server_hello == MessageType.BAD_CERT.encode():
        print("[CLIENT] ❌ Server rejected our certificate. Aborting.")
        return False
        
    server_hello_data = json.loads(raw_server_hello.decode())
    print("[CLIENT] 2. Received SERVER HELLO from Server.")
    
    # Server Certificate Validation
    server_cert_pem = b64_decode(server_hello_data["cert"])
    try:
        validate_certificate(server_cert_pem, "server.local", TRUSTED_CA)
        print("[CLIENT] ✅ Server Certificate is VALID and TRUSTED.")
    except CertificateValidationError as e:
        print(f"[CLIENT] ❌ Server Certificate validation failed: {e}. Aborting.")
        return False

    # --- Phase 2: DH Key Exchange for K ---
    K = perform_key_exchange(server_socket)
    if not K:
        return False
        
    cipher = AESCipher(K)
    
    # --- Phase 3: Encrypt and Send Credentials ---
    auth_data = AuthData(
        email=email if email else "", 
        username=username, 
        password=password
    )
    
    plaintext_payload = auth_data.to_json_bytes()
    ciphertext = cipher.encrypt(plaintext_payload)
    
    msg_type = MessageType.REGISTER if is_register else MessageType.LOGIN
    encrypted_msg = EncryptedMessage(
        type=msg_type, 
        encrypted_payload=b64_encode(ciphertext)
    )
    
    server_socket.sendall(json.dumps(encrypted_msg.to_dict()).encode())
    print(f"[CLIENT] 7. Sending ENCRYPTED {msg_type.upper()} payload to Server.")
    
    # Phase 4: Receive Auth Confirmation
    response = server_socket.recv(1024).decode()
    
    if response == MessageType.SUCCESS:
        print(f"[CLIENT] 8. Received {MessageType.SUCCESS}. Authentication is complete!")
        return K # Return the key K
    else:
        print(f"[CLIENT] 8. ❌ Received {MessageType.FAILURE}. Invalid credentials/registration conflict.")
        return False


def load_client_assets():
    """Loads the client's certificate."""
    try:
        with open(os.path.join(CERT_DIR, "client_cert.pem"), "rb") as f:
            client_cert_pem = f.read()
        return client_cert_pem
    except FileNotFoundError as e:
        print(f"[CLIENT] ❌ Error loading assets: {e}")
        exit(1)

def main():
    parser = argparse.ArgumentParser(description="Secure Chat Client.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--register', action='store_true', help='Perform user registration.')
    group.add_argument('--login', action='store_true', help='Perform user login.')
    parser.add_argument('--username', required=True, help='The username.')
    parser.add_argument('--password', required=True, help='The user password.')
    parser.add_argument('--email', required='--register' in os.sys.argv, help='The user email (required for registration).')
    args = parser.parse_args()

    client_cert_pem = load_client_assets()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            print(f"[CLIENT] 🔗 Attempting to connect to {HOST}:{PORT}...")
            s.connect((HOST, PORT))
            print("[CLIENT] 🤝 Connected to Server.")

            is_register = args.register
            session_key_or_failure = perform_authentication(
                s, client_cert_pem, args.username, args.password, args.email, is_register
            )

            if session_key_or_failure and isinstance(session_key_or_failure, bytes):
                print("[CLIENT] Authentication finished. Key K established.")
            else:
                print("[CLIENT] Authentication failed. Closing connection.")

        except ConnectionRefusedError:
            print(f"[CLIENT] ❌ Connection refused. Is the server running on {HOST}:{PORT}?")
        finally:
            s.close()

if __name__ == '__main__':
    main()