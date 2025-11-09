"""Client skeleton — plain TCP; no TLS. See assignment spec."""

# --- Client-Side Authentication Logic ---

import json
import secrets
from common.utils import b64_decode, b64_encode
from crypto.pki import validate_certificate, load_root_ca, CertificateValidationError
from crypto.dh import generate_dh_keypair, serialize_public_key, derive_aes_key_from_exchange
from crypto.aes import AESCipher
from common.protocol import HelloMessage, ServerHelloMessage, AuthData, EncryptedMessage, MessageType

CLIENT_CN = "client.local"
TRUSTED_CA = load_root_ca()

def perform_authentication(server_socket, client_cert_pem: bytes, username, password, email=None, is_register=False):
    # --- Phase 1: Client Hello and DH Key Generation ---
    client_dh_priv, client_dh_pub = generate_dh_keypair()
    client_dh_pub_pem_b64 = b64_encode(serialize_public_key(client_dh_pub))
    
    # Send Client Hello
    hello_msg = HelloMessage(
        cert=b64_encode(client_cert_pem), 
        nonce=b64_encode(secrets.token_bytes(16)),
        dh_pub=client_dh_pub_pem_b64
    )
    server_socket.sendall(json.dumps(hello_msg.to_dict()).encode())
    
    # Receive Server Hello
    raw_server_hello = server_socket.recv(4096)
    if raw_server_hello == MessageType.BAD_CERT.encode():
        print("[ERROR] Server rejected our certificate.")
        return False
        
    server_hello_data = json.loads(raw_server_hello.decode())
    
    # --- Phase 2: Server Certificate Validation and Key Derivation ---
    server_cert_pem = b64_decode(server_hello_data["server cert"])
    try:
        # i, ii, iii. Validate server certificate (Chain, Expiry, CN)
        validate_certificate(server_cert_pem, "server.local", TRUSTED_CA)
    except CertificateValidationError as e:
        print(f"Server certificate validation failed: {e}. Aborting.")
        return False

    # Derive AES Key K
    server_dh_pub_pem = b64_decode(server_hello_data["dh_pub"])
    aes_key = derive_aes_key_from_exchange(client_dh_priv, server_dh_pub_pem)
    cipher = AESCipher(aes_key)
    
    # --- Phase 3: Encrypt and Send Credentials ---
    auth_data = AuthData(
        email=email if email else "", 
        username=username, 
        password=password
    )
    
    plaintext_payload = auth_data.to_json_bytes()
    ciphertext = cipher.encrypt(plaintext_payload) # Encryption prevents plaintext credential transit
    
    msg_type = MessageType.REGISTER if is_register else MessageType.LOGIN
    encrypted_msg = EncryptedMessage(
        type=msg_type, 
        encrypted_payload=b64_encode(ciphertext)
    )
    
    server_socket.sendall(json.dumps(encrypted_msg.to_dict()).encode())
    
    # --- Phase 4: Receive Auth Confirmation ---
    response = server_socket.recv(1024).decode()
    if response == MessageType.SUCCESS:
        print("[SUCCESS] Login/Registration successful.")
        return True # Proceed to next Key Agreement phase
    else:
        print("[FAILURE] Invalid credentials or registration conflict.")
        return False