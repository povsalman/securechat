#!/usr/bin/env python3
"""
SecureChat Server

Implements the server-side protocol:
1. Certificate exchange and validation
2. Temporary DH for authentication
3. Registration/Login handling
4. Session DH for chat encryption
5. Encrypted message handling with signature verification
6. Non-repudiation evidence generation
"""

import os
import socket
import json
import sys
import uuid
from dotenv import load_dotenv

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.crypto import (
    encrypt, decrypt, generate_params, generate_keypair,
    compute_shared_secret, derive_aes_key, validate_certificate,
    load_certificate, get_certificate_fingerprint, sign_data, verify_signature
)
from app.crypto.sign import load_private_key, verify_message_signature
from app.common.protocol import *
from app.common.utils import now_ms, generate_nonce, b64encode, b64decode
from app.common.exceptions import *
from app.storage import init_db, register_user, verify_login
from app.storage.transcript import TranscriptManager

# Load environment
load_dotenv()

class SecureChatServer:
    def __init__(self):
        self.host = os.getenv('SERVER_HOST', '127.0.0.1')
        self.port = int(os.getenv('SERVER_PORT', 5000))
        self.ca_cert = load_certificate(os.getenv('CA_CERT_PATH', 'certs/ca_cert.pem'))
        self.server_cert = load_certificate(os.getenv('SERVER_CERT_PATH', 'certs/server_cert.pem'))
        self.server_key = load_private_key(os.getenv('SERVER_KEY_PATH', 'certs/server_key.pem'))
        
        print(f"[*] SecureChat Server initialized")
        print(f"    Listening on: {self.host}:{self.port}")
        print(f"    Server CN: {self.server_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value}")
    
    def start(self):
        """Start the server and listen for connections."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        print(f"\n[✓] Server listening on {self.host}:{self.port}")
        print("[*] Waiting for clients...\n")
        
        try:
            while True:
                client_socket, address = server_socket.accept()
                print(f"[+] New connection from {address}")
                
                try:
                    self.handle_client(client_socket)
                except Exception as e:
                    print(f"[!] Error handling client: {e}")
                    import traceback
                    traceback.print_exc()
                finally:
                    client_socket.close()
                    print(f"[-] Client {address} disconnected\n")
        
        except KeyboardInterrupt:
            print("\n[*] Server shutting down...")
        finally:
            server_socket.close()
    
    def handle_client(self, client_socket):
        """Handle a single client connection."""
        session_id = str(uuid.uuid4())[:8]
        print(f"[*] Session ID: {session_id}")
        
        # Phase 1: Certificate Exchange
        client_cert, client_nonce = self.phase1_cert_exchange(client_socket)
        
        # Phase 2: Temporary DH for Authentication
        temp_key = self.phase2_temp_dh(client_socket)
        
        # Phase 3: Authentication (Register/Login)
        username = self.phase3_authentication(client_socket, temp_key)
        
        # Phase 4: Session DH for Chat
        session_key = self.phase4_session_dh(client_socket)
        
        # Phase 5: Encrypted Chat
        transcript = TranscriptManager(f"{session_id}_{username}", "transcripts")
        self.phase5_chat(client_socket, session_key, client_cert, transcript)
        
        # Phase 6: Non-Repudiation
        self.phase6_non_repudiation(client_socket, transcript)
    
    def phase1_cert_exchange(self, sock):
        """Phase 1: Exchange and validate certificates."""
        print("\n[Phase 1] Certificate Exchange")
        
        # Receive client hello
        data = sock.recv(8192).decode('utf-8')
        hello = HelloMessage(**json.loads(data))
        print(f"  [<] Received client hello with nonce: {hello.nonce[:16]}...")
        
        # Parse and validate client certificate
        from cryptography import x509
        client_cert = x509.load_pem_x509_certificate(hello.client_cert.encode('utf-8'))
        
        is_valid, msg = validate_certificate(client_cert, self.ca_cert)
        if not is_valid:
            error = ErrorMessage(code="BAD_CERT", message=msg)
            sock.send(error.model_dump_json().encode('utf-8'))
            raise CertificateError(msg)
        
        print(f"  [✓] Client certificate validated")
        print(f"      CN: {client_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value}")
        
        # Send server hello
        server_hello = ServerHelloMessage(
            server_cert=self.server_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
            nonce=b64encode(generate_nonce(16))
        )
        sock.send(server_hello.model_dump_json().encode('utf-8'))
        print(f"  [>] Sent server hello")
        
        return client_cert, b64decode(hello.nonce)
    
    def phase2_temp_dh(self, sock):
        """Phase 2: Temporary DH for authentication encryption."""
        print("\n[Phase 2] Temporary DH Key Exchange")
        
        # Receive client DH
        data = sock.recv(8192).decode('utf-8')
        dh_client = DHClientMessage(**json.loads(data))
        print(f"  [<] Received client DH (A: {str(dh_client.A)[:32]}...)")
        
        # Generate server DH keypair
        b, B = generate_keypair(dh_client.p, dh_client.g)
        
        # Send server DH
        dh_server = DHServerMessage(B=B)
        sock.send(dh_server.model_dump_json().encode('utf-8'))
        print(f"  [>] Sent server DH (B: {str(B)[:32]}...)")
        
        # Compute shared secret and derive key
        K_s = compute_shared_secret(b, dh_client.A, dh_client.p)
        temp_key = derive_aes_key(K_s)
        print(f"  [✓] Temporary key established: {temp_key.hex()[:32]}...")
        
        return temp_key
    
    def phase3_authentication(self, sock, temp_key):
        """Phase 3: Handle registration or login."""
        print("\n[Phase 3] Authentication")
        
        # Receive encrypted auth message
        data = sock.recv(8192).decode('utf-8')
        auth_msg_dict = json.loads(data)
        
        # Decrypt the message
        encrypted_payload = auth_msg_dict['encrypted_payload']
        decrypted_json = decrypt(encrypted_payload, temp_key)
        auth_data = json.loads(decrypted_json)
        
        if auth_data['type'] == 'register':
            return self.handle_registration(sock, auth_data, temp_key)
        elif auth_data['type'] == 'login':
            return self.handle_login(sock, auth_data, temp_key)
        else:
            raise ProtocolError(f"Unknown auth type: {auth_data['type']}")
    
    def handle_registration(self, sock, reg_data, temp_key):
        """Handle user registration."""
        print(f"  [*] Registration request for: {reg_data['username']}")
        
        try:
            # Extract password from salted hash
            # In real implementation, client should send plaintext password over encrypted channel
            # For this assignment, we'll accept the password field as-is
            register_user(
                reg_data['email'],
                reg_data['username'],
                reg_data['pwd']  # This should be plaintext password
            )
            
            response = AuthResponseMessage(
                success=True,
                message="Registration successful",
                username=reg_data['username']
            )
            print(f"  [✓] User '{reg_data['username']}' registered")
        
        except DatabaseError as e:
            response = AuthResponseMessage(
                success=False,
                message=str(e)
            )
            print(f"  [✗] Registration failed: {e}")
        
        # Send encrypted response
        encrypted_response = encrypt(response.model_dump_json(), temp_key)
        sock.send(json.dumps({"encrypted_response": encrypted_response}).encode('utf-8'))
        
        return reg_data['username'] if response.success else None
    
    def handle_login(self, sock, login_data, temp_key):
        """Handle user login."""
        print(f"  [*] Login request for: {login_data['email']}")
        
        try:
            success, username = verify_login(login_data['email'], login_data['pwd'])
            
            if success:
                response = AuthResponseMessage(
                    success=True,
                    message="Login successful",
                    username=username
                )
                print(f"  [✓] User '{username}' logged in")
            else:
                response = AuthResponseMessage(
                    success=False,
                    message="Invalid credentials"
                )
                print(f"  [✗] Login failed for {login_data['email']}")
        
        except DatabaseError as e:
            response = AuthResponseMessage(
                success=False,
                message=str(e)
            )
            print(f"  [✗] Login error: {e}")
        
        # Send encrypted response
        encrypted_response = encrypt(response.model_dump_json(), temp_key)
        sock.send(json.dumps({"encrypted_response": encrypted_response}).encode('utf-8'))
        
        return username if response.success else None
    
    def phase4_session_dh(self, sock):
        """Phase 4: Session DH for chat encryption."""
        print("\n[Phase 4] Session DH Key Exchange")
        
        # Receive client session DH
        data = sock.recv(8192).decode('utf-8')
        dh_session = DHSessionClientMessage(**json.loads(data))
        print(f"  [<] Received session DH")
        
        # Generate server session DH keypair
        b, B = generate_keypair(dh_session.p, dh_session.g)
        
        # Send server session DH
        dh_server = DHSessionServerMessage(B=B)
        sock.send(dh_server.model_dump_json().encode('utf-8'))
        print(f"  [>] Sent session DH")
        
        # Compute shared secret and derive session key
        K_s = compute_shared_secret(b, dh_session.A, dh_session.p)
        session_key = derive_aes_key(K_s)
        print(f"  [✓] Session key established: {session_key.hex()[:32]}...")
        
        return session_key
    
    def phase5_chat(self, sock, session_key, client_cert, transcript):
        """Phase 5: Handle encrypted chat messages."""
        print("\n[Phase 5] Encrypted Chat Session")
        print("  [*] Ready to receive messages (type 'exit' to end)\n")
        
        expected_seqno = 1
        client_public_key = client_cert.public_key()
        client_fingerprint = get_certificate_fingerprint(client_cert)
        
        while True:
            try:
                # Receive encrypted message
                data = sock.recv(16384).decode('utf-8')
                if not data:
                    break
                
                msg_dict = json.loads(data)
                
                if msg_dict.get('type') == 'end_session':
                    print("  [*] Client requested session end")
                    break
                
                chat_msg = ChatMessage(**msg_dict)
                
                # Verify sequence number (replay protection)
                if chat_msg.seqno != expected_seqno:
                    error = ErrorMessage(
                        code="REPLAY",
                        message=f"Expected seqno {expected_seqno}, got {chat_msg.seqno}"
                    )
                    sock.send(error.model_dump_json().encode('utf-8'))
                    print(f"  [✗] REPLAY: Expected seq {expected_seqno}, got {chat_msg.seqno}")
                    continue
                
                # Verify signature
                if not verify_message_signature(
                    chat_msg.seqno, chat_msg.ts, chat_msg.ct,
                    chat_msg.sig, client_public_key
                ):
                    error = ErrorMessage(code="SIG_FAIL", message="Signature verification failed")
                    sock.send(error.model_dump_json().encode('utf-8'))
                    print(f"  [✗] SIG_FAIL: Invalid signature for seqno {chat_msg.seqno}")
                    continue
                
                # Decrypt message
                plaintext = decrypt(chat_msg.ct, session_key)
                
                # Log to transcript
                transcript.append_message(
                    chat_msg.seqno, chat_msg.ts, chat_msg.ct,
                    chat_msg.sig, client_fingerprint
                )
                
                # Display message
                print(f"  [Client] {plaintext}")
                
                expected_seqno += 1
                
                # Send simple acknowledgment
                ack = {"type": "ack", "seqno": chat_msg.seqno}
                sock.send(json.dumps(ack).encode('utf-8'))
            
            except json.JSONDecodeError:
                break
            except Exception as e:
                print(f"  [!] Error processing message: {e}")
                break
    
    def phase6_non_repudiation(self, sock, transcript):
        """Phase 6: Generate and exchange session receipts."""
        print("\n[Phase 6] Non-Repudiation")
        
        # Generate server receipt
        receipt = transcript.generate_receipt("server", self.server_key)
        transcript.save_receipt(receipt)
        
        print(f"  [✓] Session receipt generated")
        print(f"      Messages: {transcript.first_seq} to {transcript.last_seq}")
        print(f"      Transcript hash: {receipt.transcript_sha256[:32]}...")
        
        # Send receipt to client
        sock.send(receipt.model_dump_json().encode('utf-8'))
        print(f"  [>] Sent receipt to client")


def main():
    print("="*70)
    print("  SECURECHAT SERVER - Assignment #2")
    print("  Information Security (CS-3002) - Fall 2025")
    print("="*70 + "\n")
    
    # Initialize database
    try:
        init_db()
    except DatabaseError as e:
        print(f"[!] Database initialization failed: {e}")
        print("[!] Please check your MySQL configuration in .env")
        return
    
    # Start server
    server = SecureChatServer()
    server.start()


if __name__ == "__main__":
    main()