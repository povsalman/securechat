#!/usr/bin/env python3
"""
SecureChat Client

Implements the client-side protocol.
"""

import os
import socket
import json
import sys
import uuid
import threading
import base64
from dotenv import load_dotenv

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.crypto import *
from app.crypto.sign import load_private_key, sign_message
from app.common.protocol import *
from app.common.utils import now_ms, generate_nonce, b64encode, b64decode
from app.common.exceptions import *
from app.storage.transcript import TranscriptManager
from cryptography import x509
from cryptography.hazmat.primitives import serialization

load_dotenv()

class SecureChatClient:
    def __init__(self):
        self.host = os.getenv('SERVER_HOST', '127.0.0.1')
        self.port = int(os.getenv('SERVER_PORT', 5000))
        self.ca_cert = load_certificate(os.getenv('CA_CERT_PATH', 'certs/ca_cert.pem'))
        self.client_cert = load_certificate(os.getenv('CLIENT_CERT_PATH', 'certs/client_cert.pem'))
        self.client_key = load_private_key(os.getenv('CLIENT_KEY_PATH', 'certs/client_key.pem'))
        
        self.sock = None
        self.session_key = None
        self.seqno = 1
        self.transcript = None
        self.username = None
        
        print(f"[*] SecureChat Client initialized")
        print(f"    Client CN: {self.client_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value}")
    
    def connect(self):
        """Connect to server and establish secure session."""
        print(f"\n[*] Connecting to {self.host}:{self.port}...")
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        print(f"[✓] Connected to server\n")
        
        # Phase 1: Certificate Exchange
        server_cert = self.phase1_cert_exchange()
        
        # Phase 2: Temporary DH for Authentication
        temp_key = self.phase2_temp_dh()
        
        # Phase 3: Authentication
        self.phase3_authentication(temp_key)
        
        # Phase 4: Session DH
        self.session_key = self.phase4_session_dh()
        
        # Initialize transcript
        session_id = str(uuid.uuid4())[:8]
        self.transcript = TranscriptManager(f"{session_id}_{self.username}", "transcripts")
    
    def phase1_cert_exchange(self):
        """Phase 1: Exchange and validate certificates."""
        print("[Phase 1] Certificate Exchange")
        
        # Send client hello
        hello = HelloMessage(
            client_cert=self.client_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
            nonce=b64encode(generate_nonce(16))
        )
        self.sock.send(hello.model_dump_json().encode('utf-8'))
        print(f"  [>] Sent client hello")
        
        # Receive server hello
        data = self.sock.recv(8192).decode('utf-8')
        server_hello = ServerHelloMessage(**json.loads(data))
        print(f"  [<] Received server hello")
        
        # Validate server certificate
        server_cert = x509.load_pem_x509_certificate(server_hello.server_cert.encode('utf-8'))
        is_valid, msg = validate_certificate(server_cert, self.ca_cert)
        
        if not is_valid:
            raise CertificateError(msg)
        
        print(f"  [✓] Server certificate validated")
        return server_cert
    
    def phase2_temp_dh(self):
        """Phase 2: Temporary DH for authentication."""
        print("\n[Phase 2] Temporary DH Key Exchange")
        
        # Generate DH parameters and keypair
        p, g = generate_params()
        a, A = generate_keypair(p, g)
        
        # Send client DH
        dh_client = DHClientMessage(g=g, p=p, A=A)
        self.sock.send(dh_client.model_dump_json().encode('utf-8'))
        print(f"  [>] Sent client DH")
        
        # Receive server DH
        data = self.sock.recv(8192).decode('utf-8')
        dh_server = DHServerMessage(**json.loads(data))
        print(f"  [<] Received server DH")
        
        # Compute shared secret
        K_s = compute_shared_secret(a, dh_server.B, p)
        temp_key = derive_aes_key(K_s)
        print(f"  [✓] Temporary key established")
        
        return temp_key
    
    def phase3_authentication(self, temp_key):
        """Phase 3: Register or login."""
        print("\n[Phase 3] Authentication")
        
        choice = input("  [?] (R)egister or (L)ogin? ").strip().upper()
        
        if choice == 'R':
            self.handle_registration(temp_key)
        elif choice == 'L':
            self.handle_login(temp_key)
        else:
            raise ValueError("Invalid choice")
    
    def handle_registration(self, temp_key):
        """Handle user registration."""
        email = input("  Email: ").strip()
        username = input("  Username: ").strip()
        password = input("  Password: ").strip()
        
        # Create registration message
        reg_msg = RegisterMessage(
            email=email,
            username=username,
            pwd=password,  # In production, hash this properly
            salt=b64encode(generate_nonce(16))
        )
        
        # Encrypt and send
        encrypted_payload = encrypt(reg_msg.model_dump_json(), temp_key)
        self.sock.send(json.dumps({"encrypted_payload": encrypted_payload}).encode('utf-8'))
        print(f"  [>] Sent registration request")
        
        # Receive response
        data = self.sock.recv(8192).decode('utf-8')
        response_data = json.loads(data)
        decrypted = decrypt(response_data['encrypted_response'], temp_key)
        response = AuthResponseMessage(**json.loads(decrypted))
        
        if response.success:
            print(f"  [✓] {response.message}")
            self.username = username
        else:
            raise AuthenticationError(response.message)
    
    def handle_login(self, temp_key):
        """Handle user login."""
        email = input("  Email: ").strip()
        password = input("  Password: ").strip()
        
        # Create login message
        login_msg = LoginMessage(
            email=email,
            pwd=password,
            nonce=b64encode(generate_nonce(16))
        )
        
        # Encrypt and send
        encrypted_payload = encrypt(login_msg.model_dump_json(), temp_key)
        self.sock.send(json.dumps({"encrypted_payload": encrypted_payload}).encode('utf-8'))
        print(f"  [>] Sent login request")
        
        # Receive response
        data = self.sock.recv(8192).decode('utf-8')
        response_data = json.loads(data)
        decrypted = decrypt(response_data['encrypted_response'], temp_key)
        response = AuthResponseMessage(**json.loads(decrypted))
        
        if response.success:
            print(f"  [✓] {response.message}")
            self.username = response.username
        else:
            raise AuthenticationError(response.message)
    
    def phase4_session_dh(self):
        """Phase 4: Session DH key exchange."""
        print("\n[Phase 4] Session DH Key Exchange")
        
        # Generate session DH
        p, g = generate_params()
        a, A = generate_keypair(p, g)
        
        # Send session DH
        dh_session = DHSessionClientMessage(g=g, p=p, A=A)
        self.sock.send(dh_session.model_dump_json().encode('utf-8'))
        print(f"  [>] Sent session DH")
        
        # Receive server session DH
        data = self.sock.recv(8192).decode('utf-8')
        dh_server = DHSessionServerMessage(**json.loads(data))
        print(f"  [<] Received session DH")
        
        # Compute session key
        K_s = compute_shared_secret(a, dh_server.B, p)
        session_key = derive_aes_key(K_s)
        print(f"  [✓] Session key established\n")
        
        return session_key
    
    def send_message(self, text):
        """Send encrypted and signed message."""
        # Encrypt message
        ct = encrypt(text, self.session_key)
        
        # # ========== Uncomment THIS CODE only for "Test 3: Message Tampering Detection" ==========
        # # Tamper with ciphertext (flip one bit)
        # ct_bytes = base64.b64decode(ct)
        # ct_bytes = bytearray(ct_bytes)
        # ct_bytes[0] ^= 0x01  # Flip first bit
        # ct = base64.b64encode(ct_bytes).decode('ascii')
        # print("[DEBUG] Ciphertext tampered!")
        # # ===================================

        # Sign message
        ts = now_ms()
        sig = sign_message(self.seqno, ts, ct, self.client_key)
        
        # Create message
        msg = ChatMessage(
            seqno=self.seqno,
            ts=ts,
            ct=ct,
            sig=sig
        )
        
        # Send message
        self.sock.send(msg.model_dump_json().encode('utf-8'))
        
        # Log to transcript
        server_fingerprint = "server_fingerprint_placeholder"
        self.transcript.append_message(self.seqno, ts, ct, sig, server_fingerprint)
        
        # Increment sequence number
        self.seqno += 1
        
        # Wait for ack
        ack = self.sock.recv(1024).decode('utf-8')
    
    def chat_loop(self):
        """Main chat loop."""
        print("="*70)
        print("  SECURE CHAT SESSION")
        print("  Type your messages below. Type 'exit' to end session.")
        print("="*70 + "\n")
        
        while True:
            try:
                message = input(f"[{self.username}] ")
                
                if message.lower() == 'test_replay':
                    # Send a message normally
                    self.send_message("Original message")

                    # Try to replay it (don't increment seqno)
                    self.seqno -= 1
                    self.send_message("Original message")
                    self.seqno += 1  # Fix counter
                    continue

                if message.lower() == 'exit':
                    # End session
                    self.sock.send(json.dumps({"type": "end_session"}).encode('utf-8'))
                    break
                
                if message.strip():
                    self.send_message(message)
            
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"\n[!] Error: {e}")
                break
        
        # Phase 6: Non-repudiation
        self.phase6_non_repudiation()
    
    def phase6_non_repudiation(self):
        """Phase 6: Generate and receive receipts."""
        print("\n[Phase 6] Non-Repudiation")
        
        # Generate client receipt
        receipt = self.transcript.generate_receipt("client", self.client_key)
        self.transcript.save_receipt(receipt)
        
        print(f"  [✓] Client receipt generated and saved")
        
        # Receive server receipt
        data = self.sock.recv(8192).decode('utf-8')
        server_receipt = SessionReceipt(**json.loads(data))
        
        # Save server receipt
        receipt_path = f"transcripts/server_receipt_{self.username}.json"
        with open(receipt_path, 'w') as f:
            f.write(server_receipt.model_dump_json(indent=2))
        
        print(f"  [<] Received server receipt")
        print(f"  [✓] Session complete. Evidence saved.\n")
    
    def disconnect(self):
        """Disconnect from server."""
        if self.sock:
            self.sock.close()
            print("[*] Disconnected from server")


def main():
    print("="*70)
    print("  SECURECHAT CLIENT - Assignment #2")
    print("  Information Security (CS-3002) - Fall 2025")
    print("="*70 + "\n")
    
    client = SecureChatClient()
    
    try:
        client.connect()
        client.chat_loop()
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        client.disconnect()


if __name__ == "__main__":
    main()