# 🔐 SecureChat - Information Security Assignment #2

**Course**: CS-3002 Information Security, Fall 2025  
**Institution**: FAST-NUCES (National University of Computer and Emerging Sciences)

A console-based secure chat system demonstrating practical cryptography implementation.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Certificate Generation](#certificate-generation)
- [Running the Application](#running-the-application)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Security Properties](#security-properties)
- [Troubleshooting](#troubleshooting)

---

## 🎯 Overview

SecureChat is a TCP-based secure messaging system that implements:

- **PKI Authentication**: X.509 certificates signed by a self-built Certificate Authority
- **Key Agreement**: Diffie-Hellman key exchange for session keys
- **Encryption**: AES-128 for message confidentiality
- **Integrity**: SHA-256 hashing
- **Authenticity**: RSA digital signatures
- **Non-Repudiation**: Signed session transcripts

The system achieves **CIANR**:

- **C**onfidentiality: No plaintext data on the wire
- **I**ntegrity: Tamper detection via signatures
- **A**uthenticity: Certificate-based identity verification
- **N**on-**R**epudiation: Cryptographic proof of communication

---

## ✨ Features

### Control Plane

- Mutual certificate exchange and validation
- Certificate chain verification (CA signature, expiry, CN)
- Rejection of invalid/expired/self-signed certificates

### Authentication

- Secure user registration with salted SHA-256 password hashing
- MySQL-backed credential storage (NO plaintext passwords)
- Dual-gate authentication: valid certificate AND correct credentials

### Key Agreement

- Temporary DH exchange for authentication channel
- Session DH exchange for chat encryption
- Proper key derivation: `K = Trunc_16(SHA256(big_endian(K_s)))`

### Data Plane

- AES-128 encryption with PKCS#7 padding
- Per-message RSA signatures over `SHA256(seqno||timestamp||ciphertext)`
- Replay protection via strict sequence number validation

### Non-Repudiation

- Append-only session transcripts
- Signed SessionReceipts with transcript hash
- Offline verification capability

---

## 🏗️ Architecture

```
┌──────────────┐                              ┌──────────────┐
│              │   1. Cert Exchange (TLS)     │              │
│              │ ──────────────────────────>  │              │
│    Client    │ <────────────────────────── │    Server    │
│              │   2. Temp DH (for auth)      │              │
│              │ ──────────────────────────>  │              │
│              │ <──────────────────────────  │              │
│              │   3. Encrypted Auth          │              │
│              │ ──────────────────────────>  │              │
│              │ <──────────────────────────  │              │
│              │   4. Session DH (for chat)   │              │
│              │ ──────────────────────────>  │              │
│              │ <──────────────────────────  │              │
│              │   5. Encrypted Messages      │              │
│              │ ───────────────────────────> │              │
│              │   6. Session Receipts        │              │
│              │ <──────────────────────────> │              │
└──────────────┘                              └──────────────┘
```

---

## 🔧 Prerequisites

### Software Requirements

- Python 3.8 or higher
- MySQL 8.0 or higher (Docker recommended)
- Git

### System Requirements

- Windows 10/11, macOS, or Linux
- 4GB RAM minimum
- Network access for localhost communication

---

## 📦 Installation

### 1. Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/securechat-assignment2.git
cd securechat-assignment2
```

### 2. Create Virtual Environment

```bash
# On Windows
python -m venv .venv
.venv\Scripts\activate

# On macOS/Linux
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## ⚙️ Configuration

### 1. Setup MySQL Database

**Option A: Using Docker (Recommended)**

```bash
docker run -d --name securechat-db \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat \
  -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass \
  -p 3306:3306 \
  mysql:8
```

**Option B: Local MySQL Installation**

```sql
CREATE DATABASE securechat CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'scuser'@'localhost' IDENTIFIED BY 'scpass';
GRANT ALL PRIVILEGES ON securechat.* TO 'scuser'@'localhost';
FLUSH PRIVILEGES;
```

### 2. Initialize Database Schema

```bash
python -m app.storage.db --init
```

**Expected Output:**

```
[✓] Database initialized successfully
```

### 3. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` with your configuration:

```ini
# Database
DB_HOST=localhost
DB_PORT=3306
DB_NAME=securechat
DB_USER=scuser
DB_PASSWORD=scpass

# Server
SERVER_HOST=127.0.0.1
SERVER_PORT=5000

# Certificates (will be generated)
CA_CERT_PATH=certs/ca_cert.pem
CA_KEY_PATH=certs/ca_key.pem
SERVER_CERT_PATH=certs/server_cert.pem
SERVER_KEY_PATH=certs/server_key.pem
CLIENT_CERT_PATH=certs/client_cert.pem
CLIENT_KEY_PATH=certs/client_key.pem
```

---

## 🔐 Certificate Generation

### Step 1: Generate Root CA

```bash
python scripts/gen_ca.py --name "FAST-NU Root CA" --days 3650
```

**Output:**

```
[*] Generating RSA private key (2048 bits)...
[*] Creating self-signed certificate for 'FAST-NU Root CA'...
[+] CA private key saved to: certs/ca_key.pem
[+] CA certificate saved to: certs/ca_cert.pem
[✓] Root CA created successfully!
```

**Verify CA Certificate:**

```bash
openssl x509 -in certs/ca_cert.pem -text -noout
```

### Step 2: Generate Server Certificate

```bash
python scripts/gen_cert.py --cn server.local --out certs/server --server --days 365
```

**Output:**

```
[*] Loading CA certificate and key...
[*] Generating RSA private key for 'server.local'...
[*] Creating certificate for 'server.local'...
[+] Private key saved to: certs/server_key.pem
[+] Certificate saved to: certs/server_cert.pem
[✓] Certificate issued and saved successfully!
```

### Step 3: Generate Client Certificate

```bash
python scripts/gen_cert.py --cn client.local --out certs/client --days 365
```

### Verify Certificate Chain

```bash
# Verify server certificate is signed by CA
openssl verify -CAfile certs/ca_cert.pem certs/server_cert.pem

# Should output: certs/server_cert.pem: OK
```

---

## 🚀 Running the Application

### Terminal 1: Start Server

```bash
python -m app.server
```

**Expected Output:**

```
======================================================================
  SECURECHAT SERVER - Assignment #2
  Information Security (CS-3002) - Fall 2025
======================================================================

[✓] Database initialized successfully
[*] SecureChat Server initialized
    Listening on: 127.0.0.1:5000
    Server CN: server.local

[✓] Server listening on 127.0.0.1:5000
[*] Waiting for clients...
```

### Terminal 2: Start Client

```bash
python -m app.client
```

**Expected Output:**

```
======================================================================
  SECURECHAT CLIENT - Assignment #2
  Information Security (CS-3002) - Fall 2025
======================================================================

[*] SecureChat Client initialized
    Client CN: client.local

[*] Connecting to 127.0.0.1:5000...
[✓] Connected to server

[Phase 1] Certificate Exchange
  [>] Sent client hello
  [<] Received server hello
  [✓] Server certificate validated

[Phase 2] Temporary DH Key Exchange
  [>] Sent client DH
  [<] Received server DH
  [✓] Temporary key established

[Phase 3] Authentication
  [?] (R)egister or (L)ogin? R
  Email: alice@example.com
  Username: alice
  Password: securepass123
  [>] Sent registration request
  [✓] Registration successful

[Phase 4] Session DH Key Exchange
  [>] Sent session DH
  [<] Received session DH
  [✓] Session key established

======================================================================
  SECURE CHAT SESSION
  Type your messages below. Type 'exit' to end session.
======================================================================

[alice] Hello, this is a secure message!
[alice] exit

[Phase 6] Non-Repudiation
  [✓] Client receipt generated and saved
  [<] Received server receipt
  [✓] Session complete. Evidence saved.

[*] Disconnected from server
```

---

## 🧪 Testing

### Test 1: Invalid Certificate Rejection

```bash
# Generate self-signed (invalid) certificate
openssl req -newkey rsa:2048 -nodes -keyout certs/fake_key.pem \
  -x509 -days 1 -out certs/fake_cert.pem \
  -subj "/C=PK/ST=Islamabad/L=Islamabad/O=Fake/CN=fake.local"

# Temporarily modify .env to use fake certificate
# Run client

# Expected: Server rejects with "BAD_CERT" error
```

### Test 2: Wireshark Packet Capture

```bash
# Start Wireshark, capture on loopback interface
# Filter: tcp.port == 5000

# Run complete session:
# 1. Start server
# 2. Start client
# 3. Register/Login
# 4. Send 3-5 messages
# 5. Exit

# Verify in Wireshark:
# - No plaintext passwords
# - No plaintext messages
# - All payload is base64/encrypted
```

**Display Filters:**

```
tcp.port == 5000
tcp.stream eq 0
frame contains "encrypted"
```

### Test 3: Message Tampering Detection

Modify `app/client.py` temporarily:

```python
# In send_message() method, after encryption:
ct_bytes = base64.b64decode(ct)
ct_bytes = bytearray(ct_bytes)
ct_bytes[0] ^= 0x01  # Flip one bit
ct = base64.b64encode(ct_bytes).decode('ascii')
```

**Expected**: Server returns `SIG_FAIL` error

### Test 4: Replay Attack Detection

```python
# In client chat_loop():
self.send_message("Test message")
self.seqno -= 1  # Don't increment
self.send_message("Test message")  # Send again
```

**Expected**: Server returns `REPLAY` error

### Test 5: Non-Repudiation Verification

```bash
# After completing a session:
python scripts/verify_receipt.py \
  --transcript transcripts/session_XXXXX_alice.txt \
  --receipt transcripts/receipt_XXXXX_alice.json \
  --cert certs/client_cert.pem

# Expected: All checks pass ✓

# Now edit transcript file (change one character):
nano transcripts/session_XXXXX_alice.txt

# Run verification again:
python scripts/verify_receipt.py \
  --transcript transcripts/session_XXXXX_alice.txt \
  --receipt transcripts/receipt_XXXXX_alice.json \
  --cert certs/client_cert.pem

# Expected: Transcript hash mismatch ✗
```

---

## 📁 Project Structure

```
securechat-assignment2/
├── app/
│   ├── __init__.py
│   ├── client.py                 # Client implementation
│   ├── server.py                 # Server implementation
│   ├── crypto/
│   │   ├── __init__.py
│   │   ├── aes.py               # AES-128 encryption
│   │   ├── dh.py                # Diffie-Hellman
│   │   ├── pki.py               # Certificate validation
│   │   └── sign.py              # RSA signatures
│   ├── common/
│   │   ├── __init__.py
│   │   ├── protocol.py          # Pydantic message models
│   │   ├── utils.py             # Helper functions
│   │   └── exceptions.py        # Custom exceptions
│   └── storage/
│       ├── __init__.py
│       ├── db.py                # MySQL operations
│       └── transcript.py        # Session logging
├── scripts/
│   ├── gen_ca.py                # Generate root CA
│   ├── gen_cert.py              # Issue certificates
│   └── verify_receipt.py        # Offline verification
├── tests/
│   └── manual/
│       └── NOTES.md             # Testing procedures
├── certs/                       # Certificates (gitignored)
├── transcripts/                 # Session logs (gitignored)
├── .env                         # Configuration (gitignored)
├── .env.example                 # Configuration template
├── .gitignore
├── requirements.txt
└── README.md
```

---

## 🛡️ Security Properties

### Confidentiality ✓

- All messages encrypted with AES-128
- Session keys derived via DH (never transmitted)
- Credentials encrypted during authentication

### Integrity ✓

- SHA-256 hashing of all messages
- RSA signatures prevent undetected tampering
- Any bit flip causes verification failure

### Authenticity ✓

- X.509 certificates signed by trusted CA
- Mutual authentication (client and server)
- Digital signatures prove message origin

### Non-Repudiation ✓

- Append-only session transcripts
- Signed SessionReceipts with transcript hash
- Offline verification proves communication occurred
- Neither party can deny participation

### Replay Protection ✓

- Strict sequence number enforcement
- Timestamp validation
- Old messages automatically rejected

---

## 🐛 Troubleshooting

### Connection Issues

**Problem**: `Connection refused` error

```
Solution:
1. Ensure server is running first
2. Check SERVER_HOST and SERVER_PORT in .env
3. Verify firewall allows localhost connections
```

**Problem**: Database connection error

```
Solution:
1. Verify MySQL is running:
   docker ps | grep securechat-db
2. Test connection:
   mysql -u scuser -pscpass -h localhost securechat
3. Check credentials in .env match database
```

### Certificate Issues

**Problem**: `BAD_CERT: Invalid signature`

```
Solution:
1. Regenerate all certificates:
   rm certs/*.pem
   python scripts/gen_ca.py --name "FAST-NU Root CA"
   python scripts/gen_cert.py --cn server.local --out certs/server --server
   python scripts/gen_cert.py --cn client.local --out certs/client
2. Ensure paths in .env are correct
```

**Problem**: Certificate not found

```
Solution:
1. Check certificate files exist:
   ls -la certs/
2. Verify .env paths match actual filenames
3. Ensure you're running from project root directory
```

### Encryption/Decryption Errors

**Problem**: `Decryption failed` or padding errors

```
Solution:
1. Ensure both client and server use same protocol version
2. Check session key derivation is consistent
3. Verify AES key is exactly 16 bytes
```

### Module Import Errors

**Problem**: `ModuleNotFoundError: No module named 'app'`

```
Solution:
1. Ensure you're in virtual environment:
   source .venv/bin/activate  # Linux/Mac
   .venv\Scripts\activate     # Windows
2. Install requirements:
   pip install -r requirements.txt
3. Run from project root:
   python -m app.server  (not: cd app && python server.py)
```

---

## 📊 Performance Notes

- **Connection Establishment**: ~200-300ms (includes DH exchanges)
- **Message Encryption**: <1ms per message
- **Signature Generation**: ~5-10ms per message
- **Certificate Validation**: ~10-20ms (one-time per session)

---

## 🔗 References

### Cryptography Libraries

- **cryptography**: https://cryptography.io/
- **Pydantic**: https://docs.pydantic.dev/

### Standards

- **RFC 3526**: DH MODP Groups
- **RFC 2315**: PKCS#7 Padding
- **RFC 8017**: PKCS#1 v1.5 Signatures
- **RFC 5280**: X.509 Certificates

### Assignment Resources

- **SEED Lab PKI**: https://seedsecuritylabs.org/Labs_20.04/Crypto/Crypto_PKI/

---

## 📝 Assignment Deliverables Checklist

- [ ] Forked/Cloned repository with 10+ meaningful commits
- [ ] Complete implementation (all phases working)
- [ ] MySQL schema dump with sample users
- [ ] Updated README.md with execution instructions
- [ ] `RollNumber-FullName-Report-A02.docx`
- [ ] `RollNumber-FullName-TestReport-A02.docx`
- [ ] Wireshark captures (PCAP files)
- [ ] Screenshots of all test scenarios
- [ ] Certificate inspection outputs

---

## 👥 Author

**Name**: Salman Khan  
**Roll Number**: 22I-1285  
**Course**: CS-3002 Information Security  
**Semester**: Fall 2025  
**Institution**: FAST-NUCES

---

## 📄 License

This project is for academic purposes only as part of the Information Security course at FAST-NUCES.

---

## 🙏 Acknowledgments

- FAST-NUCES Information Security Course Staff
- SEED Security Labs for PKI concepts
- Python Cryptography Library maintainers

---

**Last Updated**: November 2025
