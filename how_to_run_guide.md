# 🚀 HOW TO RUN AND VERIFY SECURECHAT

## Complete Step-by-Step Execution Guide

---

## 📋 Table of Contents

1. [Initial Setup (One-Time)](#initial-setup)
2. [Certificate Generation](#certificate-generation)
3. [Database Setup](#database-setup)
4. [Running the Application](#running-the-application)
5. [Testing Scenarios](#testing-scenarios)
6. [Evidence Collection](#evidence-collection)
7. [Offline Verification](#offline-verification)

---

## 🔧 Initial Setup (One-Time)

### Step 1: Clone and Setup Environment

```bash
# Navigate to your workspace
cd ~/workspace  # or C:\workspace on Windows

# Clone your repository
git clone https://github.com/povsalman/securechat.git
cd securechat

# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
# On Windows:
.venv\Scripts\activate
# On macOS/Linux:
source .venv/bin/activate

# Verify Python version
python --version  # Should be 3.8+
```

### Step 2: Install Dependencies

```bash
# Install all required packages
pip install -r requirements.txt

# Verify installation
pip list | Select-String cryptography
pip list | Select-String "mysql-connector-python"
pip list | Select-String "pydantic"
```

Expected output:

```
cryptography          41.0.7
mysql-connector-python 8.2.0
pydantic              2.5.2
```

### Step 3: Create Directory Structure

```bash
# Create necessary directories
New-Item -ItemType Directory -Force -Path certs, transcripts, logs | Out-Null

# Create .keep files to preserve empty directories
New-Item -ItemType File -Force -Path certs/.keep | Out-Null
New-Item -ItemType File -Force -Path transcripts/.keep | Out-Null

# Verify structure (PowerShell alternative to tree -L 1)
tree /A /F
```

---

## 🔐 Certificate Generation

### Step 1: Generate Root CA

```bash
# Generate the root Certificate Authority
python scripts/gen_ca.py --name "FAST-NU Root CA" --days 3650

# Expected output:
# [*] Generating RSA private key (2048 bits)...
# [*] Creating self-signed certificate for 'FAST-NU Root CA'...
# [+] CA private key saved to: certs/ca_key.pem
# [+] CA certificate saved to: certs/ca_cert.pem
# [✓] Root CA created successfully!
```

### Step 2: Inspect CA Certificate

```bash
# View certificate details
openssl x509 -in certs/ca_cert.pem -text -noout

# Look for:
# - Subject: CN = FAST-NU Root CA
# - Issuer: CN = FAST-NU Root CA (self-signed)
# - Validity dates
# - Basic Constraints: CA:TRUE
```

**Save this output for your report!**

### Step 3: Generate Server Certificate

```bash
# Generate server certificate
python scripts/gen_cert.py --cn server.local --out certs/server --server --days 365

# Expected output:
# [*] Loading CA certificate and key...
# [*] Generating RSA private key for 'server.local'...
# [*] Creating certificate for 'server.local'...
# [+] Certificate issued successfully!
#     Issued to: server.local
#     Issued by: FAST-NU Root CA
#     Valid from: 2025-XX-XX XX:XX:XX
#     Valid until: 2026-XX-XX XX:XX:XX
# [+] Private key saved to: certs/server_key.pem
# [+] Certificate saved to: certs/server_cert.pem
```

### Step 4: Generate Client Certificate

```bash
# Generate client certificate
python scripts/gen_cert.py --cn client.local --out certs/client --days 365

# Verify both certificates exist
Get-ChildItem certs
```

Expected files:

```
ca_cert.pem       # Root CA certificate
ca_key.pem        # Root CA private key
server_cert.pem   # Server certificate
server_key.pem    # Server private key
client_cert.pem   # Client certificate
client_key.pem    # Client private key
```

### Step 5: Verify Certificate Chain

```bash
# Verify server certificate is signed by CA
openssl verify -CAfile certs/ca_cert.pem certs/server_cert.pem

# Expected: certs/server_cert.pem: OK

# Verify client certificate
openssl verify -CAfile certs/ca_cert.pem certs/client_cert.pem

# Expected: certs/client_cert.pem: OK
```

**Screenshot these verification results!**

---

## 🗄️ Database Setup

### Option A: Using Docker (Recommended)

#### (For Windows)

```bash
# Start MySQL container
docker run -d --name securechat-db `
  -e MYSQL_ROOT_PASSWORD=rootpass `
  -e MYSQL_DATABASE=securechat `
  -e MYSQL_USER=scuser `
  -e MYSQL_PASSWORD=scpass `
  -p 3306:3306 `
  mysql:8

# Wait 15 seconds for MySQL to start
Start-Sleep -Seconds 15

# Verify container is running
docker ps | Select-String "securechat-db"

# Test connection
docker exec -i securechat-db mysql -u scuser -pscpass securechat -e "SELECT 1;"
```

#### (For Ubuntu)

```bash
# Start MySQL container
docker run -d --name securechat-db \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat \
  -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass \
  -p 3306:3306 \
  mysql:8

# Wait 10-15 seconds for MySQL to start
sleep 15

# Verify container is running
docker ps | grep securechat-db

# Test connection
docker exec -it securechat-db mysql -u scuser -pscpass securechat -e "SELECT 1;"
```

### Option B: Local MySQL Installation (Not Tested)

```bash
# Connect to MySQL as root
mysql -u root -p

# Run these SQL commands:
CREATE DATABASE securechat CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'scuser'@'localhost' IDENTIFIED BY 'scpass';
GRANT ALL PRIVILEGES ON securechat.* TO 'scuser'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

### Initialize Database Schema (Windows Docker Version)

```bash
# Setup environment variables (Not needed in my case)
Copy-Item .env.example .env

# Edit .env if needed (ensure DB credentials match)
notepad .env  # or use your preferred editor

# Initialize database tables
python -m app.storage.db --init

# Expected output:
# [✓] Database initialized successfully
```

### Verify Database

```bash
# Connect to database
docker exec -it securechat-db mysql -u scuser -pscpass securechat

# Show tables
SHOW TABLES;

# Expected output:
# +----------------------+
# | Tables_in_securechat |
# +----------------------+
# | users                |
# +----------------------+

# View table structure
DESCRIBE users;

# Expected output:
# +------------+--------------+------+-----+-------------------+
# | Field      | Type         | Null | Key | Default           |
# +------------+--------------+------+-----+-------------------+
# | id         | int          | NO   | PRI | NULL              |
# | email      | varchar(255) | NO   | UNI | NULL              |
# | username   | varchar(255) | NO   | UNI | NULL              |
# | salt       | varbinary(16)| NO   |     | NULL              |
# | pwd_hash   | char(64)     | NO   |     | NULL              |
# | created_at | timestamp    | YES  |     | CURRENT_TIMESTAMP |
# +------------+--------------+------+-----+-------------------+

EXIT;
```

**Screenshot the table structure for your report!**

---

## 🚀 Running the Application

### Preparation

Open **THREE** terminal windows:

1. **Terminal 1**: Server
2. **Terminal 2**: Client
3. **Terminal 3**: Wireshark/monitoring

In all terminals, navigate to project directory and activate virtual environment:

```bash
cd ~/workspace/securechat
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
```

---

### Terminal 1: Start Server

```bash
# Start the server
python -m app.server

# Expected output:
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

**Leave this terminal running!**

---

### Terminal 2: Start Client

```bash
# Start the client
python -m app.client

# You'll see:
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
  [?] (R)egister or (L)ogin?
```

---

### First Time: Registration

```
[?] (R)egister or (L)ogin? R
Email: alice@example.com
Username: alice
Password: SecurePass123!
  [>] Sent registration request
  [✓] Registration successful

[Phase 4] Session DH Key Exchange
  [>] Sent session DH
  [<] Received server DH
  [✓] Session key established

======================================================================
  SECURE CHAT SESSION
  Type your messages below. Type 'exit' to end session.
======================================================================

[alice]
```

---

### Subsequent Times: Login

```
[?] (R)egister or (L)ogin? L
Email: alice@example.com
Password: SecurePass123!
  [>] Sent login request
  [✓] Login successful

[Phase 4] Session DH Key Exchange
  [>] Sent session DH
  [<] Received server DH
  [✓] Session key established

======================================================================
  SECURE CHAT SESSION
  Type your messages below. Type 'exit' to end session.
======================================================================

[alice]
```

---

### Send Messages

```
[alice] Hello, this is my first secure message!
[alice] Testing AES-128 encryption
[alice] This message is digitally signed
[alice] Nobody can read this except the server
[alice] exit

[Phase 6] Non-Repudiation
  [✓] Client receipt generated and saved
  [<] Received server receipt
  [✓] Session complete. Evidence saved.

[*] Disconnected from server
```

**Check Server Terminal** - you should see the messages displayed there!

---

## 🧪 Testing Scenarios

### Test 1: Invalid Certificate Test

#### Generate Fake Certificate

```bash
# Generate self-signed certificate (NOT signed by our CA)
openssl req -newkey rsa:2048 -nodes `
  -keyout certs/fake_key.pem `
  -x509 -days 1 `
  -out certs/fake_cert.pem `
  -subj "/C=PK/ST=Islamabad/L=Islamabad/O=FakeOrg/CN=fake.local"
```

#### Modify .env Temporarily

```bash
# Backup original .env
Copy-Item .env .env.backup

# Edit .env using Notepad
notepad .env
# Change:
# CLIENT_CERT_PATH=certs/fake_cert.pem
# CLIENT_KEY_PATH=certs/fake_key.pem
```

#### Run Client with Fake Certificate

```bash
python -m app.client

# Expected error on server:
[Phase 1] Certificate Exchange
  [<] Received client hello with nonce: ...
  [✗] BAD_CERT: Invalid signature (not signed by trusted CA)
[!] Error handling client: BAD_CERT: Invalid signature (not signed by trusted CA)
```

**Screenshot this error!**

#### Restore Original Configuration

```bash
# Restore .env
Move-Item -Force .env.backup .env
```

---

### Test 2: Wireshark Packet Capture

#### Start Wireshark

```bash
# On Linux/Mac:
sudo wireshark

# On Windows:
# Run Wireshark as Administrator
```

#### Configure Capture

1. Select **Loopback** interface (lo, lo0, Loopback: lo or Adapter for loopback traffic capture)
2. Click **Start Capturing**
3. Apply display filter: `tcp.port == 5000`

#### Run Complete Session

1. Start server
2. Start client
3. Register/Login
4. Send 5 messages:
   - "Hello World"
   - "Testing encryption"
   - "This is confidential"
   - "AES-128 in action"
   - "Digital signatures work"
5. Type `exit`

#### Analyze Capture

**Check for:**

1. Right-click on any of the packets
2. Go to Follow > TCP Stream.

- ✅ JSON structure visible
- ✅ Base64-encoded ciphertext (no readable plaintext)
- ✅ No plaintext passwords
- ✅ "encrypted_payload" fields
- ✅ "ct" (ciphertext) fields with base64 data

**Apply filters:**

- `frame contains "client_cert"`: This will show you the first "hello" message where the certificate is exchanged.

- `frame contains "encrypted_payload"`: This will show you the encrypted login/registration packets.

- `frame contains "ct"`: This will find all your chat messages.

#### Save Capture

1. File → Export Specified Packets
2. Save as: `evidence/securechat_encrypted_traffic.pcapng`

**Take screenshots:**

- Packet list view
- One packet detail showing encrypted payload
- Follow TCP Stream showing no plaintext

---

### Test 3: Message Tampering

#### Modify Client Code Temporarily

Edit `app/client.py`:

```python
# Find the send_message method
def send_message(self, text):
    # Encrypt message
    ct = encrypt(text, self.session_key)

    # ========== ADD THIS CODE ==========
    # Tamper with ciphertext (flip one bit)
    ct_bytes = base64.b64decode(ct)
    ct_bytes = bytearray(ct_bytes)
    ct_bytes[0] ^= 0x01  # Flip first bit
    ct = base64.b64encode(ct_bytes).decode('ascii')
    print("[DEBUG] Ciphertext tampered!")
    # ===================================

    # Sign message
    ts = now_ms()
    sig = sign_message(self.seqno, ts, ct, self.client_key)
    # ... rest of method
```

#### Run Test

```bash
# Start server
python -m app.server

# Start client
python -m app.client

# Login and send a message
[alice] This message will be tampered with

# Expected on server:
[✗] SIG_FAIL: Invalid signature for seqno 1
```

**Screenshot the SIG_FAIL error!**

#### Revert Changes

```bash
# Remove the tampering code from app/client.py
git checkout app/client.py
```

---

### Test 4: Replay Attack

#### Modify Client Code

Edit `app/client.py`:

```python
# In chat_loop method, after sending a message:
def chat_loop(self):
    # ... existing code ...

    while True:
        message = input(f"[{self.username}] ")

        if message.lower() == 'test_replay':
            # Send a message normally
            self.send_message("Original message")

            # Try to replay it (don't increment seqno)
            self.seqno -= 1
            self.send_message("Original message")
            self.seqno += 1  # Fix counter
            continue

        # ... rest of code ...
```

#### Run Test

```bash
# Start server and client
# Login and type:
[alice] test_replay

# Expected on server:
[✓] Message 1 received and verified
[✗] REPLAY: Expected seqno 2, got 1
```

**Screenshot the REPLAY error!**

---

### Test 5: Non-Repudiation Verification

#### Complete a Session

```bash
# Run a complete session with 5+ messages
python -m app.client

# Login and send messages:
[alice] Message 1
[alice] Message 2
[alice] Message 3
[alice] Message 4
[alice] Message 5
[alice] exit

# Note the session ID in transcript filenames
```

#### Verify Transcript

```bash
# List transcript files
Get-ChildItem transcripts\

# You should see files like:
# session_a1b2c3d4_alice.txt
# receipt_a1b2c3d4_alice.json
```

#### Run Offline Verification

```bash
# Verify the receipt
python scripts/verify_receipt_script.py `
  --transcript transcripts/session_XXXXXXXX_alice.txt `
  --receipt transcripts/receipt_XXXXXXXX_alice.json `
  --cert certs/client_cert.pem

# For Debugging, use below
python scripts/debug_receipt.py transcripts/receipt_XXXXXXXX_alice.json transcripts/session_XXXXXXXX_alice.txt certs/client_cert.pem


# Expected output:
======================================================================
  SESSION RECEIPT VERIFICATION
======================================================================

[1] Loading certificate: certs/client_cert.pem
    Certificate CN: client.local
    Valid from: ...
    Valid until: ...

[2] Loading receipt: transcripts/receipt_XXXXXXXX_alice.json
    Peer: client
    First sequence: 1
    Last sequence: 5
    Transcript hash: abc123...

[3] Verifying individual message signatures...
    [✓] Message 1: VALID
    [✓] Message 2: VALID
    [✓] Message 3: VALID
    [✓] Message 4: VALID
    [✓] Message 5: VALID

    Summary: 5/5 messages have valid signatures

[4] Computing transcript hash...
    Computed:  abc123def456...
    Expected:  abc123def456...
    [✓] Transcript hash MATCHES

[5] Verifying SessionReceipt signature...
    [✓] Receipt signature VALID

======================================================================
  VERIFICATION RESULT: ✓ ALL CHECKS PASSED
  Non-repudiation evidence is valid and authentic.
======================================================================
```

**Screenshot this output!**

#### Test Tamper Detection

```bash
# Edit the transcript file
notepad transcripts/session_XXXXXXXX_alice.txt

# Change ANY character in the file (e.g., flip one digit)
# Save and exit

# Run verification again
# Verify the receipt
python scripts/verify_receipt_script.py `
  --transcript transcripts/session_XXXXXXXX_alice.txt `
  --receipt transcripts/receipt_XXXXXXXX_alice.json `
  --cert certs/client_cert.pem

# Expected output:
[4] Computing transcript hash...
    Computed:  xyz789abc123...
    Expected:  abc123def456...
    [✗] Transcript hash MISMATCH - transcript may have been modified!

======================================================================
  VERIFICATION RESULT: ✗ VERIFICATION FAILED
  Evidence may have been tampered with or is invalid.
======================================================================
```

**Screenshot this failure!**

---

## 📸 Evidence Collection

### Required Screenshots

1. **Certificate Generation**

   - CA creation output
   - Server certificate issuance
   - Client certificate issuance
   - `openssl x509` inspection output

2. **Database Setup**

   - Table structure (`DESCRIBE users;`)
   - Sample user records (`SELECT * FROM users;`)
   - Salted password hashes visible

3. **Server Running**

   - Server startup message
   - Client connection log
   - Message reception and verification

4. **Client Running**

   - All 6 phases displayed
   - Chat session active
   - Non-repudiation receipt generation

5. **Wireshark Captures**

   - Packet list with tcp.port filter
   - Packet details showing encrypted payloads
   - TCP stream with no readable plaintext
   - Multiple filter examples

6. **Invalid Certificate Test**

   - BAD_CERT error message
   - Connection rejection

7. **Tamper Test**

   - SIG_FAIL error message

8. **Replay Test**

   - REPLAY error with sequence numbers

9. **Non-Repudiation**

   - Successful verification output
   - Failed verification after tampering

10. **Code Quality**
    - GitHub repository showing 10+ commits
    - Clean commit messages
    - No secrets in repository

---

## 💾 MySQL Dump

### Export Complete Database

```bash
# Create folder
mkdir submission

# Go to MySQL bin
cd "C:\Program Files\MySQL\MySQL Server 8.0\bin\"
```

```bash
# Export schema and data
.\mysqldump.exe -u scuser -pscpass --no-tablespaces securechat > "C:\Users\hp\OneDrive\Desktop\Info A2\securechat\submission\securechat_dump.sql"

# Verify export (PowerShell way to count lines)
(Get-Content submission/securechat_dump.sql).Count
# Should show ~50+ lines
```

### Export Schema Only

```bash
# Export just the structure
.\mysqldump.exe -u scuser -pscpass --no-data --no-tablespaces securechat > "C:\Users\hp\OneDrive\Desktop\Info A2\securechat\submission\securechat_schema.sql"
```

### Export Sample Data

```bash
# Export only user records
.\mysqldump.exe -u scuser -pscpass --no-create-info --no-tablespaces securechat users > "C:\Users\hp\OneDrive\Desktop\Info A2\securechat\submission\sample_users.sql"

# View the export
cat submission/sample_users.sql
```

Expected content:

```sql
INSERT INTO `users` VALUES
(1,'alice@example.com','alice',_binary '\x1a\x2b\x3c\x4d...','a1b2c3d4e5f6...','2025-11-15 10:30:00'),
(2,'bob@example.com','bob',_binary '\x9f\x8e\x7d\x6c...','f6e5d4c3b2a1...','2025-11-15 10:35:00');
```

**Include these files in your submission!**

---

## ✅ Pre-Submission Checklist

Before submitting, verify:

- [ ] All certificates generated and verified
- [ ] Database initialized with sample users
- [ ] Server runs without errors
- [ ] Client connects and authenticates successfully
- [ ] Can send and receive encrypted messages
- [ ] Invalid certificate rejected (BAD_CERT)
- [ ] Tampered messages detected (SIG_FAIL)
- [ ] Replayed messages rejected (REPLAY)
- [ ] Non-repudiation verification works
- [ ] Wireshark captures show encryption
- [ ] 10+ meaningful commits on GitHub
- [ ] No secrets committed (.gitignore working)
- [ ] README updated with your information
- [ ] All screenshots collected
- [ ] MySQL dump created

---
