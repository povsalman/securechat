# Manual Testing Notes for SecureChat

## Test Environment Setup

### Prerequisites

- Python 3.8+
- MySQL 8.0
- Wireshark installed
- OpenSSL command-line tools

### Initial Setup

```bash
# 1. Setup virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 2. Configure environment
cp .env.example .env
# Edit .env with your MySQL credentials

# 3. Start MySQL
docker run -d --name securechat-db \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat \
  -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass \
  -p 3306:3306 mysql:8

# 4. Initialize database
python -m app.storage.db --init

# 5. Generate certificates
python scripts/gen_ca.py --name "FAST-NU Root CA"
python scripts/gen_cert.py --cn server.local --out certs/server --server
python scripts/gen_cert.py --cn client.local --out certs/client
```

## Test Procedures

### Test 1: Certificate Validation

**Objective**: Verify that invalid certificates are rejected.

**Procedure**:

1. Generate a self-signed certificate (not signed by CA):

```bash
openssl req -newkey rsa:2048 -nodes -keyout certs/fake_key.pem \
  -x509 -days 1 -out certs/fake_cert.pem -subj "/CN=fake.local"
```

2. Modify `client.py` to temporarily use the fake certificate

3. Run server and client

**Expected Result**:

- Server should reject connection with error message: `BAD_CERT`
- Connection should be terminated

**Screenshot**: Save terminal output showing `BAD_CERT` error

---

### Test 2: Expired Certificate

**Objective**: Verify expired certificates are rejected.

**Procedure**:

1. Generate an expired certificate:

```bash
python scripts/gen_cert.py --cn expired.local --out certs/expired --days -1
```

2. Use expired certificate in client

**Expected Result**:

- Validation fails with message: "Certificate expired"

---

### Test 3: Wireshark Packet Capture

**Objective**: Verify all sensitive data is encrypted.

**Procedure**:

1. Start Wireshark, capture on loopback interface (lo or lo0)

2. Apply display filter: `bash tcp.port == 5000 `

3. Start server and client, perform complete session:

   - Registration
   - Send 3-5 messages
   - Exit

4. Stop capture and analyze packets

**Expected Observations**:

- No plaintext passwords visible
- No plaintext messages visible
- All payload data appears as base64/encrypted
- JSON structure visible but content encrypted

**Display Filters to Use**:

```bash
tcp.port == 5000
tcp.stream eq 0
frame contains "hello"
```

**Screenshot**:

- Packet list showing encrypted traffic
- Packet details showing base64 ciphertext
- Follow TCP Stream showing no plaintext

---

### Test 4: Message Tampering

**Objective**: Verify that tampered messages are detected.

**Procedure**:

1. Setup: Run server and client, establish session

2. Modify client code to flip one bit in ciphertext:

```python
# In send_message() function, after encryption:
ct_bytes = base64.b64decode(ct)
ct_bytes = bytearray(ct_bytes)
ct_bytes[0] ^= 0x01  # Flip one bit
ct = base64.b64encode(ct_bytes).decode('ascii')
```

3. Send message

**Expected Result**:

- Server detects signature verification failure
- Returns error: `SIG_FAIL`
- Message is not processed

**Screenshot**: Terminal showing `SIG_FAIL` error

---

### Test 5: Replay Attack

**Objective**: Verify replay protection works.

**Procedure**:

1. Capture a valid message (save the JSON)

2. Send the same message twice without incrementing seqno

3. Modify client to send message:

```python
# Send same message twice
self.send_message("Test message")
# Don't increment seqno, send again
self.seqno -= 1
self.send_message("Test message")
```

**Expected Result**:

- Server rejects second message
- Returns error: `REPLAY`
- Shows expected vs received sequence number

**Screenshot**: Terminal showing `REPLAY` error

---

### Test 6: Non-Repudiation Verification

**Objective**: Verify session receipts can be verified offline.

**Procedure**:

1. Complete a chat session (send 5+ messages)

2. Exit and generate receipts

3. Verify receipt using script:

```bash
python scripts/verify_receipt.py \
  --transcript transcripts/session_XXXXX.txt \
  --receipt transcripts/receipt_XXXXX.json \
  --cert certs/client_cert.pem
```

4. Manually edit transcript file (change one character)

5. Run verification again

**Expected Results**:

- First verification: All checks pass ✓
- Second verification: Transcript hash mismatch ✗

**Screenshot**:

- Successful verification output
- Failed verification after tampering

---

## Test Evidence Checklist

Test Report, include:

- [ ] Screenshot: BAD_CERT rejection for invalid certificate
- [ ] Screenshot: Wireshark capture showing encrypted traffic (3+ images)
- [ ] Screenshot: Wireshark display filters used
- [ ] Screenshot: SIG_FAIL error for tampered message
- [ ] Screenshot: REPLAY error for replayed message
- [ ] Screenshot: Successful receipt verification
- [ ] Screenshot: Failed verification after transcript modification
- [ ] Screenshot: Database with registered users
- [ ] Terminal logs showing complete session flow

## MySQL Dump Command

```bash
# Export schema and sample data
mysqldump -u scuser -pscpass securechat > submission/securechat_dump.sql

# Or export just schema:
mysqldump -u scuser -pscpass --no-data securechat > submission/securechat_schema.sql

# Export sample records:
mysqldump -u scuser -pscpass --no-create-info securechat users > submission/sample_users.sql
```

---

## Common Issues and Solutions

### Issue: "Connection refused" when running client

**Solution**: Ensure server is running first

### Issue: Database connection error

**Solution**: Check MySQL is running and .env credentials are correct

### Issue: Certificate validation fails

**Solution**: Ensure all certificates are generated and paths in .env are correct

### Issue: "Module not found" errors

**Solution**: Ensure you're in the virtual environment and installed requirements.txt
