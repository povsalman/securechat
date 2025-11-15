"""
Session Transcript Management for Non-Repudiation

Maintains append-only transcript files containing:
seqno | timestamp | ciphertext | signature | peer_cert_fingerprint

Generates signed SessionReceipts for verification.
"""

import os
import hashlib
import json
from typing import Optional
from app.common.protocol import SessionReceipt
from app.crypto.sign import sign_data


class TranscriptManager:
    """
    Manages session transcripts for non-repudiation.
    """
    
    def __init__(self, session_id: str, transcript_dir: str = "transcripts"):
        """
        Initialize transcript manager.
        
        Args:
            session_id: Unique session identifier
            transcript_dir: Directory to store transcripts
        """
        self.session_id = session_id
        self.transcript_dir = transcript_dir
        self.transcript_path = os.path.join(transcript_dir, f"session_{session_id}.txt")
        self.receipt_path = os.path.join(transcript_dir, f"receipt_{session_id}.json")
        
        # Create transcript directory if it doesn't exist
        os.makedirs(transcript_dir, exist_ok=True)
        
        # Sequence tracking
        self.first_seq = None
        self.last_seq = None
    
    def append_message(
        self,
        seqno: int,
        timestamp: int,
        ciphertext: str,
        signature: str,
        peer_cert_fingerprint: str
    ):
        """
        Append a message to the transcript.
        
        Format: seqno|timestamp|ciphertext|signature|peer_cert_fingerprint
        
        Args:
            seqno: Sequence number
            timestamp: Unix timestamp in milliseconds
            ciphertext: Base64-encoded ciphertext
            signature: Base64-encoded signature
            peer_cert_fingerprint: Hex-encoded certificate fingerprint
        """
        # Track sequence numbers
        if self.first_seq is None:
            self.first_seq = seqno
        self.last_seq = seqno
        
        # Append to transcript file (append-only mode)
        line = f"{seqno}|{timestamp}|{ciphertext}|{signature}|{peer_cert_fingerprint}\n"
        
        with open(self.transcript_path, 'a') as f:
            f.write(line)
    
    def compute_transcript_hash(self) -> str:
        """
        Compute SHA-256 hash of the entire transcript.
        
        Returns:
            Hex-encoded SHA-256 hash of transcript
        """
        hasher = hashlib.sha256()
        
        try:
            with open(self.transcript_path, 'r') as f:
                for line in f:
                    hasher.update(line.encode('utf-8'))
        except FileNotFoundError:
            # Empty transcript
            pass
        
        return hasher.hexdigest()
    
    def generate_receipt(
        self,
        peer_type: str,
        private_key
    ) -> SessionReceipt:
        """
        Generate a signed SessionReceipt for non-repudiation.
        
        Args:
            peer_type: "client" or "server"
            private_key: RSA private key for signing
        
        Returns:
            SessionReceipt object
        """
        # Compute transcript hash
        transcript_hash = self.compute_transcript_hash()
        
        # Sign the transcript hash
        signature = sign_data(bytes.fromhex(transcript_hash), private_key)
        
        # Create receipt
        receipt = SessionReceipt(
            peer=peer_type,
            first_seq=self.first_seq or 0,
            last_seq=self.last_seq or 0,
            transcript_sha256=transcript_hash,
            sig=signature
        )
        
        return receipt
    
    def save_receipt(self, receipt: SessionReceipt):
        """
        Save SessionReceipt to JSON file.
        
        Args:
            receipt: SessionReceipt to save
        """
        with open(self.receipt_path, 'w') as f:
            f.write(receipt.model_dump_json(indent=2))
        
        print(f"[✓] Session receipt saved to: {self.receipt_path}")
    
    def get_message_count(self) -> int:
        """
        Get the number of messages in the transcript.
        
        Returns:
            Number of messages
        """
        try:
            with open(self.transcript_path, 'r') as f:
                return sum(1 for line in f if line.strip())
        except FileNotFoundError:
            return 0


# Test function
if __name__ == "__main__":
    import tempfile
    from cryptography.hazmat.primitives.asymmetric import rsa
    
    print("[*] Testing TranscriptManager")
    
    # Create temporary directory for testing
    with tempfile.TemporaryDirectory() as tmpdir:
        # Initialize transcript manager
        tm = TranscriptManager("test_session", transcript_dir=tmpdir)
        print(f"\n[1] Transcript initialized at: {tm.transcript_path}")
        
        # Add some test messages
        print("\n[2] Adding test messages...")
        for i in range(1, 4):
            tm.append_message(
                seqno=i,
                timestamp=1234567890000 + i * 1000,
                ciphertext=f"ciphertext_{i}",
                signature=f"signature_{i}",
                peer_cert_fingerprint=f"fingerprint_{i}"
            )
        
        message_count = tm.get_message_count()
        print(f"    Messages in transcript: {message_count}")
        
        # Compute transcript hash
        print("\n[3] Computing transcript hash...")
        transcript_hash = tm.compute_transcript_hash()
        print(f"    Transcript hash: {transcript_hash}")
        
        # Generate receipt
        print("\n[4] Generating receipt...")
        test_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        receipt = tm.generate_receipt("client", test_key)
        
        print(f"    Receipt:")
        print(f"      Peer: {receipt.peer}")
        print(f"      First seq: {receipt.first_seq}")
        print(f"      Last seq: {receipt.last_seq}")
        print(f"      Transcript hash: {receipt.transcript_sha256}")
        print(f"      Signature: {receipt.sig[:64]}...")
        
        # Save receipt
        print("\n[5] Saving receipt...")
        tm.save_receipt(receipt)
        
        # Verify receipt file exists
        assert os.path.exists(tm.receipt_path), "Receipt file not created!"
        
    print("\n[✓] TranscriptManager test passed!")
