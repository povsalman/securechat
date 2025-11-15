"""
Protocol message definitions using Pydantic.

All messages are serialized to/from JSON for transmission over TCP.
"""

from typing import Optional, Literal
from pydantic import BaseModel, Field


class HelloMessage(BaseModel):
    """Initial client hello with certificate."""
    type: Literal["hello"] = "hello"
    client_cert: str = Field(..., description="PEM-encoded client certificate")
    nonce: str = Field(..., description="Base64-encoded random nonce")


class ServerHelloMessage(BaseModel):
    """Server hello response with certificate."""
    type: Literal["server_hello"] = "server_hello"
    server_cert: str = Field(..., description="PEM-encoded server certificate")
    nonce: str = Field(..., description="Base64-encoded random nonce")


class DHClientMessage(BaseModel):
    """Client DH parameters and public key (temporary for auth)."""
    type: Literal["dh_client"] = "dh_client"
    g: int = Field(..., description="DH generator")
    p: int = Field(..., description="DH prime modulus")
    A: int = Field(..., description="Client's DH public key (g^a mod p)")


class DHServerMessage(BaseModel):
    """Server DH public key (temporary for auth)."""
    type: Literal["dh_server"] = "dh_server"
    B: int = Field(..., description="Server's DH public key (g^b mod p)")


class RegisterMessage(BaseModel):
    """User registration message (encrypted with temp DH key)."""
    type: Literal["register"] = "register"
    email: str
    username: str
    pwd: str = Field(..., description="Base64-encoded salted password hash")
    salt: str = Field(..., description="Base64-encoded salt")


class LoginMessage(BaseModel):
    """User login message (encrypted with temp DH key)."""
    type: Literal["login"] = "login"
    email: str
    pwd: str = Field(..., description="Base64-encoded salted password hash")
    nonce: str = Field(..., description="Base64-encoded nonce for freshness")


class AuthResponseMessage(BaseModel):
    """Authentication response from server."""
    type: Literal["auth_response"] = "auth_response"
    success: bool
    message: str
    username: Optional[str] = None


class DHSessionClientMessage(BaseModel):
    """Client DH for session key establishment."""
    type: Literal["dh_session_client"] = "dh_session_client"
    g: int = Field(..., description="DH generator")
    p: int = Field(..., description="DH prime modulus")
    A: int = Field(..., description="Client's DH public key")


class DHSessionServerMessage(BaseModel):
    """Server DH for session key establishment."""
    type: Literal["dh_session_server"] = "dh_session_server"
    B: int = Field(..., description="Server's DH public key")


class ChatMessage(BaseModel):
    """Encrypted chat message with signature."""
    type: Literal["msg"] = "msg"
    seqno: int = Field(..., description="Sequence number for replay protection")
    ts: int = Field(..., description="Unix timestamp in milliseconds")
    ct: str = Field(..., description="Base64-encoded AES ciphertext")
    sig: str = Field(..., description="Base64-encoded RSA signature over SHA256(seqno||ts||ct)")


class SessionReceipt(BaseModel):
    """Session receipt for non-repudiation."""
    type: Literal["receipt"] = "receipt"
    peer: Literal["client", "server"]
    first_seq: int
    last_seq: int
    transcript_sha256: str = Field(..., description="Hex-encoded SHA-256 of transcript")
    sig: str = Field(..., description="Base64-encoded RSA signature over transcript_sha256")


class ErrorMessage(BaseModel):
    """Error message."""
    type: Literal["error"] = "error"
    code: str = Field(..., description="Error code (e.g., BAD_CERT, SIG_FAIL, REPLAY)")
    message: str = Field(..., description="Human-readable error message")


# Helper functions for serialization

def serialize_message(msg: BaseModel) -> str:
    """Serialize Pydantic message to JSON string."""
    return msg.model_dump_json()


def deserialize_message(json_str: str) -> dict:
    """Deserialize JSON string to dictionary."""
    import json
    return json.loads(json_str)


# Test function
if __name__ == "__main__":
    import json
    
    print("[*] Testing protocol messages")
    
    # Test HelloMessage
    hello = HelloMessage(
        client_cert="-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
        nonce="abcd1234=="
    )
    print(f"\n[1] HelloMessage:")
    print(f"    {hello.model_dump_json(indent=2)}")
    
    # Test ChatMessage
    chat = ChatMessage(
        seqno=1,
        ts=1234567890000,
        ct="aGVsbG8gd29ybGQ=",
        sig="c2lnbmF0dXJl"
    )
    print(f"\n[2] ChatMessage:")
    print(f"    {chat.model_dump_json(indent=2)}")
    
    # Test SessionReceipt
    receipt = SessionReceipt(
        peer="client",
        first_seq=1,
        last_seq=10,
        transcript_sha256="abc123...",
        sig="signature123..."
    )
    print(f"\n[3] SessionReceipt:")
    print(f"    {receipt.model_dump_json(indent=2)}")
    
    # Test serialization/deserialization
    serialized = serialize_message(chat)
    deserialized = deserialize_message(serialized)
    reconstructed = ChatMessage(**deserialized)
    
    print(f"\n[4] Serialization test:")
    print(f"    Original seqno: {chat.seqno}")
    print(f"    Reconstructed seqno: {reconstructed.seqno}")
    assert chat.seqno == reconstructed.seqno
    
    print("\n[✓] Protocol message test passed!")