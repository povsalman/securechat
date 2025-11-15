"""
Diffie-Hellman Key Exchange

Implements classical DH key exchange and derives AES-128 session keys.
"""

import hashlib
import secrets
from typing import Tuple


# RFC 3526 - 2048-bit MODP Group (Group 14)
# This is a safe prime for DH key exchange
DH_PRIME_2048 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)

DH_GENERATOR = 2


def generate_params() -> Tuple[int, int]:
    """
    Generate DH public parameters (p, g).
    
    Returns:
        Tuple of (prime p, generator g)
    """
    return (DH_PRIME_2048, DH_GENERATOR)


def generate_keypair(p: int, g: int) -> Tuple[int, int]:
    """
    Generate a DH keypair.
    
    Args:
        p: Prime modulus
        g: Generator
    
    Returns:
        Tuple of (private_key, public_key)
        private_key: Random integer in range [2, p-2]
        public_key: g^private_key mod p
    """
    # Generate private key (random integer)
    # We use bit_length to ensure the private key is large enough
    private_key = secrets.randbelow(p - 2) + 2
    
    # Compute public key: g^private_key mod p
    public_key = pow(g, private_key, p)
    
    return (private_key, public_key)


def compute_shared_secret(private_key: int, peer_public_key: int, p: int) -> int:
    """
    Compute the shared secret using peer's public key.
    
    Args:
        private_key: Own private key
        peer_public_key: Peer's public key (A or B)
        p: Prime modulus
    
    Returns:
        Shared secret K_s = peer_public_key^private_key mod p
    """
    return pow(peer_public_key, private_key, p)


def derive_aes_key(shared_secret: int) -> bytes:
    """
    Derive AES-128 key from DH shared secret.
    
    The key is derived as:
        K = Trunc_16(SHA256(big_endian(K_s)))
    
    Args:
        shared_secret: DH shared secret (integer)
    
    Returns:
        16-byte AES key
    """
    # Convert shared secret to bytes (big-endian)
    # We need to determine the byte length
    byte_length = (shared_secret.bit_length() + 7) // 8
    shared_secret_bytes = shared_secret.to_bytes(byte_length, byteorder='big')
    
    # Compute SHA-256 hash
    hash_digest = hashlib.sha256(shared_secret_bytes).digest()
    
    # Truncate to first 16 bytes for AES-128
    aes_key = hash_digest[:16]
    
    return aes_key


# Test function for development
if __name__ == "__main__":
    print("[*] Testing Diffie-Hellman Key Exchange")
    
    # Generate parameters
    p, g = generate_params()
    print(f"\n[1] Parameters generated:")
    print(f"    p (prime): {p} ({p.bit_length()} bits)")
    print(f"    g (generator): {g}")
    
    # Alice generates keypair
    alice_private, alice_public = generate_keypair(p, g)
    print(f"\n[2] Alice's keypair:")
    print(f"    Private: {alice_private} ({alice_private.bit_length()} bits)")
    print(f"    Public: {alice_public} ({alice_public.bit_length()} bits)")
    
    # Bob generates keypair
    bob_private, bob_public = generate_keypair(p, g)
    print(f"\n[3] Bob's keypair:")
    print(f"    Private: {bob_private} ({bob_private.bit_length()} bits)")
    print(f"    Public: {bob_public} ({bob_public.bit_length()} bits)")
    
    # Both compute shared secret
    alice_shared = compute_shared_secret(alice_private, bob_public, p)
    bob_shared = compute_shared_secret(bob_private, alice_public, p)
    
    print(f"\n[4] Shared secrets:")
    print(f"    Alice computed: {alice_shared}")
    print(f"    Bob computed:   {bob_shared}")
    print(f"    Match: {alice_shared == bob_shared}")
    
    # Derive AES keys
    alice_aes_key = derive_aes_key(alice_shared)
    bob_aes_key = derive_aes_key(bob_shared)
    
    print(f"\n[5] Derived AES-128 keys:")
    print(f"    Alice's key: {alice_aes_key.hex()}")
    print(f"    Bob's key:   {bob_aes_key.hex()}")
    print(f"    Match: {alice_aes_key == bob_aes_key}")
    
    assert alice_shared == bob_shared, "Shared secrets don't match!"
    assert alice_aes_key == bob_aes_key, "AES keys don't match!"
    
    print("\n[✓] Diffie-Hellman key exchange test passed!")
