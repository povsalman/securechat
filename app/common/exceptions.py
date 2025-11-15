"""
Custom exceptions for SecureChat.
"""


class SecureChatException(Exception):
    """Base exception for SecureChat errors."""
    pass


class CertificateError(SecureChatException):
    """Certificate validation failed."""
    pass


class AuthenticationError(SecureChatException):
    """Authentication failed."""
    pass


class EncryptionError(SecureChatException):
    """Encryption/decryption failed."""
    pass


class SignatureError(SecureChatException):
    """Signature verification failed."""
    pass


class ReplayError(SecureChatException):
    """Replay attack detected."""
    pass


class ProtocolError(SecureChatException):
    """Protocol violation detected."""
    pass


class DatabaseError(SecureChatException):
    """Database operation failed."""
    pass
