"""
Storage modules for SecureChat.

Includes:
- Database (MySQL) for user credentials
- Transcript management for non-repudiation
"""

from .db import init_db, register_user, verify_login, user_exists
from .transcript import TranscriptManager

__all__ = [
    'init_db',
    'register_user',
    'verify_login',
    'user_exists',
    'TranscriptManager',
]
