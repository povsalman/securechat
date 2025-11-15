"""
MySQL Database Management for SecureChat Users

Stores user credentials with salted SHA-256 password hashing.
NEVER stores plaintext passwords.
"""

import os
import hashlib
import secrets
import mysql.connector
from typing import Optional, Tuple
from dotenv import load_dotenv
from app.common.exceptions import DatabaseError, AuthenticationError
from app.common.utils import constant_time_compare

# Load environment variables
load_dotenv()


def get_db_connection():
    """
    Create and return a MySQL database connection.
    
    Returns:
        MySQL connection object
    
    Raises:
        DatabaseError: If connection fails
    """
    try:
        conn = mysql.connector.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            port=int(os.getenv('DB_PORT', 3306)),
            database=os.getenv('DB_NAME', 'securechat'),
            user=os.getenv('DB_USER', 'scuser'),
            password=os.getenv('DB_PASSWORD', 'scpass'),
        )
        return conn
    except mysql.connector.Error as e:
        raise DatabaseError(f"Database connection failed: {e}")


def init_db():
    """
    Initialize database schema.
    Creates the users table if it doesn't exist.
    """
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                username VARCHAR(255) UNIQUE NOT NULL,
                salt VARBINARY(16) NOT NULL,
                pwd_hash CHAR(64) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_email (email),
                INDEX idx_username (username)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)
        
        conn.commit()
        print("[✓] Database initialized successfully")
        
    except mysql.connector.Error as e:
        raise DatabaseError(f"Database initialization failed: {e}")
    
    finally:
        if conn:
            conn.close()


def compute_password_hash(password: str, salt: bytes) -> str:
    """
    Compute salted password hash.
    
    Hash = hex(SHA256(salt || password))
    
    Args:
        password: User's password
        salt: 16-byte random salt
    
    Returns:
        Hex-encoded SHA-256 hash (64 characters)
    """
    # Concatenate salt and password
    salted = salt + password.encode('utf-8')
    
    # Compute SHA-256 hash
    hash_bytes = hashlib.sha256(salted).digest()
    
    # Return hex-encoded hash
    return hash_bytes.hex()


def register_user(email: str, username: str, password: str) -> bool:
    """
    Register a new user with salted password hashing.
    
    Args:
        email: User's email address
        username: Username
        password: Plaintext password (will be hashed)
    
    Returns:
        True if registration successful
    
    Raises:
        DatabaseError: If user already exists or database error occurs
    """
    conn = None
    try:
        # Generate random salt (16 bytes)
        salt = secrets.token_bytes(16)
        
        # Compute password hash
        pwd_hash = compute_password_hash(password, salt)
        
        # Insert into database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
            (email, username, salt, pwd_hash)
        )
        
        conn.commit()
        print(f"[✓] User '{username}' registered successfully")
        return True
        
    except mysql.connector.IntegrityError:
        raise DatabaseError("User with this email or username already exists")
    
    except mysql.connector.Error as e:
        raise DatabaseError(f"Registration failed: {e}")
    
    finally:
        if conn:
            conn.close()


def verify_login(email: str, password: str) -> Tuple[bool, Optional[str]]:
    """
    Verify user login credentials.
    
    Uses constant-time comparison to prevent timing attacks.
    
    Args:
        email: User's email
        password: Plaintext password
    
    Returns:
        Tuple of (success, username)
        success: True if credentials are valid
        username: Username if successful, None otherwise
    
    Raises:
        DatabaseError: If database error occurs
    """
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Retrieve user's salt and password hash
        cursor.execute(
            "SELECT username, salt, pwd_hash FROM users WHERE email = %s",
            (email,)
        )
        
        result = cursor.fetchone()
        
        if not result:
            # User not found - still compute a hash to prevent timing attacks
            dummy_salt = secrets.token_bytes(16)
            compute_password_hash(password, dummy_salt)
            return False, None
        
        username, salt, stored_hash = result
        
        # Compute hash with provided password
        computed_hash = compute_password_hash(password, salt)
        
        # Constant-time comparison to prevent timing attacks
        hashes_match = constant_time_compare(
            computed_hash.encode('ascii'),
            stored_hash.encode('ascii')
        )
        
        if hashes_match:
            print(f"[✓] User '{username}' logged in successfully")
            return True, username
        else:
            return False, None
        
    except mysql.connector.Error as e:
        raise DatabaseError(f"Login verification failed: {e}")
    
    finally:
        if conn:
            conn.close()


def user_exists(email: str = None, username: str = None) -> bool:
    """
    Check if a user exists by email or username.
    
    Args:
        email: Email to check (optional)
        username: Username to check (optional)
    
    Returns:
        True if user exists, False otherwise
    """
    if not email and not username:
        raise ValueError("Must provide either email or username")
    
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if email:
            cursor.execute("SELECT 1 FROM users WHERE email = %s", (email,))
        else:
            cursor.execute("SELECT 1 FROM users WHERE username = %s", (username,))
        
        return cursor.fetchone() is not None
        
    except mysql.connector.Error as e:
        raise DatabaseError(f"User existence check failed: {e}")
    
    finally:
        if conn:
            conn.close()


# CLI for database management
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Database management for SecureChat")
    parser.add_argument("--init", action="store_true", help="Initialize database schema")
    parser.add_argument("--register", action="store_true", help="Register a test user")
    parser.add_argument("--test-login", action="store_true", help="Test login")
    
    args = parser.parse_args()
    
    if args.init:
        print("[*] Initializing database...")
        init_db()
    
    elif args.register:
        print("[*] Registering test user...")
        try:
            register_user("test@example.com", "testuser", "testpass123")
            print("[✓] Test user registered")
        except DatabaseError as e:
            print(f"[✗] Registration failed: {e}")
    
    elif args.test_login:
        print("[*] Testing login...")
        try:
            success, username = verify_login("test@example.com", "testpass123")
            if success:
                print(f"[✓] Login successful for user: {username}")
            else:
                print("[✗] Login failed")
        except DatabaseError as e:
            print(f"[✗] Login test failed: {e}")
    
    else:
        parser.print_help()
