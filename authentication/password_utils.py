"""Password hashing and validation utilities using bcrypt."""

import re
from typing import Tuple
import bcrypt


def hash_password(plain_password: str) -> str:
    """Hash a plain text password using bcrypt with salt.
    
    Args:
        plain_password: Plain text password string.
        
    Returns:
        Decoded UTF-8 string containing the bcrypt hash.
    """
    if not plain_password:
        raise ValueError("Password cannot be empty.")
    
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a bcrypt hash.
    
    Args:
        plain_password: Plain text password string.
        hashed_password: Stored bcrypt hash string.
        
    Returns:
        True if password matches hash, False otherwise.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except Exception:
        return False


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """Validate password against security policy requirements.
    
    Requirements:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one numeric digit
    - At least one special symbol (!@#$%^&*()-_=+[]{}|;:,.<>?)
    
    Returns:
        (is_valid, error_message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]", password):
        return False, "Password must contain at least one special character (!@#$%^&* etc.)."
    
    return True, ""
