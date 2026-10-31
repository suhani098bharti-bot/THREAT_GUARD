"""Unit and integration tests for authentication and password utilities."""

import pytest
import sqlite3
import tempfile
from pathlib import Path

from authentication.auth import authenticate_user, register_user
from authentication.password_utils import (
    hash_password,
    validate_password_strength,
    verify_password,
)
from database.db_setup import initialize_database


@pytest.fixture
def temp_db():
    """Create an isolated temporary SQLite database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_path = Path(f.name)
    
    initialize_database(db_path=temp_path)
    yield temp_path
    
    if temp_path.exists():
        temp_path.unlink()


def test_password_hashing():
    """Test bcrypt hashing security properties."""
    plain = "Secur3P@ssw0rd!"
    hashed = hash_password(plain)
    
    assert hashed != plain
    assert hashed.startswith("$2b$")
    assert verify_password(plain, hashed) is True
    assert verify_password("WrongPassword123!", hashed) is False
    assert verify_password("", hashed) is False


def test_password_validation_rules():
    """Test password strength validation checks."""
    # Too short
    valid, msg = validate_password_strength("Short1!")
    assert not valid
    assert "at least 8 characters" in msg

    # Missing uppercase
    valid, msg = validate_password_strength("lowercase123!@#")
    assert not valid
    assert "uppercase" in msg

    # Missing lowercase
    valid, msg = validate_password_strength("UPPERCASE123!@#")
    assert not valid
    assert "lowercase" in msg

    # Missing digit
    valid, msg = validate_password_strength("NoDigitsHere!@#")
    assert not valid
    assert "digit" in msg

    # Missing special character
    valid, msg = validate_password_strength("NoSpecialChar123")
    assert not valid
    assert "special character" in msg

    # Valid password
    valid, msg = validate_password_strength("ValidP@ssw0rd2026")
    assert valid
    assert msg == ""


def test_user_registration_and_authentication(temp_db):
    """Test user registration and subsequent authentication lifecycle."""
    username = "test_analyst"
    password = "Secur3P@ssw0rd!"

    # Successful registration
    success, msg = register_user(username, password, role="Analyst", db_path=temp_db)
    assert success is True
    assert "successfully" in msg

    # Duplicate registration should fail
    dup_ok, dup_msg = register_user(username, password, role="Analyst", db_path=temp_db)
    assert dup_ok is False
    assert "already exists" in dup_msg

    # Authentication success
    auth_ok, user_dict, auth_msg = authenticate_user(username, password, db_path=temp_db)
    assert auth_ok is True
    assert user_dict is not None
    assert user_dict["username"] == username
    assert user_dict["role"] == "Analyst"
    assert "password_hash" not in user_dict  # Never expose password hash

    # Authentication failure with invalid password
    bad_ok, bad_user, bad_msg = authenticate_user(username, "WrongP@ss123", db_path=temp_db)
    assert bad_ok is False
    assert bad_user is None
    assert "Invalid username or password" in bad_msg

    # Authentication failure with non-existent user
    none_ok, _, _ = authenticate_user("nonexistent_user", password, db_path=temp_db)
    assert none_ok is False


def test_admin_bootstrap_user(temp_db):
    """Test default admin user was bootstrapped correctly during DB init."""
    auth_ok, admin_user, _ = authenticate_user("admin", "Admin@ThreatGuard2026!", db_path=temp_db)
    assert auth_ok is True
    assert admin_user["role"] == "Admin"
