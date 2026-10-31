"""Session-based authentication and role-based access control (RBAC) for ThreatGuard."""

import re
from typing import Any, Dict, Optional, Tuple, Union
from pathlib import Path
import streamlit as st

from authentication.password_utils import (
    hash_password,
    validate_password_strength,
    verify_password,
)
from database.db_operations import create_user, get_user_by_username


def init_session_state() -> None:
    """Initialize authentication session state variables."""
    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False
    if "user" not in st.session_state:
        st.session_state["user"] = None
    if "username" not in st.session_state:
        st.session_state["username"] = ""
    if "role" not in st.session_state:
        st.session_state["role"] = ""


def is_authenticated() -> bool:
    """Check if a user is currently logged in."""
    init_session_state()
    return bool(st.session_state.get("authenticated", False))


def get_current_user() -> Optional[Dict[str, Any]]:
    """Retrieve details of the currently authenticated user."""
    init_session_state()
    return st.session_state.get("user")


def get_current_role() -> str:
    """Get the active user's role (Admin/Analyst) or empty string."""
    init_session_state()
    return st.session_state.get("role", "")


def is_admin() -> bool:
    """Check if current user has Admin privileges."""
    return get_current_role() == "Admin"


def authenticate_user(
    username: str, password: str, db_path: Optional[Union[str, Path]] = None
) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    """Verify credentials and return user record if authenticated."""
    username = (username or "").strip()
    if not username or not password:
        return False, None, "Please enter both username and password."

    user = get_user_by_username(username, db_path=db_path)
    if not user:
        return False, None, "Invalid username or password."

    if not verify_password(password, user["password_hash"]):
        return False, None, "Invalid username or password."

    # Return safe user dict without password hash
    safe_user = {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "created_at": user.get("created_at"),
    }
    return True, safe_user, "Authentication successful."


def login(user_dict: Dict[str, Any]) -> None:
    """Establish authenticated session in Streamlit session state."""
    init_session_state()
    st.session_state["authenticated"] = True
    st.session_state["user"] = user_dict
    st.session_state["username"] = user_dict.get("username", "")
    st.session_state["role"] = user_dict.get("role", "Analyst")


def logout() -> None:
    """Clear authenticated session."""
    init_session_state()
    st.session_state["authenticated"] = False
    st.session_state["user"] = None
    st.session_state["username"] = ""
    st.session_state["role"] = ""


def register_user(
    username: str,
    password: str,
    role: str = "Analyst",
    db_path: Optional[Union[str, Path]] = None,
) -> Tuple[bool, str]:
    """Validate registration parameters, enforce password policy, and create user."""
    username = (username or "").strip()
    
    # Input validation
    if not username:
        return False, "Username cannot be empty."
    if len(username) < 3 or len(username) > 30:
        return False, "Username must be between 3 and 30 characters."
    if not re.match(r"^[a-zA-Z0-9_\-\.]+$", username):
        return False, "Username may only contain letters, numbers, hyphens, and underscores."
    
    # Check if username already exists
    existing = get_user_by_username(username, db_path=db_path)
    if existing:
        return False, "A user with this username already exists."

    # Validate password strength
    valid_pwd, pwd_error = validate_password_strength(password)
    if not valid_pwd:
        return False, pwd_error

    # Validate role
    if role not in ["Admin", "Analyst"]:
        return False, "Invalid role specified."

    # Hash password and persist
    try:
        hashed = hash_password(password)
        create_user(username, hashed, role=role, db_path=db_path)
        return True, "User registered successfully! You may now log in."
    except Exception as e:
        return False, f"Failed to register user: {str(e)}"


def enforce_authentication() -> bool:
    """Guard helper for multi-page apps.
    
    Returns True if authenticated, else renders an alert and stops page execution.
    """
    init_session_state()
    if not is_authenticated():
        st.warning("⚠️ Access Restricted: Please log in from the main portal to access this page.")
        st.info("Navigate to the **ThreatGuard Home / Login** page using the sidebar to authenticate.")
        st.stop()
        return False
    return True


def enforce_admin() -> bool:
    """Guard helper requiring Admin privileges.
    
    Returns True if Admin, else renders an alert and stops page execution.
    """
    enforce_authentication()
    if not is_admin():
        st.error("⛔ Access Denied: Administrator role required for this feature.")
        st.info(f"Your current role is **{get_current_role()}**. Contact your system administrator.")
        st.stop()
        return False
    return True
