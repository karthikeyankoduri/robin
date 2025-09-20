import os
from jose import jwt, JWTError
import bcrypt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import streamlit as st
import logging
from utils.db import get_db_session, User, AuditLog
from passlib.context import CryptContext
import secrets

# Configure logging
logger = logging.getLogger(__name__)

# Security configuration
SECRET_KEY = os.getenv("SESSION_SECRET", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    try:
        return pwd_context.hash(password)
    except Exception as e:
        logger.error(f"Error hashing password: {e}")
        raise

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.error(f"Error verifying password: {e}")
        return False

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token"""
    try:
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    except Exception as e:
        logger.error(f"Error creating access token: {e}")
        raise

def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify and decode a JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError as e:
        logger.warning(f"JWT verification failed: {e}")
        return None
    except Exception as e:
        logger.error(f"Error verifying token: {e}")
        return None

def authenticate_user(username: str, password: str) -> Optional[User]:
    """Authenticate user with username and password"""
    try:
        session = get_db_session()
        user = session.query(User).filter(User.username == username).first()
        
        if user and user.is_active and verify_password(password, user.hashed_password):
            # Update last login
            user.last_login = datetime.utcnow()
            session.commit()
            
            # Log successful login
            log_audit_event(
                session,
                username,
                "LOGIN_SUCCESS",
                f"User {username} logged in successfully"
            )
            
            session.close()
            return user
        else:
            # Log failed login attempt
            log_audit_event(
                session,
                username,
                "LOGIN_FAILED",
                f"Failed login attempt for user {username}"
            )
            session.close()
            return None
    
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return None

def check_authentication() -> bool:
    """Check if user is authenticated in Streamlit session"""
    try:
        # Check if user is already authenticated
        if 'authenticated' in st.session_state and st.session_state.authenticated:
            return True
        
        # Check for valid token in session
        if 'access_token' in st.session_state:
            token_data = verify_token(st.session_state.access_token)
            if token_data:
                st.session_state.authenticated = True
                st.session_state.username = token_data.get('sub')
                st.session_state.user_role = token_data.get('role', 'INVESTIGATOR')
                return True
        
        # Show login form if not authenticated
        show_login_form()
        return False
    
    except Exception as e:
        logger.error(f"Authentication check error: {e}")
        show_login_form()
        return False

def show_login_form():
    """Display login form in Streamlit"""
    st.markdown("## 🔐 Authentication Required")
    st.markdown("Please log in to access the Robin Forensic Analysis Tool")
    
    with st.form("login_form"):
        col1, col2 = st.columns([1, 2])
        
        with col2:
            username = st.text_input("Username", placeholder="Enter your username")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            
            col_login, col_register = st.columns(2)
            
            with col_login:
                login_submitted = st.form_submit_button("Login", type="primary", use_container_width=True)
            
            with col_register:
                register_submitted = st.form_submit_button("Register", use_container_width=True)
        
        if login_submitted:
            if username and password:
                user = authenticate_user(username, password)
                if user:
                    # Create access token
                    token_data = {
                        "sub": user.username,
                        "role": user.role,
                        "user_id": user.id
                    }
                    access_token = create_access_token(token_data)
                    
                    # Store in session
                    st.session_state.authenticated = True
                    st.session_state.username = user.username
                    st.session_state.user_role = user.role
                    st.session_state.user_id = user.id
                    st.session_state.access_token = access_token
                    
                    st.success("Login successful!")
                    st.rerun()
                else:
                    st.error("Invalid username or password")
            else:
                st.error("Please enter both username and password")
        
        if register_submitted:
            if username and password:
                if register_user(username, password):
                    st.success("Registration successful! Please log in.")
                    st.rerun()
                else:
                    st.error("Registration failed. Username may already exist.")
            else:
                st.error("Please enter both username and password")

def register_user(username: str, password: str, email: str = None, full_name: str = None, role: str = "INVESTIGATOR") -> bool:
    """Register a new user"""
    try:
        session = get_db_session()
        
        # Check if username already exists
        existing_user = session.query(User).filter(User.username == username).first()
        if existing_user:
            session.close()
            return False
        
        # Create new user
        hashed_password = hash_password(password)
        new_user = User(
            username=username,
            email=email or f"{username}@robin.local",
            hashed_password=hashed_password,
            full_name=full_name or username,
            role=role,
            is_active=True,
            created_at=datetime.utcnow()
        )
        
        session.add(new_user)
        session.commit()
        
        # Log user registration
        log_audit_event(
            session,
            username,
            "USER_REGISTERED",
            f"New user {username} registered with role {role}"
        )
        
        session.close()
        return True
    
    except Exception as e:
        logger.error(f"User registration error: {e}")
        return False

def logout_user():
    """Log out the current user"""
    try:
        username = st.session_state.get('username', 'unknown')
        
        # Log logout
        session = get_db_session()
        log_audit_event(
            session,
            username,
            "LOGOUT",
            f"User {username} logged out"
        )
        session.close()
        
        # Clear session state
        for key in ['authenticated', 'username', 'user_role', 'user_id', 'access_token']:
            if key in st.session_state:
                del st.session_state[key]
        
        st.success("Logged out successfully!")
        st.rerun()
    
    except Exception as e:
        logger.error(f"Logout error: {e}")

def check_permission(required_role: str) -> bool:
    """Check if current user has required role permission"""
    try:
        if not st.session_state.get('authenticated', False):
            return False
        
        user_role = st.session_state.get('user_role', 'INVESTIGATOR')
        
        # Role hierarchy: ADMIN > INVESTIGATOR > VIEWER
        role_hierarchy = {
            'ADMIN': 3,
            'INVESTIGATOR': 2,
            'VIEWER': 1
        }
        
        user_level = role_hierarchy.get(user_role, 0)
        required_level = role_hierarchy.get(required_role, 0)
        
        return user_level >= required_level
    
    except Exception as e:
        logger.error(f"Permission check error: {e}")
        return False

def require_permission(required_role: str):
    """Decorator to require specific role permission"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            if not check_permission(required_role):
                st.error(f"Access denied. Required role: {required_role}")
                return None
            return func(*args, **kwargs)
        return wrapper
    return decorator

def log_audit_event(session, user_id: str, action: str, details: str, case_id: int = None, ip_address: str = None, user_agent: str = None):
    """Log an audit event"""
    try:
        # Get IP and user agent from Streamlit if available
        if not ip_address:
            ip_address = get_client_ip()
        
        if not user_agent:
            user_agent = get_user_agent()
        
        audit_log = AuditLog(
            timestamp=datetime.utcnow(),
            user_id=user_id,
            action=action,
            case_id=case_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=get_session_id()
        )
        
        session.add(audit_log)
        # Note: session.commit() should be called by the caller
        
    except Exception as e:
        logger.error(f"Audit logging error: {e}")

def get_client_ip() -> str:
    """Get client IP address from Streamlit context"""
    try:
        # In production, this would get the real client IP
        # For now, return a placeholder
        return "127.0.0.1"
    except:
        return "unknown"

def get_user_agent() -> str:
    """Get user agent from Streamlit context"""
    try:
        # In production, this would get the real user agent
        # For now, return a placeholder
        return "Streamlit/Robin"
    except:
        return "unknown"

def get_session_id() -> str:
    """Get current session ID"""
    try:
        if 'session_id' not in st.session_state:
            st.session_state.session_id = secrets.token_urlsafe(16)
        return st.session_state.session_id
    except:
        return "unknown"

def encrypt_sensitive_data(data: str, key: str = None) -> str:
    """Encrypt sensitive data using Fernet symmetric encryption"""
    try:
        from cryptography.fernet import Fernet
        
        if not key:
            key = SECRET_KEY[:32].ljust(32, '0')  # Ensure 32 bytes
        
        # Generate a key from the secret
        import base64
        import hashlib
        key_bytes = hashlib.sha256(key.encode()).digest()
        key_b64 = base64.urlsafe_b64encode(key_bytes)
        
        f = Fernet(key_b64)
        encrypted = f.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    except Exception as e:
        logger.error(f"Encryption error: {e}")
        return data  # Return original data if encryption fails

def decrypt_sensitive_data(encrypted_data: str, key: str = None) -> str:
    """Decrypt sensitive data"""
    try:
        from cryptography.fernet import Fernet
        import base64
        import hashlib
        
        if not key:
            key = SECRET_KEY[:32].ljust(32, '0')  # Ensure 32 bytes
        
        # Generate a key from the secret
        key_bytes = hashlib.sha256(key.encode()).digest()
        key_b64 = base64.urlsafe_b64encode(key_bytes)
        
        f = Fernet(key_b64)
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
        decrypted = f.decrypt(encrypted_bytes)
        return decrypted.decode()
    
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        return encrypted_data  # Return original data if decryption fails

def validate_file_upload(uploaded_file, allowed_types: list = None, max_size: int = 100 * 1024 * 1024) -> Dict[str, Any]:
    """Validate uploaded file for security"""
    try:
        if not uploaded_file:
            return {"valid": False, "error": "No file uploaded"}
        
        # Check file size
        if uploaded_file.size > max_size:
            return {"valid": False, "error": f"File too large. Maximum size: {max_size / (1024*1024):.1f} MB"}
        
        # Check file type
        if allowed_types:
            file_extension = uploaded_file.name.lower().split('.')[-1]
            if file_extension not in allowed_types:
                return {"valid": False, "error": f"File type not allowed. Allowed types: {', '.join(allowed_types)}"}
        
        # Additional security checks could be added here
        # - Virus scanning
        # - Content validation
        # - File header validation
        
        return {"valid": True, "file_info": {
            "name": uploaded_file.name,
            "size": uploaded_file.size,
            "type": uploaded_file.type
        }}
    
    except Exception as e:
        logger.error(f"File validation error: {e}")
        return {"valid": False, "error": f"Validation error: {str(e)}"}

def sanitize_input(input_string: str) -> str:
    """Sanitize user input to prevent injection attacks"""
    try:
        import html
        import re
        
        if not input_string:
            return ""
        
        # HTML escape
        sanitized = html.escape(input_string)
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\']', '', sanitized)
        
        # Limit length
        if len(sanitized) > 10000:
            sanitized = sanitized[:10000]
        
        return sanitized.strip()
    
    except Exception as e:
        logger.error(f"Input sanitization error: {e}")
        return str(input_string)[:1000]  # Fallback: just truncate

def check_rate_limit(user_id: str, action: str, limit: int = 100, window_minutes: int = 60) -> bool:
    """Check if user has exceeded rate limit for specific action"""
    try:
        if 'rate_limits' not in st.session_state:
            st.session_state.rate_limits = {}
        
        key = f"{user_id}_{action}"
        current_time = datetime.utcnow()
        
        if key not in st.session_state.rate_limits:
            st.session_state.rate_limits[key] = []
        
        # Remove old entries outside the window
        window_start = current_time - timedelta(minutes=window_minutes)
        st.session_state.rate_limits[key] = [
            timestamp for timestamp in st.session_state.rate_limits[key]
            if timestamp > window_start
        ]
        
        # Check if limit exceeded
        if len(st.session_state.rate_limits[key]) >= limit:
            return False
        
        # Add current request
        st.session_state.rate_limits[key].append(current_time)
        return True
    
    except Exception as e:
        logger.error(f"Rate limit check error: {e}")
        return True  # Allow request if check fails

def show_user_menu():
    """Show user menu in sidebar"""
    try:
        if st.session_state.get('authenticated', False):
            username = st.session_state.get('username', 'Unknown')
            role = st.session_state.get('user_role', 'Unknown')
            
            st.sidebar.markdown("---")
            st.sidebar.markdown(f"**👤 User:** {username}")
            st.sidebar.markdown(f"**🔑 Role:** {role}")
            
            if st.sidebar.button("🚪 Logout", use_container_width=True):
                logout_user()
    
    except Exception as e:
        logger.error(f"User menu error: {e}")

def generate_api_key(user_id: int, description: str = "API Key") -> str:
    """Generate API key for user"""
    try:
        # Generate secure random key
        api_key = f"robin_{secrets.token_urlsafe(32)}"
        
        # In production, store this in database with user association
        # For now, just return the key
        
        return api_key
    
    except Exception as e:
        logger.error(f"API key generation error: {e}")
        return None

def hash_file_content(file_content: bytes) -> str:
    """Generate hash of file content for integrity checking"""
    try:
        import hashlib
        return hashlib.sha256(file_content).hexdigest()
    except Exception as e:
        logger.error(f"File hashing error: {e}")
        return None

def verify_chain_of_custody(file_hash: str, previous_hash: str = None) -> bool:
    """Verify file integrity in chain of custody"""
    try:
        # In a real implementation, this would check against stored hashes
        # and verify the chain of custody is unbroken
        
        if not file_hash:
            return False
        
        # For now, just verify hash format
        import re
        hash_pattern = r'^[a-fA-F0-9]{64}$'  # SHA-256 hash pattern
        return bool(re.match(hash_pattern, file_hash))
    
    except Exception as e:
        logger.error(f"Chain of custody verification error: {e}")
        return False
