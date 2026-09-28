from functools import wraps
from flask import request, jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from models import User
import bcrypt
import re

def hash_password(password):
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt(rounds=10)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password, password_hash):
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_phone(phone):
    """Validate phone number (basic validation)"""
    # Remove common separators
    clean_phone = re.sub(r'[\s\-\(\)]+', '', phone)
    # Check if it contains only digits and is 7-15 characters
    return bool(re.match(r'^\d{7,15}$', clean_phone))

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit"
    return True, "Password is valid"

def token_required(f):
    """Decorator to require JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            if not user or user.account_status != 'ACTIVE':
                return jsonify({'success': False, 'message': 'User not found or inactive'}), 401
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({'success': False, 'message': 'Invalid or expired token'}), 401
    return decorated

def role_required(*allowed_roles):
    """Decorator to require specific roles"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            try:
                verify_jwt_in_request()
                user_id = get_jwt_identity()
                user = User.query.get(user_id)
                if not user or user.account_status != 'ACTIVE':
                    return jsonify({'success': False, 'message': 'User not found or inactive'}), 401
                if user.role not in allowed_roles:
                    return jsonify({'success': False, 'message': f'Access denied. Required role: {", ".join(allowed_roles)}'}), 403
                return f(*args, **kwargs)
            except Exception as e:
                return jsonify({'success': False, 'message': 'Invalid or expired token'}), 401
        return decorated
    return decorator

def admin_required(f):
    """Decorator to require admin role"""
    return role_required('ADMIN')(f)

def donor_required(f):
    """Decorator to require donor role"""
    return role_required('DONOR')(f)

def ngo_required(f):
    """Decorator to require NGO role"""
    return role_required('NGO')(f)
