# myground/utils/mfa_utils.py
import pyotp
import qrcode
import qrcode.image.svg
import base64
import random
import string
from io import BytesIO
from django.core.cache import cache
from django.utils import timezone

def generate_secret_key():
    """Generate a random secret key for TOTP"""
    return pyotp.random_base32()

def generate_qr_code(secret_key, email, issuer_name="Cloud Management"):
    """Generate QR code as base64 string"""
    totp = pyotp.TOTP(secret_key)
    uri = totp.provisioning_uri(name=email, issuer_name=issuer_name)
    
    # Generate QR code
    img = qrcode.make(uri)
    
    # Convert to base64
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return f"data:image/png;base64,{img_str}"

def generate_backup_codes(count=10):
    """Generate backup codes - XXXX-XXXX-XXXX format (14 characters)"""
    codes = []
    for _ in range(count):
        # Format: XXXX-XXXX-XXXX (12 characters + 2 hyphens = 14 total)
        code = '-'.join([
            ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
            for _ in range(3)  # Changed from 4 to 3
        ])
        codes.append(code)
    return codes

def verify_totp_code(secret_key, code):
    """Verify TOTP code with tolerance"""
    totp = pyotp.TOTP(secret_key)
    return totp.verify(code, valid_window=1)  # Allow 30 seconds before/after

def check_rate_limit(user_id, action, limit=5, window=300):
    """Rate limiting for MFA attempts"""
    cache_key = f"mfa_rate_limit:{user_id}:{action}"
    attempts = cache.get(cache_key, 0)
    
    if attempts >= limit:
        return False
    
    cache.set(cache_key, attempts + 1, window)
    return True