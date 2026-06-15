from django.shortcuts import render
from django.shortcuts import redirect
from django.http import HttpResponse
from django.contrib import messages
from .low_level_db_service import LowLevelServiceDB
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User, auth
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate, get_user_model
from django.conf import settings
from rest_framework.permissions import AllowAny
from rest_framework import status
import requests
import base64
from django.core.mail import send_mail
import random
from rest_framework.views import APIView
from rest_framework.response import Response
from django.http import JsonResponse
from rest_framework import status
from django.views.decorators.http import require_GET
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from datetime import datetime, timedelta
from decimal import Decimal
import boto3
from django.db import transaction
import time
import threading
import json
# from .serializers import AWSAccountConnectionSerializer, CostAnalyticsSerializer, ResourceSummarySerializer
from .models import VerificationCode, MFAConfiguration, BackupCode, MFALog, CostDriver, AWSCostCache  # AWSAccountConnection, MonthlyCostSummary, DailySpend, RecentDailySpend, ResourceSummary, LowLevelServiceSnapshot, LowLevelServiceCategory, LowLevelServiceCostHistory, LowLevelServiceDefinition, LowLevelServiceResource 
import uuid
import os
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.core.cache import cache
# Add this at the very top of views.py with your other imports
import logging

# Create logger instance
import logging
logger = logging.getLogger(__name__)

# AWS Client imports
from .aws_client import assume_role

# # Tasks imports
# from .tasks import (
#     fetch_aws_costs, update_monthly_summary, 
#     update_cost_forecast, update_recent_daily_spend
# )
# At the top of views.py with other imports, add:

# Serializers imports
from .serializers import UserSerializer

# MFA Utils imports
from .utils.mfa_utils import (
    generate_secret_key, 
    generate_qr_code, 
    generate_backup_codes,
    verify_totp_code,
    check_rate_limit
)

# # Resource tracker imports
# from .resource_tracker import get_aws_resources, get_resource_usage_summary

# Rest Framework imports
from rest_framework import viewsets, generics
from rest_framework.decorators import action

# Create your views here.

@api_view(["GET", 'POST'])
def register_user(request):
    if request.method == "POST":
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')
        verification_code = request.data.get('verification_code')
        
        if not all([username, email, password]):
            return Response({"error": "All fields are required"}, status=status.HTTP_400_BAD_REQUEST)
        
        if User.objects.filter(email=email).exists():
            return Response({"error":'Email already exists'}, status=400)
        
        if User.objects.filter(username=username).exists():
            return Response({"error":'Username already exists'}, status=400) 
        
        if not verification_code:
            return send_verification_code(email)
        
        # Call the updated verify_and_register function
        return verify_and_register(username, email, password, verification_code)
    
    elif request.method == "GET":
        # FIXED: Serialize the queryset properly
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)  # Serialize the queryset
        return Response(serializer.data)  # Now this is correct!
    

def send_verification_code(email):
    """Helper function to send verification code"""
    # Generate a 6-digit code
    code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
    
    # Save the code (without creating a user yet)
    verification_code, created = VerificationCode.objects.update_or_create(
        email=email,  # We use email as identifier since user doesn't exist yet
        defaults={'code': code, 'is_used': False}
    )
    
    # Send email (using Django's built-in email backend)
    subject = 'Your Account Verification Code'
    message = f'Your verification code is: {code}'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    
    try:
        send_mail(subject, message, email_from, recipient_list)
        return Response({
            "message": "Verification code sent to your email",
            "next_step": "Submit the code to complete registration"
        }, status=status.HTTP_200_OK)
    except Exception as e:
        print("Email send failed:", str(e))
        return Response({"error": f"Failed to send verification code: {str(e)}"}, 
                       status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def verify_and_register(username, email, password, verification_code):
    """Helper function to verify code and register user"""
    try:
        # Check verification code
        verification = VerificationCode.objects.get(
            email=email,
            code=verification_code,
            is_used=False
        )
    except VerificationCode.DoesNotExist:
        return Response({"error": "Invalid or expired verification code"}, 
                       status=status.HTTP_400_BAD_REQUEST)
    
    # Mark code as used
    verification.is_used = True
    verification.save()
    
    # Create the user
    try:
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password
        )
        
        # Create token for immediate authentication
        token, _ = Token.objects.get_or_create(user=user)
        
        # Generate MFA secret key immediately after registration (disabled by default)
        secret_key = generate_secret_key()
        MFAConfiguration.objects.create(user=user, secret_key=secret_key, is_enabled=False)
        
        return Response({
            "message": "Registration successful",
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
            "token": token.key,  # Return token for immediate auth
            "next_step": "mfa_setup"
        }, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        return Response({"error": f"Failed to create user: {str(e)}"}, 
                       status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# myground/views.py - Update your login_user function

@api_view(['POST'])
def login_user(request):
    """
    Login user with username or email, supports MFA
    """
    # Debug logging
    print("=" * 60)
    print("🔍 LOGIN ATTEMPT RECEIVED")
    print(f"Request method: {request.method}")
    print(f"Request content type: {request.content_type}")
    print(f"Request data: {request.data}")
    print("=" * 60)
    
    # Get credentials
    username_or_email = request.data.get('username')
    password = request.data.get('password')
    mfa_code = request.data.get('mfa_code')
    
    print(f"Login attempt for: {username_or_email}")
    
    # Validate required fields
    if not username_or_email or not password:
        print("❌ Missing username/email or password")
        return Response(
            {"error": "Username/email and password are required"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Authenticate with username or email
    user = None
    
    if '@' in username_or_email:
        # Try email authentication
        try:
            from django.contrib.auth import get_user_model
            User = get_user_model()
            user_obj = User.objects.get(email=username_or_email)
            user = authenticate(username=user_obj.username, password=password)
            print(f"📧 Email login attempt for: {username_or_email} -> {user_obj.username}")
        except User.DoesNotExist:
            print(f"❌ No user found with email: {username_or_email}")
    else:
        # Try username authentication
        user = authenticate(username=username_or_email, password=password)
        print(f"👤 Username login attempt for: {username_or_email}")
    
    # Process authenticated user
    if user:
        print(f"✅ Authentication successful for: {user.username}")
        
        # Check MFA
        try:
            mfa_config = MFAConfiguration.objects.get(user=user, is_enabled=True)
            print(f"🔐 MFA is enabled for {user.username}")
            
            if not mfa_code:
                print("🔐 MFA code required")
                return Response({
                    "mfa_required": True,
                    "user_id": user.id,
                    "message": "MFA code required"
                }, status=status.HTTP_200_OK)
            
            if not verify_totp_code(mfa_config.secret_key, mfa_code):
                print("❌ Invalid MFA code")
                return Response({"error": "Invalid MFA code"}, status=status.HTTP_400_BAD_REQUEST)
            
            print("✅ MFA code verified")
                
        except MFAConfiguration.DoesNotExist:
            print("🔓 No MFA enabled for this user")
        
        # Generate token
        token, _ = Token.objects.get_or_create(user=user)
        
        return Response({
            "token": token.key,
            "message": "Login successful",
            "user_id": user.id,
            "username": user.username,
            "email": user.email
        }, status=status.HTTP_200_OK)
    
    else:
        print(f"❌ Authentication failed for: {username_or_email}")
        return Response(
            {"error": "Invalid credentials"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
# ============================================================
# TOKEN-BASED MFA ENDPOINTS (for post-registration setup)
# ============================================================

@api_view(['GET'])
def mfa_setup_init_token(request):
    """
    Initialize MFA setup using token from registration
    Does NOT require @permission_classes([IsAuthenticated])
    """
    # Get token from query parameter or header
    token = request.query_params.get('token') or request.headers.get('Authorization')
    
    if not token:
        return Response({"error": "Token is required"}, status=status.HTTP_400_BAD_REQUEST)
    
    # Clean token if it's in "Token <key>" format
    if isinstance(token, str) and token.startswith('Token '):
        token = token[6:]
    
    try:
        # Find user by token
        token_obj = Token.objects.get(key=token)
        user = token_obj.user
        
        # Get or create MFA configuration
        try:
            mfa_config = MFAConfiguration.objects.get(user=user)
            if mfa_config.is_enabled:
                return Response({
                    "error": "MFA is already enabled for this account"
                }, status=status.HTTP_400_BAD_REQUEST)
            secret_key = mfa_config.secret_key
        except MFAConfiguration.DoesNotExist:
            # Generate new secret key
            secret_key = generate_secret_key()
            MFAConfiguration.objects.create(user=user, secret_key=secret_key, is_enabled=False)
            mfa_config = MFAConfiguration.objects.get(user=user)
        
        # Generate QR code
        qr_code_data = generate_qr_code(secret_key, user.email)
        
        return Response({
            "user_id": user.id,
            "username": user.username,
            "secret_key": secret_key,
            "qr_code": qr_code_data,
            "message": "Scan QR code with authenticator app"
        }, status=status.HTTP_200_OK)
        
    except Token.DoesNotExist:
        return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
    except Exception as e:
        return Response({"error": f"Server error: {str(e)}"}, 
                       status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def mfa_enable_token(request):
    """
    Enable MFA using token from registration
    """
    token = request.data.get('token') or request.query_params.get('token')
    code = request.data.get('code')
    
    if not all([token, code]):
        return Response({"error": "Token and verification code are required"}, 
                       status=status.HTTP_400_BAD_REQUEST)
    
    # Clean token if needed
    if isinstance(token, str) and token.startswith('Token '):
        token = token[6:]
    
    try:
        # Find user by token
        token_obj = Token.objects.get(key=token)
        user = token_obj.user
        
        # Check rate limit
        if not check_rate_limit(user.id, 'mfa_enable', limit=3, window=300):
            return Response({"error": "Too many attempts. Please try again later."},
                           status=status.HTTP_429_TOO_MANY_REQUESTS)
        
        mfa_config = MFAConfiguration.objects.get(user=user)
        
        # Verify the code
        if not verify_totp_code(mfa_config.secret_key, code):
            return Response({"error": "Invalid verification code"}, 
                           status=status.HTTP_400_BAD_REQUEST)
        
        # Enable MFA
        mfa_config.is_enabled = True
        mfa_config.save()
        
        # Generate backup codes (TEMPORARY FIX - use 8-character codes)
        import random
        import string
        
        def generate_short_backup_codes(count=10):
            """Generate 8-character backup codes to fit in varchar(10)"""
            codes = []
            for _ in range(count):
                code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
                codes.append(code)
            return codes
        
        backup_codes_list = generate_short_backup_codes(10)
        for backup_code in backup_codes_list:
            BackupCode.objects.create(user=user, code=backup_code)
        
        # Log the action
        MFALog.objects.create(
            user=user,
            action='enable',
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        return Response({
            "message": "MFA enabled successfully",
            "backup_codes": backup_codes_list,
            "warning": "Save these backup codes in a secure place. They won't be shown again."
        }, status=status.HTTP_200_OK)
        
    except Token.DoesNotExist:
        return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
    except MFAConfiguration.DoesNotExist:
        return Response({"error": "MFA not configured for user"},
                       status=status.HTTP_400_BAD_REQUEST)

# ============================================================
# AUTHENTICATED MFA ENDPOINTS (for logged-in users)
# ============================================================

@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication]) 
@permission_classes([IsAuthenticated])
def mfa_setup_init(request):
    """Initialize MFA setup - generate secret and QR code (for logged-in users)"""
    user = request.user
    
    # Check if MFA is already enabled
    try:
        mfa_config = MFAConfiguration.objects.get(user=user)
        if mfa_config.is_enabled:
            return Response({
                "error": "MFA is already enabled for this account"
            }, status=status.HTTP_400_BAD_REQUEST)
        secret_key = mfa_config.secret_key
    except MFAConfiguration.DoesNotExist:
        # Generate new secret key
        secret_key = generate_secret_key()
        MFAConfiguration.objects.create(user=user, secret_key=secret_key, is_enabled=False)
    
    # Generate QR code
    qr_code_data = generate_qr_code(secret_key, user.email)
    
    return Response({
        "secret_key": secret_key,
        "qr_code": qr_code_data,
        "message": "Scan QR code with authenticator app"
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def mfa_enable(request):
    """Enable MFA after verifying code (for logged-in users)"""
    user = request.user
    code = request.data.get('code')
    
    if not code:
        return Response({"error": "Verification code is required"}, 
                       status=status.HTTP_400_BAD_REQUEST)
    
    # Check rate limit
    if not check_rate_limit(user.id, 'mfa_enable', limit=3, window=300):
        return Response({"error": "Too many attempts. Please try again later."},
                       status=status.HTTP_429_TOO_MANY_REQUESTS)
    
    try:
        mfa_config = MFAConfiguration.objects.get(user=user)
        
        # Verify the code
        if not verify_totp_code(mfa_config.secret_key, code):
            return Response({"error": "Invalid verification code"}, 
                           status=status.HTTP_400_BAD_REQUEST)
        
        # Enable MFA
        mfa_config.is_enabled = True
        mfa_config.save()
        
        # Generate backup codes
        backup_codes_list = generate_backup_codes(10)
        backup_codes = []
        for backup_code in backup_codes_list:
            bc = BackupCode.objects.create(
                user=user,
                code=backup_code
            )
            backup_codes.append(backup_code)
        
        # Log the action
        MFALog.objects.create(
            user=user,
            action='enable',
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        return Response({
            "message": "MFA enabled successfully",
            "backup_codes": backup_codes,
            "warning": "Save these backup codes in a secure place. They won't be shown again."
        }, status=status.HTTP_200_OK)
        
    except MFAConfiguration.DoesNotExist:
        return Response({"error": "MFA not configured. Run setup first."},
                       status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def mfa_verify(request):
    """Verify MFA code for login"""
    code = request.data.get('code')
    user_id = request.data.get('user_id')
    
    if not all([code, user_id]):
        return Response({"error": "Code and user ID are required"},
                       status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(id=user_id)
        mfa_config = MFAConfiguration.objects.get(user=user, is_enabled=True)
        
        # Check rate limit
        if not check_rate_limit(user.id, 'mfa_verify', limit=5, window=300):
            return Response({"error": "Too many attempts. Please try again later."},
                           status=status.HTTP_429_TOO_MANY_REQUESTS)
        
        # Try TOTP code first
        if verify_totp_code(mfa_config.secret_key, code):
            MFALog.objects.create(
                user=user,
                action='verify_success',
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            return Response({
                "verified": True,
                "message": "MFA verification successful"
            }, status=status.HTTP_200_OK)
        
        # Check backup codes
        try:
            backup_code = BackupCode.objects.get(
                user=user,
                code=code,
                is_used=False
            )
            backup_code.is_used = True
            backup_code.save()
            
            MFALog.objects.create(
                user=user,
                action='verify_success_backup',
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            return Response({
                "verified": True,
                "message": "Backup code accepted",
                "warning": "This backup code has been used. Generate new ones if needed."
            }, status=status.HTTP_200_OK)
            
        except BackupCode.DoesNotExist:
            pass
        
        # Log failed attempt
        MFALog.objects.create(
            user=user,
            action='verify_failed',
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        return Response({
            "verified": False,
            "error": "Invalid verification code"
        }, status=status.HTTP_400_BAD_REQUEST)
        
    except (User.DoesNotExist, MFAConfiguration.DoesNotExist):
        return Response({"error": "MFA not enabled for this user"},
                       status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def mfa_disable(request):
    """Disable MFA for user"""
    user = request.user
    code = request.data.get('code')  # Require current MFA code to disable
    
    try:
        mfa_config = MFAConfiguration.objects.get(user=user, is_enabled=True)
        
        # Verify code before disabling
        if not verify_totp_code(mfa_config.secret_key, code):
            return Response({"error": "Invalid verification code"},
                           status=status.HTTP_400_BAD_REQUEST)
        
        # Delete backup codes
        BackupCode.objects.filter(user=user).delete()
        
        # Disable MFA
        mfa_config.is_enabled = False
        mfa_config.save()
        
        # Log the action
        MFALog.objects.create(
            user=user,
            action='disable',
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        return Response({
            "message": "MFA disabled successfully"
        }, status=status.HTTP_200_OK)
        
    except MFAConfiguration.DoesNotExist:
        return Response({"error": "MFA is not enabled"},
                       status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def mfa_status(request):
    """Get MFA status for current user"""
    user = request.user
    
    try:
        mfa_config = MFAConfiguration.objects.get(user=user)
        backup_codes = BackupCode.objects.filter(user=user, is_used=False)
        
        return Response({
            "is_enabled": mfa_config.is_enabled,
            "created_at": mfa_config.created_at,
            "backup_codes_count": backup_codes.count()
        }, status=status.HTTP_200_OK)
        
    except MFAConfiguration.DoesNotExist:
        return Response({
            "is_enabled": False,
            "message": "MFA not configured"
        }, status=status.HTTP_200_OK)


@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def regenerate_backup_codes(request):
    """Regenerate backup codes"""
    user = request.user
    code = request.data.get('code')  # Require current MFA code
    
    try:
        mfa_config = MFAConfiguration.objects.get(user=user, is_enabled=True)
        
        # Verify code
        if not verify_totp_code(mfa_config.secret_key, code):
            return Response({"error": "Invalid verification code"},
                           status=status.HTTP_400_BAD_REQUEST)
        
        # Delete old backup codes
        BackupCode.objects.filter(user=user).delete()
        
        # Generate new backup codes
        backup_codes_list = generate_backup_codes(10)
        backup_codes = []
        for backup_code in backup_codes_list:
            bc = BackupCode.objects.create(
                user=user,
                code=backup_code
            )
            backup_codes.append(backup_code)
        
        return Response({
            "message": "Backup codes regenerated",
            "backup_codes": backup_codes,
            "warning": "Save these new backup codes. Old codes are no longer valid."
        }, status=status.HTTP_200_OK)
        
    except MFAConfiguration.DoesNotExist:
        return Response({"error": "MFA is not enabled"},
                       status=status.HTTP_400_BAD_REQUEST)



@api_view(['POST'])
def password_reset_request(request):
    """
    Step 1: Send a 6-digit reset code to the user's email.
    Accepts: { "email": "user@example.com" }
    """
    email = request.data.get('email')
    if not email:
        return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

    # Always return success to prevent user enumeration
    if not User.objects.filter(email=email).exists():
        return Response({
            "message": "If an account with that email exists, a reset code has been sent."
        }, status=status.HTTP_200_OK)

    # Generate 6-digit code
    code = ''.join([str(random.randint(0, 9)) for _ in range(6)])

    # Reuse VerificationCode model — store by email, mark unused
    VerificationCode.objects.update_or_create(
        email=email,
        defaults={'code': code, 'is_used': False}
    )

    subject = 'Your Password Reset Code'
    message = (
        f'You requested a password reset.\n\n'
        f'Your reset code is: {code}\n\n'
        f'This code expires in 15 minutes. If you did not request this, ignore this email.'
    )
    email_from = settings.EMAIL_HOST_USER

    try:
        send_mail(subject, message, email_from, [email])
    except Exception as e:
        return Response(
            {"error": f"Failed to send reset email: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

    return Response({
        "message": "If an account with that email exists, a reset code has been sent."
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
def password_reset_verify(request):
    """
    Step 2: Verify the reset code (without consuming it yet).
    Accepts: { "email": "user@example.com", "code": "123456" }
    """
    email = request.data.get('email')
    code = request.data.get('code')

    if not all([email, code]):
        return Response({"error": "Email and code are required"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        verification = VerificationCode.objects.get(email=email, code=code, is_used=False)
    except VerificationCode.DoesNotExist:
        return Response({"error": "Invalid or expired reset code"}, status=status.HTTP_400_BAD_REQUEST)

    return Response({"message": "Code verified. Proceed to set new password."}, status=status.HTTP_200_OK)


@api_view(['POST'])
def password_reset_confirm(request):
    """
    Step 3: Verify code again and set the new password.
    Accepts: { "email": "user@example.com", "code": "123456", "new_password": "newpass123" }
    """
    email = request.data.get('email')
    code = request.data.get('code')
    new_password = request.data.get('new_password')

    if not all([email, code, new_password]):
        return Response(
            {"error": "Email, code, and new_password are required"},
            status=status.HTTP_400_BAD_REQUEST
        )

    if len(new_password) < 8:
        return Response(
            {"error": "Password must be at least 8 characters"},
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        verification = VerificationCode.objects.get(email=email, code=code, is_used=False)
    except VerificationCode.DoesNotExist:
        return Response({"error": "Invalid or expired reset code"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    # Mark code as used
    verification.is_used = True
    verification.save()

    # Set new password
    user.set_password(new_password)
    user.save()

    # Invalidate existing tokens so user must log in again
    Token.objects.filter(user=user).delete()

    return Response({"message": "Password reset successfully. Please log in."}, status=status.HTTP_200_OK)

# ============================================================
# aws_views.py  — Add these to your views.py OR keep as a separate file
# and include in urls.py
# ============================================================
# Requirements: pip install boto3
# ============================================================

import uuid
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import date, timedelta, datetime
from decimal import Decimal
from statistics import mean

from django.utils import timezone
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from .models import AWSAccount
# ─────────────────────────────────────────────
# HELPER: Assume the user's IAM role via STS
# ─────────────────────────────────────────────

import uuid
from datetime import datetime
from django.utils import timezone
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from .models import AWSAccount
from .aws_client import test_connection

# ─────────────────────────────────────────────────────────
# STEP 1: Generate External ID (called before user creates role)
# ─────────────────────────────────────────────────────────

# views.py - Replace your generate_external_id function

from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from django.conf import settings
import uuid


# views.py - Replace your generate_external_id function

@api_view(['GET', 'POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def generate_external_id(request):
    """
    Generate or retrieve existing external ID from database.
    Saves to database once per user.
    """
    print("=" * 60)
    print("🔍 generate_external_id called")
    print(f"   Method: {request.method}")
    print(f"   User: {request.user.username}")
    print("=" * 60)
    
    if not request.user.is_authenticated:
        return Response({"error": "Authentication required"}, status=401)
    
    try:
        # Check if user already has an AWS account with an external ID
        existing_account = AWSAccount.objects.filter(user=request.user).first()
        
        if existing_account:
            # User already has a connected account - use its external ID
            external_id = str(existing_account.external_id)
            app_account_id = existing_account.account_id
            print(f"📌 Using existing external ID from database: {external_id}")
            print(f"📌 Connected to AWS Account: {app_account_id}")
            
            return Response({
                "success": True,
                "external_id": external_id,
                "app_account_id": app_account_id,
                "is_new": False,
                "message": "Using existing external ID from your connected AWS account"
            }, status=200)
        
        # Check if user has a pending AWS account (created but not connected)
        pending_account = AWSAccount.objects.filter(
            user=request.user, 
            status='pending'
        ).first()
        
        if pending_account:
            # Use the pending account's external ID
            external_id = str(pending_account.external_id)
            print(f"📌 Using pending external ID from database: {external_id}")
            
            return Response({
                "success": True,
                "external_id": external_id,
                "app_account_id": getattr(settings, 'AWS_ACCOUNT_ID', '026395503692'),
                "is_new": False,
                "message": "Using existing pending external ID"
            }, status=200)
        
        # No existing account - create a new pending AWS account with a unique external ID
        external_id = str(uuid.uuid4())
        app_account_id = getattr(settings, 'AWS_ACCOUNT_ID', '026395503692')
        
        # Create a pending AWS account in the database
        new_account = AWSAccount.objects.create(
            user=request.user,
            account_id=app_account_id,  # Temporary, will be updated when connected
            role_arn="",  # Empty for now
            external_id=external_id,
            status='pending',
            account_alias=f"Pending Setup - {request.user.username}"
        )
        
        print(f"✨ Created NEW pending AWS account with external ID: {external_id}")
        print(f"   Database ID: {new_account.id}")
        
        return Response({
            "success": True,
            "external_id": external_id,
            "app_account_id": app_account_id,
            "is_new": True,
            "message": "New external ID generated and saved to database"
        }, status=200)
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return Response({"error": str(e)}, status=500)
# ─────────────────────────────────────────────────────────
# STEP 2: Connect AWS Account (verify and save)
# ─────────────────────────────────────────────────────────
# views.py - Update your connect_aws_account function
@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def connect_aws_account(request):
    """Connects a user's AWS account by testing role assumption."""
    user = request.user
    role_arn = request.data.get('role_arn', '').strip()
    account_alias = request.data.get('account_alias', '').strip()
    
    print("=" * 60)
    print(f"🔍 connect_aws_account called")
    print(f"   User: {user.username}")
    print(f"   Role ARN: {role_arn}")
    print("=" * 60)
    
    if not role_arn:
        return Response({"error": "role_arn is required"}, status=400)
    
    # Extract account ID from ARN
    try:
        account_id = role_arn.split(':')[4]
    except:
        return Response({"error": "Invalid role ARN format"}, status=400)
    
    # Check if account already exists
    existing_account = AWSAccount.objects.filter(user=user, account_id=account_id).first()
    
    # Get or create external ID
    if existing_account:
        external_id = str(existing_account.external_id)
        print(f"📌 Using existing account with external ID: {external_id}")
    else:
        external_id = str(uuid.uuid4())
        print(f"✨ Created new external ID: {external_id}")
    
    try:
        from .aws_client import assume_role, test_connection
        
        print(f"🔐 Attempting to assume role: {role_arn}")
        print(f"   External ID: {external_id}")
        
        credentials = assume_role(role_arn, external_id)
        connection_test = test_connection(credentials)
        
        if not connection_test.get('success'):
            return Response({
                "error": "Failed to assume role. Please check the Role ARN and External ID match.",
                "external_id_used": external_id
            }, status=400)
        
        # Update or create account with ALL fields
        if existing_account:
            # Update existing account
            existing_account.role_arn = role_arn  # CRITICAL: Ensure this is set
            existing_account.account_alias = account_alias or existing_account.account_alias or f"AWS Account {account_id}"
            existing_account.status = 'connected'
            existing_account.connected_at = timezone.now()
            existing_account.save()
            print(f"✅ Updated existing AWS account with role ARN: {role_arn}")
        else:
            # Create new account
            pending_account = AWSAccount.objects.create(
                user=user,
                account_id=account_id,
                role_arn=role_arn,  # CRITICAL: Must be set
                external_id=external_id,
                status='connected',
                account_alias=account_alias or f"AWS Account {account_id}",
                connected_at=timezone.now()
            )
            print(f"✅ Created new AWS account with role ARN: {role_arn}")
        
        return Response({
            "success": True,
            "message": "AWS account connected successfully!",
            "account_id": account_id,
            "external_id_used": external_id,
            "verified": True
        }, status=200)
        
    except Exception as e:
        error_message = str(e)
        print(f"❌ Connection error: {error_message}")
        
        return Response({
            "error": f"Connection failed: {error_message}",
        }, status=400)
# ─────────────────────────────────────────────────────────
# STEP 3: List user's connected AWS accounts
# ─────────────────────────────────────────────────────────
@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def list_aws_accounts(request):
    """Returns all AWS accounts linked to the authenticated user."""
    accounts = AWSAccount.objects.filter(user=request.user)
    
    data = []
    for acc in accounts:
        data.append({
            "id": acc.id,
            "aws_account_id": acc.account_id,  # Map account_id to aws_account_id for frontend
            "account_id": acc.account_id,    # Add both for compatibility
            "account_alias": acc.account_alias,
            "status": acc.status,
            "connected_at": acc.connected_at,
            "external_id": str(acc.external_id),
            "role_arn": acc.role_arn,
        })
    
    return Response({"accounts": data}, status=status.HTTP_200_OK)
# ─────────────────────────────────────────────────────────
# STEP 4: Disconnect AWS Account
# ─────────────────────────────────────────────────────────

@api_view(['DELETE'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def disconnect_aws_account(request, account_db_id):
    """Disconnects a user's AWS account."""
    try:
        aws_account = AWSAccount.objects.get(id=account_db_id, user=request.user)
    except AWSAccount.DoesNotExist:
        return Response(
            {"error": "AWS account not found"}, 
            status=status.HTTP_404_NOT_FOUND
        )
    
    account_id = aws_account.account_id
    aws_account.delete()
    
    return Response({
        "message": f"AWS account {account_id} disconnected successfully."
    }, status=status.HTTP_200_OK)

from .models import AWSAccount

@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_cost_dashboard_data(request, account_db_id):
    """
    Get all cost data for the dashboard (with caching)
    """
    try:
        aws_account = AWSAccount.objects.get(
            id=account_db_id, 
            user=request.user,
            status='connected'
        )
        
        from .aws_cost import (
            get_cached_90_days_cost, 
            get_cached_monthly_cost, 
            get_cached_yesterday_cost,
            get_cached_7_days_cost,
            get_cached_cost_drivers  # ✅ USE CACHED VERSION
        )
        
        # Get cached data
        total_90_days = get_cached_90_days_cost(aws_account)
        monthly_cost = get_cached_monthly_cost(aws_account)
        yesterday_cost = get_cached_yesterday_cost(aws_account)
        chart_data = get_cached_7_days_cost(aws_account)
        
        # ✅ Get cached cost drivers (this will be fast after first load)
        cost_drivers = get_cached_cost_drivers(aws_account, monthly_cost)
        
        # Format drivers for frontend
        drivers_list = []
        if cost_drivers:
            for driver in cost_drivers:
                drivers_list.append({
                    'title': driver['title'],
                    'description': driver['description'],
                    'service': driver['service'],
                    'percentage': driver['percentage'],
                    'recommendation': driver['recommendation'],
                    'estimated_savings': driver['estimated_savings']
                })
        
        return Response({
            'total_90_days': total_90_days,
            'monthly_cost': monthly_cost,
            'latest_daily_cost': yesterday_cost,
            'chart_data': chart_data,
            'cost_drivers': drivers_list,
            'mom_change': 23,
            'account_alias': aws_account.account_alias,
            'account_id': aws_account.account_id
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'Connected AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=400)

@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def clear_cost_cache(request, account_db_id):
    """
    Delete all cached cost data from database
    """
    try:
        aws_account = AWSAccount.objects.get(
            id=account_db_id,
            user=request.user
        )
        
        # Clear cost data from database
        from .aws_cost import clear_cost_data
        deleted_count = clear_cost_data(aws_account)
        
        # Also clear AWSCostCache if still using it
        AWSCostCache.objects.filter(aws_account=aws_account).delete()
        
        return Response({
            'message': f'Cache cleared successfully. {deleted_count} items removed.',
            'cache_status': 'empty'
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=400)

@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_cache_status(request, account_db_id):
    """
    Check what's in the cache
    """
    try:
        aws_account = AWSAccount.objects.get(
            id=account_db_id, 
            user=request.user
        )
        
        caches = AWSCostCache.objects.filter(aws_account=aws_account)
        cache_info = []
        
        for cache in caches:
            expires_in = (cache.expires_at - timezone.now()).total_seconds() / 3600
            data_size = len(json.dumps(cache.cache_data)) if cache.cache_data else 0
            
            cache_info.append({
                'cache_key': cache.cache_key,
                'created_at': cache.created_at,
                'expires_in_hours': round(expires_in, 1),
                'data_size_kb': round(data_size / 1024, 1)
            })
        
        return Response({
            'account': aws_account.account_alias,
            'cache_entries': cache_info,
            'total_entries': len(cache_info)
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)


@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def generate_ai_cost_analysis(request, account_db_id):
    """
    Generate AI-powered cost analysis (only when user clicks button)
    """
    try:
        aws_account = AWSAccount.objects.get(
            id=account_db_id, 
            user=request.user,
            status='connected'
        )
        
        from .aws_cost import (
            get_cached_90_days_cost,
            get_cached_monthly_cost,
            get_cached_7_days_cost,
            get_cached_yesterday_cost,
            get_cached_cost_drivers,
            generate_cost_analysis
        )
        
        # Get fresh data for analysis
        total_90_days = get_cached_90_days_cost(aws_account)
        monthly_cost = get_cached_monthly_cost(aws_account)
        chart_data = get_cached_7_days_cost(aws_account)
        latest_daily = get_cached_yesterday_cost(aws_account)
        cost_drivers = get_cached_cost_drivers(aws_account, monthly_cost)
        
        # Prepare cost data
        cost_data = {
            'total_90_days': total_90_days,
            'monthly_cost': monthly_cost,
            'chart_data': chart_data,
            'latest_daily_cost': latest_daily.get('amount', 0) if isinstance(latest_daily, dict) else latest_daily
        }
        
        # Generate analysis (force new, not cached)
        analysis = generate_cost_analysis(aws_account, cost_data, cost_drivers)
        
        return Response({
            'success': True,
            'analysis': analysis,
            'generated_at': timezone.now().isoformat()
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        logger.error(f"Error generating AI analysis: {e}")
        return Response({'error': str(e)}, status=400)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_cached_ai_analysis(request, account_db_id):
    """
    Get the latest cached AI analysis (if exists)
    """
    try:
        from .models import AWSCostAnalysis
        
        aws_account = AWSAccount.objects.get(
            id=account_db_id, 
            user=request.user
        )
        
        latest_analysis = AWSCostAnalysis.objects.filter(
            aws_account=aws_account,
            analysis_type='ai_insights'
        ).first()
        
        if latest_analysis:
            return Response({
                'success': True,
                'analysis': latest_analysis.analysis_result,
                'generated_at': latest_analysis.created_at,
                'cost_drivers_used': latest_analysis.cost_drivers_used
            }, status=200)
        else:
            return Response({
                'success': False,
                'message': 'No analysis available. Click "Generate AI Analysis" to create one.'
            }, status=200)
            
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_low_level_cost_breakdown(request, account_db_id):
    """
    Get granular low-level cost breakdown (NAT Gateway, Data Transfer, etc.)
    """
    try:
        aws_account = AWSAccount.objects.get(
            id=account_db_id, 
            user=request.user,
            status='connected'
        )
        
        from .aws_cost import get_cached_low_level_costs
        
        low_level_data = get_cached_low_level_costs(aws_account)
        
        if 'error' in low_level_data:
            return Response({'error': low_level_data['error']}, status=400)
        
        return Response(low_level_data, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=400)


# Add these imports at the top
from .models import GitHubRepo, DeploymentEvent, CostSpike, GitHubUser
from .github_service import GitHubService, exchange_code_for_token, get_user_from_token
from django.db import transaction
from django.utils import timezone

# ============================================================
# GITHUB INTEGRATION ENDPOINTS

# ============================================================
@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def github_auth_url(request):
    print("=" * 60)
    print("🔍 GITHUB AUTH URL REQUEST RECEIVED")
    print(f"User: {request.user.username}")
    print(f"GITHUB_CLIENT_ID from settings: {settings.GITHUB_CLIENT_ID}")
    print(f"GITHUB_REDIRECT_URI from settings: {settings.GITHUB_REDIRECT_URL}")
    
    auth_url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={settings.GITHUB_CLIENT_ID}"
        f"&redirect_uri={settings.GITHUB_REDIRECT_URL}"
        f"&scope=repo,read:user"
        f"&state={request.user.id}"
    )
    
    print(f"Generated auth URL: {auth_url}")
    print("=" * 60)
    
    return Response({'auth_url': auth_url}, status=200)

@api_view(['GET', 'POST'])
def github_callback(request):
    code = request.GET.get('code') or request.data.get('code')
    state = request.GET.get('state')
    
    print(f"🔍 GitHub callback received - code: {code[:10] if code else 'None'}..., state: {state}")
    
    if not code:
        return Response({'error': 'Code is required'}, status=400)
    
    if not state:
        print("⚠️ No state parameter received - falling back to authenticated user")
        if request.user.is_authenticated:
            user = request.user
        else:
            return Response({'error': 'State parameter missing and user not authenticated'}, status=400)
    else:
        try:
            user = User.objects.get(id=state)
        except User.DoesNotExist:
            return Response({'error': 'Invalid user'}, status=400)
    
    # Exchange code for token - make sure GITHUB_REDIRECT_URI is passed
    access_token = exchange_code_for_token(code)
    if not access_token:
        print("❌ Failed to get access token")
        return Response({'error': 'Failed to get access token'}, status=400)
    
    print(f"✅ Got access token: {access_token[:10]}...")
    
    # Get user info
    github_user_data = get_user_from_token(access_token)
    if not github_user_data:
        print("❌ Failed to get user info from GitHub")
        return Response({'error': 'Failed to get user info'}, status=400)
    
    print(f"✅ GitHub user: {github_user_data.get('login')} (ID: {github_user_data.get('id')})")
    
    # Save to database
    from .models import GitHubUser
    github_user, created = GitHubUser.objects.update_or_create(
        user=user,
        defaults={
            'github_id': github_user_data.get('id'),
            'github_username': github_user_data.get('login'),
            'access_token': access_token
        }
    )
    
    print(f"{'Created' if created else 'Updated'} GitHubUser for {user.username}")
    
    # Redirect to frontend success page instead of returning JSON
    frontend_url = 'https://cloud-management-frontend.vercel.app/cost-analytics/aws'
    return redirect(f'{frontend_url}/dashboard?github_connected=true')

@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def list_github_repos(request):
    """
    List user's GitHub repositories (for selection) with Terraform detection
    """
    print(f"🔍 list_github_repos called")
    print(f"Authenticated user: {request.user.username} (ID: {request.user.id})")
    
    try:
        from .models import GitHubUser
        github_user = GitHubUser.objects.get(user=request.user)
        print(f"✅ Found GitHubUser: {github_user.github_username}")
        access_token = github_user.access_token
    except GitHubUser.DoesNotExist:
        print("❌ No GitHubUser found for this user")
        return Response({'error': 'GitHub not connected. Please connect first.'}, status=400)
    
    github = GitHubService(access_token)
    repos = github.get_user_repos()
    print(f"GitHub API returned {len(repos) if repos else 0} repos")
    
    filtered_repos = []
    
    if repos:
        # Limit to first 20 repos to avoid rate limiting
        repos_to_check = repos[:20]
        
        for repo in repos_to_check:
            owner = repo.get('owner', {}).get('login')
            repo_name = repo.get('name')
            repo_id = repo.get('id')
            repo_full_name = repo.get('full_name')
            
            # Check cache first
            cache_key = f"github_terraform_{owner}_{repo_name}"
            has_tf = cache.get(cache_key)
            
            if has_tf is None:
                print(f"🔍 Checking repo {repo_full_name} for Terraform files...")
                try:
                    has_tf = github.has_terraform_files(owner, repo_name)
                    if has_tf:
                        print(f"✅ Found Terraform files in {repo_full_name}")
                except Exception as e:
                    print(f"⚠️ Error checking {repo_full_name}: {e}")
                    has_tf = False
            else:
                print(f"📦 Using cached result for {repo_full_name}: {has_tf}")
            
            filtered_repos.append({
                'id': repo_id,
                'name': repo_name,
                'full_name': repo_full_name,
                'url': repo.get('html_url'),
                'private': repo.get('private', False),
                'has_terraform': has_tf,
                'description': repo.get('description', ''),
                'stargazers_count': repo.get('stargazers_count', 0),
                'forks_count': repo.get('forks_count', 0),
                'language': repo.get('language', ''),
                'updated_at': repo.get('updated_at')
            })
    
    print(f"Returning {len(filtered_repos)} repos to frontend")
    
    return Response({
        'repos': filtered_repos,
        'total': len(filtered_repos)
    }, status=200)
# myground/views.py - Add this function

from django.contrib.auth import logout
from django.http import JsonResponse

@csrf_exempt
def logout_user(request):
    """Logout user"""
    if request.method == 'POST':
        logout(request)
        return JsonResponse({'message': 'Logged out successfully'})
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@api_view(['POST'])
@csrf_exempt 
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def connect_github_repo(request):
    user = request.user
    repo_id = request.data.get('repo_id')
    repo_name = request.data.get('repo_name')
    repo_full_name = request.data.get('repo_full_name')
    repo_url = request.data.get('repo_url')
    aws_account_id = request.data.get('aws_account_id')
    
    print(f"🔍 connect_github_repo called")
    print(f"  repo_id: {repo_id}")
    print(f"  repo_full_name: {repo_full_name}")
    print(f"  aws_account_id: {aws_account_id}")
    
    if not all([repo_id, repo_name, repo_full_name, repo_url, aws_account_id]):
        return Response({'error': 'All fields are required'}, status=400)
    
    # Check user's repo limit (max 2)
    existing_repos = GitHubRepo.objects.filter(user=user, status='connected').count()
    if existing_repos >= 2:
        return Response({'error': 'Maximum 2 repositories allowed. Please disconnect one first.'}, status=400)
    
    # Get AWS account
    try:
        aws_account = AWSAccount.objects.get(id=aws_account_id, user=user, status='connected')
        print(f"✅ Found AWS account: {aws_account.account_alias}")
    except AWSAccount.DoesNotExist:
        print(f"❌ AWS account not found: {aws_account_id}")
        return Response({'error': 'AWS account not found'}, status=404)
    
    # Get token from GitHubUser model
    try:
        github_user = GitHubUser.objects.get(user=user)
        access_token = github_user.access_token
        print(f"✅ Got GitHub token for user: {github_user.github_username}")
    except GitHubUser.DoesNotExist:
        print("❌ GitHubUser not found - user hasn't connected GitHub")
        return Response({'error': 'GitHub not connected. Please connect GitHub first.'}, status=400)
    
    # Check if repo already connected
    if GitHubRepo.objects.filter(user=user, repo_id=repo_id).exists():
        return Response({'error': 'Repository already connected'}, status=400)
    
    # Create webhook
    github = GitHubService(access_token)
    owner, repo = repo_full_name.split('/')
    webhook_url = f"{settings.BASE_URL}/api/github/webhook/"
    
    print(f"📡 Creating webhook for {owner}/{repo} at {webhook_url}")
    
    try:
        webhook = github.create_webhook(owner, repo, webhook_url)
        webhook_id = webhook.get('id') if webhook else None
        print(f"✅ Webhook created with ID: {webhook_id}")
    except Exception as e:
        print(f"⚠️ Failed to create webhook: {e}")
        webhook_id = None
    
    # Save to database
    with transaction.atomic():
        github_repo = GitHubRepo.objects.create(
            user=user,
            aws_account=aws_account,
            repo_id=repo_id,
            repo_name=repo_name,
            repo_full_name=repo_full_name,
            repo_url=repo_url,
            access_token=access_token,
            webhook_id=webhook_id,
            status='connected',
            last_sync_at=timezone.now()
        )
        print(f"✅ Saved GitHubRepo with ID: {github_repo.id}")
        
        # Initial sync - run in background or synchronously
        sync_repo_deployments(github_repo.id)
    
    return Response({
        'success': True,
        'repo_id': github_repo.id,
        'message': 'Repository connected successfully'
    }, status=200)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def list_connected_repos(request):
    """
    List user's connected GitHub repositories
    """
    repos = GitHubRepo.objects.filter(user=request.user, status='connected')
    
    data = []
    for repo in repos:
        # Count deployments
        deployment_count = DeploymentEvent.objects.filter(repo=repo).count()
        
        # Get latest deployment
        latest_deployment = DeploymentEvent.objects.filter(repo=repo).first()
        
        data.append({
            'id': repo.id,
            'repo_name': repo.repo_name,
            'repo_full_name': repo.repo_full_name,
            'repo_url': repo.repo_url,
            'aws_account_id': repo.aws_account.id if repo.aws_account else None,
            'aws_account_alias': repo.aws_account.account_alias if repo.aws_account else None,
            'status': repo.status,
            'deployment_count': deployment_count,
            'latest_deployment_at': latest_deployment.merged_at if latest_deployment else None,
            'latest_deployment_pr': latest_deployment.pr_number if latest_deployment else None,
            'connected_at': repo.connected_at,
            'last_sync_at': repo.last_sync_at
        })
    
    return Response({'repos': data}, status=200)


@api_view(['DELETE'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def disconnect_github_repo(request, repo_id):
    """
    Disconnect a GitHub repository
    """
    try:
        repo = GitHubRepo.objects.get(id=repo_id, user=request.user)
    except GitHubRepo.DoesNotExist:
        return Response({'error': 'Repository not found'}, status=404)
    
    # Delete webhook from GitHub
    if repo.webhook_id and repo.repo_full_name:
        github = GitHubService(repo.access_token)
        owner, repo_name = repo.repo_full_name.split('/')
        github.delete_webhook(owner, repo_name, repo.webhook_id)
    
    # Delete the repo (deployments will cascade delete)
    repo.delete()
    
    return Response({'message': 'Repository disconnected successfully'}, status=200)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def list_deployments(request, repo_id):
    """
    List deployment events for a connected repository
    """
    try:
        repo = GitHubRepo.objects.get(id=repo_id, user=request.user)
    except GitHubRepo.DoesNotExist:
        return Response({'error': 'Repository not found'}, status=404)
    
    deployments = DeploymentEvent.objects.filter(repo=repo)[:50]
    
    data = []
    for dep in deployments:
        data.append({
            'id': dep.id,
            'pr_number': dep.pr_number,
            'pr_title': dep.pr_title,
            'pr_url': dep.pr_url,
            'merged_by': dep.merged_by,
            'merged_at': dep.merged_at,
            'files_changed': dep.files_changed[:10],  # Limit to 10 files
            'services_affected': dep.services_affected,
            'is_correlated': dep.is_correlated,
            'cost_impact': float(dep.cost_impact) if dep.cost_impact else None
        })
    
    return Response({'deployments': data}, status=200)


@api_view(['POST'])
def github_webhook(request):
    """
    GitHub webhook endpoint - receives PR merge events
    """
    # Verify signature (simplified for now)
    event_type = request.headers.get('X-GitHub-Event')
    
    if event_type == 'ping':
        return Response({'message': 'pong'}, status=200)
    
    if event_type != 'pull_request':
        return Response({'message': 'Ignored event'}, status=200)
    
    payload = request.data
    action = payload.get('action')
    
    # Only process merged pull requests
    if action != 'closed':
        return Response({'message': 'Not a closed event'}, status=200)
    
    pr = payload.get('pull_request', {})
    if not pr.get('merged'):
        return Response({'message': 'Not merged'}, status=200)
    
    # Extract PR details
    repo_info = payload.get('repository', {})
    repo_full_name = repo_info.get('full_name')
    pr_number = pr.get('number')
    pr_title = pr.get('title')
    pr_url = pr.get('html_url')
    merged_by = pr.get('merged_by', {}).get('login', 'unknown')
    merged_at = pr.get('merged_at')
    
    # Find the connected repo
    try:
        repo = GitHubRepo.objects.get(repo_full_name=repo_full_name, status='connected')
    except GitHubRepo.DoesNotExist:
        return Response({'message': 'Repository not connected'}, status=200)
    
    # Fetch files changed in this PR
    github = GitHubService(repo.access_token)
    owner, repo_name = repo_full_name.split('/')
    files = github.get_pr_files(owner, repo_name, pr_number)
    
    # Determine services affected
    services_affected = github.get_services_from_files(files)
    
    # Save deployment event
    deployment, created = DeploymentEvent.objects.update_or_create(
        repo=repo,
        pr_number=pr_number,
        defaults={
            'aws_account': repo.aws_account,
            'pr_title': pr_title,
            'pr_url': pr_url,
            'merged_by': merged_by,
            'merged_at': merged_at,
            'files_changed': files,
            'services_affected': services_affected
        }
    )
    
    return Response({'message': 'Deployment recorded'}, status=200)


def sync_repo_deployments(repo_id):
    """
    Sync recent deployments for a repository (background task)
    """
    try:
        repo = GitHubRepo.objects.get(id=repo_id)
    except GitHubRepo.DoesNotExist:
        return
    
    github = GitHubService(repo.access_token)
    owner, repo_name = repo.repo_full_name.split('/')
    
    # Get recent merged PRs
    pulls = github.get_pull_requests(owner, repo_name, state='closed', per_page=30)
    
    for pr in pulls:
        pr_number = pr.get('number')
        pr_title = pr.get('title')
        pr_url = pr.get('html_url')
        merged_by = pr.get('merged_by', {}).get('login', 'unknown')
        merged_at = pr.get('merged_at')
        
        if not merged_at:
            continue
        
        # Get files changed
        files = github.get_pr_files(owner, repo_name, pr_number)
        
        # Determine services affected
        services_affected = github.get_services_from_files(files)
        
        # Save or update
        DeploymentEvent.objects.update_or_create(
            repo=repo,
            pr_number=pr_number,
            defaults={
                'aws_account': repo.aws_account,
                'pr_title': pr_title,
                'pr_url': pr_url,
                'merged_by': merged_by,
                'merged_at': merged_at,
                'files_changed': files,
                'services_affected': services_affected
            }
        )
    
    repo.last_sync_at = timezone.now()
    repo.save()


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def github_status(request):
    """
    Check if user has GitHub connected
    """
    try:
        github_user = GitHubUser.objects.get(user=request.user)
        return Response({
            'connected': True,
            'username': github_user.github_username,
            'github_id': github_user.github_id
        }, status=200)
    except GitHubUser.DoesNotExist:
        return Response({
            'connected': False
        }, status=200)


@csrf_exempt
@api_view(['POST'])
@authentication_classes([TokenAuthentication])  # Only TokenAuthentication
@permission_classes([IsAuthenticated])
def start_github_scan(request):
    """
    Start scanning repositories and return scan ID for polling
    """
    scan_id = f"scan_{request.user.id}_{int(time.time())}"
    
    def scan_repos():
        try:
            from .models import GitHubUser
            from .github_service import GitHubService
            
            # Store initial status with LONGER timeout (10 minutes)
            cache.set(f"{scan_id}_status", "scanning", timeout=600)
            cache.set(f"{scan_id}_message", "Starting scan...", timeout=600)
            cache.set(f"{scan_id}_scanned", 0, timeout=600)
            cache.set(f"{scan_id}_total", 0, timeout=600)
            cache.set(f"{scan_id}_percentage", 0, timeout=600)
            cache.set(f"{scan_id}_current", "Initializing...", timeout=600)
            cache.set(f"{scan_id}_found", [], timeout=600)
            
            logger.info(f"Starting GitHub scan for user {request.user.id}")
            
            github_user = GitHubUser.objects.get(user=request.user)
            github = GitHubService(github_user.access_token)
            
            repos = github.get_user_repos()
            total_repos = len(repos) if repos else 0
            cache.set(f"{scan_id}_total", total_repos, timeout=600)
            
            logger.info(f"Found {total_repos} repositories to scan")
            
            filtered_repos = []
            tf_found_count = 0
            scanned_count = 0
            found_terraform_repos = []
            
            if repos:
                for repo in repos:
                    scanned_count += 1
                    owner = repo.get('owner', {}).get('login')
                    repo_name = repo.get('name')
                    repo_full_name = repo.get('full_name')
                    repo_id = repo.get('id')
                    
                    # Update progress
                    percentage = round((scanned_count / total_repos) * 100, 1)
                    cache.set(f"{scan_id}_current", repo_full_name, timeout=600)
                    cache.set(f"{scan_id}_scanned", scanned_count, timeout=600)
                    cache.set(f"{scan_id}_percentage", percentage, timeout=600)
                    
                    logger.info(f"Scanning [{scanned_count}/{total_repos}] {repo_full_name} ({percentage}%)")
                    
                    # Check cache first for Terraform detection
                    cache_key = f"github_terraform_{repo_id}"
                    has_tf = cache.get(cache_key)
                    
                    if has_tf is None:
                        try:
                            # Check for Terraform files
                            has_tf = github.has_terraform_files(owner, repo_name)
                            if has_tf:
                                tf_found_count += 1
                                found_terraform_repos.append(repo_full_name)
                                logger.info(f"✅ Found Terraform in {repo_full_name}")
                                # Update found list
                                cache.set(f"{scan_id}_found", found_terraform_repos, timeout=600)
                            else:
                                logger.info(f"❌ No Terraform files in {repo_full_name}")
                            
                            # Cache the result
                            cache.set(cache_key, has_tf, timeout=3600)  # 1 hour cache
                        except Exception as e:
                            logger.error(f"Error checking {repo_full_name}: {e}")
                            has_tf = False
                    else:
                        logger.info(f"Using cached result for {repo_full_name}: {has_tf}")
                        if has_tf:
                            if repo_full_name not in found_terraform_repos:
                                tf_found_count += 1
                                found_terraform_repos.append(repo_full_name)
                                cache.set(f"{scan_id}_found", found_terraform_repos, timeout=600)
                    
                    filtered_repos.append({
                        'id': repo_id,
                        'name': repo_name,
                        'full_name': repo_full_name,
                        'url': repo.get('html_url'),
                        'private': repo.get('private', False),
                        'has_terraform': has_tf,
                        'updated_at': repo.get('updated_at')
                    })
                    
                    # Delay to make scanning visible and avoid rate limits
                    time.sleep(0.15)  # 150ms delay per repo
            else:
                logger.warning(f"No repositories found for user {request.user.id}")
            
            # Store results with LONGER timeout
            cache.set(f"{scan_id}_repos", filtered_repos, timeout=600)
            cache.set(f"{scan_id}_status", "complete", timeout=600)
            cache.set(f"{scan_id}_terraform_count", tf_found_count, timeout=600)
            cache.set(f"{scan_id}_found_terraform", found_terraform_repos, timeout=600)
            cache.set(f"{scan_id}_message", f"Scan complete! Found {tf_found_count} repositories with Terraform files", timeout=600)
            
            logger.info(f"Scan complete for user {request.user.id}: {tf_found_count}/{total_repos} repos with Terraform")
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            logger.error(f"Scan failed for user {request.user.id}: {e}")
            cache.set(f"{scan_id}_status", "error", timeout=600)
            cache.set(f"{scan_id}_error", str(e), timeout=600)
            cache.set(f"{scan_id}_message", f"Scan failed: {str(e)}", timeout=600)
    
    # Start background thread
    thread = threading.Thread(target=scan_repos)
    thread.daemon = True
    thread.start()
    
    logger.info(f"Started scan with ID: {scan_id} for user {request.user.id}")
    
    return Response({
        'scan_id': scan_id,
        'message': 'Scan started',
        'status_url': f'/github/scan/status/{scan_id}/'
    }, status=status.HTTP_200_OK)




@csrf_exempt
@require_http_methods(["POST"])
def start_github_scan_manual(request):
    """
    Manual version of start_github_scan that doesn't use DRF authentication
    This bypasses all DRF authentication classes and handles token manually
    """
    print("=" * 60)
    print("🔍 start_github_scan_manual called")
    
    # Get token from header
    auth_header = request.headers.get('Authorization', '')
    token_key = None
    if auth_header.startswith('Token '):
        token_key = auth_header[6:]
    
    print(f"Authorization header: {auth_header[:20] if auth_header else 'None'}...")
    print(f"Token extracted: {token_key[:10] if token_key else 'None'}...")
    
    if not token_key:
        return JsonResponse({'error': 'Authentication required. Please provide a valid token.'}, status=401)
    
    # Validate token and get user
    try:
        token = Token.objects.get(key=token_key)
        user = token.user
        print(f"✅ Authenticated user: {user.username} (ID: {user.id})")
    except Token.DoesNotExist:
        print("❌ Invalid token")
        return JsonResponse({'error': 'Invalid or expired token. Please log in again.'}, status=401)
    except Exception as e:
        print(f"❌ Token error: {e}")
        return JsonResponse({'error': f'Authentication error: {str(e)}'}, status=401)
    
    # Parse request body
    try:
        import json
        data = json.loads(request.body.decode('utf-8'))
        repo_ids = data.get('repo_ids', [])
        print(f"Repos to scan: {repo_ids}")
    except json.JSONDecodeError as e:
        print(f"❌ JSON decode error: {e}")
        return JsonResponse({'error': 'Invalid JSON payload'}, status=400)
    except Exception as e:
        print(f"❌ Error parsing request: {e}")
        return JsonResponse({'error': 'Invalid request body'}, status=400)
    
    if not repo_ids:
        return JsonResponse({'error': 'No repositories selected. Please select at least one repository to scan.'}, status=400)
    
    # Generate unique scan ID
    scan_id = f"scan_{user.id}_{int(time.time())}"
    print(f"Generated scan ID: {scan_id}")
    
    def scan_repos():
        """Background thread function to scan repositories"""
        try:
            from .models import GitHubUser, GitHubRepo
            from .github_service import GitHubService
            
            # Store initial status with LONGER timeout (10 minutes)
            cache.set(f"{scan_id}_status", "scanning", timeout=600)
            cache.set(f"{scan_id}_message", "Starting scan...", timeout=600)
            cache.set(f"{scan_id}_scanned", 0, timeout=600)
            cache.set(f"{scan_id}_total", 0, timeout=600)
            cache.set(f"{scan_id}_percentage", 0, timeout=600)
            cache.set(f"{scan_id}_current", "Initializing...", timeout=600)
            cache.set(f"{scan_id}_found", [], timeout=600)
            
            logger.info(f"Starting GitHub scan for user {user.id}")
            
            # Get GitHub user's access token
            try:
                github_user = GitHubUser.objects.get(user=user)
                access_token = github_user.access_token
                print(f"✅ Got GitHub token for user: {github_user.github_username}")
            except GitHubUser.DoesNotExist:
                print("❌ GitHubUser not found")
                cache.set(f"{scan_id}_status", "error", timeout=600)
                cache.set(f"{scan_id}_error", "GitHub not connected. Please connect GitHub first.", timeout=600)
                cache.set(f"{scan_id}_message", "GitHub not connected. Please connect GitHub first.", timeout=600)
                return
            
            github = GitHubService(access_token)
            
            # Get repositories to scan
            repos_to_scan = []
            for repo_id in repo_ids:
                try:
                    repo = GitHubRepo.objects.get(id=repo_id, user=user)
                    repos_to_scan.append(repo)
                except GitHubRepo.DoesNotExist:
                    print(f"⚠️ Repo {repo_id} not found for user")
            
            total_repos = len(repos_to_scan)
            cache.set(f"{scan_id}_total", total_repos, timeout=600)
            
            logger.info(f"Found {total_repos} repositories to scan")
            
            scan_results = []
            tf_found_count = 0
            scanned_count = 0
            found_terraform_repos = []
            
            for repo in repos_to_scan:
                scanned_count += 1
                repo_full_name = repo.repo_full_name
                repo_id = repo.repo_id
                
                # Update progress
                percentage = round((scanned_count / total_repos) * 100, 1) if total_repos > 0 else 0
                cache.set(f"{scan_id}_current", repo_full_name, timeout=600)
                cache.set(f"{scan_id}_scanned", scanned_count, timeout=600)
                cache.set(f"{scan_id}_percentage", percentage, timeout=600)
                
                logger.info(f"Scanning [{scanned_count}/{total_repos}] {repo_full_name} ({percentage}%)")
                
                # Check cache first for Terraform detection
                cache_key = f"github_terraform_{repo_id}"
                has_tf = cache.get(cache_key)
                
                if has_tf is None:
                    try:
                        owner, repo_name = repo_full_name.split('/')
                        # Check for Terraform files
                        has_tf = github.has_terraform_files(owner, repo_name)
                        if has_tf:
                            tf_found_count += 1
                            found_terraform_repos.append(repo_full_name)
                            logger.info(f"✅ Found Terraform in {repo_full_name}")
                            cache.set(f"{scan_id}_found", found_terraform_repos, timeout=600)
                        else:
                            logger.info(f"❌ No Terraform files in {repo_full_name}")
                        
                        # Cache the result
                        cache.set(cache_key, has_tf, timeout=3600)  # 1 hour cache
                    except Exception as e:
                        logger.error(f"Error checking {repo_full_name}: {e}")
                        has_tf = False
                else:
                    logger.info(f"Using cached result for {repo_full_name}: {has_tf}")
                    if has_tf:
                        if repo_full_name not in found_terraform_repos:
                            tf_found_count += 1
                            found_terraform_repos.append(repo_full_name)
                            cache.set(f"{scan_id}_found", found_terraform_repos, timeout=600)
                
                scan_results.append({
                    'repo_id': repo.id,
                    'repo_name': repo_full_name,
                    'has_terraform': has_tf,
                    'status': 'completed'
                })
                
                # Small delay to avoid rate limits
                time.sleep(0.15)
            
            # Store results
            cache.set(f"{scan_id}_repos", scan_results, timeout=600)
            cache.set(f"{scan_id}_status", "complete", timeout=600)
            cache.set(f"{scan_id}_terraform_count", tf_found_count, timeout=600)
            cache.set(f"{scan_id}_found_terraform", found_terraform_repos, timeout=600)
            cache.set(f"{scan_id}_message", f"Scan complete! Found {tf_found_count} repositories with Terraform files", timeout=600)
            cache.set(f"{scan_id}_results", scan_results, timeout=600)
            
            logger.info(f"Scan complete for user {user.id}: {tf_found_count}/{total_repos} repos with Terraform")
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            logger.error(f"Scan failed for user {user.id}: {e}")
            cache.set(f"{scan_id}_status", "error", timeout=600)
            cache.set(f"{scan_id}_error", str(e), timeout=600)
            cache.set(f"{scan_id}_message", f"Scan failed: {str(e)}", timeout=600)
    
    # Start background thread
    thread = threading.Thread(target=scan_repos)
    thread.daemon = True
    thread.start()
    
    logger.info(f"Started scan with ID: {scan_id} for user {user.username}")
    
    return JsonResponse({
        'success': True,
        'scan_id': scan_id,
        'message': 'Scan started successfully',
        'status_url': f'/github/scan/status/{scan_id}/'
    }, status=200)


@csrf_exempt
@require_http_methods(["GET"])
def get_scan_status_manual(request, scan_id):
    """
    Manual version of get_scan_status that doesn't use DRF authentication
    """
    print(f"🔍 get_scan_status_manual called for scan_id: {scan_id}")
    
    # Get token from header
    auth_header = request.headers.get('Authorization', '')
    token_key = None
    if auth_header.startswith('Token '):
        token_key = auth_header[6:]
    
    if not token_key:
        return JsonResponse({'error': 'Authentication required'}, status=401)
    
    # Validate token and get user
    try:
        token = Token.objects.get(key=token_key)
        user = token.user
        print(f"✅ Authenticated user: {user.username}")
    except Token.DoesNotExist:
        return JsonResponse({'error': 'Invalid token'}, status=401)
    
    # Get scan status from cache
    status_val = cache.get(f"{scan_id}_status")
    
    if status_val is None:
        print(f"❌ Scan not found: {scan_id}")
        return JsonResponse({'error': 'Scan not found or expired'}, status=404)
    
    # Get all progress data
    scanned = cache.get(f"{scan_id}_scanned", 0)
    total = cache.get(f"{scan_id}_total", 0)
    percentage = cache.get(f"{scan_id}_percentage", 0)
    current_repo = cache.get(f"{scan_id}_current", "")
    found_terraform = cache.get(f"{scan_id}_found", [])
    terraform_count = cache.get(f"{scan_id}_terraform_count", 0)
    message = cache.get(f"{scan_id}_message", "")
    
    response_data = {
        'status': status_val,
        'current_repo': current_repo,
        'scanned': scanned,
        'total': total,
        'percentage': percentage,
        'found_terraform': found_terraform,
        'terraform_count': terraform_count,
        'message': message,
    }
    
    if status_val == "complete":
        results = cache.get(f"{scan_id}_results", [])
        repos = cache.get(f"{scan_id}_repos", [])
        response_data['results'] = results or repos
        response_data['found_terraform_repos'] = cache.get(f"{scan_id}_found_terraform", [])
        print(f"✅ Returning complete scan results: {len(response_data['results'])} repos, {terraform_count} with Terraform")
    
    if status_val == "error":
        response_data['error'] = cache.get(f"{scan_id}_error", "Unknown error")
        print(f"❌ Returning error for scan {scan_id}: {response_data['error']}")
    
    return JsonResponse(response_data, status=200)

@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_scan_status(request, scan_id):
    """
    Poll for scan progress
    """
    status_val = cache.get(f"{scan_id}_status")
    
    if status_val is None:
        logger.warning(f"Scan not found: {scan_id}")
        return Response({'error': 'Scan not found or expired'}, status=status.HTTP_404_NOT_FOUND)
    
    # Get all progress data
    scanned = cache.get(f"{scan_id}_scanned", 0)
    total = cache.get(f"{scan_id}_total", 0)
    percentage = cache.get(f"{scan_id}_percentage", 0)
    current_repo = cache.get(f"{scan_id}_current", "")
    found_terraform = cache.get(f"{scan_id}_found", [])
    terraform_count = cache.get(f"{scan_id}_terraform_count", 0)
    message = cache.get(f"{scan_id}_message", "")
    
    response_data = {
        'status': status_val,
        'current_repo': current_repo,
        'scanned': scanned,
        'total': total,
        'percentage': percentage,
        'found_terraform': found_terraform,
        'terraform_count': terraform_count,
        'message': message,
    }
    
    if status_val == "complete":
        repos = cache.get(f"{scan_id}_repos", [])
        response_data['repos'] = repos
        response_data['found_terraform_repos'] = cache.get(f"{scan_id}_found_terraform", [])
        logger.info(f"Returning complete scan results: {len(repos)} repos, {terraform_count} with Terraform")
    
    if status_val == "error":
        response_data['error'] = cache.get(f"{scan_id}_error", "Unknown error")
        logger.error(f"Returning error for scan {scan_id}: {response_data['error']}")
    
    return Response(response_data, status=status.HTTP_200_OK)

@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def test_terraform_detection(request, owner, repo):
    """
    Test endpoint to debug Terraform detection for a specific repo
    """
    try:
        from .models import GitHubUser
        from .github_service import GitHubService
        
        github_user = GitHubUser.objects.get(user=request.user)
        github = GitHubService(github_user.access_token)
        
        # Check the repo
        has_tf = github.has_terraform_files(owner, repo)
        
        # Also check root contents
        contents = github.get_repo_contents(owner, repo)
        
        return Response({
            'has_terraform': has_tf,
            'repo': f"{owner}/{repo}",
            'contents_preview': contents[:5] if contents else []
        }, status=200)
        
    except Exception as e:
        return Response({'error': str(e)}, status=400)



# views.py - Add these new view functions

import json
import logging
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.utils import timezone
from django.db import transaction
from decimal import Decimal
from datetime import datetime, timedelta
import statistics

from .models import AWSAccount, AWSCostCache, CostDataHistory, CostDriver, AWSCostAnalysis
from .models import GitHubUser, GitHubRepo, DeploymentEvent, CostSpike
from .aws_cost import (
    get_cached_90_days_cost, get_cached_monthly_cost, 
    get_cached_7_days_cost, get_cached_yesterday_cost,
    get_cached_low_level_costs, get_cached_cost_drivers,
    get_cached_cost_analysis, save_cost_data, clear_cost_data
)
from .aws_client import assume_role, test_connection
from .low_level_db_service import LowLevelServiceDB
from .github_service import GitHubService, exchange_code_for_token, get_user_from_token

logger = logging.getLogger(__name__)

def get_auth_token(request):
    """Helper to get auth token from request"""
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Token '):
        return auth_header[6:]
    return None

# views.py - Replace the existing get_cost_analytics function

# Remove the old @login_required version and use DRF decorators instead

@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_cost_analytics(request, account_db_id):
    """Get comprehensive cost analytics for dashboard"""
    try:
        account = AWSAccount.objects.get(id=account_db_id, user=request.user)
        
        # Get cached data
        total_90_days = get_cached_90_days_cost(account)
        monthly_cost = get_cached_monthly_cost(account)
        seven_days = get_cached_7_days_cost(account)
        yesterday = get_cached_yesterday_cost(account)
        cost_drivers = get_cached_cost_drivers(account, monthly_cost)
        
        # Calculate monthly change (compare to previous month)
        monthly_change = 0
        try:
            
            previous_month_start = datetime.now().replace(day=1) - timedelta(days=1)
            previous_month_cost = get_cached_monthly_cost(account)
            if previous_month_cost and previous_month_cost > 0:
                monthly_change = ((monthly_cost - previous_month_cost) / previous_month_cost) * 100
        except:
            pass
        
        # Prepare service breakdown from cost drivers
        service_breakdown = []
        if cost_drivers:
            for driver in cost_drivers[:10]:
                service_breakdown.append({
                    'service': driver.get('service', driver.get('title', 'Unknown')),
                    'amount': float(driver.get('amount', 0)),
                    'percentage': float(driver.get('percentage', 0)),
                    'recommendation': driver.get('recommendation', ''),
                    'estimated_savings': float(driver.get('estimated_savings', 0))
                })
        
        # Prepare forecast
        forecast = {
            'thirtyDay': float(monthly_cost) if monthly_cost else 0,
            'sevenDay': float(sum(day.get('cost', 0) for day in seven_days)) if seven_days else 0
        }
        
        # Format daily spend
        daily_spend = []
        if seven_days:
            for day in seven_days:
                date_str = day.get('name', '')
                try:
                    date_obj = datetime.strptime(date_str, '%b %d')
                    daily_spend.append({
                        'date': date_str,
                        'day_name': date_obj.strftime('%A')[:3] if date_obj else '',
                        'full_date': f"{date_obj.year}-{date_obj.month:02d}-{date_obj.day:02d}" if date_obj else '',
                        'amount': float(day.get('cost', 0))
                    })
                except:
                    daily_spend.append({
                        'date': date_str,
                        'amount': float(day.get('cost', 0))
                    })
        
        return Response({
            'total_spend': float(total_90_days) if total_90_days else 0,
            'today_spend': float(yesterday.get('amount', 0)) if yesterday else 0,
            'current_month_spend': float(monthly_cost) if monthly_cost else 0,
            'current_month_name': datetime.now().strftime('%B %Y'),
            'monthly_change': round(float(monthly_change), 1),
            'forecast': forecast,
            'daily_spend': daily_spend,
            'service_breakdown': service_breakdown,
            'cost_drivers': cost_drivers
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        logger.error(f"Error getting cost analytics: {e}")
        return Response({'error': str(e)}, status=500)

# views.py - Update these functions to use DRF decorators

@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def sync_aws_data(request, account_db_id):
    """Force sync AWS data"""
    try:
        account = AWSAccount.objects.get(id=account_db_id, user=request.user)
        
        # Clear existing cache
        clear_cost_data(account)
        
        # Fetch fresh data
        total_90_days = get_cached_90_days_cost(account)
        monthly_cost = get_cached_monthly_cost(account)
        seven_days = get_cached_7_days_cost(account)
        yesterday = get_cached_yesterday_cost(account)
        cost_drivers = get_cached_cost_drivers(account, monthly_cost)
        low_level = get_cached_low_level_costs(account)
        
        return Response({
            'message': 'Data sync completed successfully',
            'data': {
                'total_90_days': float(total_90_days) if total_90_days else 0,
                'monthly_cost': float(monthly_cost) if monthly_cost else 0,
                'seven_days': seven_days,
                'yesterday': yesterday,
                'cost_drivers': cost_drivers,
                'low_level': low_level
            }
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        logger.error(f"Error syncing AWS data: {e}")
        return Response({'error': str(e)}, status=500)



@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
@csrf_exempt
def clear_aws_data(request, account_db_id):
    """Clear all cached AWS data"""
    try:
        account = AWSAccount.objects.get(id=account_db_id, user=request.user)
        
        # Clear all data
        cleared = clear_cost_data(account)
        
        return Response({
            'message': f'Cleared {cleared} data records',
            'cleared_records': cleared
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        logger.error(f"Error clearing AWS data: {e}")
        return Response({'error': str(e)}, status=500)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_low_level_services_fast(request, account_id):
    """Get low-level services from database (fast endpoint)"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        # Get services from database
        services_data = LowLevelServiceDB.get_services(account_id, force_refresh=False)
        
        # Check if there was an error
        if services_data and 'error' in services_data:
            return Response({'error': services_data['error']}, status=500)
        
        # Add source info
        services_data['source'] = 'database'
        services_data['cached'] = True
        
        return Response(services_data, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        logger.error(f"Error getting low-level services: {e}")
        return Response({'error': str(e)}, status=500)



@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def refresh_low_level_services(request, account_id):
    """Force refresh low-level services from AWS"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        # Force refresh
        services_data = LowLevelServiceDB.get_services(account_id, force_refresh=True)
        
        # Check if there was an error
        if services_data and 'error' in services_data:
            return Response({'error': services_data['error']}, status=500)
        
        # Add source info
        services_data['source'] = 'aws_api'
        services_data['cached'] = False
        
        return Response(services_data, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        logger.error(f"Error refreshing low-level services: {e}")
        return Response({'error': str(e)}, status=500)


@login_required
def get_low_level_services_summary(request, account_id):
    """Get summary of low-level services"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        summary = LowLevelServiceDB.get_cost_summary(account_id)
        
        if summary:
            return JsonResponse(summary)
        else:
            return JsonResponse({'error': 'No data available'}, status=404)
            
    except AWSAccount.DoesNotExist:
        return JsonResponse({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        logger.error(f"Error getting low-level services summary: {e}")
        return JsonResponse({'error': str(e)}, status=500)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_paid_resources(request, account_id):
    """Get paid resources breakdown - FIXED VERSION"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        # Get low-level data directly from database
        from .models import LowLevelServiceResource, LowLevelServiceDefinition
        
        # Get all active resources
        resources = LowLevelServiceResource.objects.filter(
            account=account,
            is_active=True
        ).select_related('service_definition__category')
        
        if not resources.exists():
            # Return sample data for testing if no real data exists
            return Response({
                'cost_categories': {},
                'summary': {
                    'total_paid_resources': 0,
                    'high_cost_resources': 0,
                    'medium_cost_resources': 0,
                    'low_cost_resources': 0,
                    'categories_found': 0,
                    'timestamp': timezone.now().isoformat()
                },
                'message': 'No resource data available yet. Please sync your AWS account first.'
            }, status=200)
        
        # Define cost thresholds
        HIGH_COST_THRESHOLD = 50
        MEDIUM_COST_THRESHOLD = 10
        
        # Process resources into categories
        cost_categories = {}
        total_resources_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for resource in resources:
            service_def = resource.service_definition
            category_name = service_def.category.name if service_def.category else 'Other'
            amount = float(resource.estimated_monthly_cost or 0)
            resource_name = service_def.name
            resource_id = resource.resource_id
            region = resource.region or 'N/A'
            
            total_resources_count += 1
            
            # Determine cost level for this resource
            if amount >= HIGH_COST_THRESHOLD:
                high_count += 1
                cost_level = 'HIGH'
            elif amount >= MEDIUM_COST_THRESHOLD:
                medium_count += 1
                cost_level = 'MEDIUM'
            else:
                low_count += 1
                cost_level = 'LOW'
            
            # Create category key
            category_key = category_name.lower().replace(' ', '_').replace('&', '')
            
            if category_key not in cost_categories:
                cost_categories[category_key] = {
                    'name': category_name,
                    'description': f'Resources in the {category_name} category',
                    'cost_level': cost_level,
                    'cost_driver': resource_name[:50] if amount >= HIGH_COST_THRESHOLD else 'Minor contributor',
                    'resources': [],
                    'count': 0,
                    'estimated_monthly_cost': 0
                }
            
            # Add resource to category
            cost_categories[category_key]['resources'].append({
                'name': resource_name,
                'resource_id': resource_id,
                'region': region,
                'amount': round(amount, 2),
                'cost_level': cost_level
            })
            cost_categories[category_key]['count'] += 1
            cost_categories[category_key]['estimated_monthly_cost'] += amount
            
            # Update category cost level based on total
            if cost_categories[category_key]['estimated_monthly_cost'] >= HIGH_COST_THRESHOLD:
                cost_categories[category_key]['cost_level'] = 'HIGH'
            elif cost_categories[category_key]['estimated_monthly_cost'] >= MEDIUM_COST_THRESHOLD:
                cost_categories[category_key]['cost_level'] = 'MEDIUM'
            else:
                cost_categories[category_key]['cost_level'] = 'LOW'
        
        # Calculate summary
        summary = {
            'total_paid_resources': total_resources_count,
            'high_cost_resources': high_count,
            'medium_cost_resources': medium_count,
            'low_cost_resources': low_count,
            'categories_found': len(cost_categories),
            'timestamp': timezone.now().isoformat()
        }
        
        return Response({
            'cost_categories': cost_categories,
            'summary': summary,
            'raw_resources': [{
                'name': r.service_definition.name,
                'amount': float(r.estimated_monthly_cost or 0),
                'resource_id': r.resource_id,
                'region': r.region
            } for r in resources[:20]]
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        logger.error(f"Error getting paid resources: {e}")
        return Response({'error': str(e)}, status=500)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_resource_summary(request, account_id):
    """Get resource summary for the account - FIXED VERSION"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        # Get resources from database with proper filtering
        from .models import LowLevelServiceResource, LowLevelServiceDefinition
        
        resources = LowLevelServiceResource.objects.filter(
            account=account,
            is_active=True
        ).select_related('service_definition__category')
        
        # Initialize summary with all possible services
        resource_summary = {
            'total_resources': 0,
            'total_monthly_cost': 0,
            'services': {}
        }
        
        # Service name mappings for display
        service_mappings = {
            'ec2': {'display': 'EC2 Instances', 'icon': 'Cpu', 'category': 'Compute'},
            'instance': {'display': 'EC2 Instances', 'icon': 'Cpu', 'category': 'Compute'},
            'lambda': {'display': 'Lambda Functions', 'icon': 'Code', 'category': 'Compute'},
            'eks': {'display': 'EKS Clusters', 'icon': 'Container', 'category': 'Compute'},
            'ecs': {'display': 'ECS Services', 'icon': 'Container', 'category': 'Compute'},
            'rds': {'display': 'RDS Instances', 'icon': 'Database', 'category': 'Database'},
            'database': {'display': 'RDS Instances', 'icon': 'Database', 'category': 'Database'},
            'dynamodb': {'display': 'DynamoDB Tables', 'icon': 'Box', 'category': 'Database'},
            'elasticache': {'display': 'ElastiCache Clusters', 'icon': 'Zap', 'category': 'Database'},
            'redshift': {'display': 'Redshift Clusters', 'icon': 'Sparkles', 'category': 'Database'},
            's3': {'display': 'S3 Buckets', 'icon': 'HardDrive', 'category': 'Storage'},
            'bucket': {'display': 'S3 Buckets', 'icon': 'HardDrive', 'category': 'Storage'},
            'ebs': {'display': 'EBS Volumes', 'icon': 'HardDrive', 'category': 'Storage'},
            'volume': {'display': 'EBS Volumes', 'icon': 'HardDrive', 'category': 'Storage'},
            'efs': {'display': 'EFS File Systems', 'icon': 'FileText', 'category': 'Storage'},
            'load balancer': {'display': 'Load Balancers', 'icon': 'Scale', 'category': 'Networking'},
            'alb': {'display': 'Load Balancers', 'icon': 'Scale', 'category': 'Networking'},
            'elb': {'display': 'Load Balancers', 'icon': 'Scale', 'category': 'Networking'},
            'nat': {'display': 'NAT Gateways', 'icon': 'Network', 'category': 'Networking'},
            'vpc': {'display': 'VPC Resources', 'icon': 'Network', 'category': 'Networking'},
            'endpoint': {'display': 'VPC Endpoints', 'icon': 'Key', 'category': 'Networking'},
            'cloudfront': {'display': 'CloudFront Distributions', 'icon': 'Globe', 'category': 'CDN'},
            'api gateway': {'display': 'API Gateway', 'icon': 'Settings', 'category': 'Integration'},
            'sqs': {'display': 'SQS Queues', 'icon': 'MessageSquare', 'category': 'Messaging'},
            'sns': {'display': 'SNS Topics', 'icon': 'Bell', 'category': 'Messaging'},
            'route53': {'display': 'Route53 Zones', 'icon': 'Globe', 'category': 'DNS'},
            'cloudwatch': {'display': 'CloudWatch Resources', 'icon': 'Eye', 'category': 'Monitoring'},
        }
        
        # Count resources
        for resource in resources:
            service_name = resource.service_definition.name.lower()
            monthly_cost = float(resource.estimated_monthly_cost or 0)
            
            resource_summary['total_resources'] += resource.count or 1
            resource_summary['total_monthly_cost'] += monthly_cost * (resource.count or 1)
            
            # Find matching service key
            matched_key = None
            for key, mapping in service_mappings.items():
                if key in service_name:
                    matched_key = key
                    break
            
            if not matched_key:
                matched_key = 'other'
                if 'other' not in service_mappings:
                    service_mappings['other'] = {'display': 'Other Resources', 'icon': 'Server', 'category': 'Other'}
            
            display_name = service_mappings[matched_key]['display']
            
            if display_name not in resource_summary['services']:
                resource_summary['services'][display_name] = {
                    'count': 0,
                    'monthly_cost': 0,
                    'icon': service_mappings[matched_key]['icon'],
                    'category': service_mappings[matched_key]['category'],
                    'resources': []
                }
            
            resource_summary['services'][display_name]['count'] += resource.count or 1
            resource_summary['services'][display_name]['monthly_cost'] += monthly_cost * (resource.count or 1)
            resource_summary['services'][display_name]['resources'].append({
                'id': resource.resource_id,
                'name': resource.resource_name or resource.resource_id,
                'region': resource.region,
                'monthly_cost': monthly_cost
            })
        
        # Sort services by monthly cost
        sorted_services = dict(sorted(
            resource_summary['services'].items(),
            key=lambda x: x[1]['monthly_cost'],
            reverse=True
        ))
        resource_summary['services'] = sorted_services
        
        return Response(resource_summary, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        logger.error(f"Error getting resource summary: {e}")
        return Response({'error': str(e)}, status=500)


@login_required
def get_cost_analysis(request, account_id):
    """Get AI-powered cost analysis with recommendations"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        # Get necessary data
        monthly_cost = get_cached_monthly_cost(account)
        cost_drivers = get_cached_cost_drivers(account, monthly_cost)
        low_level_data = get_cached_low_level_costs(account)
        
        # Get cached analysis or generate new
        analysis_text = get_cached_cost_analysis(account, {
            'total_90_days': get_cached_90_days_cost(account),
            'monthly_cost': monthly_cost,
            'latest_daily_cost': get_cached_yesterday_cost(account).get('amount', 0) if get_cached_yesterday_cost(account) else 0
        }, cost_drivers)
        
        # Parse analysis into structured format
        high_risk_findings = []
        medium_risk_findings = []
        low_risk_findings = []
        recommendations = []
        
        # Extract from low_level_data
        if low_level_data and low_level_data.get('items'):
            for item in low_level_data['items']:
                amount = item.get('amount', 0)
                name = item.get('name', '')
                
                if amount > 100:
                    high_risk_findings.append({
                        'category': item.get('category', 'Resource'),
                        'issue': f'High cost from {name}: ${amount:.2f}',
                        'impact': 'Significant portion of monthly spend',
                        'recommendation': f'Review {name} usage and consider optimization',
                        'potential_savings': f'${amount * 0.3:.2f}'
                    })
                elif amount > 20:
                    medium_risk_findings.append({
                        'category': item.get('category', 'Resource'),
                        'issue': f'{name} costing ${amount:.2f}',
                        'impact': 'Moderate cost impact',
                        'recommendation': f'Optimize {name} usage',
                        'potential_savings': f'${amount * 0.2:.2f}'
                    })
                else:
                    low_risk_findings.append({
                        'category': item.get('category', 'Resource'),
                        'issue': f'{name}: ${amount:.2f}',
                        'impact': 'Minor cost impact',
                        'recommendation': 'Monitor for unusual changes'
                    })
        
        # Extract recommendations from cost drivers
        for driver in cost_drivers[:5]:
            if driver.get('recommendation'):
                recommendations.append(driver['recommendation'])
        
        # Add generic recommendations if needed
        if not recommendations:
            recommendations = [
                'Enable AWS Cost Explorer to track spending patterns',
                'Set up budget alerts for cost thresholds',
                'Review idle resources and terminate unused instances',
                'Consider Reserved Instances or Savings Plans for steady workloads'
            ]
        
        # Calculate estimated savings potential
        estimated_savings = sum([
            f.get('potential_savings', '0').replace('$', '').replace(',', '')
            for f in high_risk_findings + medium_risk_findings
            if f.get('potential_savings')
        ])
        try:
            estimated_savings = float(estimated_savings) if estimated_savings else 0
        except:
            estimated_savings = monthly_cost * 0.15 if monthly_cost else 0
        
        return JsonResponse({
            'high_risk_findings': high_risk_findings[:5],
            'medium_risk_findings': medium_risk_findings[:10],
            'low_risk_findings': low_risk_findings[:15],
            'recommendations': recommendations[:10],
            'estimated_savings_potential': round(estimated_savings, 2),
            'summary': {
                'total_resources': len(low_level_data.get('items', [])) if low_level_data else 0,
                'high_cost_categories': len(high_risk_findings),
                'medium_cost_categories': len(medium_risk_findings),
                'low_cost_categories': len(low_risk_findings)
            }
        })
        
    except AWSAccount.DoesNotExist:
        return JsonResponse({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        logger.error(f"Error getting cost analysis: {e}")
        return JsonResponse({'error': str(e)}, status=500)

# Add this import at the top of views.py
from .terraform_parser import TerraformCostEstimator

@csrf_exempt
@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def analyze_terraform_costs(request):
    """
    Analyze Terraform files in connected repositories and estimate costs
    """
    try:
        data = json.loads(request.body)
        repo_ids = data.get('repo_ids', [])
        
        if not repo_ids:
            return Response({'error': 'No repositories selected'}, status=400)
        
        # Get GitHub access token
        try:
            github_user = GitHubUser.objects.get(user=request.user)
            access_token = github_user.access_token
        except GitHubUser.DoesNotExist:
            return Response({'error': 'GitHub not connected'}, status=400)
        
        github_service = GitHubService(access_token)
        estimator = TerraformCostEstimator()
        
        results = []
        
        for repo_id in repo_ids:
            try:
                repo = GitHubRepo.objects.get(id=repo_id, user=request.user)
                
                # Analyze repository
                analysis = estimator.analyze_repository(repo, github_service)
                results.append(analysis)
                
            except GitHubRepo.DoesNotExist:
                results.append({
                    'repository_id': repo_id,
                    'error': 'Repository not found'
                })
            except Exception as e:
                results.append({
                    'repository_id': repo_id,
                    'error': str(e)
                })
        
        # Calculate totals
        total_hourly = sum(r.get('total_hourly_cost', 0) for r in results if 'error' not in r)
        total_monthly = sum(r.get('total_monthly_cost', 0) for r in results if 'error' not in r)
        
        return Response({
            'success': True,
            'results': results,
            'summary': {
                'total_repositories': len(results),
                'successful_scans': len([r for r in results if 'error' not in r]),
                'total_hourly_cost': round(total_hourly, 2),
                'total_monthly_cost': round(total_monthly, 2),
                'currency': 'USD'
            }
        }, status=200)
        
    except Exception as e:
        logger.error(f"Error analyzing Terraform costs: {e}")
        return Response({'error': str(e)}, status=500)

@login_required
def list_cost_spikes(request, account_db_id):
    """List detected cost spikes for an account"""
    try:
        account = AWSAccount.objects.get(id=account_db_id, user=request.user)
        
        # Get cost spikes from database
        spikes = CostSpike.objects.filter(
            aws_account=account
        ).order_by('-start_time')[:30]
        
        spike_data = []
        for spike in spikes:
            spike_data.append({
                'id': spike.id,
                'start_time': spike.start_time.isoformat(),
                'end_time': spike.end_time.isoformat(),
                'increase_percentage': float(spike.increase_percentage),
                'before_cost': float(spike.before_cost),
                'after_cost': float(spike.after_cost),
                'services_affected': spike.services_affected,
                'is_resolved': spike.is_resolved,
                'resolved_at': spike.resolved_at.isoformat() if spike.resolved_at else None
            })
        
        return JsonResponse({
            'cost_spikes': spike_data,
            'total': len(spike_data)
        })
        
    except AWSAccount.DoesNotExist:
        return JsonResponse({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        logger.error(f"Error listing cost spikes: {e}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def get_deployment_correlation(request, account_db_id):
    """Get deployment events correlated with cost spikes"""
    try:
        account = AWSAccount.objects.get(id=account_db_id, user=request.user)
        
        # Get deployments correlated with cost spikes
        deployments = DeploymentEvent.objects.filter(
            aws_account=account,
            is_correlated=True
        ).select_related('repo', 'cost_spike_id').order_by('-merged_at')[:50]
        
        deployment_data = []
        for deploy in deployments:
            deployment_data.append({
                'id': deploy.id,
                'repo_name': deploy.repo.repo_full_name,
                'pr_number': deploy.pr_number,
                'pr_title': deploy.pr_title,
                'pr_url': deploy.pr_url,
                'merged_by': deploy.merged_by,
                'merged_at': deploy.merged_at.isoformat(),
                'files_changed': deploy.files_changed,
                'services_affected': deploy.services_affected,
                'cost_impact': float(deploy.cost_impact) if deploy.cost_impact else None,
                'cost_spike': {
                    'id': deploy.cost_spike_id.id if deploy.cost_spike_id else None,
                    'increase_percentage': float(deploy.cost_spike_id.increase_percentage) if deploy.cost_spike_id else None
                } if deploy.cost_spike_id else None
            })
        
        return JsonResponse({
            'deployments': deployment_data,
            'total': len(deployment_data)
        })
        
    except AWSAccount.DoesNotExist:
        return JsonResponse({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        logger.error(f"Error getting deployment correlation: {e}")
        return JsonResponse({'error': str(e)}, status=500)

@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def list_connected_repos(request):
    """
    List user's connected GitHub repositories
    """
    # DRF's IsAuthenticated will handle 401 automatically
    repos = GitHubRepo.objects.filter(user=request.user, status='connected')
    
    data = []
    for repo in repos:
        # Count deployments
        deployment_count = DeploymentEvent.objects.filter(repo=repo).count()
        
        # Get latest deployment
        latest_deployment = DeploymentEvent.objects.filter(repo=repo).first()
        
        data.append({
            'id': repo.id,
            'repo_name': repo.repo_name,
            'repo_full_name': repo.repo_full_name,
            'repo_url': repo.repo_url,
            'aws_account_id': repo.aws_account.id if repo.aws_account else None,
            'aws_account_name': repo.aws_account.account_alias if repo.aws_account else None,
            'status': repo.status,
            'webhook_id': repo.webhook_id,
            'last_sync_at': repo.last_sync_at.isoformat() if repo.last_sync_at else None,
            'connected_at': repo.connected_at.isoformat()
        })
    
    return Response({'repos': data}, status=status.HTTP_200_OK)

@login_required
def connect_github_repo(request):
    """Connect a GitHub repository"""
    try:
        data = json.loads(request.body)
        repo_id = data.get('repo_id')
        repo_name = data.get('repo_name')
        repo_full_name = data.get('repo_full_name')
        repo_url = data.get('repo_url')
        access_token = data.get('access_token')
        installation_id = data.get('installation_id')
        aws_account_id = data.get('aws_account_id')
        
        if not all([repo_id, repo_name, repo_full_name, repo_url, access_token]):
            return JsonResponse({'error': 'Missing required fields'}, status=400)
        
        # Get AWS account if provided
        aws_account = None
        if aws_account_id:
            try:
                aws_account = AWSAccount.objects.get(id=aws_account_id, user=request.user)
            except AWSAccount.DoesNotExist:
                pass
        
        # Create or update repo
        repo, created = GitHubRepo.objects.update_or_create(
            user=request.user,
            repo_id=repo_id,
            defaults={
                'repo_name': repo_name,
                'repo_full_name': repo_full_name,
                'repo_url': repo_url,
                'access_token': access_token,
                'installation_id': installation_id,
                'aws_account': aws_account,
                'status': 'connected'
            }
        )
        
        # Create webhook
        if aws_account:
            webhook_url = f"{settings.SITE_URL}/api/github/webhook/"
            github_service = GitHubService(access_token)
            webhook = github_service.create_webhook(
                repo_full_name.split('/')[0],
                repo_full_name.split('/')[1],
                webhook_url
            )
            if webhook and webhook.get('id'):
                repo.webhook_id = webhook['id']
                repo.save()
        
        return JsonResponse({
            'message': 'Repository connected successfully',
            'repo': {
                'id': repo.id,
                'repo_id': repo.repo_id,
                'repo_name': repo.repo_name,
                'repo_full_name': repo.repo_full_name,
                'repo_url': repo.repo_url,
                'aws_account_id': repo.aws_account.id if repo.aws_account else None,
                'status': repo.status,
                'webhook_id': repo.webhook_id
            }
        })
        
    except Exception as e:
        logger.error(f"Error connecting GitHub repo: {e}")
        return JsonResponse({'error': str(e)}, status=500)



@api_view(['DELETE'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
@csrf_exempt
def disconnect_github_repo(request, repo_id):
    """
    Disconnect a GitHub repository
    """
    try:
        repo = GitHubRepo.objects.get(id=repo_id, user=request.user)
    except GitHubRepo.DoesNotExist:
        return Response({'error': 'Repository not found'}, status=404)
    
    # Delete webhook from GitHub
    if repo.webhook_id and repo.repo_full_name:
        try:
            github = GitHubService(repo.access_token)
            owner, repo_name = repo.repo_full_name.split('/')
            github.delete_webhook(owner, repo_name, repo.webhook_id)
        except Exception as e:
            print(f"Error deleting webhook: {e}")
    
    # Delete the repo (deployments will cascade delete)
    repo.delete()
    
    return Response({'message': 'Repository disconnected successfully'}, status=200)



@login_required
def list_deployments(request, repo_id):
    """List deployments for a repository"""
    try:
        repo = GitHubRepo.objects.get(id=repo_id, user=request.user)
        
        deployments = DeploymentEvent.objects.filter(repo=repo).order_by('-merged_at')[:100]
        
        deployment_data = []
        for deploy in deployments:
            deployment_data.append({
                'id': deploy.id,
                'pr_number': deploy.pr_number,
                'pr_title': deploy.pr_title,
                'pr_url': deploy.pr_url,
                'merged_by': deploy.merged_by,
                'merged_at': deploy.merged_at.isoformat(),
                'files_changed': deploy.files_changed[:10],  # Limit to first 10 files
                'services_affected': deploy.services_affected,
                'cost_impact': float(deploy.cost_impact) if deploy.cost_impact else None,
                'is_correlated': deploy.is_correlated
            })
        
        return JsonResponse({
            'deployments': deployment_data,
            'total': len(deployment_data),
            'repo': {
                'id': repo.id,
                'name': repo.repo_full_name,
                'url': repo.repo_url
            }
        })
        
    except GitHubRepo.DoesNotExist:
        return JsonResponse({'error': 'Repository not found'}, status=404)
    except Exception as e:
        logger.error(f"Error listing deployments: {e}")
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
def github_webhook(request):
    """Handle GitHub webhook events"""
    try:
        event_type = request.headers.get('X-GitHub-Event', '')
        
        if event_type != 'pull_request':
            return JsonResponse({'message': 'Ignored event'}, status=200)
        
        data = json.loads(request.body)
        action = data.get('action', '')
        
        if action != 'closed':
            return JsonResponse({'message': 'Ignored action'}, status=200)
        
        pull_request = data.get('pull_request', {})
        if not pull_request.get('merged', False):
            return JsonResponse({'message': 'PR not merged'}, status=200)
        
        repo = data.get('repository', {})
        repo_full_name = repo.get('full_name', '')
        
        # Find connected repo in database
        github_repo = GitHubRepo.objects.filter(
            repo_full_name=repo_full_name,
            status='connected'
        ).first()
        
        if not github_repo:
            return JsonResponse({'message': 'Repo not connected'}, status=200)
        
        # Get PR files
        github_service = GitHubService(github_repo.access_token)
        pr_number = pull_request.get('number')
        files = github_service.get_pr_files(
            repo_full_name.split('/')[0],
            repo_full_name.split('/')[1],
            pr_number
        )
        
        # Determine affected services
        services_affected = github_service.get_services_from_files(files)
        
        # Create deployment event
        deployment = DeploymentEvent.objects.create(
            repo=github_repo,
            aws_account=github_repo.aws_account,
            pr_number=pr_number,
            pr_title=pull_request.get('title', ''),
            pr_url=pull_request.get('html_url', ''),
            merged_by=pull_request.get('merged_by', {}).get('login', 'unknown'),
            merged_at=timezone.datetime.fromisoformat(
                pull_request.get('merged_at', '').replace('Z', '+00:00')
            ),
            files_changed=[f.get('filename', '') for f in files[:50]],
            services_affected=services_affected
        )
        
        logger.info(f"Created deployment event: {deployment}")
        
        return JsonResponse({'message': 'Deployment recorded'}, status=200)
        
    except Exception as e:
        logger.error(f"Error in GitHub webhook: {e}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def start_github_scan(request):
    """Start scanning GitHub repositories for Terraform files"""
    try:
        data = json.loads(request.body)
        repo_ids = data.get('repo_ids', [])
        
        if not repo_ids:
            return JsonResponse({'error': 'No repositories selected'}, status=400)
        
        scan_id = f"scan_{timezone.now().timestamp()}"
        scan_results = {
            'scan_id': scan_id,
            'status': 'in_progress',
            'results': []
        }
        
        # Store in cache
        from django.core.cache import cache
        cache.set(f"github_scan_{scan_id}", scan_results, timeout=3600)
        
        # Start background task (simplified - you might want to use Celery)
        import threading
        
        def run_scan():
            results = []
            for repo_id in repo_ids:
                try:
                    repo = GitHubRepo.objects.get(id=repo_id, user=request.user)
                    github_service = GitHubService(repo.access_token)
                    
                    owner = repo.repo_full_name.split('/')[0]
                    name = repo.repo_full_name.split('/')[1]
                    
                    has_terraform = github_service.has_terraform_files(owner, name)
                    
                    results.append({
                        'repo_id': repo.id,
                        'repo_name': repo.repo_full_name,
                        'has_terraform': has_terraform,
                        'status': 'completed'
                    })
                    
                except Exception as e:
                    results.append({
                        'repo_id': repo_id,
                        'error': str(e),
                        'status': 'failed'
                    })
            
            scan_results['status'] = 'completed'
            scan_results['results'] = results
            cache.set(f"github_scan_{scan_id}", scan_results, timeout=3600)
        
        thread = threading.Thread(target=run_scan)
        thread.start()
        
        return JsonResponse({
            'scan_id': scan_id,
            'message': 'Scan started',
            'status': 'in_progress'
        })
        
    except Exception as e:
        logger.error(f"Error starting GitHub scan: {e}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def get_scan_status(request, scan_id):
    """Get status of a GitHub scan"""
    try:
        from django.core.cache import cache
        scan_results = cache.get(f"github_scan_{scan_id}")
        
        if not scan_results:
            return JsonResponse({'error': 'Scan not found'}, status=404)
        
        return JsonResponse(scan_results)
        
    except Exception as e:
        logger.error(f"Error getting scan status: {e}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def test_terraform_detection(request, owner, repo):
    """Test Terraform detection for a repository"""
    try:
        github_user = GitHubUser.objects.get(user=request.user)
        github_service = GitHubService(github_user.access_token)
        
        has_terraform = github_service.has_terraform_files(owner, repo)
        
        return JsonResponse({
            'owner': owner,
            'repo': repo,
            'has_terraform': has_terraform
        })
        
    except GitHubUser.DoesNotExist:
        return JsonResponse({'error': 'GitHub not connected'}, status=401)
    except Exception as e:
        logger.error(f"Error testing terraform detection: {e}")
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
@require_http_methods(["POST"])
def connect_github_repo_legacy(request):
    """
    Legacy endpoint for GitHub repo connection (no CSRF)
    """
    print("🔍 connect_github_repo_legacy called")
    print(f"Request method: {request.method}")
    print(f"Request body: {request.body}")
    
    # Get token from header
    auth_header = request.headers.get('Authorization', '')
    token = None
    if auth_header.startswith('Token '):
        token = auth_header[6:]
    
    print(f"Auth header: {auth_header[:20] if auth_header else 'None'}...")
    print(f"Token extracted: {token[:10] if token else 'None'}...")
    
    if not token:
        return JsonResponse({'error': 'Authentication required'}, status=401)
    
    try:
        from rest_framework.authtoken.models import Token
        token_obj = Token.objects.get(key=token)
        user = token_obj.user
        print(f"✅ Authenticated user: {user.username} (ID: {user.id})")
    except Token.DoesNotExist:
        print("❌ Invalid token")
        return JsonResponse({'error': 'Invalid token'}, status=401)
    except Exception as e:
        print(f"❌ Token error: {e}")
        return JsonResponse({'error': f'Token error: {str(e)}'}, status=401)
    
    # Parse request body
    try:
        data = json.loads(request.body.decode('utf-8'))
        print(f"✅ Parsed data: {data}")
    except json.JSONDecodeError as e:
        print(f"❌ JSON decode error: {e}")
        return JsonResponse({'error': f'Invalid JSON: {str(e)}'}, status=400)
    
    # Extract fields with proper validation
    repo_id = data.get('repo_id')
    repo_name = data.get('repo_name')
    repo_full_name = data.get('repo_full_name')
    repo_url = data.get('repo_url')
    aws_account_id = data.get('aws_account_id')
    
    print(f"repo_id: {repo_id} (type: {type(repo_id)})")
    print(f"repo_name: {repo_name}")
    print(f"repo_full_name: {repo_full_name}")
    print(f"repo_url: {repo_url}")
    print(f"aws_account_id: {aws_account_id}")
    
    # Validate required fields
    if not repo_id:
        return JsonResponse({'error': 'repo_id is required'}, status=400)
    if not repo_name:
        return JsonResponse({'error': 'repo_name is required'}, status=400)
    if not repo_full_name:
        return JsonResponse({'error': 'repo_full_name is required'}, status=400)
    if not aws_account_id:
        return JsonResponse({'error': 'aws_account_id is required'}, status=400)
    
    # If repo_url is missing, construct it from repo_full_name
    if not repo_url:
        repo_url = f"https://github.com/{repo_full_name}"
        print(f"Constructed repo_url: {repo_url}")
    
    # Import models inside function to avoid circular imports
    try:
        from .models import GitHubRepo, GitHubUser, AWSAccount
        print("✅ Models imported successfully")
    except Exception as e:
        print(f"❌ Failed to import models: {e}")
        return JsonResponse({'error': f'Model import error: {str(e)}'}, status=500)
    
    # Check user's repo limit (max 2)
    try:
        existing_repos = GitHubRepo.objects.filter(user=user, status='connected').count()
        print(f"Existing connected repos: {existing_repos}")
        if existing_repos >= 2:
            return JsonResponse({'error': 'Maximum 2 repositories allowed. Please disconnect one first.'}, status=400)
    except Exception as e:
        print(f"❌ Error checking repo limit: {e}")
        return JsonResponse({'error': f'Error checking repo limit: {str(e)}'}, status=500)
    
    # Get AWS account
    try:
        aws_account = AWSAccount.objects.get(id=aws_account_id, user=user, status='connected')
        print(f"✅ Found AWS account: {aws_account.account_alias}")
    except AWSAccount.DoesNotExist:
        print(f"❌ AWS account not found: {aws_account_id}")
        return JsonResponse({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        print(f"❌ Error fetching AWS account: {e}")
        return JsonResponse({'error': f'Error fetching AWS account: {str(e)}'}, status=500)
    
    # Get token from GitHubUser model
    try:
        github_user = GitHubUser.objects.get(user=user)
        access_token = github_user.access_token
        print(f"✅ Got GitHub token for user: {github_user.github_username}")
    except GitHubUser.DoesNotExist:
        print("❌ GitHubUser not found - user hasn't connected GitHub")
        return JsonResponse({'error': 'GitHub not connected. Please connect GitHub first.'}, status=400)
    except Exception as e:
        print(f"❌ Error fetching GitHub user: {e}")
        return JsonResponse({'error': f'Error fetching GitHub user: {str(e)}'}, status=500)
    
    # Check if repo already connected
    try:
        if GitHubRepo.objects.filter(user=user, repo_id=repo_id).exists():
            return JsonResponse({'error': 'Repository already connected'}, status=400)
    except Exception as e:
        print(f"❌ Error checking existing repo: {e}")
        return JsonResponse({'error': f'Error checking existing repo: {str(e)}'}, status=500)
    
    # Create webhook (optional, continue even if webhook fails)
    webhook_id = None
    try:
        from .github_service import GitHubService
        github = GitHubService(access_token)
        owner, repo = repo_full_name.split('/')
        webhook_url = f"{settings.BASE_URL}/api/github/webhook/"
        
        print(f"📡 Creating webhook for {owner}/{repo} at {webhook_url}")
        
        webhook = github.create_webhook(owner, repo, webhook_url)
        webhook_id = webhook.get('id') if webhook else None
        print(f"✅ Webhook created with ID: {webhook_id}")
    except Exception as e:
        print(f"⚠️ Failed to create webhook: {e}")
        # Continue without webhook
    
    # Save to database
    from django.db import transaction
    from django.utils import timezone
    
    try:
        with transaction.atomic():
            print("Creating GitHubRepo record...")
            github_repo = GitHubRepo(
                user=user,
                aws_account=aws_account,
                repo_id=int(repo_id),  # Ensure it's an integer
                repo_name=str(repo_name),
                repo_full_name=str(repo_full_name),
                repo_url=str(repo_url),
                access_token=access_token,
                webhook_id=webhook_id,
                status='connected',
                last_sync_at=timezone.now()
            )
            print(f"Repo object created: {github_repo}")
            
            github_repo.save()
            print(f"✅ Saved GitHubRepo with ID: {github_repo.id}")
            
            # Initial sync (optional, don't fail if it doesn't work)
            try:
                from .github_service import sync_repo_deployments
                sync_repo_deployments(github_repo.id)
                print("✅ Initial sync completed")
            except Exception as e:
                print(f"⚠️ Initial sync failed: {e}")
                # Don't fail the whole request
    except Exception as e:
        print(f"❌ Error saving to database: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'error': f'Database error: {str(e)}'}, status=500)
    
    return JsonResponse({
        'success': True,
        'repo_id': github_repo.id,
        'message': 'Repository connected successfully'
    }, status=200)


# Add these imports
from .forecast_service import CostForecastEngine

@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_cost_forecast(request, account_db_id):
    """Get comprehensive cost forecasts for all timeframes"""
    try:
        account = AWSAccount.objects.get(id=account_db_id, user=request.user)
        
        # Initialize forecast engine
        engine = CostForecastEngine(account)
        engine.load_historical_data()
        
        # Get all predictions
        forecast_data = {
            'two_days': engine.predict_2_days(),
            'one_week': engine.predict_1_week(),
            'one_month': engine.predict_1_month(),
            'two_months': engine.predict_2_months(),
            'three_months': engine.predict_3_months(),
            'top_growing_services': engine.get_top_growing_services(5),
            'service_forecasts': engine.get_all_service_forecasts(),
            'current_month_cost': engine.monthly_cost if hasattr(engine, 'monthly_cost') else 0,
            'timestamp': timezone.now().isoformat()
        }
        
        return Response(forecast_data, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        logger.error(f"Error generating forecast: {e}")
        return Response({'error': str(e)}, status=500)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_service_forecast_detail(request, account_db_id, service_name):
    """Get detailed forecast for a specific service"""
    try:
        account = AWSAccount.objects.get(id=account_db_id, user=request.user)
        
        engine = CostForecastEngine(account)
        engine.load_historical_data()
        
        forecast = engine.get_service_forecast(service_name)
        
        if not forecast:
            return Response({'error': 'Service not found'}, status=404)
        
        return Response(forecast, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        logger.error(f"Error getting service forecast: {e}")
        return Response({'error': str(e)}, status=500)

# In Django shell, after getting the account info:
# storage_views.py - Create this new file in your myground directory
# Add these to your views.py (they should already exist, but verify)

from .storage_optimization_service import (
    test_ebs_volumes,
    test_elastic_ips,
    test_rds_instances,
    test_snapshots,
    test_unattached_ebs_volumes_only,
    test_duplicate_snapshots,
    test_idle_rds_instances,
    test_unused_amis
)

@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def scan_ebs_volumes_view(request, account_id):
    """View to scan EBS volumes"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user, status='connected')
        result = test_ebs_volumes(account.role_arn, str(account.external_id))
        return Response(result, status=200)
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found', 'success': False}, status=404)
    except Exception as e:
        return Response({'error': str(e), 'success': False}, status=500)

@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def scan_elastic_ips_view(request, account_id):
    """View to scan Elastic IPs"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user, status='connected')
        result = test_elastic_ips(account.role_arn, str(account.external_id))
        return Response(result, status=200)
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found', 'success': False}, status=404)
    except Exception as e:
        return Response({'error': str(e), 'success': False}, status=500)

@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def scan_rds_instances_view(request, account_id):
    """View to scan RDS instances"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user, status='connected')
        result = test_rds_instances(account.role_arn, str(account.external_id))
        return Response(result, status=200)
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found', 'success': False}, status=404)
    except Exception as e:
        return Response({'error': str(e), 'success': False}, status=500)

@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def scan_snapshots_view(request, account_id):
    """View to scan EBS snapshots"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user, status='connected')
        result = test_snapshots(account.role_arn, str(account.external_id))
        return Response(result, status=200)
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found', 'success': False}, status=404)
    except Exception as e:
        return Response({'error': str(e), 'success': False}, status=500)

@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def scan_unattached_ebs_volumes(request, account_id):
    """Scan for unattached EBS volumes only"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user, status='connected')
        result = test_unattached_ebs_volumes_only(account.role_arn, str(account.external_id))
        return Response(result, status=200)
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found', 'success': False}, status=404)
    except Exception as e:
        return Response({'error': str(e), 'success': False}, status=500)

@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def scan_duplicate_snapshots(request, account_id):
    """Scan for duplicate snapshots"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user, status='connected')
        result = test_duplicate_snapshots(account.role_arn, str(account.external_id))
        return Response(result, status=200)
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found', 'success': False}, status=404)
    except Exception as e:
        return Response({'error': str(e), 'success': False}, status=500)

@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def scan_idle_rds_instances(request, account_id):
    """Scan for idle RDS instances (low CPU usage)"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user, status='connected')
        result = test_idle_rds_instances(account.role_arn, str(account.external_id))
        return Response(result, status=200)
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found', 'success': False}, status=404)
    except Exception as e:
        return Response({'error': str(e), 'success': False}, status=500)

@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def scan_unused_amis(request, account_id):
    """Scan for unused AMIs"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user, status='connected')
        result = test_unused_amis(account.role_arn, str(account.external_id))
        return Response(result, status=200)
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found', 'success': False}, status=404)
    except Exception as e:
        return Response({'error': str(e), 'success': False}, status=500)

@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def run_complete_storage_scan(request, account_id):
    """Run all storage optimization scans at once"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user, status='connected')
        
        # Run all scans in parallel (simplified - sequentially for reliability)
        ebs_result = test_ebs_volumes(account.role_arn, str(account.external_id))
        eip_result = test_elastic_ips(account.role_arn, str(account.external_id))
        rds_result = test_rds_instances(account.role_arn, str(account.external_id))
        snapshot_result = test_snapshots(account.role_arn, str(account.external_id))
        unattached_ebs_result = test_unattached_ebs_volumes_only(account.role_arn, str(account.external_id))
        duplicate_snapshot_result = test_duplicate_snapshots(account.role_arn, str(account.external_id))
        idle_rds_result = test_idle_rds_instances(account.role_arn, str(account.external_id))
        unused_amis_result = test_unused_amis(account.role_arn, str(account.external_id))
        
        total_findings = (
            unattached_ebs_result.get('count', 0) +
            duplicate_snapshot_result.get('count', 0) +
            idle_rds_result.get('count', 0) +
            unused_amis_result.get('count', 0)
        )
        
        total_savings = 0
        for vol in unattached_ebs_result.get('unattached_volumes', []):
            total_savings += vol.get('monthly_cost', 0)
        for group in duplicate_snapshot_result.get('duplicate_groups', []):
            total_savings += group.get('monthly_cost', 0)
        for rds in idle_rds_result.get('idle_instances', []):
            total_savings += rds.get('monthly_cost', 0)
        for ami in unused_amis_result.get('unused_amis', []):
            total_savings += ami.get('monthly_cost', 0)
        
        return Response({
            'success': True,
            'total_findings': total_findings,
            'total_potential_savings': round(total_savings, 2),
            'ebs_volumes': {
                'total': ebs_result.get('count', 0),
                'unattached': unattached_ebs_result.get('count', 0),
                'unattached_volumes': unattached_ebs_result.get('unattached_volumes', []),
                'items': ebs_result.get('volumes', [])
            },
            'rds_instances': {
                'total': rds_result.get('count', 0),
                'items': rds_result.get('instances', [])
            },
            'elastic_ips': {
                'total': eip_result.get('count', 0),
                'unused': eip_result.get('unused', 0),
                'items': eip_result.get('addresses', [])
            },
            'snapshots': {
                'total': snapshot_result.get('count', 0),
                'old': snapshot_result.get('old_count', 0),
                'items': snapshot_result.get('snapshots', [])
            },
            'idle_rds_instances': {
                'count': idle_rds_result.get('count', 0),
                'items': idle_rds_result.get('idle_instances', [])
            },
            'unused_amis': {
                'count': unused_amis_result.get('count', 0),
                'items': unused_amis_result.get('unused_amis', [])
            },
            'duplicate_snapshots': {
                'count': duplicate_snapshot_result.get('count', 0),
                'items': duplicate_snapshot_result.get('duplicate_groups', [])
            }
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found', 'success': False}, status=404)
    except Exception as e:
        return Response({'error': str(e), 'success': False}, status=500)

# Add these imports at the top of views.py
from .storage_optimization_service import (
    test_ebs_volumes, test_elastic_ips, test_rds_instances, test_snapshots,
    test_unattached_ebs_volumes_only, test_duplicate_snapshots,
    test_idle_rds_instances, test_unused_amis,
    save_scan_results_to_db, get_cached_scan_results
)

@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def run_complete_storage_scan(request, account_id):
    """Run all storage optimization scans and save to database"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user, status='connected')
        
        # Check if we have cached results (less than 24 hours old)
        if not request.query_params.get('force_refresh', False):
            cached_results = get_cached_scan_results(request.user, account)
            if cached_results:
                return Response(cached_results, status=200)
        
        # Run all scans
        ebs_result = test_ebs_volumes(account.role_arn, str(account.external_id))
        eip_result = test_elastic_ips(account.role_arn, str(account.external_id))
        rds_result = test_rds_instances(account.role_arn, str(account.external_id))
        snapshot_result = test_snapshots(account.role_arn, str(account.external_id))
        unattached_ebs_result = test_unattached_ebs_volumes_only(account.role_arn, str(account.external_id))
        duplicate_snapshot_result = test_duplicate_snapshots(account.role_arn, str(account.external_id))
        idle_rds_result = test_idle_rds_instances(account.role_arn, str(account.external_id))
        unused_amis_result = test_unused_amis(account.role_arn, str(account.external_id))
        
        total_findings = (
            unattached_ebs_result.get('count', 0) +
            duplicate_snapshot_result.get('count', 0) +
            idle_rds_result.get('count', 0) +
            unused_amis_result.get('count', 0)
        )
        
        total_savings = 0
        for vol in unattached_ebs_result.get('unattached_volumes', []):
            total_savings += vol.get('monthly_cost', 0)
        for group in duplicate_snapshot_result.get('duplicate_groups', []):
            total_savings += group.get('monthly_cost', 0)
        for rds in idle_rds_result.get('idle_instances', []):
            total_savings += rds.get('monthly_cost', 0)
        for ami in unused_amis_result.get('unused_amis', []):
            total_savings += ami.get('monthly_cost', 0)
        
        scan_results = {
            'success': True,
            'cached': False,
            'total_findings': total_findings,
            'total_potential_savings': round(total_savings, 2),
            'ebs_volumes': {
                'total': ebs_result.get('count', 0),
                'unattached': unattached_ebs_result.get('count', 0),
                'unattached_volumes': unattached_ebs_result.get('unattached_volumes', []),
                'items': ebs_result.get('volumes', [])
            },
            'rds_instances': {
                'total': rds_result.get('count', 0),
                'items': rds_result.get('instances', [])
            },
            'elastic_ips': {
                'total': eip_result.get('count', 0),
                'unused': eip_result.get('unused', 0),
                'items': [
                    {
                        'public_ip': addr.get('PublicIp'),
                        'allocation_id': addr.get('AllocationId'),
                        'domain': addr.get('Domain'),
                        'is_associated': bool(addr.get('InstanceId') or addr.get('NetworkInterfaceId'))
                    }
                    for addr in eip_result.get('addresses', [])
                ]
            },
            'snapshots': {
                'total': snapshot_result.get('count', 0),
                'old': snapshot_result.get('old_count', 0),
                'items': snapshot_result.get('snapshots', [])
            },
            'idle_rds_instances': {
                'count': idle_rds_result.get('count', 0),
                'items': idle_rds_result.get('idle_instances', [])
            },
            'unused_amis': {
                'count': unused_amis_result.get('count', 0),
                'items': unused_amis_result.get('unused_amis', [])
            },
            'duplicate_snapshots': {
                'count': duplicate_snapshot_result.get('count', 0),
                'items': duplicate_snapshot_result.get('duplicate_groups', [])
            }
        }
        
        # Save results to database
        save_scan_results_to_db(request.user, account, scan_results)
        
        return Response(scan_results, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found', 'success': False}, status=404)
    except Exception as e:
        logger.error(f"Storage scan error: {e}")
        return Response({'error': str(e), 'success': False}, status=500)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_storage_findings(request, account_id):
    """Get stored storage optimization findings"""
    try:
        from .models import StorageOptimizationFinding
        
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        findings = StorageOptimizationFinding.objects.filter(
            aws_account=account,
            status='active'
        ).order_by('-estimated_monthly_cost')
        
        return Response({
            'success': True,
            'findings': [
                {
                    'id': str(f.id),
                    'resource_type': f.resource_type,
                    'resource_id': f.resource_id,
                    'resource_name': f.resource_name,
                    'region': f.region,
                    'estimated_monthly_cost': float(f.estimated_monthly_cost),
                    'reason': f.reason,
                    'recommendation': f.recommendation,
                    'severity': f.severity,
                    'detected_at': f.detected_at.isoformat()
                }
                for f in findings
            ],
            'total_waste': sum(float(f.estimated_monthly_cost) for f in findings)
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)

# Idle resources views code for display


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def scan_idle_ec2_instances(request, account_id):
    """Scan for idle EC2 instances and save to database"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user, status='connected')
        
        # Import the checker function
        from .idle_resources import check_idle_ec2_instances
        
        # Run the scan
        idle_instances = check_idle_ec2_instances(
            role_arn=account.role_arn,
            external_id=str(account.external_id),
            region='us-east-1'
        )
        
        # Save to database
        from .models import IdleEC2Instance
        
        # Delete old findings for this account
        IdleEC2Instance.objects.filter(aws_account=account, is_resolved=False).delete()
        
        # Save new findings
        for inst in idle_instances:
            IdleEC2Instance.objects.create(
                user=request.user,
                aws_account=account,
                instance_id=inst['instance_id'],
                instance_name=inst['instance_name'],
                instance_type=inst['instance_type'],
                cpu_avg=inst['metrics']['avg_cpu'],
                network_in_mb=inst['metrics']['network_in_mb'],
                network_out_mb=inst['metrics']['network_out_mb'],
                disk_read_mb=inst['metrics']['disk_read_mb'],
                disk_write_mb=inst['metrics']['disk_write_mb'],
                monthly_cost=inst['estimated_monthly_cost'],
                reasons=inst['idle_reasons']
            )
        
        return Response({
            'success': True,
            'count': len(idle_instances),
            'total_savings': sum(i['estimated_monthly_cost'] for i in idle_instances),
            'instances': idle_instances
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_idle_ec2_instances(request, account_id):
    """Get saved idle EC2 instances from database"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        from .models import IdleEC2Instance
        idle_instances = IdleEC2Instance.objects.filter(
            aws_account=account, 
            is_resolved=False
        ).order_by('-monthly_cost')
        
        data = [{
            'id': inst.id,
            'instance_id': inst.instance_id,
            'instance_name': inst.instance_name,
            'instance_type': inst.instance_type,
            'cpu_avg': inst.cpu_avg,
            'monthly_cost': float(inst.monthly_cost),
            'reasons': inst.reasons,
            'detected_at': inst.detected_at
        } for inst in idle_instances]
        
        return Response({
            'count': len(data),
            'total_savings': sum(float(i['monthly_cost']) for i in data),
            'instances': data
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)


@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def scan_idle_asg(request, account_id):
    """Scan for idle Auto Scaling Groups and save to database"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user, status='connected')
        
        # Import the checker function
        from .idle_resources import check_idle_auto_scaling_groups
        
        # Run the scan
        idle_asgs = check_idle_auto_scaling_groups(
            role_arn=account.role_arn,
            external_id=str(account.external_id),
            region='us-east-1'
        )
        
        # Save to database
        from .models import IdleAutoScalingGroup
        
        # Delete old findings for this account
        IdleAutoScalingGroup.objects.filter(aws_account=account, is_resolved=False).delete()
        
        # Save new findings
        for asg in idle_asgs:
            IdleAutoScalingGroup.objects.create(
                user=request.user,
                aws_account=account,
                asg_name=asg['asg_name'],
                min_size=asg['min_size'],
                max_size=asg['max_size'],
                desired_capacity=asg['desired_capacity'],
                current_instances=asg['current_instances'],
                avg_cpu=asg['avg_cpu'],
                monthly_cost=asg['estimated_monthly_cost'],
                reasons=asg['idle_reasons']
            )
        
        return Response({
            'success': True,
            'count': len(idle_asgs),
            'total_savings': sum(a['estimated_monthly_cost'] for a in idle_asgs),
            'asgs': idle_asgs
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_idle_asg(request, account_id):
    """Get saved idle Auto Scaling Groups from database"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        from .models import IdleAutoScalingGroup
        idle_asgs = IdleAutoScalingGroup.objects.filter(
            aws_account=account, 
            is_resolved=False
        ).order_by('-monthly_cost')
        
        data = [{
            'id': asg.id,
            'asg_name': asg.asg_name,
            'min_size': asg.min_size,
            'max_size': asg.max_size,
            'desired_capacity': asg.desired_capacity,
            'current_instances': asg.current_instances,
            'avg_cpu': asg.avg_cpu,
            'monthly_cost': float(asg.monthly_cost),
            'reasons': asg.reasons,
            'detected_at': asg.detected_at
        } for asg in idle_asgs]
        
        return Response({
            'count': len(data),
            'total_savings': sum(float(a['monthly_cost']) for a in data),
            'asgs': data
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['PUT'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def resolve_idle_asg(request, asg_id):
    """Mark an idle ASG as resolved"""
    try:
        from .models import IdleAutoScalingGroup
        asg = IdleAutoScalingGroup.objects.get(id=asg_id, user=request.user)
        asg.is_resolved = True
        asg.save()
        
        return Response({'success': True, 'message': 'ASG marked as resolved'}, status=200)
        
    except IdleAutoScalingGroup.DoesNotExist:
        return Response({'error': 'ASG finding not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def scan_idle_load_balancers(request, account_id):
    """Scan for idle Load Balancers and save to database"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user, status='connected')
        
        # Import the checker function
        from .idle_resources import check_idle_load_balancers
        
        # Run the scan
        idle_lbs = check_idle_load_balancers(
            role_arn=account.role_arn,
            external_id=str(account.external_id),
            region='us-east-1'
        )
        
        # Save to database
        from .models import IdleLoadBalancer
        
        # Delete old findings for this account
        IdleLoadBalancer.objects.filter(aws_account=account, is_resolved=False).delete()
        
        # Save new findings
        for lb in idle_lbs:
            IdleLoadBalancer.objects.create(
                user=request.user,
                aws_account=account,
                lb_name=lb['lb_name'],
                lb_type=lb['lb_type'],
                lb_scheme=lb['lb_scheme'],
                lb_state=lb['lb_state'],
                total_requests=lb['total_requests'],
                processed_gb=lb['processed_gb'],
                healthy_targets=lb['healthy_targets'],
                total_targets=lb['total_targets'],
                monthly_cost=lb['estimated_monthly_cost'],
                reasons=lb['idle_reasons']
            )
        
        return Response({
            'success': True,
            'count': len(idle_lbs),
            'total_savings': sum(lb['estimated_monthly_cost'] for lb in idle_lbs),
            'load_balancers': idle_lbs
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def scan_idle_lambda_functions(request, account_id):
    """Scan for idle Lambda functions and save to database"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user, status='connected')
        
        # Import the checker function
        from .idle_resources import check_idle_lambda_functions
        
        # Run the scan
        idle_lambdas = check_idle_lambda_functions(
            role_arn=account.role_arn,
            external_id=str(account.external_id),
            region='us-east-1'
        )
        
        # Save to database
        from .models import IdleLambdaFunction
        
        # Delete old findings for this account
        IdleLambdaFunction.objects.filter(aws_account=account, is_resolved=False).delete()
        
        # Save new findings
        for func in idle_lambdas:
            IdleLambdaFunction.objects.create(
                user=request.user,
                aws_account=account,
                function_name=func['function_name'],
                runtime=func['runtime'],
                memory_mb=func['memory_mb'],
                last_modified=func['last_modified'],
                invocations_30d=func['invocations_30d'],
                invocations_7d=func['invocations_7d'],
                avg_duration_ms=func['avg_duration_ms'],
                monthly_cost=func['estimated_monthly_cost'],
                reasons=func['idle_reasons']
            )
        
        return Response({
            'success': True,
            'count': len(idle_lambdas),
            'total_savings': sum(f['estimated_monthly_cost'] for f in idle_lambdas),
            'lambda_functions': idle_lambdas
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def scan_all_idle_resources(request, account_id):
    """Scan all idle resources (Load Balancers + Lambda) and save to database"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user, status='connected')
        
        from .idle_resources import check_idle_load_balancers, check_idle_lambda_functions
        from .models import IdleLoadBalancer, IdleLambdaFunction
        
        # Scan Load Balancers
        idle_lbs = check_idle_load_balancers(
            role_arn=account.role_arn,
            external_id=str(account.external_id),
            region='us-east-1'
        )
        
        # Scan Lambda functions
        idle_lambdas = check_idle_lambda_functions(
            role_arn=account.role_arn,
            external_id=str(account.external_id),
            region='us-east-1'
        )
        
        # Delete old findings
        IdleLoadBalancer.objects.filter(aws_account=account, is_resolved=False).delete()
        IdleLambdaFunction.objects.filter(aws_account=account, is_resolved=False).delete()
        
        # Save Load Balancers
        for lb in idle_lbs:
            IdleLoadBalancer.objects.create(
                user=request.user,
                aws_account=account,
                lb_name=lb['lb_name'],
                lb_type=lb['lb_type'],
                lb_scheme=lb['lb_scheme'],
                lb_state=lb['lb_state'],
                total_requests=lb['total_requests'],
                processed_gb=lb['processed_gb'],
                healthy_targets=lb['healthy_targets'],
                total_targets=lb['total_targets'],
                monthly_cost=lb['estimated_monthly_cost'],
                reasons=lb['idle_reasons']
            )
        
        # Save Lambda functions
        for func in idle_lambdas:
            IdleLambdaFunction.objects.create(
                user=request.user,
                aws_account=account,
                function_name=func['function_name'],
                runtime=func['runtime'],
                memory_mb=func['memory_mb'],
                last_modified=func['last_modified'],
                invocations_30d=func['invocations_30d'],
                invocations_7d=func['invocations_7d'],
                avg_duration_ms=func['avg_duration_ms'],
                monthly_cost=func['estimated_monthly_cost'],
                reasons=func['idle_reasons']
            )
        
        total_savings = sum(lb['estimated_monthly_cost'] for lb in idle_lbs) + \
                       sum(f['estimated_monthly_cost'] for f in idle_lambdas)
        
        return Response({
            'success': True,
            'load_balancers': {
                'count': len(idle_lbs),
                'items': idle_lbs,
                'savings': sum(lb['estimated_monthly_cost'] for lb in idle_lbs)
            },
            'lambda_functions': {
                'count': len(idle_lambdas),
                'items': idle_lambdas,
                'savings': sum(f['estimated_monthly_cost'] for f in idle_lambdas)
            },
            'total_savings': total_savings
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_idle_load_balancers(request, account_id):
    """Get saved idle Load Balancers from database"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        from .models import IdleLoadBalancer
        idle_lbs = IdleLoadBalancer.objects.filter(
            aws_account=account, 
            is_resolved=False
        ).order_by('-monthly_cost')
        
        data = [{
            'id': lb.id,
            'lb_name': lb.lb_name,
            'lb_type': lb.lb_type,
            'lb_scheme': lb.lb_scheme,
            'lb_state': lb.lb_state,
            'total_requests': lb.total_requests,
            'processed_gb': lb.processed_gb,
            'healthy_targets': lb.healthy_targets,
            'total_targets': lb.total_targets,
            'monthly_cost': float(lb.monthly_cost),
            'reasons': lb.reasons,
            'detected_at': lb.detected_at
        } for lb in idle_lbs]
        
        return Response({
            'count': len(data),
            'total_savings': sum(float(lb['monthly_cost']) for lb in data),
            'load_balancers': data
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_idle_lambda_functions(request, account_id):
    """Get saved idle Lambda functions from database"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        from .models import IdleLambdaFunction
        idle_lambdas = IdleLambdaFunction.objects.filter(
            aws_account=account, 
            is_resolved=False
        ).order_by('-invocations_30d')
        
        data = [{
            'id': func.id,
            'function_name': func.function_name,
            'runtime': func.runtime,
            'memory_mb': func.memory_mb,
            'last_modified': func.last_modified,
            'invocations_30d': func.invocations_30d,
            'invocations_7d': func.invocations_7d,
            'avg_duration_ms': func.avg_duration_ms,
            'monthly_cost': float(func.monthly_cost),
            'reasons': func.reasons,
            'detected_at': func.detected_at
        } for func in idle_lambdas]
        
        return Response({
            'count': len(data),
            'total_savings': sum(float(f['monthly_cost']) for f in data),
            'lambda_functions': data
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['PUT'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def resolve_idle_lb(request, lb_id):
    """Mark an idle Load Balancer as resolved"""
    try:
        from .models import IdleLoadBalancer
        lb = IdleLoadBalancer.objects.get(id=lb_id, user=request.user)
        lb.is_resolved = True
        lb.save()
        
        return Response({'success': True, 'message': 'Load Balancer marked as resolved'}, status=200)
        
    except IdleLoadBalancer.DoesNotExist:
        return Response({'error': 'Load Balancer finding not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['PUT'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def resolve_idle_lambda(request, lambda_id):
    """Mark an idle Lambda function as resolved"""
    try:
        from .models import IdleLambdaFunction
        func = IdleLambdaFunction.objects.get(id=lambda_id, user=request.user)
        func.is_resolved = True
        func.save()
        
        return Response({'success': True, 'message': 'Lambda function marked as resolved'}, status=200)
        
    except IdleLambdaFunction.DoesNotExist:
        return Response({'error': 'Lambda function finding not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def dismiss_storage_finding(request, finding_id):
    """Dismiss a storage optimization finding"""
    try:
        from .models import StorageOptimizationFinding
        
        finding = StorageOptimizationFinding.objects.get(id=finding_id, user=request.user)
        finding.status = 'dismissed'
        finding.save()
        
        return Response({'success': True, 'message': 'Finding dismissed'}, status=200)
        
    except StorageOptimizationFinding.DoesNotExist:
        return Response({'error': 'Finding not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def scan_idle_ecs_services(request, account_id):
    """Scan for idle ECS/Fargate services and save to database"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user, status='connected')
        
        # Import the checker function
        from .idle_resources import check_idle_ecs_services
        
        # Run the scan
        idle_services = check_idle_ecs_services(
            role_arn=account.role_arn,
            external_id=str(account.external_id),
            region='us-east-1'
        )
        
        # Save to database
        from .models import IdleECSService
        
        # Delete old findings for this account
        IdleECSService.objects.filter(aws_account=account, is_resolved=False).delete()
        
        # Save new findings
        for service in idle_services:
            IdleECSService.objects.create(
                user=request.user,
                aws_account=account,
                service_name=service['service_name'],
                cluster_name=service['cluster_name'],
                cpu=service['cpu'],
                memory_mb=service['memory_mb'],
                running_tasks=service['running_tasks'],
                desired_tasks=service['desired_tasks'],
                cpu_utilization=service['cpu_utilization'],
                memory_utilization=service['memory_utilization'],
                monthly_cost=service['estimated_monthly_cost'],
                reasons=service['idle_reasons']
            )
        
        return Response({
            'success': True,
            'count': len(idle_services),
            'total_savings': sum(s['estimated_monthly_cost'] for s in idle_services),
            'services': idle_services
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def scan_idle_nat_gateways(request, account_id):
    """Scan for idle NAT Gateways and save to database"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user, status='connected')
        
        # Import the checker function
        from .idle_resources import check_idle_nat_gateways
        
        # Run the scan
        idle_nats = check_idle_nat_gateways(
            role_arn=account.role_arn,
            external_id=str(account.external_id),
            region='us-east-1'
        )
        
        # Save to database
        from .models import IdleNATGateway
        
        # Delete old findings for this account
        IdleNATGateway.objects.filter(aws_account=account, is_resolved=False).delete()
        
        # Save new findings
        for nat in idle_nats:
            IdleNATGateway.objects.create(
                user=request.user,
                aws_account=account,
                nat_gateway_id=nat['nat_gateway_id'],
                vpc_id=nat['vpc_id'],
                subnet_id=nat['subnet_id'],
                data_processed_gb=nat['data_processed_gb'],
                packets_processed=nat['packets_processed'],
                avg_connections=nat['avg_connections'],
                monthly_cost=nat['estimated_monthly_cost'],
                yearly_cost=nat['estimated_yearly_cost'],
                reasons=nat['idle_reasons']
            )
        
        return Response({
            'success': True,
            'count': len(idle_nats),
            'total_savings': sum(n['estimated_monthly_cost'] for n in idle_nats),
            'nat_gateways': idle_nats
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def scan_idle_vpc_endpoints(request, account_id):
    """Scan for idle VPC Endpoints and save to database"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user, status='connected')
        
        # Import the checker function
        from .idle_resources import check_idle_vpc_endpoints
        
        # Run the scan
        idle_endpoints = check_idle_vpc_endpoints(
            role_arn=account.role_arn,
            external_id=str(account.external_id),
            region='us-east-1'
        )
        
        # Save to database
        from .models import IdleVPCEndpoint
        
        # Delete old findings for this account
        IdleVPCEndpoint.objects.filter(aws_account=account, is_resolved=False).delete()
        
        # Save new findings
        for ep in idle_endpoints:
            IdleVPCEndpoint.objects.create(
                user=request.user,
                aws_account=account,
                endpoint_id=ep['endpoint_id'],
                service_name=ep['service_name'],
                endpoint_type=ep['endpoint_type'],
                vpc_id=ep['vpc_id'],
                total_packets=ep['total_packets'],
                monthly_cost=ep['estimated_monthly_cost'],
                reasons=ep['idle_reasons']
            )
        
        return Response({
            'success': True,
            'count': len(idle_endpoints),
            'total_savings': sum(e['estimated_monthly_cost'] for e in idle_endpoints),
            'endpoints': idle_endpoints
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)

# Add/update in views.py

from .idle_resources import get_cached_idle_results, clear_all_idle_data

@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def scan_all_idle_resources_advanced(request, account_id):
    """
    Scan ALL idle resources and save to database
    force_refresh=true makes new AWS API calls
    force_refresh=false uses cached database results
    """
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user, status='connected')
        force_refresh = request.query_params.get('force_refresh', 'false').lower() == 'true'
        
        print(f"🔍 Idle Resources Scan - force_refresh: {force_refresh}")
        
        # Check for cached results first (unless force_refresh is true)
        if not force_refresh:
            from .idle_resources import get_cached_idle_results
            cached_results = get_cached_idle_results(request.user, account, force_refresh=False)
            if cached_results:
                print("📦 Returning cached idle results from database")
                return Response(cached_results, status=200)
        
        # Force refresh - make fresh AWS API calls
        logger.info(f"🔄 Running fresh idle resources scan for account {account.account_id}")
        
        from .idle_resources import (
            check_idle_ec2_instances,
            check_idle_auto_scaling_groups,
            check_idle_load_balancers,
            check_idle_lambda_functions,
            check_idle_ecs_services,
            check_idle_nat_gateways,
            check_idle_vpc_endpoints,
            check_idle_api_gateways,
            check_idle_cloudwatch_resources
        )
        
        from .models import (
            IdleEC2Instance, IdleAutoScalingGroup, IdleLoadBalancer,
            IdleLambdaFunction, IdleECSService, IdleNATGateway,
            IdleVPCEndpoint, IdleAPIGateway, IdleCloudWatchLogGroup,
            IdleCloudWatchAlarm, IdleCloudWatchDashboard, IdleCloudWatchMetric
        )
        
        # Delete ALL old findings (complete refresh)
        print("🗑️ Deleting old idle resource records...")
        IdleEC2Instance.objects.filter(aws_account=account).delete()
        IdleAutoScalingGroup.objects.filter(aws_account=account).delete()
        IdleLoadBalancer.objects.filter(aws_account=account).delete()
        IdleLambdaFunction.objects.filter(aws_account=account).delete()
        IdleECSService.objects.filter(aws_account=account).delete()
        IdleNATGateway.objects.filter(aws_account=account).delete()
        IdleVPCEndpoint.objects.filter(aws_account=account).delete()
        IdleAPIGateway.objects.filter(aws_account=account).delete()
        IdleCloudWatchLogGroup.objects.filter(aws_account=account).delete()
        IdleCloudWatchAlarm.objects.filter(aws_account=account).delete()
        IdleCloudWatchDashboard.objects.filter(aws_account=account).delete()
        IdleCloudWatchMetric.objects.filter(aws_account=account).delete()
        
        # 1. Scan EC2 Instances
        print("\n📊 SCANNING EC2 INSTANCES...")
        idle_ec2 = check_idle_ec2_instances(
            role_arn=account.role_arn,
            external_id=str(account.external_id),
            region='us-east-1'
        )
        if idle_ec2:
            for inst in idle_ec2:
                IdleEC2Instance.objects.create(
                    user=request.user,
                    aws_account=account,
                    instance_id=inst['instance_id'],
                    instance_name=inst['instance_name'],
                    instance_type=inst['instance_type'],
                    cpu_avg=inst['metrics']['avg_cpu'],
                    network_in_mb=inst['metrics']['network_in_mb'],
                    network_out_mb=inst['metrics']['network_out_mb'],
                    disk_read_mb=inst['metrics']['disk_read_mb'],
                    disk_write_mb=inst['metrics']['disk_write_mb'],
                    monthly_cost=inst['estimated_monthly_cost'],
                    reasons=inst['idle_reasons'],
                    is_resolved=False
                )
        
        # 2. Scan Auto Scaling Groups
        print("\n📊 SCANNING AUTO SCALING GROUPS...")
        idle_asgs = check_idle_auto_scaling_groups(
            role_arn=account.role_arn,
            external_id=str(account.external_id),
            region='us-east-1'
        )
        if idle_asgs:
            for asg in idle_asgs:
                IdleAutoScalingGroup.objects.create(
                    user=request.user,
                    aws_account=account,
                    asg_name=asg['asg_name'],
                    min_size=asg['min_size'],
                    max_size=asg['max_size'],
                    desired_capacity=asg['desired_capacity'],
                    current_instances=asg['current_instances'],
                    avg_cpu=asg['avg_cpu'],
                    monthly_cost=asg['estimated_monthly_cost'],
                    reasons=asg['idle_reasons'],
                    is_resolved=False
                )
        
        # 3. Scan Load Balancers
        print("\n📊 SCANNING LOAD BALANCERS...")
        idle_lbs = check_idle_load_balancers(
            role_arn=account.role_arn,
            external_id=str(account.external_id),
            region='us-east-1'
        )
        if idle_lbs:
            for lb in idle_lbs:
                IdleLoadBalancer.objects.create(
                    user=request.user,
                    aws_account=account,
                    lb_name=lb['lb_name'],
                    lb_type=lb['lb_type'],
                    lb_scheme=lb['lb_scheme'],
                    lb_state=lb['lb_state'],
                    total_requests=lb['total_requests'],
                    processed_gb=lb['processed_gb'],
                    healthy_targets=lb['healthy_targets'],
                    total_targets=lb['total_targets'],
                    monthly_cost=lb['estimated_monthly_cost'],
                    reasons=lb['idle_reasons'],
                    is_resolved=False
                )
        
        # 4. Scan Lambda Functions
        print("\n📊 SCANNING LAMBDA FUNCTIONS...")
        idle_lambdas = check_idle_lambda_functions(
            role_arn=account.role_arn,
            external_id=str(account.external_id),
            region='us-east-1'
        )
        if idle_lambdas:
            for func in idle_lambdas:
                IdleLambdaFunction.objects.create(
                    user=request.user,
                    aws_account=account,
                    function_name=func['function_name'],
                    runtime=func['runtime'],
                    memory_mb=func['memory_mb'],
                    last_modified=func['last_modified'],
                    invocations_30d=func['invocations_30d'],
                    invocations_7d=func['invocations_7d'],
                    avg_duration_ms=func['avg_duration_ms'],
                    monthly_cost=func['estimated_monthly_cost'],
                    reasons=func['idle_reasons'],
                    is_resolved=False
                )
        
        # 5. Scan ECS Services
        print("\n📊 SCANNING ECS SERVICES...")
        idle_ecs = check_idle_ecs_services(
            role_arn=account.role_arn,
            external_id=str(account.external_id),
            region='us-east-1'
        )
        if idle_ecs:
            for service in idle_ecs:
                IdleECSService.objects.create(
                    user=request.user,
                    aws_account=account,
                    service_name=service['service_name'],
                    cluster_name=service['cluster_name'],
                    cpu=service['cpu'],
                    memory_mb=service['memory_mb'],
                    running_tasks=service['running_tasks'],
                    desired_tasks=service['desired_tasks'],
                    cpu_utilization=service['cpu_utilization'],
                    memory_utilization=service['memory_utilization'],
                    monthly_cost=service['estimated_monthly_cost'],
                    reasons=service['idle_reasons'],
                    is_resolved=False
                )
        
        # 6. Scan NAT Gateways
        print("\n📊 SCANNING NAT GATEWAYS...")
        idle_nats = check_idle_nat_gateways(
            role_arn=account.role_arn,
            external_id=str(account.external_id),
            region='us-east-1'
        )
        if idle_nats:
            for nat in idle_nats:
                IdleNATGateway.objects.create(
                    user=request.user,
                    aws_account=account,
                    nat_gateway_id=nat['nat_gateway_id'],
                    vpc_id=nat['vpc_id'],
                    subnet_id=nat['subnet_id'],
                    data_processed_gb=nat['data_processed_gb'],
                    packets_processed=nat['packets_processed'],
                    avg_connections=nat['avg_connections'],
                    monthly_cost=nat['estimated_monthly_cost'],
                    yearly_cost=nat['estimated_yearly_cost'],
                    reasons=nat['idle_reasons'],
                    is_resolved=False
                )
        
        # 7. Scan VPC Endpoints
        print("\n📊 SCANNING VPC ENDPOINTS...")
        idle_vpce = check_idle_vpc_endpoints(
            role_arn=account.role_arn,
            external_id=str(account.external_id),
            region='us-east-1'
        )
        if idle_vpce:
            for ep in idle_vpce:
                IdleVPCEndpoint.objects.create(
                    user=request.user,
                    aws_account=account,
                    endpoint_id=ep['endpoint_id'],
                    service_name=ep['service_name'],
                    endpoint_type=ep['endpoint_type'],
                    vpc_id=ep['vpc_id'],
                    total_packets=ep['total_packets'],
                    monthly_cost=ep['estimated_monthly_cost'],
                    reasons=ep['idle_reasons'],
                    is_resolved=False
                )
        
        # 8. Scan API Gateways
        print("\n📊 SCANNING API GATEWAYS...")
        idle_apis = check_idle_api_gateways(
            role_arn=account.role_arn,
            external_id=str(account.external_id),
            region='us-east-1'
        )
        if idle_apis:
            for api in idle_apis:
                IdleAPIGateway.objects.create(
                    user=request.user,
                    aws_account=account,
                    api_id=api['api_id'],
                    api_name=api['api_name'],
                    api_type=api['api_type'],
                    total_requests_30d=api['total_requests_30d'],
                    requests_7d=api['requests_7d'],
                    active_stages=api.get('active_stages', 0),
                    avg_connections=api.get('avg_connections', 0),
                    monthly_cost=api['estimated_monthly_cost'],
                    reasons=api['idle_reasons'],
                    is_resolved=False
                )
        
        # 9. Scan CloudWatch Resources
        print("\n📊 SCANNING CLOUDWATCH RESOURCES...")
        cw_results = check_idle_cloudwatch_resources(
            role_arn=account.role_arn,
            external_id=str(account.external_id),
            region='us-east-1'
        )
        
        if cw_results.get('log_groups'):
            for lg in cw_results.get('log_groups', []):
                IdleCloudWatchLogGroup.objects.create(
                    user=request.user,
                    aws_account=account,
                    log_group_name=lg['log_group_name'],
                    stored_gb=lg['stored_gb'],
                    retention_days=lg['retention_days'],
                    days_since_last_log=lg['days_since_last_log'],
                    monthly_cost=lg['estimated_monthly_cost'],
                    reasons=lg['idle_reasons'],
                    is_resolved=False
                )
        
        if cw_results.get('alarms'):
            for alarm in cw_results.get('alarms', []):
                IdleCloudWatchAlarm.objects.create(
                    user=request.user,
                    aws_account=account,
                    alarm_name=alarm['alarm_name'],
                    state=alarm['state'],
                    actions_enabled=alarm['actions_enabled'],
                    monthly_cost=alarm['estimated_monthly_cost'],
                    reasons=alarm['idle_reasons'],
                    is_resolved=False
                )
        
        if cw_results.get('dashboards'):
            for dashboard in cw_results.get('dashboards', []):
                IdleCloudWatchDashboard.objects.create(
                    user=request.user,
                    aws_account=account,
                    dashboard_name=dashboard['dashboard_name'],
                    days_since_modified=dashboard['days_since_modified'],
                    reasons=dashboard['idle_reasons'],
                    is_resolved=False
                )
        
        if cw_results.get('metrics'):
            for metric in cw_results.get('metrics', []):
                IdleCloudWatchMetric.objects.create(
                    user=request.user,
                    aws_account=account,
                    namespace=metric['namespace'],
                    metric_name=metric['metric_name'],
                    monthly_cost=metric['estimated_monthly_cost'],
                    reasons=metric['idle_reasons'],
                    is_resolved=False
                )
        
        # Return the cached results (which will now include the fresh data)
        from .idle_resources import get_cached_idle_results
        fresh_results = get_cached_idle_results(request.user, account, force_refresh=False)
        
        if fresh_results:
            fresh_results['cached'] = False
            return Response(fresh_results, status=200)
        
        # Fallback: Build response manually if cache function fails
        ec2_instances = IdleEC2Instance.objects.filter(aws_account=account, is_resolved=False)
        asg_instances = IdleAutoScalingGroup.objects.filter(aws_account=account, is_resolved=False)
        lb_instances = IdleLoadBalancer.objects.filter(aws_account=account, is_resolved=False)
        lambda_instances = IdleLambdaFunction.objects.filter(aws_account=account, is_resolved=False)
        ecs_instances = IdleECSService.objects.filter(aws_account=account, is_resolved=False)
        nat_instances = IdleNATGateway.objects.filter(aws_account=account, is_resolved=False)
        vpce_instances = IdleVPCEndpoint.objects.filter(aws_account=account, is_resolved=False)
        api_instances = IdleAPIGateway.objects.filter(aws_account=account, is_resolved=False)
        log_groups = IdleCloudWatchLogGroup.objects.filter(aws_account=account, is_resolved=False)
        alarms = IdleCloudWatchAlarm.objects.filter(aws_account=account, is_resolved=False)
        dashboards = IdleCloudWatchDashboard.objects.filter(aws_account=account, is_resolved=False)
        metrics = IdleCloudWatchMetric.objects.filter(aws_account=account, is_resolved=False)
        
        total_findings = (
            ec2_instances.count() + asg_instances.count() + lb_instances.count() +
            lambda_instances.count() + ecs_instances.count() + nat_instances.count() +
            vpce_instances.count() + api_instances.count() + log_groups.count() +
            alarms.count() + dashboards.count() + metrics.count()
        )
        
        total_savings = (
            sum(inst.monthly_cost for inst in ec2_instances) +
            sum(asg.monthly_cost for asg in asg_instances) +
            sum(lb.monthly_cost for lb in lb_instances) +
            sum(func.monthly_cost for func in lambda_instances) +
            sum(service.monthly_cost for service in ecs_instances) +
            sum(nat.monthly_cost for nat in nat_instances) +
            sum(ep.monthly_cost for ep in vpce_instances) +
            sum(api.monthly_cost for api in api_instances) +
            sum(lg.monthly_cost for lg in log_groups) +
            sum(alarm.monthly_cost for alarm in alarms) +
            sum(metric.monthly_cost for metric in metrics)
        )
        
        result = {
            'success': True,
            'cached': False,
            'total_findings': total_findings,
            'total_savings': float(total_savings),
            'ec2_instances': {
                'count': ec2_instances.count(),
                'savings': sum(float(inst.monthly_cost) for inst in ec2_instances),
                'items': [
                    {
                        'instance_id': inst.instance_id,
                        'instance_name': inst.instance_name,
                        'instance_type': inst.instance_type,
                        'cpu_avg': float(inst.cpu_avg),
                        'monthly_cost': float(inst.monthly_cost),
                        'reasons': inst.reasons
                    }
                    for inst in ec2_instances
                ]
            },
            'auto_scaling_groups': {
                'count': asg_instances.count(),
                'savings': sum(float(asg.monthly_cost) for asg in asg_instances),
                'items': [
                    {
                        'asg_name': asg.asg_name,
                        'min_size': asg.min_size,
                        'max_size': asg.max_size,
                        'desired_capacity': asg.desired_capacity,
                        'current_instances': asg.current_instances,
                        'avg_cpu': float(asg.avg_cpu),
                        'monthly_cost': float(asg.monthly_cost),
                        'reasons': asg.reasons
                    }
                    for asg in asg_instances
                ]
            },
            'load_balancers': {
                'count': lb_instances.count(),
                'savings': sum(float(lb.monthly_cost) for lb in lb_instances),
                'items': [
                    {
                        'lb_name': lb.lb_name,
                        'lb_type': lb.lb_type,
                        'lb_scheme': lb.lb_scheme,
                        'total_requests': lb.total_requests,
                        'processed_gb': float(lb.processed_gb),
                        'healthy_targets': lb.healthy_targets,
                        'total_targets': lb.total_targets,
                        'monthly_cost': float(lb.monthly_cost),
                        'reasons': lb.reasons
                    }
                    for lb in lb_instances
                ]
            },
            'lambda_functions': {
                'count': lambda_instances.count(),
                'savings': sum(float(func.monthly_cost) for func in lambda_instances),
                'items': [
                    {
                        'function_name': func.function_name,
                        'runtime': func.runtime,
                        'memory_mb': func.memory_mb,
                        'invocations_30d': func.invocations_30d,
                        'invocations_7d': func.invocations_7d,
                        'avg_duration_ms': float(func.avg_duration_ms),
                        'monthly_cost': float(func.monthly_cost),
                        'reasons': func.reasons
                    }
                    for func in lambda_instances
                ]
            },
            'ecs_services': {
                'count': ecs_instances.count(),
                'savings': sum(float(service.monthly_cost) for service in ecs_instances),
                'items': [
                    {
                        'service_name': service.service_name,
                        'cluster_name': service.cluster_name,
                        'cpu': service.cpu,
                        'memory_mb': service.memory_mb,
                        'running_tasks': service.running_tasks,
                        'desired_tasks': service.desired_tasks,
                        'cpu_utilization': float(service.cpu_utilization),
                        'memory_utilization': float(service.memory_utilization),
                        'monthly_cost': float(service.monthly_cost),
                        'reasons': service.reasons
                    }
                    for service in ecs_instances
                ]
            },
            'nat_gateways': {
                'count': nat_instances.count(),
                'savings': sum(float(nat.monthly_cost) for nat in nat_instances),
                'items': [
                    {
                        'nat_gateway_id': nat.nat_gateway_id,
                        'vpc_id': nat.vpc_id,
                        'data_processed_gb': float(nat.data_processed_gb),
                        'packets_processed': nat.packets_processed,
                        'avg_connections': float(nat.avg_connections),
                        'monthly_cost': float(nat.monthly_cost),
                        'reasons': nat.reasons
                    }
                    for nat in nat_instances
                ]
            },
            'vpc_endpoints': {
                'count': vpce_instances.count(),
                'savings': sum(float(ep.monthly_cost) for ep in vpce_instances),
                'items': [
                    {
                        'endpoint_id': ep.endpoint_id,
                        'service_name': ep.service_name,
                        'endpoint_type': ep.endpoint_type,
                        'total_packets': ep.total_packets,
                        'monthly_cost': float(ep.monthly_cost),
                        'reasons': ep.reasons
                    }
                    for ep in vpce_instances
                ]
            },
            'api_gateways': {
                'count': api_instances.count(),
                'savings': sum(float(api.monthly_cost) for api in api_instances),
                'items': [
                    {
                        'api_id': api.api_id,
                        'api_name': api.api_name,
                        'api_type': api.api_type,
                        'total_requests_30d': api.total_requests_30d,
                        'requests_7d': api.requests_7d,
                        'monthly_cost': float(api.monthly_cost),
                        'reasons': api.reasons
                    }
                    for api in api_instances
                ]
            },
            'cloudwatch': {
                'log_groups': {
                    'count': log_groups.count(),
                    'savings': sum(float(lg.monthly_cost) for lg in log_groups),
                    'items': [
                        {
                            'log_group_name': lg.log_group_name,
                            'stored_gb': float(lg.stored_gb),
                            'retention_days': lg.retention_days,
                            'days_since_last_log': lg.days_since_last_log,
                            'monthly_cost': float(lg.monthly_cost),
                            'reasons': lg.reasons
                        }
                        for lg in log_groups
                    ]
                },
                'alarms': {
                    'count': alarms.count(),
                    'savings': sum(float(alarm.monthly_cost) for alarm in alarms),
                    'items': [
                        {
                            'alarm_name': alarm.alarm_name,
                            'state': alarm.state,
                            'actions_enabled': alarm.actions_enabled,
                            'monthly_cost': float(alarm.monthly_cost),
                            'reasons': alarm.reasons
                        }
                        for alarm in alarms
                    ]
                },
                'dashboards': {
                    'count': dashboards.count(),
                    'items': [
                        {
                            'dashboard_name': dash.dashboard_name,
                            'days_since_modified': dash.days_since_modified,
                            'reasons': dash.reasons
                        }
                        for dash in dashboards
                    ]
                },
                'metrics': {
                    'count': metrics.count(),
                    'savings': sum(float(metric.monthly_cost) for metric in metrics),
                    'items': [
                        {
                            'namespace': metric.namespace,
                            'metric_name': metric.metric_name,
                            'monthly_cost': float(metric.monthly_cost),
                            'reasons': metric.reasons
                        }
                        for metric in metrics
                    ]
                }
            }
        }
        
        return Response(result, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        logger.error(f"Error in idle resources scan: {e}")
        import traceback
        traceback.print_exc()
        return Response({'error': str(e)}, status=500)

@api_view(['DELETE'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def clear_idle_results_cache(request, account_id):
    """
    Clear all idle resources cached data from database
    """
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        from .idle_resources import clear_all_idle_data
        
        total_deleted = clear_all_idle_data(account)
        
        return Response({
            'success': True,
            'message': f'Cleared {total_deleted} idle resource records',
            'deleted_count': total_deleted
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)

    
@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_idle_ecs_services(request, account_id):
    """Get saved idle ECS services from database"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        from .models import IdleECSService
        idle_services = IdleECSService.objects.filter(
            aws_account=account, 
            is_resolved=False
        ).order_by('-monthly_cost')
        
        data = [{
            'id': s.id,
            'service_name': s.service_name,
            'cluster_name': s.cluster_name,
            'cpu': s.cpu,
            'memory_mb': s.memory_mb,
            'running_tasks': s.running_tasks,
            'desired_tasks': s.desired_tasks,
            'cpu_utilization': s.cpu_utilization,
            'memory_utilization': s.memory_utilization,
            'monthly_cost': float(s.monthly_cost),
            'reasons': s.reasons,
            'detected_at': s.detected_at
        } for s in idle_services]
        
        return Response({
            'count': len(data),
            'total_savings': sum(float(s['monthly_cost']) for s in data),
            'services': data
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_idle_nat_gateways(request, account_id):
    """Get saved idle NAT Gateways from database"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        from .models import IdleNATGateway
        idle_nats = IdleNATGateway.objects.filter(
            aws_account=account, 
            is_resolved=False
        ).order_by('-monthly_cost')
        
        data = [{
            'id': n.id,
            'nat_gateway_id': n.nat_gateway_id,
            'vpc_id': n.vpc_id,
            'subnet_id': n.subnet_id,
            'data_processed_gb': n.data_processed_gb,
            'packets_processed': n.packets_processed,
            'avg_connections': n.avg_connections,
            'monthly_cost': float(n.monthly_cost),
            'yearly_cost': float(n.yearly_cost),
            'reasons': n.reasons,
            'detected_at': n.detected_at
        } for n in idle_nats]
        
        return Response({
            'count': len(data),
            'total_savings': sum(float(n['monthly_cost']) for n in data),
            'nat_gateways': data
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_idle_vpc_endpoints(request, account_id):
    """Get saved idle VPC Endpoints from database"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        from .models import IdleVPCEndpoint
        idle_endpoints = IdleVPCEndpoint.objects.filter(
            aws_account=account, 
            is_resolved=False
        ).order_by('-monthly_cost')
        
        data = [{
            'id': e.id,
            'endpoint_id': e.endpoint_id,
            'service_name': e.service_name,
            'endpoint_type': e.endpoint_type,
            'vpc_id': e.vpc_id,
            'total_packets': e.total_packets,
            'monthly_cost': float(e.monthly_cost),
            'reasons': e.reasons,
            'detected_at': e.detected_at
        } for e in idle_endpoints]
        
        return Response({
            'count': len(data),
            'total_savings': sum(float(e['monthly_cost']) for e in data),
            'endpoints': data
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


# Resolve endpoints
@api_view(['PUT'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def resolve_idle_ecs_service(request, service_id):
    """Mark an idle ECS service as resolved"""
    try:
        from .models import IdleECSService
        service = IdleECSService.objects.get(id=service_id, user=request.user)
        service.is_resolved = True
        service.save()
        return Response({'success': True, 'message': 'ECS service marked as resolved'}, status=200)
    except IdleECSService.DoesNotExist:
        return Response({'error': 'ECS service not found'}, status=404)


@api_view(['PUT'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def resolve_idle_nat_gateway(request, nat_id):
    """Mark an idle NAT Gateway as resolved"""
    try:
        from .models import IdleNATGateway
        nat = IdleNATGateway.objects.get(id=nat_id, user=request.user)
        nat.is_resolved = True
        nat.save()
        return Response({'success': True, 'message': 'NAT Gateway marked as resolved'}, status=200)
    except IdleNATGateway.DoesNotExist:
        return Response({'error': 'NAT Gateway not found'}, status=404)


@api_view(['PUT'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def resolve_idle_vpc_endpoint(request, endpoint_id):
    """Mark an idle VPC Endpoint as resolved"""
    try:
        from .models import IdleVPCEndpoint
        ep = IdleVPCEndpoint.objects.get(id=endpoint_id, user=request.user)
        ep.is_resolved = True
        ep.save()
        return Response({'success': True, 'message': 'VPC Endpoint marked as resolved'}, status=200)
    except IdleVPCEndpoint.DoesNotExist:
        return Response({'error': 'VPC Endpoint not found'}, status=404)

@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def scan_idle_api_gateways(request, account_id):
    """Scan for idle API Gateways and save to database"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user, status='connected')
        
        # Import the checker function
        from .idle_resources import check_idle_api_gateways
        
        # Run the scan
        idle_apis = check_idle_api_gateways(
            role_arn=account.role_arn,
            external_id=str(account.external_id),
            region='us-east-1'
        )
        
        # Save to database
        from .models import IdleAPIGateway
        
        # Delete old findings for this account
        IdleAPIGateway.objects.filter(aws_account=account, is_resolved=False).delete()
        
        # Save new findings
        for api in idle_apis:
            IdleAPIGateway.objects.create(
                user=request.user,
                aws_account=account,
                api_id=api['api_id'],
                api_name=api['api_name'],
                api_type=api['api_type'],
                total_requests_30d=api['total_requests_30d'],
                requests_7d=api['requests_7d'],
                active_stages=api.get('active_stages', 0),
                avg_connections=api.get('avg_connections', 0),
                monthly_cost=api['estimated_monthly_cost'],
                reasons=api['idle_reasons']
            )
        
        return Response({
            'success': True,
            'count': len(idle_apis),
            'total_savings': sum(a['estimated_monthly_cost'] for a in idle_apis),
            'apis': idle_apis
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def scan_idle_cloudwatch_resources(request, account_id):
    """Scan for idle CloudWatch resources and save to database"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user, status='connected')
        
        # Import the checker function
        from .idle_resources  import check_idle_cloudwatch_resources
        
        # Run the scan
        cw_results = check_idle_cloudwatch_resources(
            role_arn=account.role_arn,
            external_id=str(account.external_id),
            region='us-east-1'
        )
        
        from .models import IdleCloudWatchLogGroup, IdleCloudWatchAlarm, IdleCloudWatchDashboard, IdleCloudWatchMetric
        
        # Delete old findings
        IdleCloudWatchLogGroup.objects.filter(aws_account=account, is_resolved=False).delete()
        IdleCloudWatchAlarm.objects.filter(aws_account=account, is_resolved=False).delete()
        IdleCloudWatchDashboard.objects.filter(aws_account=account, is_resolved=False).delete()
        IdleCloudWatchMetric.objects.filter(aws_account=account, is_resolved=False).delete()
        
        # Save Log Groups
        for lg in cw_results.get('log_groups', []):
            IdleCloudWatchLogGroup.objects.create(
                user=request.user,
                aws_account=account,
                log_group_name=lg['log_group_name'],
                stored_gb=lg['stored_gb'],
                retention_days=lg['retention_days'],
                days_since_last_log=lg['days_since_last_log'],
                monthly_cost=lg['estimated_monthly_cost'],
                reasons=lg['idle_reasons']
            )
        
        # Save Alarms
        for alarm in cw_results.get('alarms', []):
            IdleCloudWatchAlarm.objects.create(
                user=request.user,
                aws_account=account,
                alarm_name=alarm['alarm_name'],
                state=alarm['state'],
                actions_enabled=alarm['actions_enabled'],
                monthly_cost=alarm['estimated_monthly_cost'],
                reasons=alarm['idle_reasons']
            )
        
        # Save Dashboards
        for dashboard in cw_results.get('dashboards', []):
            IdleCloudWatchDashboard.objects.create(
                user=request.user,
                aws_account=account,
                dashboard_name=dashboard['dashboard_name'],
                days_since_modified=dashboard['days_since_modified'],
                reasons=dashboard['idle_reasons']
            )
        
        # Save Metrics
        for metric in cw_results.get('metrics', []):
            IdleCloudWatchMetric.objects.create(
                user=request.user,
                aws_account=account,
                namespace=metric['namespace'],
                metric_name=metric['metric_name'],
                monthly_cost=metric['estimated_monthly_cost'],
                reasons=metric['idle_reasons']
            )
        
        total_savings = sum(lg['estimated_monthly_cost'] for lg in cw_results.get('log_groups', [])) + \
                       sum(a['estimated_monthly_cost'] for a in cw_results.get('alarms', [])) + \
                       sum(m['estimated_monthly_cost'] for m in cw_results.get('metrics', []))
        
        return Response({
            'success': True,
            'log_groups': {
                'count': len(cw_results.get('log_groups', [])),
                'items': cw_results.get('log_groups', []),
                'savings': sum(lg['estimated_monthly_cost'] for lg in cw_results.get('log_groups', []))
            },
            'alarms': {
                'count': len(cw_results.get('alarms', [])),
                'items': cw_results.get('alarms', []),
                'savings': sum(a['estimated_monthly_cost'] for a in cw_results.get('alarms', []))
            },
            'dashboards': {
                'count': len(cw_results.get('dashboards', [])),
                'items': cw_results.get('dashboards', [])
            },
            'metrics': {
                'count': len(cw_results.get('metrics', [])),
                'items': cw_results.get('metrics', []),
                'savings': sum(m['estimated_monthly_cost'] for m in cw_results.get('metrics', []))
            },
            'total_savings': total_savings
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def scan_all_idle_resources_complete(request, account_id):
    """Scan ALL idle resources (API Gateway + CloudWatch) and save to database"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user, status='connected')
        
        from .idle_resources  import check_idle_api_gateways, check_idle_cloudwatch_resources
        from .models import IdleAPIGateway, IdleCloudWatchLogGroup, IdleCloudWatchAlarm, IdleCloudWatchDashboard, IdleCloudWatchMetric
        
        # Scan API Gateway
        idle_apis = check_idle_api_gateways(
            role_arn=account.role_arn,
            external_id=str(account.external_id),
            region='us-east-1'
        )
        
        # Scan CloudWatch
        cw_results = check_idle_cloudwatch_resources(
            role_arn=account.role_arn,
            external_id=str(account.external_id),
            region='us-east-1'
        )
        
        # Delete old findings
        IdleAPIGateway.objects.filter(aws_account=account, is_resolved=False).delete()
        IdleCloudWatchLogGroup.objects.filter(aws_account=account, is_resolved=False).delete()
        IdleCloudWatchAlarm.objects.filter(aws_account=account, is_resolved=False).delete()
        IdleCloudWatchDashboard.objects.filter(aws_account=account, is_resolved=False).delete()
        IdleCloudWatchMetric.objects.filter(aws_account=account, is_resolved=False).delete()
        
        # Save API Gateways
        for api in idle_apis:
            IdleAPIGateway.objects.create(
                user=request.user,
                aws_account=account,
                api_id=api['api_id'],
                api_name=api['api_name'],
                api_type=api['api_type'],
                total_requests_30d=api['total_requests_30d'],
                requests_7d=api['requests_7d'],
                active_stages=api.get('active_stages', 0),
                avg_connections=api.get('avg_connections', 0),
                monthly_cost=api['estimated_monthly_cost'],
                reasons=api['idle_reasons']
            )
        
        # Save Log Groups
        for lg in cw_results.get('log_groups', []):
            IdleCloudWatchLogGroup.objects.create(
                user=request.user,
                aws_account=account,
                log_group_name=lg['log_group_name'],
                stored_gb=lg['stored_gb'],
                retention_days=lg['retention_days'],
                days_since_last_log=lg['days_since_last_log'],
                monthly_cost=lg['estimated_monthly_cost'],
                reasons=lg['idle_reasons']
            )
        
        # Save Alarms
        for alarm in cw_results.get('alarms', []):
            IdleCloudWatchAlarm.objects.create(
                user=request.user,
                aws_account=account,
                alarm_name=alarm['alarm_name'],
                state=alarm['state'],
                actions_enabled=alarm['actions_enabled'],
                monthly_cost=alarm['estimated_monthly_cost'],
                reasons=alarm['idle_reasons']
            )
        
        # Save Dashboards
        for dashboard in cw_results.get('dashboards', []):
            IdleCloudWatchDashboard.objects.create(
                user=request.user,
                aws_account=account,
                dashboard_name=dashboard['dashboard_name'],
                days_since_modified=dashboard['days_since_modified'],
                reasons=dashboard['idle_reasons']
            )
        
        # Save Metrics
        for metric in cw_results.get('metrics', []):
            IdleCloudWatchMetric.objects.create(
                user=request.user,
                aws_account=account,
                namespace=metric['namespace'],
                metric_name=metric['metric_name'],
                monthly_cost=metric['estimated_monthly_cost'],
                reasons=metric['idle_reasons']
            )
        
        total_savings = sum(a['estimated_monthly_cost'] for a in idle_apis) + \
                       sum(lg['estimated_monthly_cost'] for lg in cw_results.get('log_groups', [])) + \
                       sum(a['estimated_monthly_cost'] for a in cw_results.get('alarms', [])) + \
                       sum(m['estimated_monthly_cost'] for m in cw_results.get('metrics', []))
        
        return Response({
            'success': True,
            'api_gateways': {
                'count': len(idle_apis),
                'items': idle_apis,
                'savings': sum(a['estimated_monthly_cost'] for a in idle_apis)
            },
            'cloudwatch': {
                'log_groups': {
                    'count': len(cw_results.get('log_groups', [])),
                    'items': cw_results.get('log_groups', []),
                    'savings': sum(lg['estimated_monthly_cost'] for lg in cw_results.get('log_groups', []))
                },
                'alarms': {
                    'count': len(cw_results.get('alarms', [])),
                    'items': cw_results.get('alarms', []),
                    'savings': sum(a['estimated_monthly_cost'] for a in cw_results.get('alarms', []))
                },
                'dashboards': {
                    'count': len(cw_results.get('dashboards', [])),
                    'items': cw_results.get('dashboards', [])
                },
                'metrics': {
                    'count': len(cw_results.get('metrics', [])),
                    'items': cw_results.get('metrics', []),
                    'savings': sum(m['estimated_monthly_cost'] for m in cw_results.get('metrics', []))
                }
            },
            'total_savings': total_savings
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


# GET endpoints for retrieving saved data
@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_idle_api_gateways(request, account_id):
    """Get saved idle API Gateways from database"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        from .models import IdleAPIGateway
        idle_apis = IdleAPIGateway.objects.filter(
            aws_account=account, 
            is_resolved=False
        ).order_by('-monthly_cost')
        
        data = [{
            'id': api.id,
            'api_id': api.api_id,
            'api_name': api.api_name,
            'api_type': api.api_type,
            'total_requests_30d': api.total_requests_30d,
            'requests_7d': api.requests_7d,
            'active_stages': api.active_stages,
            'avg_connections': api.avg_connections,
            'monthly_cost': float(api.monthly_cost),
            'reasons': api.reasons,
            'detected_at': api.detected_at
        } for api in idle_apis]
        
        return Response({
            'count': len(data),
            'total_savings': sum(float(api['monthly_cost']) for api in data),
            'apis': data
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_idle_cloudwatch_log_groups(request, account_id):
    """Get saved idle CloudWatch Log Groups from database"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        from .models import IdleCloudWatchLogGroup
        log_groups = IdleCloudWatchLogGroup.objects.filter(
            aws_account=account, 
            is_resolved=False
        ).order_by('-monthly_cost')
        
        data = [{
            'id': lg.id,
            'log_group_name': lg.log_group_name,
            'stored_gb': lg.stored_gb,
            'retention_days': lg.retention_days,
            'days_since_last_log': lg.days_since_last_log,
            'monthly_cost': float(lg.monthly_cost),
            'reasons': lg.reasons,
            'detected_at': lg.detected_at
        } for lg in log_groups]
        
        return Response({
            'count': len(data),
            'total_savings': sum(float(lg['monthly_cost']) for lg in data),
            'log_groups': data
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_idle_cloudwatch_alarms(request, account_id):
    """Get saved idle CloudWatch Alarms from database"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        from .models import IdleCloudWatchAlarm
        alarms = IdleCloudWatchAlarm.objects.filter(
            aws_account=account, 
            is_resolved=False
        ).order_by('-alarm_name')
        
        data = [{
            'id': alarm.id,
            'alarm_name': alarm.alarm_name,
            'state': alarm.state,
            'actions_enabled': alarm.actions_enabled,
            'monthly_cost': float(alarm.monthly_cost),
            'reasons': alarm.reasons,
            'detected_at': alarm.detected_at
        } for alarm in alarms]
        
        return Response({
            'count': len(data),
            'alarms': data
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_idle_cloudwatch_dashboards(request, account_id):
    """Get saved idle CloudWatch Dashboards from database"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        from .models import IdleCloudWatchDashboard
        dashboards = IdleCloudWatchDashboard.objects.filter(
            aws_account=account, 
            is_resolved=False
        ).order_by('-days_since_modified')
        
        data = [{
            'id': dash.id,
            'dashboard_name': dash.dashboard_name,
            'days_since_modified': dash.days_since_modified,
            'reasons': dash.reasons,
            'detected_at': dash.detected_at
        } for dash in dashboards]
        
        return Response({
            'count': len(data),
            'dashboards': data
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_idle_cloudwatch_metrics(request, account_id):
    """Get saved idle CloudWatch Custom Metrics from database"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        from .models import IdleCloudWatchMetric
        metrics = IdleCloudWatchMetric.objects.filter(
            aws_account=account, 
            is_resolved=False
        ).order_by('-monthly_cost')
        
        data = [{
            'id': metric.id,
            'namespace': metric.namespace,
            'metric_name': metric.metric_name,
            'monthly_cost': float(metric.monthly_cost),
            'reasons': metric.reasons,
            'detected_at': metric.detected_at
        } for metric in metrics]
        
        return Response({
            'count': len(data),
            'total_savings': sum(float(m['monthly_cost']) for m in data),
            'metrics': data
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


# Resolve endpoints
@api_view(['PUT'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def resolve_idle_api_gateway(request, api_id):
    """Mark an idle API Gateway as resolved"""
    try:
        from .models import IdleAPIGateway
        api = IdleAPIGateway.objects.get(id=api_id, user=request.user)
        api.is_resolved = True
        api.save()
        return Response({'success': True, 'message': 'API Gateway marked as resolved'}, status=200)
    except IdleAPIGateway.DoesNotExist:
        return Response({'error': 'API Gateway not found'}, status=404)


@api_view(['PUT'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def resolve_idle_log_group(request, log_group_id):
    """Mark an idle Log Group as resolved"""
    try:
        from .models import IdleCloudWatchLogGroup
        lg = IdleCloudWatchLogGroup.objects.get(id=log_group_id, user=request.user)
        lg.is_resolved = True
        lg.save()
        return Response({'success': True, 'message': 'Log Group marked as resolved'}, status=200)
    except IdleCloudWatchLogGroup.DoesNotExist:
        return Response({'error': 'Log Group not found'}, status=404)

@api_view(['DELETE'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def clear_idle_results_cache(request, account_id):
    """Clear all cached idle results for an account"""
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        from .models import (
            IdleEC2Instance, IdleAutoScalingGroup, IdleLoadBalancer,
            IdleLambdaFunction, IdleECSService, IdleNATGateway,
            IdleVPCEndpoint, IdleAPIGateway, IdleCloudWatchLogGroup,
            IdleCloudWatchAlarm, IdleCloudWatchDashboard, IdleCloudWatchMetric
        )
        
        # Delete all findings
        ec2_count = IdleEC2Instance.objects.filter(aws_account=account).delete()[0]
        asg_count = IdleAutoScalingGroup.objects.filter(aws_account=account).delete()[0]
        lb_count = IdleLoadBalancer.objects.filter(aws_account=account).delete()[0]
        lambda_count = IdleLambdaFunction.objects.filter(aws_account=account).delete()[0]
        ecs_count = IdleECSService.objects.filter(aws_account=account).delete()[0]
        nat_count = IdleNATGateway.objects.filter(aws_account=account).delete()[0]
        vpce_count = IdleVPCEndpoint.objects.filter(aws_account=account).delete()[0]
        api_count = IdleAPIGateway.objects.filter(aws_account=account).delete()[0]
        log_count = IdleCloudWatchLogGroup.objects.filter(aws_account=account).delete()[0]
        alarm_count = IdleCloudWatchAlarm.objects.filter(aws_account=account).delete()[0]
        dashboard_count = IdleCloudWatchDashboard.objects.filter(aws_account=account).delete()[0]
        metric_count = IdleCloudWatchMetric.objects.filter(aws_account=account).delete()[0]
        
        total_deleted = (ec2_count + asg_count + lb_count + lambda_count + ecs_count + 
                        nat_count + vpce_count + api_count + log_count + alarm_count + 
                        dashboard_count + metric_count)
        
        return Response({
            'success': True,
            'message': f'Cleared {total_deleted} idle resource findings',
            'deleted_count': total_deleted
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)




@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_service_breakdown_from_db(request, account_db_id):
    """
    Get service breakdown directly from low-level services database
    This will be more accurate than AWS Cost Explorer
    """
    try:
        account = AWSAccount.objects.get(id=account_db_id, user=request.user)
        
        from .models import LowLevelServiceResource, LowLevelServiceDefinition
        
        # Get all active resources
        resources = LowLevelServiceResource.objects.filter(
            account=account,
            is_active=True
        ).select_related('service_definition')
        
        # Group by service category
        service_costs = {}
        
        for resource in resources:
            service_name = resource.service_definition.category.name if resource.service_definition.category else 'Other'
            amount = float(resource.estimated_monthly_cost or 0) * (resource.count or 1)
            
            if amount > 0.50:  # Only include services costing more than $0.50
                if service_name not in service_costs:
                    service_costs[service_name] = {
                        'service': service_name,
                        'amount': 0,
                        'count': 0,
                        'resources': []
                    }
                service_costs[service_name]['amount'] += amount
                service_costs[service_name]['count'] += 1
                service_costs[service_name]['resources'].append({
                    'name': resource.service_definition.name,
                    'resource_id': resource.resource_id,
                    'monthly_cost': amount
                })
        
        # Calculate total
        total = sum(data['amount'] for data in service_costs.values())
        
        # Build response
        service_breakdown = []
        for service_name, data in service_costs.items():
            service_breakdown.append({
                'service': service_name,
                'amount': round(data['amount'], 2),
                'percentage': round((data['amount'] / total) * 100, 1) if total > 0 else 0,
                'resource_count': data['count'],
                'recommendation': get_recommendation_for_service(service_name)
            })
        
        # Sort by amount descending
        service_breakdown.sort(key=lambda x: x['amount'], reverse=True)
        
        return Response({
            'service_breakdown': service_breakdown[:10],
            'total_monthly': round(total, 2),
            'source': 'low_level_services_database'
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        logger.error(f"Error getting service breakdown from DB: {e}")
        return Response({'error': str(e)}, status=500)

def get_recommendation_for_service(service_name):
    """Get recommendation based on service category"""
    recommendations = {
        'Virtual Private Cloud': 'Review NAT Gateways and VPC Endpoints for optimization',
        'Elastic Compute Cloud': 'Check for idle EC2 instances and consider rightsizing',
        'Relational Database Service': 'Review RDS instances for idle databases',
        'Simple Storage Service': 'Implement lifecycle policies for S3 buckets',
        'CloudFront': 'Optimize CloudFront distribution settings',
        'Lambda': 'Review Lambda function memory settings and invocation patterns',
        'DynamoDB': 'Consider using DynamoDB auto-scaling',
        'Elastic Load Balancing': 'Check for idle load balancers',
    }
    return recommendations.get(service_name, 'Review resource utilization and optimize where possible')

# Add this to views.py
from django.core.cache import cache

@api_view(['POST'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def generate_low_level_ai_recommendations(request, account_db_id):
    """
    Generate AI recommendations based on low-level resources and save to database
    """
    try:
        account = AWSAccount.objects.get(id=account_db_id, user=request.user)
        
        # Check if we have a cached analysis less than 24 hours old
        from .models import AWSCostAnalysis
        cached_analysis = AWSCostAnalysis.objects.filter(
            aws_account=account,
            analysis_type='ai_low_level',  # Use a different type
            created_at__gte=timezone.now() - timedelta(hours=24)
        ).first()
        
        if cached_analysis:
            return Response({
                'success': True,
                'analysis': cached_analysis.analysis_result,
                'generated_at': cached_analysis.created_at,
                'from_cache': True,
                'summary': cached_analysis.analysis_data
            }, status=200)
        
        # Get low-level resources from database
        from .models import LowLevelServiceResource, LowLevelServiceDefinition
        
        resources = LowLevelServiceResource.objects.filter(
            account=account,
            is_active=True,
            estimated_monthly_cost__gt=0
        ).select_related('service_definition__category')
        
        if not resources.exists():
            return Response({
                'success': False,
                'message': 'No resource data available. Please sync your AWS account first.'
            }, status=200)
        
        # Prepare data for AI analysis
        resource_summary = []
        total_monthly_cost = 0
        
        # Group by category
        category_costs = {}
        expensive_resources = []
        
        for resource in resources:
            cost = float(resource.estimated_monthly_cost or 0) * (resource.count or 1)
            total_monthly_cost += cost
            
            category = resource.service_definition.category.name if resource.service_definition.category else 'Other'
            service_name = resource.service_definition.name
            resource_name = resource.resource_name or resource.resource_id
            
            if category not in category_costs:
                category_costs[category] = 0
            category_costs[category] += cost
            
            if cost > 10:
                expensive_resources.append({
                    'name': service_name,
                    'resource_id': resource_name,
                    'monthly_cost': round(cost, 2),
                    'category': category
                })
            
            resource_summary.append({
                'service': service_name,
                'category': category,
                'count': resource.count or 1,
                'monthly_cost': round(cost, 2),
                'details': resource.details if resource.details else {}
            })
        
        top_categories = sorted(category_costs.items(), key=lambda x: x[1], reverse=True)[:3]
        
        # Build prompt for AI - instruct to format with clear sections
        prompt = f"""As a Senior AWS FinOps Expert, analyze this AWS account's low-level resources.

ACCOUNT SUMMARY:
- Total Monthly Cost: ${round(total_monthly_cost, 2)}
- Total Resources: {resources.count()}
- Most Expensive Categories: {', '.join([f"{cat}: ${round(cost, 2)}" for cat, cost in top_categories])}

TOP EXPENSIVE RESOURCES (>$10/month):
{chr(10).join([f"- {r['name']} ({r['category']}): ${r['monthly_cost']}/month - ID: {r['resource_id']}" for r in expensive_resources[:10]])}

RESOURCE BREAKDOWN:
{chr(10).join([f"- {r['service']} ({r['category']}): {r['count']} unit(s) @ ${r['monthly_cost']}/month" for r in resource_summary[:15]])}

Format your response EXACTLY with these three sections using the headers below:

## 🔴 WHY These Costs Are High
(Explain 3-5 specific reasons based on the actual resources)

## 🟡 HOW To Fix Each Issue
(List numbered, actionable steps for each problem)

## 🟢 WHAT You'll Save
(Expected outcomes with dollar amounts and timelines)

Make each section detailed and specific to the resources shown above. Do NOT give generic advice."""
        
        # Call GROQ API
        headers = {
            "Authorization": f"Bearer {settings.GROQ_API_KEY}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": "llama-3.3-70b-versatile",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a Senior AWS FinOps Expert. Always use the exact three-section format with the headers provided. Be specific and actionable."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.7,
            "max_tokens": 1200
        }
        
        import requests
        import time
        
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=45
        )
        
        if response.status_code == 200:
            result = response.json()
            analysis = result['choices'][0]['message']['content']
            
            # Save to database for caching
            AWSCostAnalysis.objects.update_or_create(
                aws_account=account,
                analysis_type='ai_low_level',
                defaults={
                    'analysis_data': {
                        'total_monthly_cost': total_monthly_cost,
                        'resources_count': resources.count(),
                        'top_categories': [{'name': cat, 'cost': round(cost, 2)} for cat, cost in top_categories],
                        'expensive_resources': expensive_resources[:10]
                    },
                    'analysis_result': analysis,
                    'cost_drivers_used': [r['name'] for r in expensive_resources[:5]]
                }
            )
            
            return Response({
                'success': True,
                'analysis': analysis,
                'generated_at': timezone.now().isoformat(),
                'from_cache': False,
                'summary': {
                    'total_monthly_cost': round(total_monthly_cost, 2),
                    'resources_count': resources.count(),
                    'top_categories': [{'name': cat, 'cost': round(cost, 2)} for cat, cost in top_categories]
                }
            }, status=200)
        else:
            return Response({
                'success': False,
                'error': f'AI service error: {response.status_code}'
            }, status=500)
            
    except Exception as e:
        logger.error(f"Error generating AI recommendations: {e}")
        return Response({'success': False, 'error': str(e)}, status=500)


@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def get_low_level_ai_recommendations_cached(request, account_db_id):
    """
    Get cached AI recommendations from database (no new API call)
    """
    try:
        account = AWSAccount.objects.get(id=account_db_id, user=request.user)
        
        from .models import AWSCostAnalysis
        
        # Get most recent analysis (any age - never expires from DB, UI will show age)
        latest_analysis = AWSCostAnalysis.objects.filter(
            aws_account=account,
            analysis_type='ai_low_level'
        ).order_by('-created_at').first()
        
        if latest_analysis:
            age_hours = (timezone.now() - latest_analysis.created_at).total_seconds() / 3600
            
            return Response({
                'success': True,
                'analysis': latest_analysis.analysis_result,
                'generated_at': latest_analysis.created_at.isoformat(),
                'from_cache': True,
                'age_hours': round(age_hours, 1),
                'summary': latest_analysis.analysis_data
            }, status=200)
        else:
            return Response({
                'success': False,
                'message': 'No cached analysis available. Click "Generate Analysis" to create one.',
                'from_cache': False
            }, status=200)
            
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)

# Add to views.py - Replace existing storage view functions

from .storage_optimization_service import (
    get_cached_storage_results,
    save_scan_results_to_db,
    clear_all_storage_data,
    test_ebs_volumes,
    test_elastic_ips,
    test_rds_instances,
    test_snapshots,
    test_unattached_ebs_volumes_only,
    test_duplicate_snapshots,
    test_idle_rds_instances,
    test_unused_amis
)

# views.py - Replace your run_complete_storage_scan function

@api_view(['GET'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def run_complete_storage_scan(request, account_id):
    """
    Run all storage optimization scans and save to database
    force_refresh=true makes new AWS API calls
    force_refresh=false uses cached database results
    """
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user, status='connected')
        force_refresh = request.query_params.get('force_refresh', 'false').lower() == 'true'
        
        print(f"🔍 Storage Scan - force_refresh: {force_refresh}")
        
        # Check for cached results first (unless force_refresh is true)
        if not force_refresh:
            from .storage_optimization_service import get_cached_storage_results
            cached_results = get_cached_storage_results(request.user, account, force_refresh=False)
            if cached_results:
                print("📦 Returning cached storage results from database")
                return Response(cached_results, status=200)
        
        # Force refresh - make fresh AWS API calls
        logger.info(f"🔄 Running fresh storage scan for account {account.account_id}")
        
        from .storage_optimization_service import (
            test_ebs_volumes,
            test_elastic_ips,
            test_rds_instances,
            test_snapshots,
            test_unattached_ebs_volumes_only,
            test_duplicate_snapshots,
            test_idle_rds_instances,
            test_unused_amis,
            save_scan_results_to_db
        )
        
        print("📊 Running storage scans...")
        
        # Run all scans
        ebs_result = test_ebs_volumes(account.role_arn, str(account.external_id))
        eip_result = test_elastic_ips(account.role_arn, str(account.external_id))
        rds_result = test_rds_instances(account.role_arn, str(account.external_id))
        snapshot_result = test_snapshots(account.role_arn, str(account.external_id))
        unattached_ebs_result = test_unattached_ebs_volumes_only(account.role_arn, str(account.external_id))
        duplicate_snapshot_result = test_duplicate_snapshots(account.role_arn, str(account.external_id))
        idle_rds_result = test_idle_rds_instances(account.role_arn, str(account.external_id))
        unused_amis_result = test_unused_amis(account.role_arn, str(account.external_id))
        
        total_findings = (
            unattached_ebs_result.get('count', 0) +
            duplicate_snapshot_result.get('count', 0) +
            idle_rds_result.get('count', 0) +
            unused_amis_result.get('count', 0)
        )
        
        total_savings = 0
        for vol in unattached_ebs_result.get('unattached_volumes', []):
            total_savings += vol.get('monthly_cost', 0)
        for group in duplicate_snapshot_result.get('duplicate_groups', []):
            total_savings += group.get('monthly_cost', 0)
        for rds in idle_rds_result.get('idle_instances', []):
            total_savings += rds.get('monthly_cost', 0)
        for ami in unused_amis_result.get('unused_amis', []):
            total_savings += ami.get('monthly_cost', 0)
        
        scan_results = {
            'success': True,
            'cached': False,
            'total_findings': total_findings,
            'total_potential_savings': round(total_savings, 2),
            'ebs_volumes': {
                'total': ebs_result.get('count', 0),
                'unattached': unattached_ebs_result.get('count', 0),
                'unattached_volumes': unattached_ebs_result.get('unattached_volumes', []),
                'items': ebs_result.get('volumes', [])
            },
            'rds_instances': {
                'total': rds_result.get('count', 0),
                'items': rds_result.get('instances', [])
            },
            'elastic_ips': {
                'total': eip_result.get('count', 0),
                'unused': eip_result.get('unused', 0),
                'items': [
                    {
                        'public_ip': addr.get('PublicIp'),
                        'allocation_id': addr.get('AllocationId'),
                        'domain': addr.get('Domain'),
                        'is_associated': bool(addr.get('InstanceId') or addr.get('NetworkInterfaceId'))
                    }
                    for addr in eip_result.get('addresses', [])
                ]
            },
            'snapshots': {
                'total': snapshot_result.get('count', 0),
                'old': snapshot_result.get('old_count', 0),
                'items': [
                    {
                        'snapshot_id': snap.get('SnapshotId'),
                        'volume_size': snap.get('VolumeSize', 0),
                        'age_days': (timezone.now() - snap.get('StartTime').replace(tzinfo=timezone.utc)).days if snap.get('StartTime') else 0,
                        'monthly_cost': snap.get('VolumeSize', 0) * 0.05
                    }
                    for snap in snapshot_result.get('snapshots', [])
                ]
            },
            'idle_rds_instances': {
                'count': idle_rds_result.get('count', 0),
                'items': idle_rds_result.get('idle_instances', [])
            },
            'unused_amis': {
                'count': unused_amis_result.get('count', 0),
                'items': unused_amis_result.get('unused_amis', [])
            },
            'duplicate_snapshots': {
                'count': duplicate_snapshot_result.get('count', 0),
                'items': duplicate_snapshot_result.get('duplicate_groups', [])
            }
        }
        
        # Save results to database
        print("💾 Saving storage results to database...")
        save_scan_results_to_db(request.user, account, scan_results)
        
        # Return the fresh results
        return Response(scan_results, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found', 'success': False}, status=404)
    except Exception as e:
        logger.error(f"Storage scan error: {e}")
        import traceback
        traceback.print_exc()
        return Response({'error': str(e), 'success': False}, status=500)

@api_view(['DELETE'])
@authentication_classes([TokenAuthentication, SessionAuthentication])
@permission_classes([IsAuthenticated])
def clear_storage_cache(request, account_id):
    """
    Clear all storage optimization cached data from database
    """
    try:
        account = AWSAccount.objects.get(id=account_id, user=request.user)
        
        from .storage_optimization_service import clear_all_storage_data
        
        result = clear_all_storage_data(account)
        
        return Response({
            'success': True,
            'message': f"Cleared {result['total_deleted']} storage optimization records",
            'details': result
        }, status=200)
        
    except AWSAccount.DoesNotExist:
        return Response({'error': 'AWS account not found'}, status=404)
    except Exception as e:
        logger.error(f"Error clearing storage cache: {e}")
        return Response({'error': str(e)}, status=500)

# Add these imports at the top of views.py if not already there
from django.core.management import call_command
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import io
import sys
import json


@csrf_exempt
def wipe_all_data_simple(request):
    """
    Wipe all data - NO SUPERUSER REQUIRED
    Just needs username, password, MFA code, and confirmation
    """
    if request.method == 'GET':
        # Show a simple form in browser
        return HttpResponse("""
        <html>
        <head>
            <title>Wipe All Data</title>
            <style>
                body { font-family: Arial; padding: 20px; max-width: 500px; margin: auto; }
                input, button { padding: 10px; margin: 5px; width: 100%; }
                .danger { background-color: #ff4444; color: white; border: none; }
                .warning { background-color: #ffaa00; padding: 10px; margin-bottom: 20px; }
            </style>
        </head>
        <body>
            <h1>⚠️ DANGER: Wipe All Data</h1>
            <div class="warning">
                <strong>WARNING:</strong> This will delete ALL data from the database!<br>
                This action cannot be undone!
            </div>
            <form method="POST">
                <label>Username:</label>
                <input type="text" name="username" value="uchimevictor_12" required>
                
                <label>Password:</label>
                <input type="password" name="password" required>
                
                <label>MFA Code:</label>
                <input type="text" name="mfa_code" placeholder="Enter your authenticator code" required>
                
                <label>Type "DELETE ALL" to confirm:</label>
                <input type="text" name="confirm" placeholder="DELETE ALL" required>
                
                <label>Keep users? (leave unchecked to delete everything)</label>
                <input type="checkbox" name="keep_users" value="yes">
                
                <label>Keep AWS accounts?</label>
                <input type="checkbox" name="keep_aws_accounts" value="yes">
                
                <button type="submit" class="danger">🗑️ DELETE ALL DATA</button>
            </form>
        </body>
        </html>
        """)
    
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=400)
    
    # Handle form data or JSON
    if request.content_type == 'application/json':
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')
        mfa_code = data.get('mfa_code')
        confirm = data.get('confirm', '')
        keep_users = data.get('keep_users', False)
        keep_aws_accounts = data.get('keep_aws_accounts', False)
    else:
        # Form data
        username = request.POST.get('username')
        password = request.POST.get('password')
        mfa_code = request.POST.get('mfa_code')
        confirm = request.POST.get('confirm', '')
        keep_users = request.POST.get('keep_users') == 'yes'
        keep_aws_accounts = request.POST.get('keep_aws_accounts') == 'yes'
    
    # Authenticate user
    from django.contrib.auth import authenticate
    user = authenticate(request, username=username, password=password)
    
    if not user:
        return JsonResponse({'error': 'Invalid username or password'}, status=401)
    
    # Verify MFA
    try:
        from security.models import MFAConfiguration
        import pyotp
        mfa_config = MFAConfiguration.objects.get(user=user, is_enabled=True)
        
        if not mfa_code:
            return JsonResponse({'error': 'MFA code required'}, status=401)
        
        totp = pyotp.TOTP(mfa_config.secret_key)
        if not totp.verify(mfa_code):
            return JsonResponse({'error': 'Invalid MFA code'}, status=401)
            
    except MFAConfiguration.DoesNotExist:
        # No MFA configured, continue
        pass
    
    # Require confirmation
    if confirm != 'DELETE ALL':
        return JsonResponse({
            'error': 'Confirmation required',
            'message': 'You must type "DELETE ALL" to confirm'
        }, status=400)
    
    try:
        # Capture command output
        out = io.StringIO()
        err = io.StringIO()
        sys.stdout = out
        sys.stderr = err
        
        # Execute the wipe command
        call_command(
            'wipe_all_data',
            yes=True,
            keep_users=keep_users,
            keep_aws_accounts=keep_aws_accounts,
            stdout=out
        )
        
        # Restore stdout
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
        
        output = out.getvalue()
        
        return JsonResponse({
            'success': True,
            'message': 'Data wipe completed successfully',
            'output': output,
            'keep_users': keep_users,
            'keep_aws_accounts': keep_aws_accounts
        }, status=200)
        
    except Exception as e:
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
        
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@csrf_exempt
def clear_cache_only_simple(request):
    """
    Clear only cached data - NO SUPERUSER REQUIRED
    Safer option - only deletes scan/cache data, preserves user accounts and AWS connections
    """
    if request.method == 'GET':
        return HttpResponse("""
        <html>
        <head>
            <title>Clear Cache Only</title>
            <style>
                body { font-family: Arial; padding: 20px; max-width: 500px; margin: auto; }
                input, button { padding: 10px; margin: 5px; width: 100%; }
                .warning { background-color: #ffaa00; padding: 10px; margin-bottom: 20px; }
                .safe { background-color: #4CAF50; color: white; border: none; }
            </style>
        </head>
        <body>
            <h1>🧹 Clear Cache Only</h1>
            <div class="warning">
                This will only clear scan/cache data.<br>
                Your user accounts and AWS connections will be preserved!
            </div>
            <form method="POST">
                <label>Username:</label>
                <input type="text" name="username" value="uchimevictor_12" required>
                
                <label>Password:</label>
                <input type="password" name="password" required>
                
                <label>MFA Code:</label>
                <input type="text" name="mfa_code" placeholder="Enter your authenticator code" required>
                
                <label>Type "CLEAR" to confirm:</label>
                <input type="text" name="confirm" placeholder="CLEAR" required>
                
                <button type="submit" class="safe">🧹 CLEAR CACHE</button>
            </form>
        </body>
        </html>
        """)
    
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=400)
    
    # Handle form data or JSON
    if request.content_type == 'application/json':
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')
        mfa_code = data.get('mfa_code')
        confirm = data.get('confirm', '')
    else:
        username = request.POST.get('username')
        password = request.POST.get('password')
        mfa_code = request.POST.get('mfa_code')
        confirm = request.POST.get('confirm', '')
    
    # Authenticate
    from django.contrib.auth import authenticate
    user = authenticate(request, username=username, password=password)
    
    if not user:
        return JsonResponse({'error': 'Invalid credentials'}, status=401)
    
    # Verify MFA
    try:
        from security.models import MFAConfiguration
        import pyotp
        mfa_config = MFAConfiguration.objects.get(user=user, is_enabled=True)
        
        if not mfa_code:
            return JsonResponse({'error': 'MFA code required'}, status=401)
        
        totp = pyotp.TOTP(mfa_config.secret_key)
        if not totp.verify(mfa_code):
            return JsonResponse({'error': 'Invalid MFA code'}, status=401)
    except MFAConfiguration.DoesNotExist:
        pass
    
    if confirm != 'CLEAR':
        return JsonResponse({'error': 'Type "CLEAR" to confirm'}, status=400)
    
    deleted_counts = {}
    
    try:
        # Import models
        from myground.models import (
            CostDataHistory, CostDriver, AWSCostAnalysis, ResourceSummary,
            LowLevelServiceSnapshot, LowLevelServiceResource, LowLevelServiceCostHistory,
            AWSCostCache, StorageOptimizationFinding, DuplicateStorageFinding,
            ResourceUsageSnapshot, CpuUsageSnapshot, StorageOptimizationSummary
        )
        from security.models import (
            IAMFinding, IAMSecurityReport, PublicExposureFinding, PublicExposureReport,
            SecurityGroupAnalysis, SecurityGroupChangeLog, SecurityGroupAnalysisCache,
            EncryptionFinding, EncryptionSummary, EncryptionScanCache, EncryptionAction, EncryptionRecommendation
        )
        
        # Clear Security app data
        security_models = [
            (IAMFinding, 'IAM Findings'),
            (IAMSecurityReport, 'IAM Reports'),
            (PublicExposureFinding, 'Public Exposure Findings'),
            (PublicExposureReport, 'Public Exposure Reports'),
            (SecurityGroupAnalysis, 'Security Group Analyses'),
            (SecurityGroupChangeLog, 'Security Group Change Logs'),
            (SecurityGroupAnalysisCache, 'Security Group Cache'),
            (EncryptionFinding, 'Encryption Findings'),
            (EncryptionSummary, 'Encryption Summaries'),
            (EncryptionScanCache, 'Encryption Cache'),
            (EncryptionAction, 'Encryption Actions'),
            (EncryptionRecommendation, 'Encryption Recommendations'),
        ]
        
        for model, name in security_models:
            count = model.objects.all().count()
            if count > 0:
                model.objects.all().delete()
                deleted_counts[name] = count
        
        # Clear Myground cache data
        myground_models = [
            (CostDataHistory, 'Cost Data History'),
            (CostDriver, 'Cost Drivers'),
            (AWSCostAnalysis, 'Cost Analyses'),
            (ResourceSummary, 'Resource Summaries'),
            (LowLevelServiceSnapshot, 'Low-Level Service Snapshots'),
            (LowLevelServiceResource, 'Low-Level Service Resources'),
            (LowLevelServiceCostHistory, 'Low-Level Cost History'),
            (AWSCostCache, 'AWS Cost Cache'),
            (StorageOptimizationFinding, 'Storage Findings'),
            (DuplicateStorageFinding, 'Duplicate Findings'),
            (ResourceUsageSnapshot, 'Resource Usage Snapshots'),
            (CpuUsageSnapshot, 'CPU Usage Snapshots'),
            (StorageOptimizationSummary, 'Storage Summaries'),
        ]
        
        for model, name in myground_models:
            count = model.objects.all().count()
            if count > 0:
                model.objects.all().delete()
                deleted_counts[name] = count
        
        return JsonResponse({
            'success': True,
            'message': 'Cache cleared successfully',
            'deleted_counts': deleted_counts,
            'total_deleted': sum(deleted_counts.values())
        }, status=200)
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)