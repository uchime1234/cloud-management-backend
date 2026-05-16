"""
Django settings for authhentication project.
"""

from pathlib import Path
import socket
import os
import dj_database_url


# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = "django-insecure-td5cb0=q3)1a$lt(6ev##*qu+avuwn1f!by_e9k++@2=i4b*7b"
DEBUG = True
ALLOWED_HOSTS = [
    "*",     
    ".onrender.com",
    "localhost",
    "127.0.0.1",
    "cloud-management-frontend.vercel.app"
]

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    "rest_framework",
    'rest_framework.authtoken',
    'corsheaders',
    'myground.apps.MygroundConfig',
    'security.apps.SecurityConfig',
    'django_apscheduler',
    'sendgrid_backend'
    
   
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware', 
   # 'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# settings.py - Add this if not already there

CORS_ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://cloud-management-frontend.vercel.app",
    
]

# Add this for CSRF protection
CSRF_TRUSTED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "https://cloud-management-frontend.vercel.app",
    
]

# If you want to allow all origins for development (temporary fix)
CORS_ALLOW_ALL_ORIGINS = True

ROOT_URLCONF = 'authhentication.urls'

# Add these CORS settings
CORS_ALLOW_METHODS = [
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
]

CORS_ALLOW_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
]

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'authhentication.wsgi.application'

"""
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'cloud analysis',  # FIXED: Remove space or use underscore
        'USER': 'postgres',
        'PASSWORD': 'Uchimevictor',
        'HOST': '127.0.0.1',
        'PORT': '5432'
    }
}
"""

import dj_database_url
import os


DATABASES = {
    "default": dj_database_url.config(
        default=os.environ.get("DATABASE_URL"),
        conn_max_age=600,
        ssl_require=True,
    )
}

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')  # ← ADD THIS LINE
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'
# settings.py - Complete working email section

import ssl
# Disable SSL verification for development ONLY
ssl._create_default_https_context = ssl._create_unverified_context

# ============================================================
# EMAIL CONFIGURATION - SENDGRID WEB API
# ============================================================
EMAIL_BACKEND = "sendgrid_backend.SendgridBackend"
SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY')
DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL')
SENDGRID_SANITIZE_HTML = True
SENDGRID_TRACK_CLICKS = False
SENDGRID_TRACK_OPENS = False
SENDGRID_SANDBOX_MODE_IN_DEBUG = False

# REST Framework settings
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.AllowAny',
    ],
    'UNAUTHENTICATED_USER': None,
}



# Debugging
try:
    socket.gethostbyname('localhost')
    print("✅ DNS resolution successful")
except socket.gaierror as e:
    print(f"❌ DNS resolution failed: {e}")

APSCHEDULER_DATETIME_FORMAT = "N j, Y, f:s a"
APSCHEDULER_RUN_NOW_TIMEOUT = 25  # Seconds


# Timezone
TIME_ZONE = 'UTC'
USE_TZ = True



# Add to your settings.py
# settings.py - Use local memory cache with longer default timeout
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
        'TIMEOUT': 600,  # 10 minutes default timeout
        'OPTIONS': {
            'MAX_ENTRIES': 1000
        }
    }
}
# timeout settings

# For production, use:
# "LOCATION": "redis://:password@127.0.0.1:6379/0"

# settings.py
import os
from django.core.cache import cache

# Set up cache with fallback logic
CACHE_ENABLED = True

def safe_cache_get(key, default=None):
    """Safely get from cache, return default if cache fails"""
    if not CACHE_ENABLED:
        return default
    try:
        return cache.get(key, default)
    except Exception as e:
        print(f"⚠️ Cache get failed: {e}")
        return default

def safe_cache_set(key, value, timeout=None):
    """Safely set cache value"""
    if not CACHE_ENABLED:
        return
    try:
        cache.set(key, value, timeout)
    except Exception as e:
        print(f"⚠️ Cache set failed: {e}")

def safe_cache_delete(key):
    """Safely delete from cache"""
    if not CACHE_ENABLED:
        return
    try:
        cache.delete(key)
    except Exception as e:
        print(f"⚠️ Cache delete failed: {e}")

# Cache TTLs
RESOURCE_CACHE_TTL = 60 * 60 * 6
COST_CACHE_TTL = 60 * 60
SUMMARY_CACHE_TTL = 60 * 60 * 2

# settings.py
import os
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

# AWS Credentials

AWS_ACCOUNT_ID = os.environ.get('AWS_ACCOUNT_ID') 
AWS_ROLE_NAME = "CloudCostReadOnlyRole"
AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
AWS_REGION = os.environ.get('AWS_REGION')
GROQ_API_KEY = os.environ.get('GROQ_API_KEY')

# settings.py - Add this near your other keys
import os
import base64
from cryptography.fernet import Fernet

# Generate this once and keep it secure
# You can generate with: Fernet.generate_key().decode()
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
# settings.py - Add these

# GitHub OAuth
GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET')
GITHUB_REDIRECT_URL = os.environ.get('GITHUB_REDIRECT_URL')
GITHUB_WEBHOOK_SECRET = os.environ.get('GITHUB_WEBHOOK_SECRET')

# Base URL for webhooks
BASE_URL = os.environ.get('BASE_URL', 'http://localhost:8000')

# Encryption key (generate once)