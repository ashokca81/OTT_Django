"""
Django settings for ott_admin project.

Generated by 'django-admin startproject' using Django 4.2.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""

import os
from pathlib import Path
import pymysql
from dotenv import load_dotenv
pymysql.install_as_MySQLdb()

# Load environment variables
load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-$4ba3!s+0wnaf*s1-ic5e246ue@yisbxf__p71ey($ubf3wok!'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'storages',
    'corsheaders',
    'rest_framework',
    'main_accounts',
    'users',
    
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'ott_admin.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'ott_admin.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {
    # 'default': {
    #     'ENGINE': 'django.db.backends.sqlite3',
    #     'NAME': BASE_DIR / 'db.sqlite3',
    # }
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'new_ott',
        'USER': 'admin',
        'PASSWORD': 'ashokca810',
        'HOST': 'database-1.chuc440webif.ap-south-1.rds.amazonaws.com',',
        'PORT': '3306',
        'OPTIONS': {
            'charset': 'utf8mb4',
        },
    }
}


# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

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


# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Asia/Kolkata'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = "static/"
STATICFILES_DIRS = [os.path.join(BASE_DIR, "static")]
STATIC_ROOT = os.path.join(BASE_DIR, "assets")
MEDIA_URL = "/media/"

MEDIA_ROOT = os.path.join(BASE_DIR, "media")

# Custom settings
LOGIN_URL = 'login'

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# REST Framework settings
REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.BasicAuthentication',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
    ],
}

# Session Settings
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_AGE = 86400  # 24 hours in seconds
SESSION_COOKIE_SECURE = False  # Changed to False for development
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'

# CORS settings
CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOWED_ORIGINS = [
    # "http://localhost:8080",
    # "http://127.0.0.1:8080",
    # "http://localhost:5173",
    # "http://192.168.0.124:8080",
    # "http://192.168.0.124:5173",
    "https://www.no1ott.com",
    "http://www.no1ott.com",
    "https://no1ott.com",
    "http://no1ott.com",
    "http://admin.no1ott.com"
]

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

CORS_EXPOSE_HEADERS = [
    'Content-Type', 
    'X-CSRFToken',
    'X-Requested-With',
    'X-CSRFToken',
    'X-Requested-With',
    ]

CSRF_TRUSTED_ORIGINS = [
    # "http://localhost:8080",
    # "http://127.0.0.1:8080",
    # "http://localhost:5173",
    # "http://192.168.0.124:8080",
    # "http://192.168.0.124:5173"
    "https://www.no1ott.com",
    "http://www.no1ott.com",
    "https://no1ott.com",
    "http://no1ott.com",
    "http://admin.no1ott.com"
]

# CSRF settings
CSRF_COOKIE_SECURE = False  # Set to True in production
CSRF_COOKIE_HTTPONLY = False
CSRF_USE_SESSIONS = False
CSRF_COOKIE_SAMESITE = 'Lax'

# MSG91 Settings
MSG91_AUTH_KEY = os.getenv('MSG91_AUTH_KEY', '440371AUT3I3zJpWiv681df3d6P1')
MSG91_TEMPLATE_ID = os.getenv('MSG91_TEMPLATE_ID', '679f6743d6fc054835399a22')
MSG91_SENDER_ID = os.getenv('MSG91_SENDER_ID', 'VGMPLD')
MSG91_SUBSCRIPTION_SUCCESS_TEMPLATE_ID = os.getenv('MSG91_SUBSCRIPTION_SUCCESS_TEMPLATE_ID', '681f7e38d6fc050a1d482774')  # Replace with your actual template ID

# Razorpay settings
RAZORPAY_KEY_ID = 'rzp_test_EDnxUsWaufciN6'  # Replace with your test key
RAZORPAY_KEY_SECRET = 'Cg1IFgjlYCLwGoHk1UhpysKB'  # Replace with your test secret




# AWS S3 Configuration
AWS_ACCESS_KEY_ID = 'AKIASIVGK4VVOKWZDRVX'
AWS_SECRET_ACCESS_KEY = 'ODVpwudsBRnKw7S3UaiNLO46ZMoDB62LGjMHLogk'
AWS_STORAGE_BUCKET_NAME = 'noonenews'
AWS_S3_REGION_NAME = 'ap-south-1'
AWS_S3_FILE_OVERWRITE = False
AWS_DEFAULT_ACL = None  # Changed from 'public-read' to None
AWS_S3_VERIFY = True
AWS_S3_SIGNATURE_VERSION = 's3v4'
AWS_QUERYSTRING_AUTH = False
AWS_S3_ADDRESSING_STYLE = 'virtual'
AWS_S3_CUSTOM_DOMAIN = f'{AWS_STORAGE_BUCKET_NAME}.s3.amazonaws.com'
AWS_S3_OBJECT_PARAMETERS = {
    'CacheControl': 'max-age=86400',
}

# Disable ACL for S3
AWS_ACCESS_CONTROL_LIST = None
AWS_BUCKET_ACL = None
AWS_DEFAULT_ACL = None

# S3 static settings
STATIC_LOCATION = 'static'
STATIC_URL = f'https://{AWS_S3_CUSTOM_DOMAIN}/{STATIC_LOCATION}/'
STATICFILES_STORAGE = 'ott_admin.storage_backends.StaticStorage'

# S3 public media settings
PUBLIC_MEDIA_LOCATION = 'media'
MEDIA_URL = f'https://{AWS_S3_CUSTOM_DOMAIN}/{PUBLIC_MEDIA_LOCATION}/'
DEFAULT_FILE_STORAGE = 'ott_admin.storage_backends.PublicMediaStorage'

# File Upload Settings
FILE_UPLOAD_MAX_MEMORY_SIZE = 52428800  # 50MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 52428800  # 50MB
FILE_UPLOAD_PERMISSIONS = 0o644
FILE_UPLOAD_DIRECTORY_PERMISSIONS = 0o755
FILE_UPLOAD_HANDLERS = [
    'django.core.files.uploadhandler.MemoryFileUploadHandler',
    'django.core.files.uploadhandler.TemporaryFileUploadHandler',
]
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Maximum size that can be uploaded (50GB)
AWS_MAX_MEMORY_SIZE = 53687091200  # 50GB in bytes
AWS_S3_MAX_MEMORY_SIZE = 53687091200  # 50GB in bytes

# Increase timeout for large files
AWS_S3_CONNECT_TIMEOUT = 300  # 5 minutes
AWS_S3_READ_TIMEOUT = 300    # 5 minutes

# Enable multipart upload for large files
AWS_S3_MULTIPART_THRESHOLD = 1024 * 1024 * 100  # 100MB
AWS_S3_MULTIPART_CHUNKSIZE = 1024 * 1024 * 25   # 25MB per chunk

# Logging Configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'file': {
            'class': 'logging.FileHandler',
            'filename': 'debug.log',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'ott_admin.storage_backends': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
        },
        'main_accounts.views': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
        },
    },
}

