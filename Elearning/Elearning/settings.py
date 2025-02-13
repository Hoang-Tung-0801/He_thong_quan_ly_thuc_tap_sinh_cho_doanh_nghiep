import os
from pathlib import Path

# Đường dẫn cơ bản
BASE_DIR = Path(__file__).resolve().parent.parent

# SECRET_KEY: Sử dụng giá trị mặc định (chỉ dùng trong development)
SECRET_KEY = 'django-insecure-default-key-for-development'  # Thay thế bằng giá trị thực tế trong production

# DEBUG: Đặt thành False trong production
DEBUG = True  # Đặt thành False khi triển khai production

# ALLOWED_HOSTS: Chỉ định các host được phép (sử dụng '*' chỉ trong development)
ALLOWED_HOSTS = ['*']  # Thay thế bằng danh sách host thực tế trong production

# Ứng dụng được cài đặt
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'home',  # Ứng dụng của bạn
]

# Middleware
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',  # Đảm bảo có dòng này
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# ROOT URLCONF
ROOT_URLCONF = 'Elearning.urls'

# Templates
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
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

# WSGI Application
WSGI_APPLICATION = 'Elearning.wsgi.application'

# Database
DATABASES = {
    'default': {
<<<<<<< HEAD
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'data',  
=======
        'ENGINE': 'django.db.backends.mysql', 
        'NAME': 'db',  
>>>>>>> baf5f88b8508858ead90cc278f574315b29700dd
        'USER': 'root',      
        'PASSWORD': '123456', 
        'HOST': '127.0.0.1',  
        'PORT': '3306',      
    }
}

# Password validation
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

# Ngôn ngữ và múi giờ
LANGUAGE_CODE = 'vi'
TIME_ZONE = 'Asia/Ho_Chi_Minh'
USE_I18N = True
USE_L10N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATICFILES_DIRS = [os.path.join(BASE_DIR, 'home', 'static')]
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')    # Thư mục chứa static files trong production

# Media files (Uploaded files)
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Cấu hình email (sử dụng Gmail SMTP làm ví dụ)
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'  # Máy chủ SMTP
EMAIL_PORT = 587  # Cổng SMTP
EMAIL_USE_TLS = True  # Sử dụng TLS
EMAIL_HOST_USER = 'dungdao10az@gmail.com'  # Email gửi
EMAIL_HOST_PASSWORD = 'whmq ykle puko zydq'  # Mật khẩu email

# Cấu hình đăng nhập
LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'home'
LOGOUT_REDIRECT_URL = 'login'

# Cấu hình session
SESSION_COOKIE_AGE = 30 * 24 * 60 * 60  # Session hết hạn sau 30 ngày
SESSION_SAVE_EVERY_REQUEST = True  # Lưu session sau mỗi request
SESSION_EXPIRE_AT_BROWSER_CLOSE = False  # Session không hết hạn khi đóng trình duyệt

# Cấu hình bảo mật (chỉ áp dụng trong production)
if not DEBUG:
    SECURE_HSTS_SECONDS = 31536000  # 1 năm
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SECURE_SSL_REDIRECT = True  # Chuyển hướng tất cả các request sang HTTPS
    SESSION_COOKIE_SECURE = True  # Chỉ sử dụng cookie qua HTTPS
    CSRF_COOKIE_SECURE = True  # Chỉ sử dụng CSRF cookie qua HTTPS

# Cấu hình logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': os.path.join(BASE_DIR, 'debug.log'),
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}