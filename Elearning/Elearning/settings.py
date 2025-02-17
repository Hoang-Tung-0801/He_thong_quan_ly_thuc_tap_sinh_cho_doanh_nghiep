import os
from pathlib import Path
from decouple import config  # Sử dụng python-decouple để quản lý biến môi trường

# Đường dẫn cơ bản
BASE_DIR = Path(__file__).resolve().parent.parent

# SECRET_KEY: Sử dụng biến môi trường
SECRET_KEY = config('SECRET_KEY', default='django-insecure-default-key-for-development')

# DEBUG: Sử dụng biến môi trường
DEBUG = config('DEBUG', default=True, cast=bool)

# ALLOWED_HOSTS: Sử dụng biến môi trường
ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='*').split(',')

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
        'ENGINE': 'django.db.backends.mysql',
<<<<<<< HEAD
        'NAME': 'data',  
        'USER': 'root',      
        'PASSWORD': '123456', 
        'HOST': '127.0.0.1',  
        'PORT': '3306',      
=======
        'NAME': config('DB_NAME', default='db'),
        'USER': config('DB_USER', default='root'),
        'PASSWORD': config('DB_PASSWORD', default='root'),
        'HOST': config('DB_HOST', default='127.0.0.1'),
        'PORT': config('DB_PORT', default='3306'),
        'OPTIONS': {
            'charset': 'utf8mb4',
            'init_command': "SET sql_mode='STRICT_TRANS_TABLES'",
        },
>>>>>>> 780c59e7f740410ec07ea64deb26a725879531c3
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
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')  # Thư mục chứa static files trong production

# Media files (Uploaded files)
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Cấu hình email (sử dụng Gmail SMTP làm ví dụ)
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = config('EMAIL_HOST', default='smtp.gmail.com')
EMAIL_PORT = config('EMAIL_PORT', default=587, cast=int)
EMAIL_USE_TLS = config('EMAIL_USE_TLS', default=True, cast=bool)
EMAIL_HOST_USER = config('EMAIL_HOST_USER', default='dungdao10az@gmail.com')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='whmq ykle puko zydq')
EMAIL_TIMEOUT = 30  # Thời gian chờ kết nối SMTP

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
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SECURE_BROWSER_XSS_FILTER = True
    X_FRAME_OPTIONS = 'DENY'

# Cấu hình logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': os.path.join(BASE_DIR, 'debug.log'),
            'formatter': 'verbose',
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
        'home': {  # Thay 'home' bằng tên ứng dụng của bạn
            'handlers': ['file', 'console'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}
