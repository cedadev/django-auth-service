# -*- coding: utf-8 -*-

import os


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INSTALLED_APPS = [
    "django.contrib.sessions",
    "authenticate",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",

    # Authentication middleware
    #"authenticate.oauth2.middleware.BearerTokenAuthenticationMiddleware",
    #"authenticate.oidc.middleware.OpenIDConnectAuthenticationMiddleware",
    #"authenticate.cookie.middleware.CookieAuthenticationMiddleware",

    # Authorization middleware
    #"authorize.saml.middleware.SAMLAuthorizationMiddleware",
    #"authorize.middleware.LoginAuthorizationMiddleware",
]

SESSION_ENGINE = "django.contrib.sessions.backends.signed_cookies"

ROOT_URLCONF = "auth_service.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "auth_service.wsgi.application"


# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = ""


# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Database
# https://docs.djangoproject.com/en/2.2/ref/settings/#databases

DATABASES = {}


# Password validation
# https://docs.djangoproject.com/en/2.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = []


# Internationalization
# https://docs.djangoproject.com/en/2.2/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.2/howto/static-files/

STATIC_URL = "/static/"


# Application settings

# Authlib settings

OAUTH_CLIENT_ID = ""
OAUTH_CLIENT_SECRET = ""
OAUTH_TOKEN_URL = ""
OAUTH_TOKEN_INTROSPECT_URL = ""

OIDC_BACKEND_CLIENT_NAME = "mybackend"
AUTHLIB_OAUTH_CLIENTS = {
    OIDC_BACKEND_CLIENT_NAME: {
        "client_id": OAUTH_CLIENT_ID,
        "client_secret": OAUTH_CLIENT_SECRET,
        "authorize_url": "",
        "userinfo_endpoint": "",
        "server_metadata_url": "",
        "client_kwargs": {"scope": "openid profile email"}
    }
}

# Athorization settings

def exempt_all(request):
    return True

AUTHORIZATION_EXEMPT_FILTER = exempt_all
AUTHORIZATION_SERVICE_URL = ""
