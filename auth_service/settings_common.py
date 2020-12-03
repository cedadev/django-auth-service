# -*- coding: utf-8 -*-

""" Common settings for the site. """

__author__ = "William Tucker"
__date__ = "2020-02-05"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


# Application definition

import os


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INSTALLED_APPS = [
    'django.contrib.sessions',
    'authenticate',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'authenticate.oauth2.middleware.BearerTokenAuthenticationMiddleware',
    'authenticate.oidc.middleware.OpenIDConnectAuthenticationMiddleware',
    'authorize.middleware.LoginAuthorizationMiddleware',
]

SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'

ROOT_URLCONF = 'auth_service.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'auth_service.wsgi.application'
