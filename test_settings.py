DEBUG = True

SECRET_KEY = 'q^es5sedujo$g@%-d4tl9ws@z+#m1mab&sdr_5)r&a80_+kd@+'

ALLOWED_HOSTS = ['*']

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'db.sqlite',
    }
}

ROOT_URLCONF = 'esteid.urls'

# Django pre-1.10 setting was MIDDLEWARE_CLASSES
MIDDLEWARE = [
    'django.contrib.sessions.middleware.SessionMiddleware',
]

INSTALLED_APPS = [
    'django.contrib.sessions',
    'esteid',
    "sslserver",
]

USE_TZ = True
TZ = "UTC"
STATIC_URL = '/static/'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.i18n',
                'django.template.context_processors.tz',
                'django.contrib.messages.context_processors.messages',
                'django.template.context_processors.request',
            ],
            'loaders': [
                'django.template.loaders.app_directories.Loader',
            ],
        },
    },
]


LOGGING = {
    'version': 1,
    'formatters': {
        'verbose': {
            'format': '%(name)s: %(message)s'
        }
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        '': {
            'handlers': ['console'],
            'level': 'DEBUG',
        },
        'django': {'handlers': [], 'propagate': True},
        'django.request': {'handlers': [], 'propagate': True},
        'django.security': {'handlers': [], 'propagate': True},
    }
}

MOBILE_ID_SERVICE_NAME = 'DEMO'
MOBILE_ID_SERVICE_UUID = '00000000-0000-0000-0000-000000000000'
MOBILE_ID_TEST_MODE = True
