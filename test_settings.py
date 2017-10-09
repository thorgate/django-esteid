DEBUG = True

SECRET_KEY = 'q^es5sedujo$g@%-d4tl9ws@z+#m1mab&sdr_5)r&a80_+kd@+'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
    }
}

ROOT_URLCONF = 'esteid.urls'

MIDDLEWARE_CLASSES = []

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.admin',
    'esteid',
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
            'level': 'INFO',
        },
        'django': {'handlers': [], 'propagate': True},
        'django.request': {'handlers': [], 'propagate': True},
        'django.security': {'handlers': [], 'propagate': True},

        # Uncomment to enable zeep debug logging
        # 'zeep.transports': {
        #     'level': 'DEBUG',
        #     'propagate': True,
        #     'handlers': ['console'],
        # },
    }
}
