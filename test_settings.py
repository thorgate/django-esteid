import os


# ****** Esteid service settings ******
# Refer to esteid.settings for a comprehensive list of settings.

ESTEID_DEMO = True
ID_CARD_ENABLED = True
MOBILE_ID_ENABLED = True
SMART_ID_ENABLED = True

# ***** End of Esteid service settings ******

DEBUG = True

SECRET_KEY = "q^es5sedujo$g@%-d4tl9ws@z+#m1mab&sdr_5)r&a80_+kd@+"

ALLOWED_HOSTS = ["*"]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": "db.sqlite",
    }
}

ROOT_URLCONF = "esteid.urls"

# Django pre-1.10 setting was MIDDLEWARE_CLASSES
MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
]

INSTALLED_APPS = [
    "django.contrib.sessions",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "rest_framework",
    "esteid",
]

if "TOX_TESTS" not in os.environ:
    INSTALLED_APPS += [
        "sslserver",
    ]

USE_TZ = True
USE_I18N = True
USE_L10N = True
TZ = "UTC"
STATIC_URL = "/static/"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.i18n",
                "django.template.context_processors.tz",
                "django.contrib.messages.context_processors.messages",
                "django.template.context_processors.request",
                "esteid.context_processors.esteid_services",
            ],
            "loaders": [
                "django.template.loaders.app_directories.Loader",
            ],
        },
    },
]

LOGGING = {
    "version": 1,
    "formatters": {"verbose": {"format": "%(asctime)s [%(levelname)s] %(name)s:%(lineno)d %(funcName)s - %(message)s"}},
    "handlers": {
        "console": {
            "level": "DEBUG",
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "loggers": {
        "": {
            "handlers": ["console"],
            "level": "DEBUG",
        },
        "esteid": {"handlers": [], "propagate": True},
        "django": {"handlers": [], "propagate": True},
        "django.request": {"handlers": [], "propagate": True},
        "django.security": {"handlers": [], "propagate": True},
    },
}
