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
