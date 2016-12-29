import sys
import django
from django.conf import settings

settings.configure(
    DEBUG=True,
    DATABASES={
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
        }
    },
    ROOT_URLCONF='esteid.urls',
    MIDDLEWARE_CLASSES=[],
    INSTALLED_APPS=(
        'django.contrib.auth',
        'django.contrib.contenttypes',
        'django.contrib.sessions',
        'django.contrib.admin',
        'esteid',
    )
)

if django.VERSION >= (1, 7):
    django.setup()

if django.VERSION < (1, 6):
    from django.test.simple import DjangoTestSuiteRunner
    test_runner = DjangoTestSuiteRunner(verbosity=1)

else:
    from django.test.runner import DiscoverRunner
    test_runner = DiscoverRunner(verbosity=1)

failures = test_runner.run_tests(['esteid', ])

if failures:
    sys.exit(failures)
