import importlib

from django.test import override_settings

import esteid.settings


def test_importlib():
    with override_settings(MOBILE_ID_TEST_MODE=False):
        importlib.reload(esteid.settings)
        assert esteid.settings.MOBILE_ID_TEST_MODE is False
