from unittest.mock import patch

from django.test import override_settings

from esteid import context_processors


def test_context_processors_esteid_services():
    with patch.object(context_processors, "settings", None):
        assert context_processors.esteid_services()["ESTEID_DEMO"]

    test_settings = {
        "ESTEID_DEMO": 1,
        "ID_CARD_ENABLED": 2,
        "MOBILE_ID_ENABLED": 3,
        "MOBILE_ID_TEST_MODE": 4,
        "SMART_ID_ENABLED": 5,
        "SMART_ID_TEST_MODE": 6,
    }
    with override_settings(**test_settings):
        assert context_processors.esteid_services() == test_settings
