from esteid import context_processors
from esteid.tests.conftest import override_esteid_settings


def test_context_processors_esteid_services():
    test_settings = {
        "ESTEID_DEMO": 1,
        "ID_CARD_ENABLED": 2,
        "MOBILE_ID_ENABLED": 3,
        "MOBILE_ID_TEST_MODE": 4,
        "SMART_ID_ENABLED": 5,
        "SMART_ID_TEST_MODE": 6,
    }

    assert tuple(context_processors.esteid_services().keys()) == tuple(test_settings.keys())

    with override_esteid_settings(**test_settings):
        assert context_processors.esteid_services() == test_settings
