from django.conf import settings


def esteid_services(*_, **__):
    return {
        "ESTEID_DEMO": getattr(settings, "ESTEID_DEMO", True),
        "ID_CARD_ENABLED": getattr(settings, "ID_CARD_ENABLED", False),
        "MOBILE_ID_ENABLED": getattr(settings, "MOBILE_ID_ENABLED", False),
        "MOBILE_ID_TEST_MODE": getattr(settings, "MOBILE_ID_TEST_MODE", True),
        "SMART_ID_ENABLED": getattr(settings, "SMART_ID_ENABLED", False),
        "SMART_ID_TEST_MODE": getattr(settings, "SMART_ID_TEST_MODE", True),
    }
