from esteid import settings


def esteid_services(*_, **__):
    return {
        "ESTEID_DEMO": settings.ESTEID_DEMO,
        "ID_CARD_ENABLED": settings.ID_CARD_ENABLED,
        "MOBILE_ID_ENABLED": settings.MOBILE_ID_ENABLED,
        "MOBILE_ID_TEST_MODE": settings.MOBILE_ID_TEST_MODE,
        "SMART_ID_ENABLED": settings.SMART_ID_ENABLED,
        "SMART_ID_TEST_MODE": settings.SMART_ID_TEST_MODE,
    }
