"""
This module contains all configuration settings for django-esteid.
"""
from django.conf import settings

from esteid import constants
from esteid.constants import Countries, Languages


# Demo mode: whether to use demo services by default, including OCSP and TSA.
ESTEID_DEMO = getattr(settings, "ESTEID_DEMO", True)

# *** ID Card ***

# Whether to use the ID card signing method
ID_CARD_ENABLED = getattr(settings, "ID_CARD_ENABLED", False)

# *** Mobile ID ***

MOBILE_ID_ENABLED = getattr(settings, "MOBILE_ID_ENABLED", False)
# Whether to use demo services and credentials for Mobile ID. Default to global demo mode
MOBILE_ID_TEST_MODE = getattr(settings, "MOBILE_ID_TEST_MODE", ESTEID_DEMO)
# MobileID Relying party name and UUID, for DEMO they are always the same so no need to explicitly set them
MOBILE_ID_SERVICE_NAME = getattr(
    settings, "MOBILE_ID_SERVICE_NAME", None if not MOBILE_ID_TEST_MODE else constants.MOBILE_ID_DEMO_SERVICE_NAME
)
MOBILE_ID_SERVICE_UUID = getattr(
    settings, "MOBILE_ID_SERVICE_UUID", None if not MOBILE_ID_TEST_MODE else constants.MOBILE_ID_DEMO_SERVICE_UUID
)
MOBILE_ID_API_ROOT = getattr(
    settings,
    "MOBILE_ID_API_ROOT",
    constants.MOBILE_ID_DEMO_URL if MOBILE_ID_TEST_MODE else constants.MOBILE_ID_LIVE_URL,
)
MOBILE_ID_DEFAULT_LANGUAGE = getattr(settings, "MOBILE_ID_DEFAULT_LANGUAGE", Languages.ENG)

# Raises an ImproperlyConfigured error if a wrong language code was attempted
MOBILE_ID_DEFAULT_LANGUAGE = Languages.identify_language(MOBILE_ID_DEFAULT_LANGUAGE)

# *** Smart ID ***

SMART_ID_ENABLED = getattr(settings, "SMART_ID_ENABLED", False)
# Whether to use demo services and credentials for Smart ID. Default to global demo mode
SMART_ID_TEST_MODE = getattr(settings, "SMART_ID_TEST_MODE", ESTEID_DEMO)
# SmartID Relying party name and UUID, for DEMO they are always the same so no need to explicitly set them
SMART_ID_SERVICE_NAME = getattr(
    settings, "SMART_ID_SERVICE_NAME", None if not SMART_ID_TEST_MODE else constants.SMART_ID_DEMO_SERVICE_NAME
)
SMART_ID_SERVICE_UUID = getattr(
    settings, "SMART_ID_SERVICE_UUID", None if not SMART_ID_TEST_MODE else constants.SMART_ID_DEMO_SERVICE_UUID
)
SMART_ID_API_ROOT = getattr(
    settings, "SMART_ID_API_ROOT", constants.SMART_ID_DEMO_URL if SMART_ID_TEST_MODE else constants.SMART_ID_LIVE_URL
)

# The default country (mostly for SmartID)
ESTEID_COUNTRY = getattr(settings, "ESTEID_COUNTRY", Countries.ESTONIA)

# *** Signature validity services: OCSP, TSA ***

# Whether to generate an LT-TS profile ASiC-E container (involves a TimeStamping confirmation)
ESTEID_USE_LT_TS = getattr(settings, "ESTEID_USE_LT_TS", True)

# URLs for OCSP and TSA services
OCSP_URL = getattr(settings, "ESTEID_OCSP_URL", constants.OCSP_DEMO_URL if ESTEID_DEMO else constants.OCSP_LIVE_URL)
TSA_URL = getattr(settings, "ESTEID_TSA_URL", constants.TSA_DEMO_URL if ESTEID_DEMO else constants.TSA_LIVE_URL)

# Used exclusively by esteid.middleware.BaseIdCardMiddleware
ESTEID_OCSP_RESPONDER_CERTIFICATE_PATH = getattr(settings, "ESTEID_OCSP_RESPONDER_CERTIFICATE_PATH", None)

# *** Misc settings ***

# Whether one signatory can sign the same container more than once. Default to allow for demo, disallow for live
ESTEID_ALLOW_ONE_PARTY_SIGN_TWICE = getattr(settings, "ESTEID_ALLOW_ONE_PARTY_SIGN_TWICE", ESTEID_DEMO)
