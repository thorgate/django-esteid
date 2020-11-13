"""
This module contains all configuration settings for django-esteid.
"""
from django.conf import settings

from esteid import constants
from esteid.constants import Countries


# Whether to use demo OCSP and TSA services.
ESTEID_DEMO = getattr(settings, "ESTEID_DEMO", True)

# Whether to use the ID card signing method
ID_CARD_ENABLED = getattr(settings, "ID_CARD_ENABLED", False)

# *** Mobile ID ***

MOBILE_ID_ENABLED = getattr(settings, "MOBILE_ID_ENABLED", False)
# Whether to use demo services and credentials for Mobile ID
# NOTE: Test mode ON by default. To prevent accidental billing
MOBILE_ID_TEST_MODE = getattr(settings, "MOBILE_ID_TEST_MODE", True)
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

# *** Smart ID ***

SMART_ID_ENABLED = getattr(settings, "SMART_ID_ENABLED", False)
# Whether to use demo services and credentials for Smart ID
# NOTE: Test mode ON by default. To prevent accidental billing
SMART_ID_TEST_MODE = getattr(settings, "SMART_ID_TEST_MODE", True)
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

# Whether to generate an LT-TS profile ASiC-E container (involves a TimeStamping confirmation)
ESTEID_USE_LT_TS = getattr(settings, "ESTEID_USE_LT_TS", True)

# URLs for OCSP and TSA services
OCSP_URL = getattr(settings, "ESTEID_OCSP_URL", constants.OCSP_DEMO_URL if ESTEID_DEMO else constants.OCSP_LIVE_URL)
TSA_URL = getattr(settings, "ESTEID_TSA_URL", constants.TSA_DEMO_URL if ESTEID_DEMO else constants.TSA_LIVE_URL)

# Used exclusively by esteid.middleware.BaseIdCardMiddleware
ESTEID_OCSP_RESPONDER_CERTIFICATE_PATH = getattr(settings, "ESTEID_OCSP_RESPONDER_CERTIFICATE_PATH", None)

# Whether one signatory can sign the same container more than once
ESTEID_ALLOW_ONE_PARTY_SIGN_TWICE = getattr(settings, "ESTEID_ALLOW_ONE_PARTY_SIGN_TWICE", True)
