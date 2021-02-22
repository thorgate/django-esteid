"""
This module contains all configuration settings for django-esteid.
"""
import re

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from esteid import constants
from esteid.constants import Countries, Languages


# Demo mode: whether to use demo services by default, including OCSP and TSA.
ESTEID_DEMO = getattr(settings, "ESTEID_DEMO", True)

# *** ID Card ***

# Whether to use the ID card signing method
ID_CARD_ENABLED = getattr(settings, "ID_CARD_ENABLED", False)

# For ID card authentication, this refers to the URLs which are allowed to open the auth iframe. '*' means any.
ID_CARD_FRAME_TARGET_ORIGIN = getattr(settings, "ID_CARD_FRAME_TARGET_ORIGIN", "*")

# *** Mobile ID ***

MOBILE_ID_ENABLED = getattr(settings, "MOBILE_ID_ENABLED", False)
# Whether to use demo services and credentials for Mobile ID. Default to global demo mode
MOBILE_ID_TEST_MODE = getattr(settings, "MOBILE_ID_TEST_MODE", ESTEID_DEMO)
# MobileID Relying party name and UUID, for DEMO they are always the same so no need to explicitly set them
MOBILE_ID_SERVICE_NAME = getattr(settings, "MOBILE_ID_SERVICE_NAME", None)
MOBILE_ID_SERVICE_UUID = getattr(settings, "MOBILE_ID_SERVICE_UUID", None)
MOBILE_ID_API_ROOT = getattr(settings, "MOBILE_ID_API_ROOT", None)

# Mobile phone number sanity check: optional, a regexp pattern. If not set or None, defaults to a simple regexp.
# To disable checks, set it to empty string.
_MOBILE_ID_PHONE_NUMBER_REGEXP = getattr(settings, "MOBILE_ID_PHONE_NUMBER_REGEXP", None)
if _MOBILE_ID_PHONE_NUMBER_REGEXP is None:
    # Mobile ID supports Estonian and Lithuanian phones
    _MOBILE_ID_PHONE_NUMBER_REGEXP = re.compile(r"^\+37[02]\d{7,8}$")
elif _MOBILE_ID_PHONE_NUMBER_REGEXP:
    try:
        _MOBILE_ID_PHONE_NUMBER_REGEXP = re.compile(_MOBILE_ID_PHONE_NUMBER_REGEXP)
    except ValueError as e:
        raise ImproperlyConfigured("MOBILE_ID_PHONE_NUMBER_REGEXP must be a valid regular expression") from e

MOBILE_ID_PHONE_NUMBER_REGEXP = _MOBILE_ID_PHONE_NUMBER_REGEXP

_MOBILE_ID_DEFAULT_LANGUAGE = getattr(settings, "MOBILE_ID_DEFAULT_LANGUAGE", None)

if _MOBILE_ID_DEFAULT_LANGUAGE is None:
    try:
        _MOBILE_ID_DEFAULT_LANGUAGE = Languages.identify_language(settings.LANGUAGE_CODE)
    except (AttributeError, ImproperlyConfigured):
        _MOBILE_ID_DEFAULT_LANGUAGE = Languages.ENG

# Raises an ImproperlyConfigured error if a wrong language code was attempted
MOBILE_ID_DEFAULT_LANGUAGE = Languages.identify_language(_MOBILE_ID_DEFAULT_LANGUAGE)

if MOBILE_ID_TEST_MODE:
    if not MOBILE_ID_SERVICE_NAME:
        MOBILE_ID_SERVICE_NAME = constants.MOBILE_ID_DEMO_SERVICE_NAME
    if not MOBILE_ID_SERVICE_UUID:
        MOBILE_ID_SERVICE_UUID = constants.MOBILE_ID_DEMO_SERVICE_UUID
    if not MOBILE_ID_API_ROOT:
        MOBILE_ID_API_ROOT = constants.MOBILE_ID_DEMO_URL
else:
    if not MOBILE_ID_API_ROOT:
        MOBILE_ID_API_ROOT = constants.MOBILE_ID_LIVE_URL


# *** Smart ID ***

SMART_ID_ENABLED = getattr(settings, "SMART_ID_ENABLED", False)
# Whether to use demo services and credentials for Smart ID. Default to global demo mode
SMART_ID_TEST_MODE = getattr(settings, "SMART_ID_TEST_MODE", ESTEID_DEMO)
# SmartID Relying party name and UUID, for DEMO they are always the same so no need to explicitly set them
SMART_ID_SERVICE_NAME = getattr(settings, "SMART_ID_SERVICE_NAME", None)
SMART_ID_SERVICE_UUID = getattr(settings, "SMART_ID_SERVICE_UUID", None)

SMART_ID_API_ROOT = getattr(settings, "SMART_ID_API_ROOT", None)

if SMART_ID_TEST_MODE:
    if not SMART_ID_SERVICE_NAME:
        SMART_ID_SERVICE_NAME = constants.SMART_ID_DEMO_SERVICE_NAME
    if not SMART_ID_SERVICE_UUID:
        SMART_ID_SERVICE_UUID = constants.SMART_ID_DEMO_SERVICE_UUID
    if not SMART_ID_API_ROOT:
        SMART_ID_API_ROOT = constants.SMART_ID_DEMO_URL
else:
    if not SMART_ID_API_ROOT:
        SMART_ID_API_ROOT = constants.SMART_ID_LIVE_URL


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
