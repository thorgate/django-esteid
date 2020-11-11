import base64
import hashlib

import pytest

from esteid.constants import HASH_SHA512, MOBILE_ID_DEMO_SERVICE_NAME, MOBILE_ID_DEMO_SERVICE_UUID, MOBILE_ID_DEMO_URL

from ..base import MobileIDService
from ..constants import EndResults
from ..i18n import TranslatedMobileIDService
from ..types import AuthenticateResult
from ..utils import get_verification_code


@pytest.fixture()
def demo_mid_api():
    return MobileIDService(MOBILE_ID_DEMO_SERVICE_UUID, MOBILE_ID_DEMO_SERVICE_NAME, MOBILE_ID_DEMO_URL)


@pytest.fixture()
def i18n_demo_mid_api():
    return TranslatedMobileIDService(MOBILE_ID_DEMO_SERVICE_UUID, MOBILE_ID_DEMO_SERVICE_NAME, MOBILE_ID_DEMO_URL)


@pytest.fixture()
def MID_DEMO_PHONE_EE_OK():
    return "+37200000766"


@pytest.fixture()
def MID_DEMO_PIN_EE_OK():
    return "60001019906"


@pytest.fixture()
def mid_auth_result(static_random_text):
    digest = hashlib.sha512(static_random_text).digest()
    return AuthenticateResult(
        session_id="FAKE",
        digest=digest,
        hash_type=HASH_SHA512,
        verification_code=get_verification_code(digest),
    )


@pytest.fixture()
def mid_auth_status_response(static_signature, static_signature_algorithm, static_certificate):
    return {
        "state": MobileIDService.ProcessingStates.COMPLETE,
        "result": EndResults.OK,
        "signature": {
            "algorithm": static_signature_algorithm,
            "value": base64.b64encode(static_signature),
        },
        "cert": base64.b64encode(static_certificate),
        "time": "2019-07-23T10:52:20",
    }


@pytest.fixture()
def mid_sign_status_response(static_signature, static_certificate, static_signature_algorithm):
    return {
        "state": MobileIDService.ProcessingStates.COMPLETE,
        "result": EndResults.OK,
        "signature": {
            "algorithm": static_signature_algorithm,
            "value": base64.b64encode(static_signature),
        },
        "time": "2019-07-23T10:52:20",
    }
