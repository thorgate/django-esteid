import base64

import pytest

from ...constants import HASH_SHA512, SMART_ID_DEMO_SERVICE_NAME, SMART_ID_DEMO_SERVICE_UUID, SMART_ID_DEMO_URL
from ...util import generate_hash
from ..base import SmartIDService
from ..constants import CERTIFICATE_LEVEL_QUALIFIED, EndResults
from ..i18n import TranslatedSmartIDService
from ..types import AuthenticateResult
from ..utils import get_verification_code


@pytest.fixture
def demo_api():
    return SmartIDService(SMART_ID_DEMO_SERVICE_UUID, SMART_ID_DEMO_SERVICE_NAME, SMART_ID_DEMO_URL)


@pytest.fixture
def i18n_demo_api():
    return TranslatedSmartIDService(SMART_ID_DEMO_SERVICE_UUID, SMART_ID_DEMO_SERVICE_NAME, SMART_ID_DEMO_URL)


@pytest.fixture
def SMARTID_DEMO_ID_CODE_EE():
    return "10101010005"


@pytest.fixture
def SMARTID_DEMO_ID_CODE_LT():
    return "10101010005"


@pytest.fixture
def SMARTID_DEMO_ID_CODE_LV():
    return "010101-10006"


@pytest.fixture
def static_auth_result(static_random_text):
    return AuthenticateResult(
        session_id="FAKE",
        hash_value=generate_hash(HASH_SHA512, static_random_text),
        hash_type=HASH_SHA512,
        verification_code=get_verification_code(static_random_text),
    )


@pytest.fixture
def static_status_response(static_signature, static_signature_algorithm, static_certificate):
    return {
        "state": SmartIDService.ProcessingStates.COMPLETE,
        "result": {
            "endResult": EndResults.OK,
            "documentNumber": "$documentNumber$",
        },
        "signature": {
            "algorithm": static_signature_algorithm,
            "value": base64.b64encode(static_signature),
        },
        "cert": {
            "value": base64.b64encode(static_certificate),
            "certificateLevel": CERTIFICATE_LEVEL_QUALIFIED,
        },
    }
