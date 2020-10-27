import base64
import uuid

import pytest

from esteid.tests.conftest import *  # noqa: F401, F403  -- force pytest to use fixtures from that file

from ...constants import HASH_SHA512
from ...util import generate_hash
from ..base import SmartIDService
from ..constants import CERTIFICATE_LEVEL_QUALIFIED, END_RESULT_OK, STATE_COMPLETE
from ..i18n import TranslatedSmartIDService
from ..types import AuthenticateResult
from ..utils import get_verification_code


@pytest.fixture
def demo_api():
    return SmartIDService(uuid.UUID("00000000-0000-0000-0000-000000000000"), "DEMO")


@pytest.fixture
def i18n_demo_api():
    return TranslatedSmartIDService(uuid.UUID("00000000-0000-0000-0000-000000000000"), "DEMO")


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
        "state": STATE_COMPLETE,
        "result": {
            "endResult": END_RESULT_OK,
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
