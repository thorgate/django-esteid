import hashlib
from time import sleep, time
from unittest.mock import patch

import pytest

import requests_mock

import pyasice

from ...constants import HASH_ALGORITHMS, HASH_SHA256, HASH_SHA384, HASH_SHA512
from ...exceptions import (
    ActionInProgress,
    BadRequest,
    CanceledByUser,
    SessionDoesNotExist,
    SignatureVerificationError,
    UserNotRegistered,
    UserTimeout,
)
from ...util import generate_hash
from .. import MobileIDError
from ..base import MobileIDService
from ..constants import EndResults
from ..types import AuthenticateResult, AuthenticateStatusResult


def run_authentication_flow(demo_mid_api, id_number, phone_number, hash_type=HASH_SHA256):
    """Run full authentication flow w/ a hash algorithm

    test data from:
    https://github.com/SK-EID/MID/wiki/Test-number-for-automated-testing-in-DEMO

    :param MobileIDService demo_mid_api:
    :param str id_number:
    :param str phone_number:
    :param str hash_type:
    :rtype: AuthenticateStatusResult
    """
    res = demo_mid_api.authenticate(id_code=id_number, phone_number=phone_number, hash_type=hash_type)
    assert isinstance(
        res, AuthenticateResult
    ), "Expected `.authenticate()` to return AuthenticateResult, got {}".format(res)

    # All fields must be set
    assert res.session_id
    assert res.hash_type == hash_type
    assert res.digest

    status_res = None  # type: AuthenticateStatusResult

    # Pull status (using a loop here since the remote might be slow)
    # We timeout in 15s compared to Smart ID ~5m.
    # There is really no reason that it should take longer IF it is working
    end_time = time() + 15
    while status_res is None and time() < end_time:
        try:
            status_res = demo_mid_api.status(res.session_id, res.digest)
        except ActionInProgress:
            sleep(1.0)

    assert isinstance(status_res, AuthenticateStatusResult)
    return status_res


@pytest.mark.parametrize("hash_type", HASH_ALGORITHMS)
def test_mobileid_authentication(demo_mid_api, hash_type, MID_DEMO_PIN_EE_OK, MID_DEMO_PHONE_EE_OK):
    raw_data = b"Hello World!"
    response_data = {"sessionID": "FAKE"}
    verification_codes = {
        HASH_SHA256: "4073",
        HASH_SHA384: "6090",
        HASH_SHA512: "4296",
    }

    known_hashes = {
        HASH_SHA256: hashlib.sha256(raw_data).digest(),
        HASH_SHA384: hashlib.sha384(raw_data).digest(),
        HASH_SHA512: hashlib.sha512(raw_data).digest(),
    }

    with patch("esteid.mobileid.base.secure_random", return_value=raw_data):
        with patch("esteid.mobileid.base.generate_hash", return_value=known_hashes[hash_type]) as mock:
            with patch.object(demo_mid_api, "invoke", return_value=response_data):
                res = demo_mid_api.authenticate(MID_DEMO_PIN_EE_OK, MID_DEMO_PHONE_EE_OK, hash_type=hash_type)

                mock.assert_called_with(hash_type, raw_data)

                assert isinstance(res, AuthenticateResult)
                assert res.session_id == "FAKE"
                assert res.hash_type == hash_type
                assert res.digest == generate_hash(hash_type, raw_data)
                assert res.verification_code == verification_codes[hash_type]


def test_mobileid_authentication_400(demo_mid_api, MID_DEMO_PHONE_EE_OK, MID_DEMO_PIN_EE_OK):
    with requests_mock.mock() as m:
        m.post(demo_mid_api.api_url(demo_mid_api.Actions.AUTH), status_code=400)
        with pytest.raises(BadRequest):
            demo_mid_api.authenticate(MID_DEMO_PIN_EE_OK, MID_DEMO_PHONE_EE_OK)


def test_mobileid_status(demo_mid_api, static_certificate, mid_auth_result, mid_auth_status_response):
    with patch.object(demo_mid_api, "invoke", return_value=mid_auth_status_response):
        res = demo_mid_api.status(mid_auth_result.session_id, mid_auth_result.digest)

        assert isinstance(res, AuthenticateStatusResult)

        assert res.certificate == static_certificate


def test_mobileid_status_signature_verification_error(demo_mid_api, mid_auth_status_response, mid_auth_result):
    with patch.object(demo_mid_api, "invoke", return_value=mid_auth_status_response):
        with patch.object(pyasice, "verify") as mock_verify:
            mock_verify.side_effect = pyasice.SignatureVerificationError
            with pytest.raises(SignatureVerificationError):
                demo_mid_api.status(mid_auth_result.session_id, mid_auth_result.digest)


def test_mobileid_status_state_running(demo_mid_api):
    response_data = {
        "state": MobileIDService.ProcessingStates.RUNNING,
    }

    with patch.object(demo_mid_api, "invoke", return_value=response_data):
        with pytest.raises(ActionInProgress) as exc_info:
            demo_mid_api.status(session_id="FAKE", digest=b"")

        # session_id should be in the message
        assert "FAKE" in str(exc_info.value)


@pytest.mark.parametrize(
    "end_result_code,exc",
    [
        (EndResults.TIMEOUT, UserTimeout),
        (EndResults.USER_CANCELLED, CanceledByUser),
        (EndResults.NOT_MID_CLIENT, UserNotRegistered),
        ("$unknown$", MobileIDError),
    ],
)
def test_mobileid_status_end_result(demo_mid_api, end_result_code, exc):
    response_data = {
        "state": MobileIDService.ProcessingStates.COMPLETE,
        "result": end_result_code,
    }

    with patch.object(demo_mid_api, "invoke", return_value=response_data):
        with pytest.raises(exc):
            demo_mid_api.status(session_id="FAKE", digest=b"")


def test_mobileid_status_unexpected_end_result(demo_mid_api):
    response_data = {
        "state": MobileIDService.ProcessingStates.COMPLETE,
        "result": "$RESULT$",
    }

    with patch.object(demo_mid_api, "invoke", return_value=response_data):
        with pytest.raises(MobileIDError) as exc_info:
            demo_mid_api.status(session_id="FAKE", digest=b"")

        assert "$RESULT$" in str(exc_info.value)


@pytest.mark.parametrize(
    "status,exc",
    [
        pytest.param(400, BadRequest),
        pytest.param(404, SessionDoesNotExist),
    ],
)
def test_mobileid_status_errors(demo_mid_api, status, exc):
    session_status_url = demo_mid_api.Actions.SESSION_STATUS.format(action=demo_mid_api.Actions.AUTH, session_id="FAKE")
    with requests_mock.mock() as m:
        m.get(demo_mid_api.api_url(session_status_url), exc=exc)
        with pytest.raises(exc):
            demo_mid_api.status(session_id="FAKE", digest=b"")


@pytest.mark.slow
@pytest.mark.parametrize("hash_type", [*HASH_ALGORITHMS, None])
def test_mobileid_authentication_flow_ee(demo_mid_api, hash_type, MID_DEMO_PIN_EE_OK, MID_DEMO_PHONE_EE_OK):
    """Test full authentication flow for EE

    Note: This does a real connection to Mobile-ID api so it's marked as a slow test
    """
    kwargs = {} if hash_type is None else dict(hash_type=hash_type)
    status_res = run_authentication_flow(
        demo_mid_api, id_number=MID_DEMO_PIN_EE_OK, phone_number=MID_DEMO_PHONE_EE_OK, **kwargs
    )

    assert status_res.certificate
