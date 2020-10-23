import hashlib
from time import sleep, time
from unittest.mock import patch

import pytest

import requests_mock
from django.utils.functional import Promise
from requests import Response
from requests.exceptions import ConnectionError, ConnectTimeout, HTTPError

import pyasice

from ...constants import HASH_ALGORITHMS, HASH_SHA256, HASH_SHA384, HASH_SHA512
from ...exceptions import (
    ActionFailed,
    ActionNotCompleted,
    InvalidCredentials,
    OfflineError,
    SessionDoesNotExist,
    SignatureVerificationError,
)
from ...util import generate_hash
from .. import MobileIDError
from ..base import MobileIDService
from ..constants import EndResults, STATE_COMPLETE, STATE_RUNNING
from ..i18n import TranslatedMobileIDService
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
        except ActionNotCompleted:
            sleep(1.0)

    assert isinstance(status_res, AuthenticateStatusResult)
    return status_res


def raise_http_error(status_code):
    def _raise_http_error(*args, **kwargs):
        response = Response()
        response.status_code = status_code

        raise HTTPError(response=response)

    return _raise_http_error


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
                res = demo_mid_api.authenticate(MID_DEMO_PHONE_EE_OK, MID_DEMO_PIN_EE_OK, hash_type=hash_type)

                mock.assert_called_with(hash_type, raw_data)

                assert isinstance(res, AuthenticateResult)
                assert res.session_id == "FAKE"
                assert res.hash_type == hash_type
                assert res.digest == generate_hash(hash_type, raw_data)
                assert res.verification_code == verification_codes[hash_type]


def test_mobileid_authentication_400(demo_mid_api, MID_DEMO_PHONE_EE_OK, MID_DEMO_PIN_EE_OK):
    with patch.object(demo_mid_api, "invoke", side_effect=raise_http_error(400)):
        with pytest.raises(HTTPError):
            demo_mid_api.authenticate(MID_DEMO_PHONE_EE_OK, MID_DEMO_PIN_EE_OK)


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
        "state": STATE_RUNNING,
    }

    with patch.object(demo_mid_api, "invoke", return_value=response_data):
        with pytest.raises(ActionNotCompleted) as exc_info:
            demo_mid_api.status(session_id="FAKE", digest=b"")

        # session_id should be in the message
        assert "FAKE" in str(exc_info.value)


def test_mobileid_status_unexpected_state(demo_mid_api):
    response_data = {
        "state": "FOO",
    }

    with patch.object(demo_mid_api, "invoke", return_value=response_data):
        with pytest.raises(MobileIDError) as exc_info:
            demo_mid_api.status(session_id="FAKE", digest=b"")

        assert "Unexpected state" in str(exc_info.value)


@pytest.mark.parametrize(
    "end_result_code",
    [
        EndResults.TIMEOUT,
        EndResults.USER_CANCELLED,
        EndResults.NOT_MID_CLIENT,
    ],
)
def test_mobileid_status_end_result(demo_mid_api, end_result_code):
    response_data = {
        "state": STATE_COMPLETE,
        "result": end_result_code,
    }

    with patch.object(demo_mid_api, "invoke", return_value=response_data):
        with pytest.raises(ActionFailed) as exc_info:
            demo_mid_api.status(session_id="FAKE", digest=b"")

        assert exc_info.value.result_code == end_result_code


def test_mobileid_status_unexpected_end_result(demo_mid_api):
    response_data = {
        "state": STATE_COMPLETE,
        "result": "$RESULT$",
    }

    with patch.object(demo_mid_api, "invoke", return_value=response_data):
        with pytest.raises(MobileIDError) as exc_info:
            demo_mid_api.status(session_id="FAKE", digest=b"")

        assert "$RESULT$" in str(exc_info.value)


def test_mobileid_status_400(demo_mid_api):
    with patch.object(demo_mid_api, "invoke", new=raise_http_error(400)):
        with pytest.raises(HTTPError):
            demo_mid_api.status(session_id="FAKE", digest=b"")


def test_mobileid_status_404(demo_mid_api):
    with patch.object(demo_mid_api, "invoke", new=raise_http_error(404)):
        with pytest.raises(SessionDoesNotExist):
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


@pytest.mark.parametrize("exc", [ConnectionError, ConnectTimeout])
def test_mobileid_invoke_timeout(demo_mid_api, exc):
    with requests_mock.mock() as m:
        m.get(demo_mid_api.api_url(""), exc=exc)

        with pytest.raises(OfflineError) as exc_info:
            demo_mid_api.invoke("")

        assert "timed out" in str(exc_info.value)


@pytest.mark.parametrize(
    "status_code,exc,needle",
    [
        (401, InvalidCredentials, "rp_uuid and verify the ip"),
        (580, OfflineError, "maintenance"),
        (502, OfflineError, "Proxy error"),
        (503, OfflineError, "Proxy error"),
        (504, OfflineError, "Proxy error"),
        (400, MobileIDError, "Bad Request."),
        (500, HTTPError, "status_code: 500"),
    ],
)
def test_mobileid_invoke_errors(demo_mid_api, status_code, exc, needle):
    with requests_mock.mock() as m:
        m.get(demo_mid_api.api_url(""), status_code=status_code)

        with pytest.raises(exc) as exc_info:
            demo_mid_api.invoke("")

    assert needle in str(exc_info.value)


def test_mobileid_i18n_version(i18n_demo_mid_api):
    assert tuple(MobileIDService.MESSAGES) == tuple(TranslatedMobileIDService.MESSAGES)
    assert tuple(MobileIDService.END_RESULT_MESSAGES) == tuple(
        TranslatedMobileIDService.END_RESULT_MESSAGES
    )  # noqa: E127

    for key, message in TranslatedMobileIDService.MESSAGES.items():
        assert isinstance(message, Promise)

        assert message == i18n_demo_mid_api.msg(key)

    for key, message in TranslatedMobileIDService.END_RESULT_MESSAGES.items():
        assert isinstance(message, Promise)

        assert message == i18n_demo_mid_api.end_result_msg(key)
