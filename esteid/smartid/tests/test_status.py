from unittest.mock import patch

import pytest

import requests_mock

import pyasice

from esteid.exceptions import (
    ActionInProgress,
    BadRequest,
    CanceledByUser,
    EsteidError,
    SessionDoesNotExist,
    SignatureVerificationError,
    UpstreamServiceError,
    UserTimeout,
)
from esteid.smartid.base import SmartIDService
from esteid.smartid.constants import CERTIFICATE_LEVEL_QUALIFIED, EndResults
from esteid.smartid.types import AuthenticateStatusResult


def test_status(demo_api, static_certificate, static_auth_result, static_status_response):
    with patch.object(demo_api, "invoke", return_value=static_status_response):
        res = demo_api.status(static_auth_result.session_id, static_auth_result.hash_value)

        assert isinstance(res, AuthenticateStatusResult)

        assert res.document_number == "$documentNumber$"
        assert res.certificate == static_certificate
        assert res.certificate_level == CERTIFICATE_LEVEL_QUALIFIED


def test_status_signature_verification(demo_api, static_auth_result, static_status_response):
    with patch.object(demo_api, "invoke", return_value=static_status_response):
        with patch.object(pyasice, "verify", side_effect=pyasice.SignatureVerificationError):
            with pytest.raises(SignatureVerificationError):
                demo_api.status(static_auth_result.session_id, static_auth_result.hash_value)


def test_status_state_running(demo_api):
    response_data = {
        "state": SmartIDService.ProcessingStates.RUNNING,
    }

    with patch.object(demo_api, "invoke", return_value=response_data):
        with pytest.raises(ActionInProgress) as exc_info:
            demo_api.status(session_id="FAKE", hash_value=b"")

        # session_id should be in the message
        assert "FAKE" in str(exc_info.value)


@pytest.mark.parametrize(
    "end_result_code,exc",
    [
        (EndResults.USER_REFUSED, CanceledByUser),
        (EndResults.TIMEOUT, UserTimeout),
        (EndResults.DOCUMENT_UNUSABLE, UpstreamServiceError),
        ("$unknown$", EsteidError),
    ],
)
def test_status_end_result(demo_api, end_result_code, exc):
    response_data = {
        "state": SmartIDService.ProcessingStates.COMPLETE,
        "result": {
            "endResult": end_result_code,
        },
    }

    with patch.object(demo_api, "invoke", return_value=response_data):
        with pytest.raises(exc):
            demo_api.status(session_id="FAKE", hash_value=b"")


def test_status_unexpected_end_result(demo_api):
    response_data = {
        "state": SmartIDService.ProcessingStates.COMPLETE,
        "result": {
            "endResult": "$RESULT$",
        },
    }

    with patch.object(demo_api, "invoke", return_value=response_data):
        with pytest.raises(EsteidError) as exc_info:
            demo_api.status(session_id="FAKE", hash_value=b"")

        assert "$RESULT$" in str(exc_info.value)


@pytest.mark.parametrize(
    "status,exc",
    [
        pytest.param(400, BadRequest),
        pytest.param(404, SessionDoesNotExist),
    ],
)
def test_status_400(demo_api, status, exc):
    with requests_mock.mock() as m:
        m.get(demo_api.api_url(demo_api.Actions.SESSION_STATUS.format(session_id="FAKE")), status_code=status)

        with pytest.raises(exc):
            demo_api.status(session_id="FAKE", hash_value=b"")
