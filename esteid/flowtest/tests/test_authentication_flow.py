import base64
import json
from unittest.mock import patch
from urllib.parse import urlencode

import pytest

from django.contrib.sessions.backends import db
from django.test import Client
from django.urls import reverse

from esteid.authentication.types import AuthenticationResult
from esteid.flowtest.views import AuthTestView
from esteid.mobileid.i18n import TranslatedMobileIDService
from esteid.mobileid.types import AuthenticateResult as MobileIdAuthInitResult
from esteid.mobileid.types import AuthenticateStatusResult as MobileIdAuthStatusResult
from esteid.smartid import SmartIdAuthenticator
from esteid.smartid.i18n import TranslatedSmartIDService
from esteid.smartid.types import AuthenticateResult as SmartIdAuthInitResult
from esteid.smartid.types import AuthenticateStatusResult as SmartIdAuthStatusResult


@pytest.fixture()
def auth_result(static_certificate):
    return AuthenticationResult(
        {
            "country": "EE",
            "id_code": "11702020200",
            "given_name": "HELLO",
            "surname": "SMART-ID",
            "certificate_b64": base64.b64encode(static_certificate).decode(),
        }
    )


@pytest.fixture()
def smartid_auth_init_response():
    return SmartIdAuthInitResult(
        session_id="smartid_session_id",
        hash_type="hash_type",
        hash_value="hash_value",
        hash_value_b64="hash_value_b64",
        verification_code="1234",
    )


@pytest.fixture()
def mobileid_auth_init_response():
    return MobileIdAuthInitResult(
        session_id="mobileid_session_id",
        hash_type="hash_type",
        hash_value="digest",
        hash_value_b64="hash_value_b64",
        verification_code="1234",
    )


@pytest.fixture()
def smartid_auth_status_response(static_certificate):
    return SmartIdAuthStatusResult(
        document_number="document_number",
        certificate=static_certificate,  # DER-encoded certificate
        certificate_b64=base64.b64encode(static_certificate).decode(),  # Base64-encoded DER-encoded certificate
        certificate_level="certificate_level",
    )


@pytest.fixture()
def mobileid_auth_status_response(static_certificate):
    return MobileIdAuthStatusResult(
        certificate=static_certificate,  # DER-encoded certificate
        certificate_b64=base64.b64encode(static_certificate).decode(),  # Base64-encoded DER-encoded certificate
    )


@pytest.fixture()
def smartid_data():
    return {"id_code": "10101010005", "country": "EE"}


@pytest.fixture()
def mobileid_data():
    return {"id_code": "60001019906", "phone_number": "+37200000766"}


@pytest.mark.parametrize(
    "urlconf,content_type",
    (
        ("auth-smartid", "application/x-www-form-urlencoded"),
        ("auth-smartid", "application/json"),
        ("auth-rest-smartid", "application/json"),
    ),
)
@patch.object(TranslatedSmartIDService, "get_instance")
def test_auth_flow_smartid(
    _, urlconf, content_type, smartid_data, smartid_auth_init_response, smartid_auth_status_response, auth_result
):
    TranslatedSmartIDService.get_instance().authenticate.return_value = smartid_auth_init_response
    TranslatedSmartIDService.get_instance().status.return_value = smartid_auth_status_response

    url = reverse(urlconf)

    client = Client()

    session = {}

    # This is a SUPER obvious way to work with test sessions.
    with patch.object(db, "SessionStore", return_value=session):
        if content_type == "application/json":
            data = json.dumps(smartid_data)
        else:
            data = urlencode(smartid_data)

        response = client.post(url, data, content_type)

        TranslatedSmartIDService.get_instance().authenticate.assert_called_once_with(
            smartid_data["id_code"],
            smartid_data["country"],
        )

        assert response.status_code == 202, f"Auth init request failed: {response.json()}"
        assert response.json() == {
            "status": AuthTestView.Status.SUCCESS,
            "verification_code": "1234",
        }
        assert session[SmartIdAuthenticator._SESSION_KEY]["session_id"] == "smartid_session_id"

        response = client.patch(url, data, content_type)
        assert response.status_code == 200
        assert response.json() == {
            "status": AuthTestView.Status.SUCCESS,
            **auth_result,
        }

        assert SmartIdAuthenticator._SESSION_KEY not in session, "Failed to clean up session"


@pytest.mark.parametrize(
    "urlconf,content_type",
    (
        ("auth-mobileid", "application/x-www-form-urlencoded"),
        ("auth-mobileid", "application/json"),
        ("auth-rest-mobileid", "application/json"),
    ),
)
@patch.object(TranslatedMobileIDService, "get_instance")
def test_auth_flow_mobileid(
    _, urlconf, content_type, mobileid_data, mobileid_auth_init_response, mobileid_auth_status_response, auth_result
):
    TranslatedMobileIDService.get_instance().authenticate.return_value = mobileid_auth_init_response
    TranslatedMobileIDService.get_instance().status.return_value = mobileid_auth_status_response

    url = reverse(urlconf)

    client = Client()

    session = {}

    # This is a SUPER obvious way to work with test sessions.
    with patch.object(db, "SessionStore", return_value=session):
        if content_type == "application/json":
            data = json.dumps(mobileid_data)
        else:
            data = urlencode(mobileid_data)

        response = client.post(url, data, content_type)

        assert response.status_code == 202, f"Auth init request failed: {response.json()}"
        assert response.json() == {
            "status": AuthTestView.Status.SUCCESS,
            "verification_code": "1234",
        }
        assert session[SmartIdAuthenticator._SESSION_KEY]["session_id"] == "mobileid_session_id"

        response = client.patch(url, data, content_type)
        assert response.status_code == 200
        assert response.json() == {
            "status": AuthTestView.Status.SUCCESS,
            **auth_result,
        }

        assert SmartIdAuthenticator._SESSION_KEY not in session, "Failed to clean up session"
