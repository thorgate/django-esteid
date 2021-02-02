import binascii
from unittest.mock import MagicMock, patch

import pytest

from django.test import RequestFactory
from oscrypto.asymmetric import load_certificate

import pyasice.ocsp

from esteid.idcard import BaseIdCardAuthenticationView
from esteid.idcard.views import AuthenticationResult
from esteid.types import CertificateHolderInfo


@pytest.fixture()
def sample_view():
    class SampleIdAuthView(BaseIdCardAuthenticationView):
        on_auth_success = MagicMock(name="on_auth_success")
        validate_certificate_ocsp = MagicMock(name="validate_certificate_ocsp")

    return SampleIdAuthView()


@pytest.fixture()
def cert_pem(static_certificate):
    return (
        "-----BEGIN CERTIFICATE-----\n\t"
        + binascii.b2a_base64(static_certificate).decode()
        + "\n\t-----BEGIN CERTIFICATE-----"
    )


@pytest.fixture()
def auth_result(static_certificate):
    """
    a
    """
    cert = load_certificate(static_certificate)

    cert_holder_info = CertificateHolderInfo.from_certificate(cert)

    return AuthenticationResult(
        country=cert_holder_info.country,
        id_code=cert_holder_info.id_code,
        given_name=cert_holder_info.given_name,
        surname=cert_holder_info.surname,
        certificate_b64=binascii.b2a_base64(static_certificate).decode(),
    )


@pytest.mark.parametrize(
    "meta_key",
    [
        pytest.param(BaseIdCardAuthenticationView.CERTIFICATE_HEADER_NAME, id="nginx style"),
        pytest.param(BaseIdCardAuthenticationView.CERTIFICATE_ENV_NAME, id="Apache style"),
    ],
)
def test_idcard_auth_nginx_style_ok(cert_pem, sample_view, meta_key, auth_result):
    req = RequestFactory().get("/auth-url", **{meta_key: cert_pem})
    resp = sample_view.get(req)
    assert resp.status_code == 200
    response_text = resp.getvalue().decode()
    assert "Authentication Successful" in response_text
    assert '"id_code": "11702020200"' in response_text
    sample_view.on_auth_success.assert_called_once_with(req, auth_result)
    sample_view.validate_certificate_ocsp.assert_called_once_with(sample_view._certificate_handle)


def test_idcard_auth_error_no_header(sample_view):
    req = RequestFactory().get("/auth-url")
    resp = sample_view.get(req)
    assert resp.status_code == 400
    response_text = resp.getvalue().decode()
    assert "Authentication Failed" in response_text
    assert "InvalidParameter" in response_text


@pytest.mark.parametrize(
    "meta_key",
    [
        pytest.param(BaseIdCardAuthenticationView.CERTIFICATE_HEADER_NAME, id="nginx style"),
        pytest.param(BaseIdCardAuthenticationView.CERTIFICATE_ENV_NAME, id="Apache style"),
    ],
)
def test_idcard_auth_error_malformed_header(sample_view, meta_key):
    req = RequestFactory().get("/auth-url", **{meta_key: "bad cert"})
    resp = sample_view.get(req)
    assert resp.status_code == 400
    response_text = resp.getvalue().decode()
    assert "Authentication Failed" in response_text
    assert "InvalidParameter" in response_text


@pytest.mark.parametrize(
    "meta_key",
    [
        pytest.param(BaseIdCardAuthenticationView.CERTIFICATE_HEADER_NAME, id="nginx style"),
        pytest.param(BaseIdCardAuthenticationView.CERTIFICATE_ENV_NAME, id="Apache style"),
    ],
)
def test_idcard_auth_error_ocsp_failed(cert_pem, sample_view, meta_key):
    req = RequestFactory().get("/auth-url", **{meta_key: cert_pem})
    with patch.object(sample_view, "validate_certificate_ocsp", side_effect=pyasice.ocsp.OCSPError):
        resp = sample_view.get(req)

    assert resp.status_code == 409
    response_text = resp.getvalue().decode()
    assert "Authentication Failed" in response_text
    assert "OCSPError" in response_text
