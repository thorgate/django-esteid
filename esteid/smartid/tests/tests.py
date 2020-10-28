from time import sleep, time
from unittest.mock import patch

import pytest

import esteid_certificates
import requests_mock
from django.utils.functional import Promise
from requests import Response
from requests.exceptions import ConnectionError, ConnectTimeout, HTTPError

import pyasice
from pyasice import Container, XmlSignature
from pyasice.ocsp import OCSP
from pyasice.tsa import TSA

from esteid.constants import HASH_ALGORITHMS, HASH_SHA256, HASH_SHA384, HASH_SHA512, OCSP_DEMO_URL, TSA_DEMO_URL

from ...exceptions import (
    ActionFailed,
    ActionNotCompleted,
    IdentityCodeDoesNotExist,
    InvalidCredentials,
    OfflineError,
    PermissionDenied,
    SessionDoesNotExist,
    SignatureVerificationError,
    UnsupportedClientImplementation,
)
from ...util import generate_hash
from .. import SmartIDError
from ..base import SmartIDService
from ..constants import (
    CERTIFICATE_LEVEL_ADVANCED,
    CERTIFICATE_LEVEL_QUALIFIED,
    COUNTRY_ESTONIA,
    COUNTRY_LATVIA,
    COUNTRY_LITHUANIA,
    END_RESULT_DOCUMENT_UNUSABLE,
    END_RESULT_TIMEOUT,
    END_RESULT_USER_REFUSED,
    STATE_COMPLETE,
    STATE_RUNNING,
)
from ..i18n import TranslatedSmartIDService
from ..types import AuthenticateResult, AuthenticateStatusResult, SignResult, SignStatusResult
from ..utils import get_verification_code


def raise_http_error(status_code):
    def _raise_http_error(*args, **kwargs):
        response = Response()
        response.status_code = status_code

        raise HTTPError(response=response)

    return _raise_http_error


def raises_exception(exc, message=None):
    def _raises_exception(*args, **kwargs):
        raise exc("err:{}".format(exc.__class__.__name__) if message is None else message)

    return _raises_exception


@pytest.mark.parametrize(
    "expected_verification_code,hash_raw",
    [
        ("7712", b"Hello World!"),
        ("3404", b"You broke it, didn't you."),
        ("0914", b"Weeeeeeeeeeeeeeeeeeeeee[bzzt]"),
    ],
)
def test_verification_code_generator(expected_verification_code, hash_raw):
    assert get_verification_code(generate_hash(HASH_SHA256, hash_raw)) == expected_verification_code


@pytest.mark.parametrize("hash_type", HASH_ALGORITHMS)
def test_authentication(demo_api, hash_type):
    raw_data = b"Hello World!"
    response_data = {"sessionID": "FAKE"}
    verification_codes = {
        HASH_SHA256: "7712",
        HASH_SHA384: "3486",
        HASH_SHA512: "4664",
    }

    known_hashes = {
        HASH_SHA256: b"\x7f\x83\xb1e\x7f\xf1\xfcS\xb9-\xc1\x81H\xa1\xd6]\xfc-K\x1f\xa3\xd6w(J\xdd\xd2\x00\x12m\x90i",
        HASH_SHA384: b"\xbf\xd7l\x0e\xbb\xd0\x06\xfe\xe5\x83A\x05G\xc1\x88{\x02\x92\xbev\xd5\x82\xd9l$-*y'#\xe3"
        b"\xfdo\xd0a\xf9\xd5\xcf\xd1;\x8f\x96\x13X\xe6\xad\xbaJ",
        HASH_SHA512: b"\x86\x18D\xd6pN\x85s\xfe\xc3M\x96~ \xbc\xfe\xf3\xd4$\xcfH\xbe\x04\xe6\xdc\x08\xf2\xbdX\xc7)t3q"
        b"\x01^\xad\x89\x1c\xc3\xcf\x1c\x9d4\xb4\x92d\xb5\x10u\x1b\x1f\xf9\xe57\x93{\xc4k]o\xf4\xec\xc8",
    }

    with patch("esteid.smartid.base.secure_random", return_value=raw_data):
        with patch("esteid.smartid.base.generate_hash", return_value=known_hashes[hash_type]) as mock:
            with patch.object(demo_api, "invoke", return_value=response_data):
                res = demo_api.authenticate("0", COUNTRY_ESTONIA, hash_type=hash_type)

                mock.assert_called_with(hash_type, raw_data)

                assert isinstance(res, AuthenticateResult)
                assert res.session_id == "FAKE"
                assert res.hash_type == hash_type
                assert res.hash_value == generate_hash(hash_type, raw_data)
                assert res.verification_code == verification_codes[hash_type]


def test_authentication_400(demo_api):
    with patch.object(demo_api, "invoke", new=raise_http_error(400)):
        with pytest.raises(HTTPError):
            demo_api.authenticate("0", COUNTRY_ESTONIA)


def test_authentication_403(demo_api):
    with patch.object(demo_api, "invoke", new=raise_http_error(403)):
        with pytest.raises(PermissionDenied) as exc_info:
            demo_api.authenticate("0", COUNTRY_ESTONIA)

        assert "certificate_level" not in str(exc_info.value)

        with pytest.raises(PermissionDenied) as exc_info:
            demo_api.authenticate("0", COUNTRY_ESTONIA, certificate_level=CERTIFICATE_LEVEL_ADVANCED)

        assert "certificate_level" in str(exc_info.value)


def test_authentication_404(demo_api):
    with patch.object(demo_api, "invoke", new=raise_http_error(404)):
        with pytest.raises(IdentityCodeDoesNotExist):
            demo_api.authenticate("0", COUNTRY_ESTONIA)


def test_status(demo_api, static_certificate, static_auth_result, static_status_response):
    with patch.object(demo_api, "invoke", return_value=static_status_response):
        res = demo_api.status(static_auth_result.session_id, static_auth_result.hash_value)

        assert isinstance(res, AuthenticateStatusResult)

        assert res.document_number == "$documentNumber$"
        assert res.certificate == static_certificate
        assert res.certificate_level == CERTIFICATE_LEVEL_QUALIFIED


def test_status_signature_verification(demo_api, static_auth_result, static_status_response):
    with patch.object(demo_api, "invoke", return_value=static_status_response):
        with patch.object(pyasice, "verify", raises_exception(SignatureVerificationError)):
            with pytest.raises(SignatureVerificationError):
                demo_api.status(static_auth_result.session_id, static_auth_result.hash_value)


def test_status_state_running(demo_api):
    response_data = {
        "state": STATE_RUNNING,
    }

    with patch.object(demo_api, "invoke", return_value=response_data):
        with pytest.raises(ActionNotCompleted) as exc_info:
            demo_api.status(session_id="FAKE", hash_value=b"")

        # session_id should be in the message
        assert "FAKE" in str(exc_info.value)


def test_status_unexpected_state(demo_api):
    response_data = {
        "state": "FOO",
    }

    with patch.object(demo_api, "invoke", return_value=response_data):
        with pytest.raises(SmartIDError) as exc_info:
            demo_api.status(session_id="FAKE", hash_value=b"")

        assert "Unexpected state" in str(exc_info.value)


@pytest.mark.parametrize(
    "end_result_code",
    [
        END_RESULT_USER_REFUSED,
        END_RESULT_TIMEOUT,
        END_RESULT_DOCUMENT_UNUSABLE,
    ],
)
def test_status_end_result(demo_api, end_result_code):
    response_data = {
        "state": STATE_COMPLETE,
        "result": {
            "endResult": end_result_code,
        },
    }

    with patch.object(demo_api, "invoke", return_value=response_data):
        with pytest.raises(ActionFailed) as exc_info:
            demo_api.status(session_id="FAKE", hash_value=b"")

        assert exc_info.value.result_code == end_result_code


def test_status_unexpected_end_result(demo_api):
    response_data = {
        "state": STATE_COMPLETE,
        "result": {
            "endResult": "$RESULT$",
        },
    }

    with patch.object(demo_api, "invoke", return_value=response_data):
        with pytest.raises(SmartIDError) as exc_info:
            demo_api.status(session_id="FAKE", hash_value=b"")

        assert "$RESULT$" in str(exc_info.value)


def test_status_400(demo_api):
    with patch.object(demo_api, "invoke", new=raise_http_error(400)):
        with pytest.raises(HTTPError):
            demo_api.status(session_id="FAKE", hash_value=b"")


def test_status_404(demo_api):
    with patch.object(demo_api, "invoke", new=raise_http_error(404)):
        with pytest.raises(SessionDoesNotExist):
            demo_api.status(session_id="FAKE", hash_value=b"")


def run_authentication_flow(demo_api, id_number, country, hash_type=HASH_SHA512, timeout=30):
    """Run full authentication flow w/ a hash algorithm

    id_number from https://github.com/SK-EID/smart-id-documentation/wiki/Environment-technical-parameters

    :param SmartIDService demo_api:
    :param str id_number:
    :param str country:
    :param str hash_type:
    :param int timeout:
    :rtype: AuthenticateStatusResult
    """
    res = demo_api.authenticate(id_number, country, hash_type=hash_type)
    assert isinstance(res, AuthenticateResult)

    # All fields must be set
    assert res.session_id
    assert res.hash_type == hash_type
    assert res.hash_value
    assert res.verification_code

    status_res = None  # type: AuthenticateStatusResult

    # Pull status (using a loop here since the remote might be slow)
    # Default timeout is 30s compared to Smart ID ~5m.
    # There is really no reason that it should take longer IF it is working
    end_time = time() + timeout
    while time() < end_time:
        try:
            status_res = demo_api.status(res.session_id, res.hash_value)
            break
        except ActionNotCompleted:
            sleep(1.0)

    if status_res is None:
        raise TimeoutError(f"Failed to get status in {timeout}s")

    assert isinstance(status_res, AuthenticateStatusResult)
    return status_res


@pytest.mark.slow
@pytest.mark.parametrize("hash_type", HASH_ALGORITHMS)
def test_all_hash_algorithms(demo_api, hash_type, SMARTID_DEMO_ID_CODE_EE):
    """Test full authentication flow w/ all hash algorithms

    Note: This does a real connection to Smart-ID api so it's marked as a slow test
    """
    status_res = run_authentication_flow(demo_api, SMARTID_DEMO_ID_CODE_EE, COUNTRY_ESTONIA, hash_type)

    assert status_res.document_number == "PNOEE-10101010005-Z1B2-Q"
    assert status_res.certificate
    assert status_res.certificate_level == CERTIFICATE_LEVEL_QUALIFIED


@pytest.mark.slow
def test_authentication_flow_ee(demo_api, SMARTID_DEMO_ID_CODE_EE):
    """Test full authentication flow for EE

    Note: This does a real connection to Smart-ID api so it's marked as a slow test
    """
    status_res = run_authentication_flow(demo_api, SMARTID_DEMO_ID_CODE_EE, COUNTRY_ESTONIA)

    assert status_res.document_number == f"PNOEE-{SMARTID_DEMO_ID_CODE_EE}-Z1B2-Q"
    assert status_res.certificate
    assert status_res.certificate_level == CERTIFICATE_LEVEL_QUALIFIED


@pytest.mark.slow
def test_authentication_flow_lv(demo_api, SMARTID_DEMO_ID_CODE_LV):
    """Test full authentication flow for LV

    Note: This does a real connection to Smart-ID api so it's marked as a slow test
    """
    status_res = run_authentication_flow(demo_api, SMARTID_DEMO_ID_CODE_LV, COUNTRY_LATVIA)

    assert status_res.document_number == f"PNOLV-{SMARTID_DEMO_ID_CODE_LV}-SGT7-Q"
    assert status_res.certificate
    assert status_res.certificate_level == CERTIFICATE_LEVEL_QUALIFIED


@pytest.mark.slow
def test_authentication_flow_lt(demo_api, SMARTID_DEMO_ID_CODE_LT):
    """Test full authentication flow for LT

    Note: This does a real connection to Smart-ID api so it's marked as a slow test
    """
    status_res = run_authentication_flow(demo_api, SMARTID_DEMO_ID_CODE_LT, COUNTRY_LITHUANIA)

    assert status_res.document_number == f"PNOLT-{SMARTID_DEMO_ID_CODE_LT}-Z52N-Q"
    assert status_res.certificate
    assert status_res.certificate_level == CERTIFICATE_LEVEL_QUALIFIED


@pytest.mark.parametrize("exc", [ConnectionError, ConnectTimeout])
def test_invoke_timeout(demo_api, exc):
    with requests_mock.mock() as m:
        m.get(demo_api.api_url(""), exc=exc)

        with pytest.raises(OfflineError) as exc_info:
            demo_api.invoke("")

        assert "timed out" in str(exc_info.value)


@pytest.mark.parametrize(
    "status_code,exc,needle",
    [
        (401, InvalidCredentials, "rp_uuid and verify the ip"),
        (480, UnsupportedClientImplementation, "not supported"),
        (580, OfflineError, "maintenance"),
        (502, OfflineError, "Proxy error"),
        (503, OfflineError, "Proxy error"),
        (504, OfflineError, "Proxy error"),
        (400, HTTPError, "status_code: 400"),
        (500, HTTPError, "status_code: 500"),
    ],
)
def test_invoke_errors(demo_api, status_code, exc, needle):
    with requests_mock.mock() as m:
        m.get(demo_api.api_url(""), status_code=status_code)

        with pytest.raises(exc) as exc_info:
            demo_api.invoke("")
            demo_api.invoke("")

    assert needle in str(exc_info.value)


def test_i18n_version(i18n_demo_api):
    assert tuple(SmartIDService.MESSAGES) == tuple(TranslatedSmartIDService.MESSAGES)
    assert tuple(SmartIDService.END_RESULT_MESSAGES) == tuple(
        TranslatedSmartIDService.END_RESULT_MESSAGES
    )  # noqa: E127

    for key, message in TranslatedSmartIDService.MESSAGES.items():
        assert isinstance(message, Promise)

        assert message == i18n_demo_api.msg(key)

    for key, message in TranslatedSmartIDService.END_RESULT_MESSAGES.items():
        assert isinstance(message, Promise)

        assert message == i18n_demo_api.end_result_msg(key)


def run_sign_flow(demo_api, id_number=None, country=None, doc_num=None, signed_data=None, timeout=60):
    """Run full sign flow w/ a hash algorithm

    id_number from https://github.com/SK-EID/smart-id-documentation/wiki/Environment-technical-parameters

    :param SmartIDService demo_api:
    :param str id_number:
    :param str country:
    :param str doc_num: alternatively to id_number+country
    :param bytes signed_data: content to sign
    :param int timeout: how long to wait for a result. NOTE: if user input is expected, ensure at least 1 minute
    :rtype: SignStatusResult
    """
    if signed_data is None:
        signed_data = b"Test"
    if doc_num is not None:
        res = demo_api.sign_by_document_number(doc_num, signed_data)
    else:
        res = demo_api.sign(id_number, country, signed_data)
    assert isinstance(res, SignResult)

    # All fields must be set
    assert res.session_id

    status_res = None  # type: SignStatusResult

    # Poll status (using a loop here since the remote might be slow)
    # We timeout in 15s compared to Smart ID ~5m.
    # There is really no reason that it should take longer IF it is working
    end_time = time() + timeout
    while status_res is None and time() < end_time:
        try:
            status_res = demo_api.sign_status(res.session_id, generate_hash(HASH_SHA256, signed_data))
        except ActionNotCompleted:
            sleep(1.0)

    assert isinstance(status_res, SignStatusResult)
    return status_res


@pytest.mark.slow
def test_sign_flow_ee(demo_api, SMARTID_DEMO_ID_CODE_EE):
    """Test full sign flow for EE

    Note: This does a number of real connections to Smart-ID apis so it's marked as a slow test
    """
    file_name = "test.txt"
    data = b"Hello World!"
    mime_type = "text/plain"

    # Authenticate user
    auth_result = run_authentication_flow(demo_api, SMARTID_DEMO_ID_CODE_EE, COUNTRY_ESTONIA)

    # Select user's certificate
    subject_cert = demo_api.select_signing_certificate(document_number=auth_result.document_number)

    # Generate a XAdES signature
    xs: XmlSignature = (
        XmlSignature.create()
        .add_document(file_name, data, mime_type)
        .set_certificate(subject_cert)
        .update_signed_info()
    )

    # Sign the XAdES structure
    sign_result = run_sign_flow(demo_api, doc_num=auth_result.document_number, signed_data=xs.signed_data())
    xs.set_signature_value(sign_result.signature)

    # prove that all went right
    xs.verify()

    issuer_cn = xs.get_certificate_issuer_common_name()
    issuer_cert = esteid_certificates.get_certificate(issuer_cn)

    # Get an OCSP status confirmation
    ocsp = OCSP(url=OCSP_DEMO_URL)
    ocsp.validate(subject_cert, issuer_cert, sign_result.signature)

    # Embed the OCSP response
    xs.set_ocsp_response(ocsp)

    # Get a signature TimeStamp
    tsa = TSA(url=TSA_DEMO_URL)
    tsr = tsa.get_timestamp(xs.get_timestamped_message())
    xs.set_timestamp_response(tsr)

    # Write results to a bdoc file
    bdoc_file = Container()
    bdoc_file.add_file(file_name, data, mime_type)
    bdoc_file.add_signature(xs)

    bdoc_file.verify_container()
    bdoc_file.verify_signatures()
