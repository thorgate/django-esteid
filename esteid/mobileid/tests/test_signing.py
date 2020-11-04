from time import sleep, time

import pytest

from esteid_certificates import get_certificate

from pyasice import Container, XmlSignature
from pyasice.ocsp import OCSP
from pyasice.tsa import TSA

from ...constants import OCSP_DEMO_URL, TSA_DEMO_URL
from ...exceptions import ActionInProgress
from ..types import SignResult, SignStatusResult


def run_sign_flow(demo_mid_api, certificate, id_number=None, phone_number=None, signed_data=None, timeout=60):
    """Run full sign flow w/ a hash algorithm

    test data from:
    https://github.com/SK-EID/MID/wiki/Test-number-for-automated-testing-in-DEMO

    :param MobileIDService demo_mid_api:
    :param bytes certificate: obtained by authentication, required to validate the signature
    :param str id_number:
    :param str phone_number:
    :param bytes signed_data: content to sign
    :param int timeout: how long to wait for a result. NOTE: if user input is expected, ensure at least 1 minute
    :rtype: SignStatusResult
    """
    if signed_data is None:
        signed_data = b"Test"
    res = demo_mid_api.sign(id_number, phone_number, signed_data)
    assert isinstance(res, SignResult)

    assert res.session_id

    status_res = None  # type: SignStatusResult

    end_time = time() + timeout
    while status_res is None and time() < end_time:
        try:
            status_res = demo_mid_api.sign_status(res.session_id, certificate, res.digest)
        except ActionInProgress:
            sleep(1.0)

    assert isinstance(status_res, SignStatusResult)
    return status_res


@pytest.mark.slow
def test_mobileid_sign_flow_ee(demo_mid_api, MID_DEMO_PHONE_EE_OK, MID_DEMO_PIN_EE_OK):
    """Test full sign flow for EE

    Note: This does a number of real connections to Smart-ID apis so it's marked as a slow test
    """
    file_name = "test.txt"
    data = b"Hello World!"
    mime_type = "text/plain"

    # Authenticate user
    user_cert = demo_mid_api.get_certificate(MID_DEMO_PIN_EE_OK, MID_DEMO_PHONE_EE_OK)

    # Generate a XAdES signature
    xs: XmlSignature = (
        XmlSignature.create().add_document(file_name, data, mime_type).set_certificate(user_cert).update_signed_info()
    )

    # Sign the XAdES structure
    sign_result = run_sign_flow(
        demo_mid_api,
        user_cert,
        id_number=MID_DEMO_PIN_EE_OK,
        phone_number=MID_DEMO_PHONE_EE_OK,
        signed_data=xs.signed_data(),
    )
    xs.set_signature_value(sign_result.signature)

    # prove that all went right
    xs.verify()

    # Get an OCSP status confirmation
    issuer_cert = get_certificate(xs.get_certificate_issuer_common_name())

    ocsp = OCSP(url=OCSP_DEMO_URL)
    ocsp.validate(user_cert, issuer_cert, sign_result.signature)

    # Embed the OCSP response
    xs.set_ocsp_response(ocsp)

    # Get a signature TimeStamp
    tsa = TSA(url=TSA_DEMO_URL)
    tsr = tsa.get_timestamp(xs.get_timestamped_message())
    xs.set_timestamp_response(tsr)

    # Write results to a bdoc file
    with Container() as bdoc_file:
        bdoc_file.add_file(file_name, data, mime_type)
        bdoc_file.add_signature(xs)

        bdoc_file.verify_container()
        bdoc_file.verify_signatures()
