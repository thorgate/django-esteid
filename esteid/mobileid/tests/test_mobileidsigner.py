import base64
import os
from tempfile import NamedTemporaryFile
from unittest.mock import patch

import pytest

from esteid.mobileid import MobileIdSigner
from esteid.mobileid import signer as signer_module

from ...exceptions import InvalidIdCode, InvalidParameter, InvalidParameters, SigningSessionDoesNotExist


@pytest.fixture()
def mobileidsigner():
    signer = MobileIdSigner({}, initial=True)
    with patch.object(signer, "open_container"), patch.object(signer, "save_session_data"):
        yield signer


@pytest.fixture()
def mobileid_session_data():
    with NamedTemporaryFile("wb", delete=False) as f:
        f.write(b"xml signature data")
    yield {
        "digest_b64": "MTIz",
        "temp_signature_file": f.name,
        "temp_container_file": "...",
        "session_id": "...",
        "timestamp": 1,
    }
    os.remove(f.name)


@pytest.fixture()
def mobileidservice():
    with patch.object(signer_module, "TranslatedMobileIDService") as service_cls:
        yield service_cls


@pytest.mark.parametrize(
    "data,error",
    [
        pytest.param(
            None,
            InvalidParameters,
            id="No data",
        ),
        pytest.param(
            {},
            InvalidParameters,
            id="Empty data",
        ),
        pytest.param(
            {"id_code": "asdf", "phone_number": "asdf"},
            InvalidParameter,
            id="Invalid Phone",
        ),
        pytest.param(
            {"id_code": "asdf", "phone_number": "+37200000766"},
            InvalidIdCode,
            id="Invalid ID Code",
        ),
        pytest.param(
            {"id_code": "60001019906", "phone_number": "+37200000766"},
            None,
            id="ID Code and Phone OK",
        ),
        pytest.param(
            {"id_code": "60001019906", "phone_number": "+37200000766", "language": "EST"},
            None,
            id="ID Code and Phone OK",
        ),
    ],
)
def test_mobileidsigner_setup(data, error):
    signer = MobileIdSigner({}, initial=True)
    if error:
        with pytest.raises(error):
            signer.setup(data)
    else:
        signer.setup(data)
        assert signer.id_code == data["id_code"]
        assert signer.phone_number == data["phone_number"]
        assert signer.language == data.get("language", "ENG")


@pytest.mark.parametrize(
    "data,error",
    [
        pytest.param(None, SigningSessionDoesNotExist, id="No session data"),
        pytest.param({}, SigningSessionDoesNotExist, id="Empty session data"),
        pytest.param({"digest_b64": "asd"}, SigningSessionDoesNotExist, id="Broken session data"),
        pytest.param(
            {
                "digest_b64": "MTIz",
                "temp_signature_file": "a",
                "temp_container_file": "b",
                "session_id": "c",
                "timestamp": 1,
            },
            None,
            id="Good session data",
        ),
    ],
)
def test_mobileidsigner_load_session(data, error):
    if error:
        with pytest.raises(error):
            MobileIdSigner({MobileIdSigner._SESSION_KEY: data})
    else:
        signer = MobileIdSigner({MobileIdSigner._SESSION_KEY: data})
        assert signer.session_data.digest == b"123"
        assert signer.session_data.session_id == "c"


def test_mobileidsigner_prepare(mobileidsigner, MID_DEMO_PHONE_EE_OK, MID_DEMO_PIN_EE_OK, mobileidservice):
    mobileidsigner.setup({"id_code": MID_DEMO_PIN_EE_OK, "phone_number": MID_DEMO_PHONE_EE_OK})

    result = mobileidsigner.prepare(None, [])

    mobileidsigner.open_container.assert_called_once_with(None, [])
    container = mobileidsigner.open_container(...)

    mobileidservice.get_instance.assert_called_once()

    service = mobileidservice.get_instance()
    service.get_certificate.assert_called_once_with(MID_DEMO_PIN_EE_OK, MID_DEMO_PHONE_EE_OK)

    cert = service.get_certificate(...)

    container.prepare_signature.assert_called_once_with(cert)

    xml_sig = mobileidsigner.open_container().prepare_signature(...)
    xml_sig.signed_data.assert_called_once()

    service.sign.assert_called_once_with(
        MID_DEMO_PIN_EE_OK, MID_DEMO_PHONE_EE_OK, xml_sig.signed_data(), language=mobileidsigner.language
    )

    sign_session = service.sign(...)

    mobileidsigner.save_session_data.assert_called_once_with(
        digest=sign_session.digest,
        container=container,
        xml_sig=xml_sig,
        session_id=sign_session.session_id,
    )

    assert result["verification_code"] == sign_session.verification_code


@patch.object(signer_module, "Container")
@patch.object(signer_module, "XmlSignature")
def test_mobileidsigner_finalize(
    XmlSignatureMock, ContainerMock, MID_DEMO_PHONE_EE_OK, MID_DEMO_PIN_EE_OK, mobileidservice, mobileid_session_data
):
    mobileidsigner = MobileIdSigner({MobileIdSigner._SESSION_KEY: mobileid_session_data})
    with patch.object(mobileidsigner, "finalize_xml_signature"):
        result = mobileidsigner.finalize()

        XmlSignatureMock.assert_called_once_with(b"xml signature data")

        mobileidsigner.finalize_xml_signature.assert_called_once_with(XmlSignatureMock())

    xml_sig = XmlSignatureMock(...)

    service = mobileidservice.get_instance()
    service.sign_status.assert_called_once_with(
        mobileid_session_data["session_id"],
        xml_sig.get_certificate_value(),
        base64.b64decode(mobileid_session_data["digest_b64"]),
    )

    sign_status = service.sign_status(...)
    xml_sig.set_signature_value.assert_called_once_with(sign_status.signature)
    ContainerMock.open.assert_called_once_with(mobileid_session_data["temp_container_file"])
    container = ContainerMock.open(...)

    assert result == container
