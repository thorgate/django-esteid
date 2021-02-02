import binascii
import os
from tempfile import NamedTemporaryFile
from time import time
from unittest.mock import Mock, patch

import pytest

from esteid.exceptions import InvalidParameter
from esteid.idcard import IdCardSigner
from esteid.idcard import signer as signer_module


@pytest.fixture()
def idcardsigner():
    signer = IdCardSigner({}, initial=True)
    mock_container = Mock(name="mock_container")
    with patch.object(signer, "open_container", return_value=mock_container), patch.object(signer, "save_session_data"):
        mock_container.prepare_signature.return_value = mock_xml_sig = Mock(name="mock_xml_sig")
        mock_xml_sig.digest.return_value = b"some binary digest"

        yield signer


@pytest.fixture()
def idcard_session_data():
    with NamedTemporaryFile("wb", delete=False) as f:
        f.write(b"xml signature data")
    yield IdCardSigner.SessionData(
        {
            "digest_b64": "MTIz",
            "temp_signature_file": f.name,
            "temp_container_file": "...",
            "timestamp": int(time()),
        }
    )
    os.remove(f.name)


def test_idcardsigner_certificate(static_certificate):
    signer = IdCardSigner({}, initial=True)
    signer.setup({"certificate": binascii.b2a_hex(static_certificate)})

    assert signer.id_code == "11702020200"

    with pytest.raises(InvalidParameter, match="Missing required parameter 'certificate'"):
        signer.setup({})

    with pytest.raises(InvalidParameter, match="Failed to decode"):
        signer.setup({"certificate": b"something not hex-encoded"})

    with pytest.raises(InvalidParameter, match="supported certificate format"):
        signer.setup({"certificate": binascii.b2a_hex(b"this is not a certificate")})


def test_idcardsigner_prepare(idcardsigner, static_certificate):
    idcardsigner.setup({"certificate": binascii.b2a_hex(static_certificate)})

    result = idcardsigner.prepare(None, [])

    idcardsigner.open_container.assert_called_once_with(None, [])
    container = idcardsigner.open_container(...)

    container.prepare_signature.assert_called_once_with(static_certificate)

    xml_sig = idcardsigner.open_container().prepare_signature(...)
    assert xml_sig._mock_name == "mock_xml_sig"

    idcardsigner.save_session_data.assert_called_once_with(
        digest=xml_sig.digest(),
        container=container,
        xml_sig=xml_sig,
    )

    assert result == {"digest": binascii.b2a_hex(xml_sig.digest()).decode()}


@patch.object(signer_module, "pyasice")
def test_idcardsigner_finalize(pyasice_mock, idcard_session_data):
    idcardsigner = IdCardSigner({IdCardSigner._SESSION_KEY: idcard_session_data}, initial=False)
    signature_value = b"test signature"
    xml_sig_mock = pyasice_mock.XmlSignature()

    with patch.object(idcardsigner, "finalize_xml_signature"):
        result = idcardsigner.finalize({"signature_value": binascii.b2a_hex(signature_value).decode()})

        pyasice_mock.verify.assert_called_once_with(
            xml_sig_mock.get_certificate_value(), signature_value, idcard_session_data.digest, prehashed=True
        )

        idcardsigner.finalize_xml_signature.assert_called_once_with(xml_sig_mock)

    assert result is pyasice_mock.Container.open(...)
    result.add_signature.assert_called_once_with(xml_sig_mock)
