import binascii
from unittest.mock import Mock, patch

import pytest

from esteid.exceptions import InvalidParameter
from esteid.idcard import IdCardSigner


@pytest.fixture()
def idcardsigner():
    signer = IdCardSigner({}, initial=True)
    mock_container = Mock(name="mock_container")
    with patch.object(signer, "open_container", return_value=mock_container), patch.object(signer, "save_session_data"):
        mock_container.prepare_signature.return_value = mock_xml_sig = Mock(name="mock_xml_sig")
        mock_xml_sig.digest.return_value = b"some binary digest"

        yield signer


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
