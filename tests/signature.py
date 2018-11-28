# -*- coding: utf-8 -*-
import pytest

from mock import patch

from platform import python_version_tuple

from cryptography.hazmat.primitives.serialization import Encoding

from OpenSSL import crypto

from esteid.digidocservice.service import DigiDocError, DigiDocService, DigiDocNotOk
from esteid.digidocservice.types import SignedDocInfo, SignatureInfo, Signer


@pytest.fixture
def dummy_p12():
    p12 = crypto.load_pkcs12(open("./tests/signer1.p12", 'rb').read(), b'signer1')

    return p12


major, minor, _ = python_version_tuple()

#  py 2.x: where pubkey_bytes is a wrapped str
if major == '2':  # pragma: no cover
    def get_hex_from_bytes(buf):
        return buf.encode('hex')

#  py 3.4: since bytes.hex was added in 3.5
elif major == '3' and int(minor) <= 4:  # pragma: no cover
    import codecs

    def get_hex_from_bytes(buf):
        return codecs.encode(buf, 'hex_codec')

else:
    def get_hex_from_bytes(buf):
        return buf.hex()


@pytest.fixture
def dummy_cert_hex(dummy_p12):
    x509 = dummy_p12.get_certificate()
    crypto_cert = x509.to_cryptography()
    pubkey_bytes = crypto_cert.public_bytes(Encoding.DER)

    return get_hex_from_bytes(pubkey_bytes)


def test_sign_idcard(digidoc_service, lazy_random_file, dummy_p12, dummy_cert_hex, signed_doc_dict):
    digidoc_service.start_session(b_hold_session=True)
    digidoc_service.create_signed_document()

    # Add some files
    ex_file = lazy_random_file()
    digidoc_service.add_datafile('Picture 1.jpg', 'image/jpeg', DigiDocService.HASHCODE, len(ex_file), ex_file)

    ex_file = lazy_random_file()
    digidoc_service.add_datafile('Picture 2.jpg', 'image/jpeg', DigiDocService.HASHCODE, len(ex_file), ex_file)

    data_file_names = [f.file_name for f in digidoc_service.data_files]

    assert len(data_file_names) == 2
    assert 'Picture 1.jpg' in data_file_names
    assert 'Picture 2.jpg' in data_file_names

    # Start signing process with idcard
    res = digidoc_service.prepare_signature(
        certificate=dummy_cert_hex,
        token_id='',

        signing_profile='LT_TM',  # Using BDOC format until ASIC-E is supported
    )

    assert isinstance(res, dict)
    assert 'id' in res and res['id']
    assert 'digest' in res and res['digest']

    signature_value = crypto.sign(dummy_p12.get_privatekey(), res['digest'], "sha256")

    # We would need a real certificate to fully test this
    #  Instead we expect a specific error and then test the method logic via patching
    with pytest.raises(DigiDocError) as exc_info:
        digidoc_service.finalize_signature(res['id'], get_hex_from_bytes(signature_value))

    assert '[/FinalizeSignature - 202]' in str(exc_info.value)

    # Should raise DigiDocNotOk if not successful
    with pytest.raises(DigiDocNotOk):
        with patch.object(digidoc_service, '_finalize_signature', return_value={
            'Status': 'failure',
        }):
            digidoc_service.finalize_signature(res['id'], get_hex_from_bytes(signature_value))

    with patch.object(digidoc_service, '_finalize_signature', return_value={
        'Status': digidoc_service.RESPONSE_STATUS_OK,
        'SignedDocInfo': signed_doc_dict,
    }):
        doc_info = digidoc_service.finalize_signature(res['id'], get_hex_from_bytes(signature_value))

        # Test that doc_info is parsed properly
        assert isinstance(doc_info, SignedDocInfo)
        assert len(doc_info.signature_info) == 1
        assert isinstance(doc_info.signature_info[0], SignatureInfo)
        assert doc_info.signature_info[0].id == 'S0'
        assert isinstance(doc_info.signature_info[0].signer, Signer)
        assert doc_info.signature_info[0].signer.id_code == '14212128025'
        assert doc_info.signature_info[0].signer.full_name == 'Seitsmes Testnumber'
