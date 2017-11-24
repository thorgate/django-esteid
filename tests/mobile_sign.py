# -*- coding: utf-8 -*-
import base64
import os

from django.utils.encoding import force_text

from esteid.digidocservice.containers import BdocContainer
from esteid.digidocservice.service import DigiDocService, DataFile
from esteid.digidocservice.types import SignedDocInfo, SignatureInfo, Signer


def test_bdoc_container(digidoc_service):
    """ This should succeed at writing a hashcode format version of input file
    """

    with open(os.path.join('esteid', 'digidocservice', 'test_data', 'test.bdoc'), 'rb') as f:
        bdoc_data = f.read()

    with BdocContainer(bdoc_data) as container:
        hash_format = container.hash_codes_format()

    # Note: The methods must return False since b_hold_session is set to False
    assert not digidoc_service.start_session(b_hold_session=False, sig_doc_xml=force_text(base64.b64encode(bdoc_data)))
    assert not digidoc_service.start_session(b_hold_session=False, sig_doc_xml=force_text(base64.b64encode(hash_format)))


def test_hashcodes_format(digidoc_service, digidoc_service2, lazy_random_file):
    """ Attempt to sign a document with mobile id, retrieve the file and check that our without_data_files
        works properly. Then attempt to start a new service session with the own_hash_file.

        Tests against the #TaaviBug
    """
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

    # Sign with mid
    digidoc_service.mobile_sign(id_code='11412090004', country='EE', phone_nr='+37200000766')

    # Wait for response
    status_info = digidoc_service.get_status_info(wait=True)

    assert status_info['StatusCode'] == 'SIGNATURE'

    # Got response, lets load the signed document
    hash_file_data = digidoc_service.get_signed_doc()
    doc_info = digidoc_service.get_signed_doc_info()

    # Get BdocContainer
    with digidoc_service.to_bdoc(hash_file_data) as container:
        container.data_files_format()
        own_hash_file_data = container.hash_codes_format()

    digidoc_service.close_session()

    # Test that doc_info is parsed properly
    assert isinstance(doc_info, SignedDocInfo)
    assert len(doc_info.signature_info) == 1
    assert isinstance(doc_info.signature_info[0], SignatureInfo)
    assert doc_info.signature_info[0].id == 'S0'
    assert isinstance(doc_info.signature_info[0].signer, Signer)
    assert doc_info.signature_info[0].signer.id_code == '11412090004'
    assert doc_info.signature_info[0].signer.full_name == u'Mary Änn O’Connež-Šuslik'

    # attempt to sign again
    digidoc_service2.start_session(True, sig_doc_xml=force_text(base64.b64encode(own_hash_file_data)))

    digidoc_service2.mobile_sign(id_code='11412090004', country='EE', phone_nr='+37200000766')
    status_info = digidoc_service2.get_status_info(wait=True)

    assert status_info['StatusCode'] == 'SIGNATURE'

    data_files = [
        DataFile('Picture 1.jpg', 'image/jpeg', DigiDocService.HASHCODE, len(ex_file), ex_file),
        DataFile('Picture 2.jpg', 'image/jpeg', DigiDocService.HASHCODE, len(ex_file), ex_file),
    ]

    assert digidoc_service2.get_file_data(data_files)
