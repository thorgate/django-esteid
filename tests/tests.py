# -*- coding: utf-8 -*-
import base64
import os

import pytest
from django.test import TestCase
from django.utils.encoding import force_text
from zeep import Transport
from zeep.cache import InMemoryCache


from esteid import config

from esteid.digidocservice.containers import BdocContainer
from esteid.digidocservice.service import DigiDocService, DataFile, DigiDocException
from esteid.digidocservice.types import SignedDocInfo, SignatureInfo, Signer


def get_random_file():
    return os.urandom(4096)


def get_digidoc_service():
    return DigiDocService(wsdl_url=config.wsdl_url(),
                          service_name='Testimine',
                          transport=Transport(cache=InMemoryCache()))


class TestSigningWithMobile(TestCase):
    def test_bdoc_container(self):
        """ This should succeed at writing a hashcode format version of input file
        """

        with open(os.path.join('esteid', 'digidocservice', 'test_data', 'test.bdoc'), 'rb') as f:
            bdoc_data = f.read()

        with BdocContainer(bdoc_data) as container:
            hash_format = container.hash_codes_format()

        service = get_digidoc_service()

        service.start_session(b_hold_session=False, sig_doc_xml=force_text(base64.b64encode(bdoc_data)))
        service.start_session(b_hold_session=False, sig_doc_xml=force_text(base64.b64encode(hash_format)))

    def test_hashcodes_format(self):
        """ Attempt to sign a document with mobile id, retrieve the file and check that our without_data_files
            works properly. Then attempt to start a new service session with the own_hash_file.

            Tests against the #TaaviBug
        """
        service = get_digidoc_service()
        service.start_session(b_hold_session=True)
        service.create_signed_document()

        # Add some files
        ex_file = get_random_file()
        service.add_datafile('Picture 1.jpg', 'image/jpeg', DigiDocService.HASHCODE, len(ex_file), ex_file)

        ex_file = get_random_file()
        service.add_datafile('Picture 2.jpg', 'image/jpeg', DigiDocService.HASHCODE, len(ex_file), ex_file)

        # Sign with mid
        service.mobile_sign(id_code='11412090004', country='EE', phone_nr='+37200000766')

        # Wait for response
        status_info = service.get_status_info(wait=True)
        self.assertEqual(status_info['StatusCode'], 'SIGNATURE')

        # Got response, lets load the signed document
        hash_file_data = service.get_signed_doc()
        doc_info = service.get_signed_doc_info()

        # Get BdocContainer
        with service.to_bdoc(hash_file_data) as container:
            container.data_files_format()
            own_hash_file_data = container.hash_codes_format()

        service.close_session()

        # Test that doc_info is parsed properly
        assert isinstance(doc_info, SignedDocInfo)
        assert len(doc_info.signature_info) == 1
        assert isinstance(doc_info.signature_info[0], SignatureInfo)
        assert doc_info.signature_info[0].id == 'S0'
        assert isinstance(doc_info.signature_info[0].signer, Signer)
        assert doc_info.signature_info[0].signer.id_code == '11412090004'
        assert doc_info.signature_info[0].signer.full_name == u'Mary Änn O’Connež-Šuslik'

        # attempt to sign again
        service2 = get_digidoc_service()
        service2.start_session(True, sig_doc_xml=force_text(base64.b64encode(own_hash_file_data)))

        with pytest.raises(DigiDocException) as exc_info:
            service2.add_datafile('x', 'text/plain', '', 0, b'')

        assert 'Cannot add files to PreviouslyCreatedContainer' in str(exc_info.value)

        service2.mobile_sign(id_code='11412090004', country='EE', phone_nr='+37200000766')
        status_info = service2.get_status_info(wait=True)
        self.assertEqual(status_info['StatusCode'], 'SIGNATURE')

        data_files = [
            DataFile('Picture 1.jpg', 'image/jpeg', DigiDocService.HASHCODE, len(ex_file), ex_file),
            DataFile('Picture 2.jpg', 'image/jpeg', DigiDocService.HASHCODE, len(ex_file), ex_file),
        ]
        service2.get_file_data(data_files)
