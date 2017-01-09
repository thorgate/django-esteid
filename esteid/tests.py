# -*- coding: utf-8 -*-
import base64
import os
try:
    from urllib.request import urlopen
except ImportError:
    from urllib2 import urlopen

from django.test import TestCase
from django.utils.encoding import force_text

from .digidocservice.containers import BdocContainer
from .digidocservice.models import Signer
from .digidocservice.service import DigiDocService, DataFile


class TestParseCommonName(TestCase):
    def __name_test(self, common_name, id_code, expected):
        result = Signer.parse_common_name(common_name, id_code)
        self.assertEqual(expected, result,
                         'parse_common_name: Expected "%s", got "%s" from common_name "%s"' % (expected, result, common_name))

    def test_simple(self):
        self.__name_test('TESTNUMBER,SEITSMES,51001091072', '51001091072', 'Seitsmes Testnumber')

    def test_two_names(self):
        self.__name_test('TEST-NUMBER,SEITSMES MEES,51001091072', '51001091072', 'Seitsmes Mees Test-Number')

    def test_complex(self):
        self.__name_test(u'O’CONNEŽ-ŠUSLIK,MARY ÄNN,11412090004', '11412090004', u'Mary Änn O’Connež-Šuslik')


class TestSigningWithMobile(TestCase):
    def get_example_file(self):
        return urlopen('http://lorempixel.com/1920/1920/').read()

    def get_service(self):
        return DigiDocService('Testimine', debug=False)

    def test_bdoc_container(self):
        """ This should succeed at writing a hashcode format version of input file
        """

        with open(os.path.join('esteid', 'digidocservice', 'test_data', 'test.bdoc'), 'rb') as f:
            bdoc_data = f.read()

        with BdocContainer(bdoc_data) as container:
            hash_format = container.hash_codes_format()

        service = self.get_service()

        service.start_session(b_hold_session=False, sig_doc_xml=force_text(base64.b64encode(bdoc_data)))
        service.start_session(b_hold_session=False, sig_doc_xml=force_text(base64.b64encode(hash_format)))

    def test_hashcodes_format(self):
        """ Attempt to sign a document with mobile id, retrieve the file and check that our without_data_files
            works properly. Then attempt to start a new service session with the own_hash_file.

            Tests against the #TaaviBug
        """
        service = DigiDocService('Testimine', debug=False)
        service.start_session(b_hold_session=True)
        service.create_signed_document()

        # Add some files
        ex_file = self.get_example_file()
        service.add_datafile('Picture 1.jpg', 'image/jpeg', DigiDocService.HASHCODE, len(ex_file), ex_file)

        ex_file = self.get_example_file()
        service.add_datafile('Picture 2.jpg', 'image/jpeg', DigiDocService.HASHCODE, len(ex_file), ex_file)

        # Sign with mid
        service.mobile_sign('', phone_nr='+37200000766')

        # Wait for response
        status_info = service.get_status_info(wait=True)
        self.assertEqual(status_info['StatusCode'], 'SIGNATURE')

        # Got response, lets load the signed document
        hash_file_data = service.get_signed_doc()

        # Get BdocContainer
        with service.to_bdoc(hash_file_data) as container:
            container.data_files_format()
            own_hash_file_data = container.hash_codes_format()

        service.close_session()

        data_files = [
            DataFile('Picture 1.jpg', 'image/jpeg', DigiDocService.HASHCODE, len(ex_file), ex_file),
            DataFile('Picture 2.jpg', 'image/jpeg', DigiDocService.HASHCODE, len(ex_file), ex_file),
        ]

        # attempt to sign again
        service2 = DigiDocService('Testimine', debug=True)
        service2.start_session(True, sig_doc_xml=force_text(base64.b64encode(own_hash_file_data)))
        service2.mobile_sign('', phone_nr='+37200000766')
        status_info = service2.get_status_info(wait=True)
        self.assertEqual(status_info['StatusCode'], 'SIGNATURE')

        service2.get_file_data(data_files)
