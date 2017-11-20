# -*- coding: utf-8 -*-
import base64
import os

import binascii

import pytest
from django.test import TestCase
from django.utils.encoding import force_text
from zeep import Transport
from zeep.cache import InMemoryCache

from mock import patch

from esteid import config

from esteid.digidocservice.containers import BdocContainer
from esteid.digidocservice.service import DigiDocService, DataFile, DigiDocError


def get_random_file():
    return os.urandom(4096)


def get_digidoc_service():
    return DigiDocService(wsdl_url=config.wsdl_url(),
                          service_name='Testimine',
                          transport=Transport(cache=InMemoryCache()))


class TestMobileAuthenticate(TestCase):
    def test_mobileauthenticate_flow(self):
        service = get_digidoc_service()
        self.assertIsNone(service.session_code)

        # Construct a static sp_challenge so we can verify that it is returned as expected
        sp_challenge = os.urandom(10)

        with patch.object(service, 'get_sp_challenge', return_value=sp_challenge):
            response, _ = service.mobile_authenticate(id_code='11412090004', country='EE',
                                                      phone_nr='+37200000766', return_cert_data=True)

        self.assertEqual(response['Status'], 'OK')
        self.assertEqual(response['UserIDCode'], '11412090004')

        self.assertEqual(response['UserCountry'], 'EE')
        self.assertEqual(response['UserGivenname'], u'MARY ÄNN')
        self.assertEqual(response['UserSurname'], u'O’CONNEŽ-ŠUSLIK')

        self.assertEqual(len(response['ChallengeID']), 4)
        self.assertGreater(len(response['UserCN']), 0)
        self.assertIsNotNone(response['CertificateData'])

        parsed_response = binascii.unhexlify(response['Challenge'])
        self.assertTrue(parsed_response.startswith(sp_challenge))

        # session should be set now
        self.assertIsNotNone(service.session_code)

        # Test get_mobile_authenticate_status works properly
        status_code, signature = service.get_mobile_authenticate_status(wait=False)
        self.assertIn(status_code, ['OUTSTANDING_TRANSACTION', 'USER_AUTHENTICATED'])

        # try again if the authentication is not completed yet
        if status_code != 'USER_AUTHENTICATED':
            status_code, signature = service.get_mobile_authenticate_status(wait=True)

        self.assertEqual(status_code, 'USER_AUTHENTICATED')
        self.assertIsNotNone(signature)
        self.assertGreater(len(signature), 0)

        # Verify signature is correct
        with pytest.raises(NotImplementedError):
            # FIXME: test signature verification
            self.assertTrue(service.verify_mid_signature(response['CertificateData'], signature, sp_challenge))

    def test_mobileauthenticate_return_cert_data(self):
        service = get_digidoc_service()
        response, _ = service.mobile_authenticate(id_code='11412090004', country='EE', phone_nr='+37200000766',
                                                  return_cert_data=True)
        self.assertIsNotNone(response['CertificateData'])

    def test_mobileauthenticate_return_revocation_data(self):
        service = get_digidoc_service()
        response, _ = service.mobile_authenticate(id_code='11412090004', country='EE', phone_nr='+37200000766',
                                                  return_revocation_data=True, language=service.LANGUAGE_ET)
        self.assertIsNotNone(response['RevocationData'])

    def test_mobileauthenticate_error(self):
        # From https://www.id.ee/?id=36381
        failing_numbers = [
            ('14212128027', 'EE', '+37200009', 302),
            ('38002240211', 'EE', '+37200001', 303),
        ]

        for id_code, country, phone_nr, error_code in failing_numbers:
            service = get_digidoc_service()

            with pytest.raises(DigiDocError) as e:
                service.mobile_authenticate(id_code=id_code, country=country, phone_nr=phone_nr)

            self.assertEqual(e.value.error_code, error_code)


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
        service2 = get_digidoc_service()
        service2.start_session(True, sig_doc_xml=force_text(base64.b64encode(own_hash_file_data)))
        service2.mobile_sign(id_code='11412090004', country='EE', phone_nr='+37200000766')
        status_info = service2.get_status_info(wait=True)
        self.assertEqual(status_info['StatusCode'], 'SIGNATURE')

        service2.get_file_data(data_files)
