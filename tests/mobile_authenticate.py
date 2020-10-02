# -*- coding: utf-8 -*-
from unittest import TestCase

import binascii
import os
import pytest

from unittest.mock import patch

from esteid.digidocservice.service import DigiDocError

from .conftest import TEST_ID_CODE, TEST_PHONE_NUMBER, get_digidoc_service


class TestMobileAuthenticate(TestCase):
    def test_mobileauthenticate_flow(self):
        service = get_digidoc_service()
        self.assertIsNone(service.session_code)

        # Construct a static sp_challenge so we can verify that it is returned as expected
        sp_challenge = os.urandom(10)

        with patch.object(service, 'get_sp_challenge', return_value=sp_challenge):
            response, _ = service.mobile_authenticate(id_code=TEST_ID_CODE, country='EE',
                                                      phone_nr=TEST_PHONE_NUMBER, return_cert_data=True)

        self.assertEqual(response['Status'], 'OK')
        self.assertEqual(response['UserIDCode'], TEST_ID_CODE)

        self.assertEqual(response['UserCountry'], 'EE')
        self.assertEqual(response['UserGivenname'], u'MARY ÄNN')
        self.assertEqual(response['UserSurname'], u'O’CONNEŽ-ŠUSLIK TESTNUMBER')

        self.assertEqual(len(response['ChallengeID']), 4)
        self.assertGreater(len(response['UserCN']), 0)
        self.assertIsNotNone(response['CertificateData'])

        parsed_response_challenge = binascii.unhexlify(response['Challenge'])
        self.assertTrue(parsed_response_challenge.startswith(sp_challenge))

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

        self.assertTrue(service.verify_mid_signature(response['CertificateData'], sp_challenge, parsed_response_challenge, signature))

        self.assertFalse(service.verify_mid_signature(response['CertificateData'], b'XXXX', parsed_response_challenge, signature))
        self.assertFalse(service.verify_mid_signature(response['CertificateData'], sp_challenge,
                                                      parsed_response_challenge, signature + b'1'))

    def test_mobileauthenticate_return_cert_data(self):
        service = get_digidoc_service()
        response, _ = service.mobile_authenticate(id_code=TEST_ID_CODE, country='EE', phone_nr=TEST_PHONE_NUMBER,
                                                  return_cert_data=True)
        self.assertIsNotNone(response['CertificateData'])

    def test_mobileauthenticate_return_revocation_data(self):
        service = get_digidoc_service()
        response, _ = service.mobile_authenticate(id_code=TEST_ID_CODE, country='EE', phone_nr=TEST_PHONE_NUMBER,
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

    def test_mobileauthenticate_user_cancel(self):
        service = get_digidoc_service()

        # Data from https://www.id.ee/?id=36381
        id_code, phone_nr, country = '14212128022', '+37200004', 'EE'
        service.mobile_authenticate(id_code=id_code, country=country, phone_nr=phone_nr)

        # Test get_mobile_authenticate_status works properly
        status_code, signature = service.get_mobile_authenticate_status(wait=False)
        self.assertIn(status_code, ['OUTSTANDING_TRANSACTION', 'USER_CANCEL'])

        # try again if the authentication is not completed yet
        if status_code != 'USER_CANCEL':
            status_code, signature = service.get_mobile_authenticate_status(wait=True)

        self.assertEqual(status_code, 'USER_CANCEL')
        self.assertIsNone(signature)
