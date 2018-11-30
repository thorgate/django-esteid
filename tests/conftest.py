import os
import sys

import pytest

from zeep import Transport
from zeep.cache import InMemoryCache

from esteid import config
from esteid.digidocservice.service import DigiDocService

BASE_DIR = os.path.dirname(__file__)

sys.path.append(os.path.join(BASE_DIR, '..'))


def get_random_file():
    return os.urandom(4096)


def get_digidoc_service():
    return DigiDocService(wsdl_url=config.wsdl_url(),
                          service_name='Testimine',
                          transport=Transport(cache=InMemoryCache()))


@pytest.fixture
def digidoc_service():
    return get_digidoc_service()


@pytest.fixture
def digidoc_service2():
    return get_digidoc_service()


@pytest.fixture
def lazy_random_file():
    return get_random_file


@pytest.fixture
def signed_doc_dict():
    return {
        'dataFileInfo': [{
            'contentType': 'HASHCODE',
            'digestType': 'sha256',
            'digestValue': 'Mmb3rosrMXMY86F4P+Pj0VQEQnpDquhEarJ00RelWXE=',
            'filename': 'something.pdf',
            'id': 'something.pdf',
            'mimeType': 'application/pdf',
            'size': 27216
        }],
        'format': 'BDOC',
        'signature_info': [{
            'confirmation': {
                'produced_at': '2016-10-03T11:00:05Z',
                'responder_certificate': {
                    'issuer': 'C=EE/O=AS Sertifitseerimiskeskus/CN=TEST of EE Certification Centre Root CA/emailAddress=pki@sk.ee',
                    'issuer_serial': '138983222239407220571566848351990841243',
                    'policies': [{
                        'description': 'Ainult testimiseks. Only for testing.',
                        'oid': '1.3.6.1.4.1.10015.3.1.1',
                        'url': 'http://www.sk.ee/ajatempel/'
                    }],
                    'subject': 'C=EE/O=AS Sertifitseerimiskeskus/OU=OCSP/CN=TEST of SK OCSP RESPONDER 2011/emailAddress=pki@sk.ee',
                    'valid_from': '2011-03-07T13:22:45Z',
                    'valid_to': '2024-09-07T12:22:45Z'
                },
                'responder_id': 'C=EE/O=AS Sertifitseerimiskeskus/OU=OCSP/CN=TEST of SK OCSP RESPONDER 2011/emailAddress=pki@sk.ee'
            },
            'id': 'S0',
            'signature_production_place': None,
            'signer': {
                'certificate': {
                    'issuer': 'C=EE/O=AS Sertifitseerimiskeskus/CN=TEST of ESTEID-SK 2011/emailAddress=pki@sk.ee',
                    'issuer_serial': '61232248526689391803484677403602728985',
                    'policies': [{
                        'description': 'Ainult testimiseks. Only for testing.',
                        'oid': '1.3.6.1.4.1.10015.3.3.1',
                        'url': 'http://www.sk.ee/cps/'
                    }],
                    'subject': 'C=EE/O=ESTEID (MOBIIL-ID)/OU=digital signature/CN=TESTNUMBER,SEITSMES,14212128025'
                               '/SN=TESTNUMBER/GN=SEITSMES/serialNumber=14212128025',
                    'valid_from': '2015-04-06T09:45:41Z',
                    'valid_to': '2016-12-31T21:59:59Z'
                },
                'full_name': 'Seitsmes Testnumber',
                'id_code': '14212128025'
            },
            'signer_role': [{
                'certified': 0,
                'role': None
            }],
            'signing_time': '2016-10-03T10:59:54Z',
            'status': True
        }],
        'version': '2.1'
    }
