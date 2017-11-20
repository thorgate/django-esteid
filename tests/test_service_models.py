from esteid.digidocservice.types import SignedDocInfo, DataFileInfo


def test_signeddocinfo_from_dict():
    # smoketest for signed doc parsing
    instance = SignedDocInfo.from_dict({
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
    })

    assert instance.format == 'BDOC'
    assert instance.version == '2.1'

    assert instance.data_file_info == [
        DataFileInfo.from_dict({
            'contentType': 'HASHCODE',
            'digestType': 'sha256',
            'digestValue': 'Mmb3rosrMXMY86F4P+Pj0VQEQnpDquhEarJ00RelWXE=',
            'filename': 'something.pdf',
            'id': 'something.pdf',
            'mime_type': 'application/pdf',
            'size': 27216,
        })
    ]
