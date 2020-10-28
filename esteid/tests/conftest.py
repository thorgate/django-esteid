import base64

import pytest


@pytest.fixture
def signed_doc_dict():
    return {
        "dataFileInfo": [
            {
                "contentType": "HASHCODE",
                "digestType": "sha256",
                "digestValue": "Mmb3rosrMXMY86F4P+Pj0VQEQnpDquhEarJ00RelWXE=",
                "filename": "something.pdf",
                "id": "something.pdf",
                "mimeType": "application/pdf",
                "size": 27216,
            }
        ],
        "format": "BDOC",
        "signature_info": [
            {
                "confirmation": {
                    "produced_at": "2016-10-03T11:00:05Z",
                    "responder_certificate": {
                        "issuer": "C=EE/O=AS Sertifitseerimiskeskus/CN=TEST of EE Certification Centre Root CA/"
                        "emailAddress=pki@sk.ee",
                        "issuer_serial": "138983222239407220571566848351990841243",
                        "policies": [
                            {
                                "description": "Ainult testimiseks. Only for testing.",
                                "oid": "1.3.6.1.4.1.10015.3.1.1",
                                "url": "http://www.sk.ee/ajatempel/",
                            }
                        ],
                        "subject": "C=EE/O=AS Sertifitseerimiskeskus/OU=OCSP/CN=TEST of SK OCSP RESPONDER 2011/"
                        "emailAddress=pki@sk.ee",
                        "valid_from": "2011-03-07T13:22:45Z",
                        "valid_to": "2024-09-07T12:22:45Z",
                    },
                    "responder_id": "C=EE/O=AS Sertifitseerimiskeskus/OU=OCSP/CN=TEST of SK OCSP RESPONDER 2011/"
                    "emailAddress=pki@sk.ee",
                },
                "id": "S0",
                "signature_production_place": None,
                "signer": {
                    "certificate": {
                        "issuer": "C=EE/O=AS Sertifitseerimiskeskus/CN=TEST of ESTEID-SK 2011/emailAddress=pki@sk.ee",
                        "issuer_serial": "61232248526689391803484677403602728985",
                        "policies": [
                            {
                                "description": "Ainult testimiseks. Only for testing.",
                                "oid": "1.3.6.1.4.1.10015.3.3.1",
                                "url": "http://www.sk.ee/cps/",
                            }
                        ],
                        "subject": "C=EE/O=ESTEID (MOBIIL-ID)/OU=digital signature/CN=TESTNUMBER,SEITSMES,14212128025"
                        "/SN=TESTNUMBER/GN=SEITSMES/serialNumber=14212128025",
                        "valid_from": "2015-04-06T09:45:41Z",
                        "valid_to": "2016-12-31T21:59:59Z",
                    },
                    "full_name": "Seitsmes Testnumber",
                    "id_code": "14212128025",
                },
                "signer_role": [{"certified": 0, "role": None}],
                "signing_time": "2016-10-03T10:59:54Z",
                "status": True,
            }
        ],
        "version": "2.1",
    }


@pytest.fixture()
def static_random_text():
    """This is the text that was used to generate the signature below"""
    return b"Hello SMART-ID"


@pytest.fixture()
def static_signature_algorithm():
    return "sha512WithRSAEncryption"


@pytest.fixture()
def static_signature():
    return base64.b64decode(
        "Ooa9Jf4Wg+SrxaXbxFavk8gL6Bo/DIggk4NUxxzzzR5piVD6fNgNdo2bYXh3gWB9I9veyf3uqGotefvOlR8X7ndPJo"
        "yqfUIdftx5GI301XLqJnIYEERFlwRDyEwIVOH149B9feLVEEzr+ArXWa12TyelxvcYv2TgLUjgokFk8j8aimdA4jY+"
        "HR/nirvQO7gy8MkzjMoagvxOSAKoRFaOPUP5KT2qIPDC2wwHwShRctdQlWsAyto1G5Pdm82FHK3OYOLQPBNuhz8+CT"
        "2iKxZY/Uqi6Xr+Mc1JKHK/IPo9MYUFDW+FvKFixF9efnDuRhOTSpj6scvvr00EQoBCAyZpPzlfd/aQddcVnyGvNxDQ"
        "02OkksmdWLgzsYGwBLyJnAjGN1MOl++mXf508/ctkWHgyrJUP8r6PWOMriz1gP8VJPe6h7e0cmvexgoZmLFV9Xev23"
        "iNyJ7VG0ovhjC2Bw84qQ6by3WebJzadmFznPbeLdxpwCJVw/aoc2pyASDATjAVWimUt2fJD4VY8f3XQz0bBIUG4TbP"
        "wbX7wyDewQOXgU0UAPqKGh/2130f3Y7eV3Sjv2xFxk4ih4RIMoruEQfOK/b92UGg6RsS9+ctHH1LftLZO3HdF8sfDQ"
        "hvWDPvbzmFa2gD3RaKR6QguGfauxbtE78ARZiAnrtkcHHOjYc/p0k="
    )


@pytest.fixture()
def static_certificate():
    return base64.b64decode(
        b"MIIHojCCBYqgAwIBAgIQV054KJa3Z/ZYkvh96o3PtzANBgkqhkiG9w0BAQsFADBnMQswCQYDVQQGEwJFRTEiMCAGA"
        b"1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxGzAZBgNVBAMMEl"
        b"RFU1Qgb2YgTlEtU0sgMjAxNjAeFw0xNzAyMDIwOTE0MzdaFw0yMjAyMDEyMTU5NTlaMIG0MQswCQYDVQQGEwJFRTE"
        b"iMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEXMBUGA1UECwwOYXV0aGVudGljYXRpb24xKTAnBgNV"
        b"BAMMIFNNQVJULUlELEhFTExPLFBOT0VFLTExNzAyMDIwMjAwMREwDwYDVQQEDAhTTUFSVC1JRDEOMAwGA1UEKgwFS"
        b"EVMTE8xGjAYBgNVBAUTEVBOT0VFLTExNzAyMDIwMjAwMIICITANBgkqhkiG9w0BAQEFAAOCAg4AMIICCQKCAgBnO0"
        b"Xm9670tbqRd8744SD+zVltpmKSOAP7/mx1uvjTLBZ2ZiCKR0Obhnl4fjwZtDr5HBk5MbzQsgtB0effkgImm2pJBhb"
        b"qhZKBwrEPaxqDIQjlq15MtrGIkVAwAw5ZMEoODZRSGW6c8qGzyy91IaSvbJLZP0tiXMZ/t4kL+Ncd7gHqvU0N/Dxj"
        b"gp9ZAm3nUegdGv8xXRm1wfULAU2mvSh5PN7AbXV+/r+4kEryWzg0IecDCcnKI7R41hnSHuHy2AGLW4OinF/gG45At"
        b"yLVQ98z039jlzvW0wTrQXqEGGgupuRL5DU1kZWCr6Jd97ZH55qCn+zKWW1GZqSJX4Bl+ZKp7p2FABJcnBY/fW4/DF"
        b"gn47Nv9353FrJCSSYuuPUV5B0udT5Esqiipa5Gd7UKSnZdP7QWPrNr8PHJYmoqrV1JU+MYOkDFxhiPkSD9+uM2lD4"
        b"w6hyHdGYjVIWsFmuZuEBscZuCoeBJ6PDRPyIXj+bUyQLA7Xk1Y+nvw2Ov/HMyX6Lm2pLS3JtNZbpoNmnEaYVx44MA"
        b"JihcI9WeSiO2OkLDdrAAZ5rR8zs7h91j0+VodwJEA21/6jz0uuj7oHkEVLEiYHu3j3xLb0mc5izw14d3v1V8U9jKd"
        b"1WTcEI+ztPLXi/J9ui1dWaLHan39NVSaeY1OLl6Y+CQ/paUk7Ip6G6/0wIDAQABo4IB+zCCAfcwCQYDVR0TBAIwAD"
        b"AOBgNVHQ8BAf8EBAMCBLAwVQYDVR0gBE4wTDBABgorBgEEAc4fAxEBMDIwMAYIKwYBBQUHAgEWJGh0dHBzOi8vd3d"
        b"3LnNrLmVlL2VuL3JlcG9zaXRvcnkvQ1BTLzAIBgYEAI96AQEwHQYDVR0OBBYEFKuuRKgRbLqsrFdZDyUhMTXlWcWv"
        b"MIGCBggrBgEFBQcBAwR2MHQwUQYGBACORgEFMEcwRRY/aHR0cHM6Ly9zay5lZS9lbi9yZXBvc2l0b3J5L2NvbmRpd"
        b"GlvbnMtZm9yLXVzZS1vZi1jZXJ0aWZpY2F0ZXMvEwJFTjAVBggrBgEFBQcLAjAJBgcEAIvsSQEBMAgGBgQAjkYBAT"
        b"AfBgNVHSMEGDAWgBSsw050xt/OPR3E74FhBbZv3UkdPTATBgNVHSUEDDAKBggrBgEFBQcDAjB2BggrBgEFBQcBAQR"
        b"qMGgwIwYIKwYBBQUHMAGGF2h0dHA6Ly9haWEuc2suZWUvbnEyMDE2MEEGCCsGAQUFBzAChjVodHRwczovL3NrLmVl"
        b"L3VwbG9hZC9maWxlcy9URVNUX29mX05RLVNLXzIwMTYuZGVyLmNydDAxBgNVHREEKjAopCYwJDEiMCAGA1UEAwwZU"
        b"E5PRUUtMTE3MDIwMjAyMDAtMDVOWC1OUTANBgkqhkiG9w0BAQsFAAOCAgEAkolGIm7+tLHXHxYVCz78m7GoUkXD/u"
        b"8lYbQyAujo9ZoyVrgPmLXbsCxTqXjUOD7nIjVSNfwEPYFmrkG34to2+JLvt0H/nGUO345VOnsRtvDau58RxU5jeT1"
        b"nFnkCZSdYxpFkr4D276d7qyfATYhEeW4h3F5gjgYslBeLRFHPQwaIyTZmtWJ5RLNzJsqpJgQCeFXu2XLSOwCbG9RT"
        b"CGoaYPv4qiD4kUTSpXQPm+QyOzMidOsVBBOxqdtGCFBp0l8omW7pwQv1nA0dlg7jELh2QaJn7/L6mFyrZGL9Nvi6l"
        b"UrGhz+0p1xPDl9iW99a+UokcWUA5DsoXKr5ogJlqDluYMk+8Jwpq4sB8mGyYrhqJjDz4c33CU5nfzVrYJDhU0TMFJ"
        b"qqFyLZYriIOYxzXrZ8nNlEQiYRwR4ESUvVXSjppjLGW6oDG63Xr6ktfaMwfucpbzE3rv+c6iJVkBeBk6C//ATClZG"
        b"DNt3oYjydFgkAccjyiOsojmO3JM3ymi17ueXC8B14vyMGkX9z3ZyOW04kAdeyYT1XIQUeeBu0OrTC+D6kuFk/dAYT"
        b"6mfSuVBFivkmzUHVMS3mFUSBCInDv29gul5PSd3kWybhvVvxTD0E/WzuGRg5iJmKsbpCgS6WcP/A3I0W/zvUTcAii"
        b"mN3NoztEEMV6tiHeDB/zjIiNcOaQQE="
    )
