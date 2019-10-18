import base64
import uuid

import pytest

from .base import SmartIDService
from .constants import CERTIFICATE_LEVEL_QUALIFIED, END_RESULT_OK, HASH_SHA512, STATE_COMPLETE
from .crypto import generate_hash, get_verification_code
from .i18n import TranslatedSmartIDService
from .types import AuthenticateResult


@pytest.fixture(scope='function')
def demo_api():
    return SmartIDService(uuid.UUID('00000000-0000-0000-0000-000000000000'), 'DEMO')


@pytest.fixture(scope='function')
def i18n_demo_api():
    return TranslatedSmartIDService(uuid.UUID('00000000-0000-0000-0000-000000000000'), 'DEMO')


@pytest.fixture()
def static_hash():
    return b'Hello SMART-ID'


@pytest.fixture()
def static_signature_algorithm():
    return 'sha512WithRSAEncryption'


@pytest.fixture()
def static_signature():
    return base64.b64decode(
        'Ooa9Jf4Wg+SrxaXbxFavk8gL6Bo/DIggk4NUxxzzzR5piVD6fNgNdo2bYXh3gWB9I9veyf3uqGotefvOlR8X7ndPJo'
        'yqfUIdftx5GI301XLqJnIYEERFlwRDyEwIVOH149B9feLVEEzr+ArXWa12TyelxvcYv2TgLUjgokFk8j8aimdA4jY+'
        'HR/nirvQO7gy8MkzjMoagvxOSAKoRFaOPUP5KT2qIPDC2wwHwShRctdQlWsAyto1G5Pdm82FHK3OYOLQPBNuhz8+CT'
        '2iKxZY/Uqi6Xr+Mc1JKHK/IPo9MYUFDW+FvKFixF9efnDuRhOTSpj6scvvr00EQoBCAyZpPzlfd/aQddcVnyGvNxDQ'
        '02OkksmdWLgzsYGwBLyJnAjGN1MOl++mXf508/ctkWHgyrJUP8r6PWOMriz1gP8VJPe6h7e0cmvexgoZmLFV9Xev23'
        'iNyJ7VG0ovhjC2Bw84qQ6by3WebJzadmFznPbeLdxpwCJVw/aoc2pyASDATjAVWimUt2fJD4VY8f3XQz0bBIUG4TbP'
        'wbX7wyDewQOXgU0UAPqKGh/2130f3Y7eV3Sjv2xFxk4ih4RIMoruEQfOK/b92UGg6RsS9+ctHH1LftLZO3HdF8sfDQ'
        'hvWDPvbzmFa2gD3RaKR6QguGfauxbtE78ARZiAnrtkcHHOjYc/p0k='
    )


@pytest.fixture()
def static_certificate():
    return base64.b64decode(
        b'MIIHojCCBYqgAwIBAgIQV054KJa3Z/ZYkvh96o3PtzANBgkqhkiG9w0BAQsFADBnMQswCQYDVQQGEwJFRTEiMCAGA'
        b'1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxGzAZBgNVBAMMEl'
        b'RFU1Qgb2YgTlEtU0sgMjAxNjAeFw0xNzAyMDIwOTE0MzdaFw0yMjAyMDEyMTU5NTlaMIG0MQswCQYDVQQGEwJFRTE'
        b'iMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEXMBUGA1UECwwOYXV0aGVudGljYXRpb24xKTAnBgNV'
        b'BAMMIFNNQVJULUlELEhFTExPLFBOT0VFLTExNzAyMDIwMjAwMREwDwYDVQQEDAhTTUFSVC1JRDEOMAwGA1UEKgwFS'
        b'EVMTE8xGjAYBgNVBAUTEVBOT0VFLTExNzAyMDIwMjAwMIICITANBgkqhkiG9w0BAQEFAAOCAg4AMIICCQKCAgBnO0'
        b'Xm9670tbqRd8744SD+zVltpmKSOAP7/mx1uvjTLBZ2ZiCKR0Obhnl4fjwZtDr5HBk5MbzQsgtB0effkgImm2pJBhb'
        b'qhZKBwrEPaxqDIQjlq15MtrGIkVAwAw5ZMEoODZRSGW6c8qGzyy91IaSvbJLZP0tiXMZ/t4kL+Ncd7gHqvU0N/Dxj'
        b'gp9ZAm3nUegdGv8xXRm1wfULAU2mvSh5PN7AbXV+/r+4kEryWzg0IecDCcnKI7R41hnSHuHy2AGLW4OinF/gG45At'
        b'yLVQ98z039jlzvW0wTrQXqEGGgupuRL5DU1kZWCr6Jd97ZH55qCn+zKWW1GZqSJX4Bl+ZKp7p2FABJcnBY/fW4/DF'
        b'gn47Nv9353FrJCSSYuuPUV5B0udT5Esqiipa5Gd7UKSnZdP7QWPrNr8PHJYmoqrV1JU+MYOkDFxhiPkSD9+uM2lD4'
        b'w6hyHdGYjVIWsFmuZuEBscZuCoeBJ6PDRPyIXj+bUyQLA7Xk1Y+nvw2Ov/HMyX6Lm2pLS3JtNZbpoNmnEaYVx44MA'
        b'JihcI9WeSiO2OkLDdrAAZ5rR8zs7h91j0+VodwJEA21/6jz0uuj7oHkEVLEiYHu3j3xLb0mc5izw14d3v1V8U9jKd'
        b'1WTcEI+ztPLXi/J9ui1dWaLHan39NVSaeY1OLl6Y+CQ/paUk7Ip6G6/0wIDAQABo4IB+zCCAfcwCQYDVR0TBAIwAD'
        b'AOBgNVHQ8BAf8EBAMCBLAwVQYDVR0gBE4wTDBABgorBgEEAc4fAxEBMDIwMAYIKwYBBQUHAgEWJGh0dHBzOi8vd3d'
        b'3LnNrLmVlL2VuL3JlcG9zaXRvcnkvQ1BTLzAIBgYEAI96AQEwHQYDVR0OBBYEFKuuRKgRbLqsrFdZDyUhMTXlWcWv'
        b'MIGCBggrBgEFBQcBAwR2MHQwUQYGBACORgEFMEcwRRY/aHR0cHM6Ly9zay5lZS9lbi9yZXBvc2l0b3J5L2NvbmRpd'
        b'GlvbnMtZm9yLXVzZS1vZi1jZXJ0aWZpY2F0ZXMvEwJFTjAVBggrBgEFBQcLAjAJBgcEAIvsSQEBMAgGBgQAjkYBAT'
        b'AfBgNVHSMEGDAWgBSsw050xt/OPR3E74FhBbZv3UkdPTATBgNVHSUEDDAKBggrBgEFBQcDAjB2BggrBgEFBQcBAQR'
        b'qMGgwIwYIKwYBBQUHMAGGF2h0dHA6Ly9haWEuc2suZWUvbnEyMDE2MEEGCCsGAQUFBzAChjVodHRwczovL3NrLmVl'
        b'L3VwbG9hZC9maWxlcy9URVNUX29mX05RLVNLXzIwMTYuZGVyLmNydDAxBgNVHREEKjAopCYwJDEiMCAGA1UEAwwZU'
        b'E5PRUUtMTE3MDIwMjAyMDAtMDVOWC1OUTANBgkqhkiG9w0BAQsFAAOCAgEAkolGIm7+tLHXHxYVCz78m7GoUkXD/u'
        b'8lYbQyAujo9ZoyVrgPmLXbsCxTqXjUOD7nIjVSNfwEPYFmrkG34to2+JLvt0H/nGUO345VOnsRtvDau58RxU5jeT1'
        b'nFnkCZSdYxpFkr4D276d7qyfATYhEeW4h3F5gjgYslBeLRFHPQwaIyTZmtWJ5RLNzJsqpJgQCeFXu2XLSOwCbG9RT'
        b'CGoaYPv4qiD4kUTSpXQPm+QyOzMidOsVBBOxqdtGCFBp0l8omW7pwQv1nA0dlg7jELh2QaJn7/L6mFyrZGL9Nvi6l'
        b'UrGhz+0p1xPDl9iW99a+UokcWUA5DsoXKr5ogJlqDluYMk+8Jwpq4sB8mGyYrhqJjDz4c33CU5nfzVrYJDhU0TMFJ'
        b'qqFyLZYriIOYxzXrZ8nNlEQiYRwR4ESUvVXSjppjLGW6oDG63Xr6ktfaMwfucpbzE3rv+c6iJVkBeBk6C//ATClZG'
        b'DNt3oYjydFgkAccjyiOsojmO3JM3ymi17ueXC8B14vyMGkX9z3ZyOW04kAdeyYT1XIQUeeBu0OrTC+D6kuFk/dAYT'
        b'6mfSuVBFivkmzUHVMS3mFUSBCInDv29gul5PSd3kWybhvVvxTD0E/WzuGRg5iJmKsbpCgS6WcP/A3I0W/zvUTcAii'
        b'mN3NoztEEMV6tiHeDB/zjIiNcOaQQE='
    )


@pytest.fixture(scope='function')
def static_auth_result(static_hash):
    return AuthenticateResult(
        session_id='FAKE',
        hash_raw=static_hash,
        hash_value=generate_hash(HASH_SHA512, static_hash),
        hash_type=HASH_SHA512,
        verification_code=get_verification_code(static_hash),
    )


@pytest.fixture(scope='function')
def static_status_response(static_signature, static_signature_algorithm, static_certificate):
    return {
        'state': STATE_COMPLETE,
        'result': {
            'endResult': END_RESULT_OK,
            'documentNumber': '$documentNumber$',
        },
        'signature': {
            'algorithm': static_signature_algorithm,
            'value': base64.b64encode(static_signature),
        },
        'cert': {
            'value': base64.b64encode(static_certificate),
            'certificateLevel': CERTIFICATE_LEVEL_QUALIFIED,
        },
    }
