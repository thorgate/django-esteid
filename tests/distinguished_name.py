# -*- coding: utf-8 -*-
import pytest

from esteid.helpers import parse_rfc_dn, parse_legacy_dn


@pytest.mark.parametrize('distinguished_name,expected_res', [
    (
        u'serialNumber=51001091072,GN=SEITSMES,SN=TESTN\\C3\\9CMBER,'
        u'CN=TESTN\\C3\\9CMBER\\,SEITSMES\\,51001091072,OU=authentication,O=ESTEID,C=EE',
        {
            'serialNumber': '51001091072',
            'GN': 'SEITSMES',
            'SN': u'TESTNÜMBER',
            'CN': u'TESTNÜMBER,SEITSMES,51001091072',
            'OU': 'authentication',
            'O': 'ESTEID',
            'C': 'EE',
        },
    )
])
def test_parse_rfc_dn(distinguished_name, expected_res):
    result = parse_rfc_dn(distinguished_name)

    assert result == expected_res


@pytest.mark.parametrize('distinguished_name,expected_res', [
    (
        u'/serialNumber=51001091072/GN=SEITSMES/SN=TESTN\\C3\\9CMBER'
        u'/CN=TESTN\\C3\\9CMBER,SEITSMES,51001091072/OU=authentication/O=ESTEID/C=EE',
        {
            'serialNumber': '51001091072',
            'GN': 'SEITSMES',
            'SN': u'TESTNÜMBER',
            'CN': u'TESTNÜMBER,SEITSMES,51001091072',
            'OU': 'authentication',
            'O': 'ESTEID',
            'C': 'EE',
        },
    )
])
def test_parse_legacy_dn(distinguished_name, expected_res):
    result = parse_legacy_dn(distinguished_name)

    assert result == expected_res
