# -*- coding: utf-8 -*-
import pytest

from esteid.helpers import parse_rfc_dn, parse_legacy_dn


@pytest.mark.parametrize('distinguished_name,expected_res', [
    (
        'serialNumber=51001091072,GN=SEITSMES,SN=TESTNUMBER,CN=TESTNUMBER\\,SEITSMES\\,51001091072,OU=authentication,O=ESTEID,C=EE',
        {
            'serialNumber': '51001091072',
            'GN': 'SEITSMES',
            'SN': 'TESTNUMBER',
            'CN': 'TESTNUMBER,SEITSMES,51001091072',
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
        '/serialNumber=51001091072/GN=SEITSMES/SN=TESTNUMBER/CN=TESTNUMBER,SEITSMES,51001091072/OU=authentication/O=ESTEID/C=EE',
        {
            'serialNumber': '51001091072',
            'GN': 'SEITSMES',
            'SN': 'TESTNUMBER',
            'CN': 'TESTNUMBER,SEITSMES,51001091072',
            'OU': 'authentication',
            'O': 'ESTEID',
            'C': 'EE',
        },
    )
])
def test_parse_legacy_dn(distinguished_name, expected_res):
    result = parse_legacy_dn(distinguished_name)

    assert result == expected_res
