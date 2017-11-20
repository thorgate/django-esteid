# -*- coding: utf-8 -*-
import pytest

from esteid.helpers import get_name_from_legacy_common_name, get_id_from_legacy_common_name


@pytest.mark.parametrize('common_name,expected_name', [
    ('TESTNUMBER,SEITSMES,51001091072', 'Seitsmes Testnumber'),
    ('TESTNUMBER\\,SEITSMES\\,51001091072', 'Seitsmes Testnumber'),
    ('TEST-NUMBER,SEITSMES MEES,51001091072', 'Seitsmes Mees Test-Number'),
    (u'O’CONNEŽ-ŠUSLIK,MARY ÄNN,11412090004', u'Mary Änn O’Connež-Šuslik'),
])
def test_get_name_from_legacy_common_name(common_name, expected_name):
    result = get_name_from_legacy_common_name(common_name)

    assert result == expected_name


@pytest.mark.parametrize('common_name,expected_id', [
    ('TESTNUMBER,SEITSMES,51001091072', '51001091072'),
    ('TESTNUMBER\\,SEITSMES\\,51001091072', '51001091072'),
    ('TEST-NUMBER,SEITSMES MEES,51001091072', '51001091072'),
    (u'O’CONNEŽ-ŠUSLIK,MARY ÄNN,11412090004', u'11412090004'),
])
def test_get_id_from_legacy_common_name(common_name, expected_id):
    result = get_id_from_legacy_common_name(common_name)

    assert result == expected_id
