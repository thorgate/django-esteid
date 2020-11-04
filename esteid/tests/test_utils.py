import hashlib

import pytest

from esteid.constants import HASH_ALGORITHMS
from esteid.util import generate_hash, id_code_ee_is_valid, id_code_lt_is_valid, id_code_lv_is_valid


@pytest.mark.parametrize("hash_algo", HASH_ALGORITHMS)
def test_hashtypes(hash_algo):
    hash_value = generate_hash(hash_algo, b"FOOBAR")

    hash_method = getattr(hashlib, hash_algo.lower())
    assert hash_value == hash_method(b"FOOBAR").digest()


def test_invalid_hash_algo_fails():
    with pytest.raises(ValueError):
        generate_hash("FAKEHASH", b"FOOBAR")


@pytest.mark.parametrize(
    "id_code, result",
    [
        pytest.param("", False, id="empty string"),
        pytest.param(None, False, id="None"),
        pytest.param(["10101010005"], False, id="list"),
        pytest.param("ABCDEFGHQWE", False, id="not digits"),
        pytest.param("10101010", False, id="not enough digits"),
        pytest.param("10101010OO5", False, id="not all digits (0-O)"),
        pytest.param("123456789O123456", False, id="too many digits"),
        pytest.param("10101010101", False, id="wrong checksum"),
        pytest.param("10101010005", True, id="test SmartID code"),
        pytest.param("60001019906", True, id="test MobileID code"),
        pytest.param("37605030299", True, id="From Wikipedia"),
    ],
)
def test_id_code_ee_lt_is_valid(id_code, result):
    assert id_code_ee_is_valid(id_code) == result
    assert id_code_lt_is_valid(id_code) == result, "LT ID codes are same format as EE"


@pytest.mark.parametrize(
    "id_code, result",
    [
        pytest.param("", False, id="empty string"),
        pytest.param(None, False, id="None"),
        pytest.param(["010101-10006"], False, id="list"),
        pytest.param("ABCDEF-QWERT", False, id="not digits"),
        pytest.param("01010110006", False, id="no dash"),
        pytest.param("010101-1OOO6", False, id="not all digits (0-O)"),
        pytest.param("123456-789O123456", False, id="too many digits"),
        pytest.param("010101-01010", False, id="wrong checksum"),
        pytest.param("010101-10006", True, id="test MobileID code"),
        pytest.param("111111-11111", True, id="From gihtub/id-lv"),
    ],
)
def test_id_code_lv_is_valid(id_code, result):
    assert id_code_lv_is_valid(id_code) == result
