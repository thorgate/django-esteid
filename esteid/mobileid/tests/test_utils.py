import hashlib

import pytest

from ..utils import get_verification_code


@pytest.mark.parametrize(
    "hash_value,expected_verification_code",
    [
        (b"\x00\x00", "0000"),
        (b"00", "1584"),
        (hashlib.sha256(b"test").digest(), "5000"),
        (hashlib.sha512(b"test").digest(), "7679"),
    ],
)
def test_mobileid_get_verification_code(expected_verification_code, hash_value):
    assert get_verification_code(hash_value) == expected_verification_code
