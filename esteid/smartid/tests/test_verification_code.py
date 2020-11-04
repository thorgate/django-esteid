import pytest

from esteid.constants import HASH_SHA256
from esteid.smartid.utils import get_verification_code
from esteid.util import generate_hash


@pytest.mark.parametrize(
    "expected_verification_code,hash_raw",
    [
        ("7712", b"Hello World!"),
        ("3404", b"You broke it, didn't you."),
        ("0914", b"Weeeeeeeeeeeeeeeeeeeeee[bzzt]"),
    ],
)
def test_verification_code_generator(expected_verification_code, hash_raw):
    assert get_verification_code(generate_hash(HASH_SHA256, hash_raw)) == expected_verification_code
