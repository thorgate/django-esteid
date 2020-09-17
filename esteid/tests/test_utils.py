import hashlib

import pytest

from esteid.constants import HASH_ALGORITHMS
from esteid.util import generate_hash


@pytest.mark.parametrize("hash_algo", HASH_ALGORITHMS)
def test_hashtypes(hash_algo):
    hash_value = generate_hash(hash_algo, b"FOOBAR")

    hash_method = getattr(hashlib, hash_algo.lower())
    assert hash_value == hash_method(b"FOOBAR").digest()


def test_invalid_hash_algo_fails():
    with pytest.raises(ValueError):
        generate_hash("FAKEHASH", b"FOOBAR")
