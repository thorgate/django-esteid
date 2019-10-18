import hashlib
import os
import struct

from .constants import HASH_ALGORITHMS


def secure_random(n):
    return os.urandom(n)


def generate_hash(algorithm, data):
    """Generate hash the data with the supplied algorithm

    based on https://github.com/SK-EID/smart-id-documentation#611-sending-authentication-request
    """
    hash_method = HASH_ALGORITHMS[algorithm]
    digest = hash_method(data).digest()

    return digest


def get_verification_code(hash_value):
    """Compute Smart-ID verification code from a hash

    Verification Code is computed with: `integer(SHA256(hash)[-2:-1]) mod 10000`

    1. Take SHA256 result of hash_value
    2. Extract 2 rightmost bytes from it
    3. Interpret them as a big-endian unsigned short
    4. Take the last 4 digits in decimal

    Note: SHA256 is always used, e.g. the algorithm used when generating the hash does not matter

    based on https://github.com/SK-EID/smart-id-documentation#612-computing-the-verification-code
    """
    digest = hashlib.sha256(hash_value).digest()

    return '{:04}'.format(struct.unpack('>H', digest[-2:])[0] % 10000)
