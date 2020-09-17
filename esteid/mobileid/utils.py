def get_verification_code(hash_value):
    """Compute Mobile-ID verification code from a hash

    Excerpt from https://github.com/SK-EID/MID#241-verification-code-calculation-algorithm

    1. 6 bits from the beginning of hash and 7 bits from the end of hash are taken.
    2. The resulting 13 bits are transformed into decimal number and printed out.

    The Verification code is a decimal 4-digits number in range 0000...8192, always 4 digits are displayed (e.g. 0041).

    :param bytes hash_value:
    """
    if not isinstance(hash_value, bytes):
        raise TypeError(f"Invalid hash value: expected bytes, got {type(hash_value)}")

    if not hash_value:
        raise ValueError("Hash value can not be empty")

    leading_byte = hash_value[0]
    trailing_byte = hash_value[-1]

    leading_6_bits = leading_byte >> 2
    trailing_7_bits = trailing_byte & 0x7F

    return "{:04d}".format((leading_6_bits << 7) + trailing_7_bits)
