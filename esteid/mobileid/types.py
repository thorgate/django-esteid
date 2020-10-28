from collections import namedtuple


AuthenticateResult = namedtuple(
    "AuthenticateResult",
    [
        "session_id",
        "hash_type",
        "digest",
        "verification_code",
    ],
)

AuthenticateStatusResult = namedtuple(
    "AuthenticateStatusResult",
    [
        "signature",
        "signature_algorithm",
        "certificate",  # DER-encoded certificate
    ],
)

SignResult = namedtuple(
    "SignResult",
    [
        "session_id",
        "digest",
        "verification_code",
    ],
)

# Note: MobileID doesn't return a certificate for SignStatus. It is set from a previous call to `/certificate`
SignStatusResult = namedtuple(
    "SignStatusResult",
    [
        "signature",
        "signature_algorithm",
        "certificate",
    ],
)
