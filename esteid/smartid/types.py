from collections import namedtuple


AuthenticateResult = namedtuple(
    "AuthenticateResult",
    [
        "session_id",
        "hash_type",
        "hash_value",
        "verification_code",
    ],
)

AuthenticateStatusResult = namedtuple(
    "AuthenticateStatusResult",
    [
        "document_number",
        "certificate",  # DER-encoded certificate
        "certificate_level",
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

SignStatusResult = namedtuple(
    "SignStatusResult",
    [
        "document_number",
        "signature",
        "signature_algorithm",
        "certificate",  # DER-encoded certificate
        "certificate_level",
    ],
)
