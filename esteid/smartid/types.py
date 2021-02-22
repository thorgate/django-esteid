from collections import namedtuple
from typing import Optional

from esteid.constants import Countries
from esteid.signing.types import InterimSessionData
from esteid.types import PredictableDict
from esteid.validators import validate_id_code


AuthenticateResult = namedtuple(
    "AuthenticateResult",
    [
        "session_id",
        "hash_type",
        "hash_value",
        "hash_value_b64",
        "verification_code",
    ],
)

AuthenticateStatusResult = namedtuple(
    "AuthenticateStatusResult",
    [
        "document_number",
        "certificate",  # DER-encoded certificate
        "certificate_b64",  # Base64-encoded DER-encoded certificate
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


class UserInput(PredictableDict):
    id_code: str
    country: Optional[str]

    def is_valid(self, raise_exception=True):
        """
        Raises InvalidIdCode or ValueError
        """
        result = super().is_valid(raise_exception=raise_exception)
        if result:
            if not (self.get("country") and self.country in Countries.ALL):
                self.country = Countries.ESTONIA

            validate_id_code(self.id_code, self.country)

        return result


class SmartIdSessionData(InterimSessionData):
    session_id: str
