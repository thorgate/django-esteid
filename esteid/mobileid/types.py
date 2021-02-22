import re
from collections import namedtuple
from typing import Optional

from esteid import settings
from esteid.constants import Languages
from esteid.exceptions import InvalidIdCode, InvalidParameter
from esteid.signing.types import InterimSessionData
from esteid.types import PredictableDict
from esteid.validators import id_code_ee_is_valid


PHONE_NUMBER_REGEXP = settings.MOBILE_ID_PHONE_NUMBER_REGEXP

AuthenticateResult = namedtuple(
    "AuthenticateResult",
    [
        "session_id",
        "hash_type",
        "hash_value",
        "verification_code",
        "hash_value_b64",
    ],
)

AuthenticateStatusResult = namedtuple(
    "AuthenticateStatusResult",
    [
        "certificate",  # DER-encoded certificate
        "certificate_b64",  # Base64-encoded DER-encoded certificate
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


class UserInput(PredictableDict):
    phone_number: str
    id_code: str
    language: Optional[str]

    def is_valid(self, raise_exception=True):
        result = super().is_valid(raise_exception=raise_exception)
        if result:
            if not self.phone_number or PHONE_NUMBER_REGEXP and not re.match(PHONE_NUMBER_REGEXP, self.phone_number):
                if not raise_exception:
                    return False
                raise InvalidParameter(param="phone_number")
            if not id_code_ee_is_valid(self.id_code):
                if not raise_exception:
                    return False
                raise InvalidIdCode
            if not (self.get("language") and self.language in Languages.ALL):
                self.language = settings.MOBILE_ID_DEFAULT_LANGUAGE
        return result


class MobileIdSessionData(InterimSessionData):
    session_id: str
