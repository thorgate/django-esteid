import base64
import typing
from typing import Literal

import pyasice

from ..constants import HASH_SHA256, HASH_SHA384, HASH_SHA512
from ..exceptions import InvalidParameters, SignatureVerificationError
from ..types import PredictableDict
from ..util import generate_hash


SignatureAlgorithm = Literal["ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512"]
SIGNATURE_ALGORITHMS = list(typing.get_args(SignatureAlgorithm))


def require_not_empty(value, param):
    if not value:
        raise InvalidParameters(f"Parameter {param} is required")


HASH_ALGORITHM_MAPPING = {
    "ES256": HASH_SHA256,
    "ES384": HASH_SHA384,
    "ES512": HASH_SHA512,
    "PS256": HASH_SHA256,
    "PS384": HASH_SHA384,
    "PS512": HASH_SHA512,
    "RS256": HASH_SHA256,
    "RS384": HASH_SHA384,
    "RS512": HASH_SHA512,
}


class LibraryAuthenticateResponse(PredictableDict):
    """
    Response to the web-eid `authenticate` call.

    Ref: https://github.com/web-eid/web-eid.js#authenticate-result
    """

    # base64-encoded DER encoded authentication certificate of the user
    unverifiedCertificate: str

    # algorithm used to produce the authentication signature
    algorithm: SignatureAlgorithm

    # base64-encoded signature of the token
    signature: str

    # type identifier and version of the token format separated by a colon character.
    #  example "web-eid:1.0"
    format: str

    # URL identifying the name and version of the application that issued the token
    #  example "https://web-eid.eu/web-eid-app/releases/2.0.0+0"
    appVersion: str

    def is_valid(self, raise_exception=True):
        res = super().is_valid(raise_exception)

        if res:
            require_not_empty(self.algorithm, "algorithm")
            require_not_empty(self.signature, "signature")

            if self.algorithm not in SIGNATURE_ALGORITHMS:
                raise InvalidParameters("Unsupported signature algorithm")

        return res

    @property
    def certificate_bytes(self):
        return base64.b64decode(self.unverifiedCertificate)

    @property
    def signature_bytes(self):
        return base64.b64decode(self.signature)

    def validate_signature(self, certificate, origin: str, challenge_nonce: bytes):
        """
        Validates that the signature of the authentication token is valid
        """
        require_not_empty(challenge_nonce, "challenge_nonce")

        hash_algorithm = HASH_ALGORITHM_MAPPING[self.algorithm]

        origin_hash = generate_hash(hash_algorithm, origin.encode())
        nonce_hash = generate_hash(hash_algorithm, challenge_nonce)
        hash_value = origin_hash + nonce_hash

        try:
            pyasice.verify(certificate, self.signature_bytes, hash_value, hash_algorithm, prehashed=False)
        except pyasice.SignatureVerificationError as e:
            raise SignatureVerificationError from e
