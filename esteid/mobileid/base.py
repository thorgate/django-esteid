import base64

import pyasice

from esteid import settings

from ..base_service import BaseSKService
from ..constants import HASH_ALGORITHMS, HASH_SHA256, Languages
from ..exceptions import CanceledByUser
from ..exceptions import EsteidError as MobileIDError
from ..exceptions import InvalidIdCode, SignatureVerificationError, UpstreamServiceError, UserNotRegistered, UserTimeout
from ..util import generate_hash, id_code_ee_is_valid, secure_random
from .constants import EndResults
from .types import AuthenticateResult, AuthenticateStatusResult, SignResult, SignStatusResult
from .utils import get_verification_code


class MobileIDService(BaseSKService):
    """Mobile-ID Authentication and signing

    Based on https://github.com/SK-EID/MID

    Test api root: https://tsp.demo.sk.ee/mid-api
    Production api root: https://mid.sk.ee/mid-api

    Fixme:
        - Add more logging
    """

    # Notes: the texts must not exceed 20 characters in length!
    DISPLAY_TEXT_AUTH = "Authenticate"
    DISPLAY_TEXT_SIGN = "Sign"

    NAME = "Mobile ID"

    class Actions:
        AUTH = "/authentication"
        SIGN = "/signature"
        SESSION_STATUS = "{action}/session/{session_id}"

    def get_certificate(self, id_code: str, phone_number: str) -> bytes:
        """
        Gets a user certificate that would be used for signing.

        Also checks if the user with these
        """
        if not (id_code and phone_number):
            # TODO proper validation
            raise ValueError("Both id_code and phone_number are required")

        if not id_code_ee_is_valid(id_code):
            raise InvalidIdCode

        endpoint = "/certificate"

        result = self.invoke(
            endpoint,
            method="POST",
            data={"phoneNumber": phone_number, "nationalIdentityNumber": id_code},
        )

        status = result["result"]
        if status == "OK":
            return base64.b64decode(result["cert"])
        if status == "NOT_FOUND":
            raise UserNotRegistered(
                "User with phone number {phone} and ID code {id_code} not found".format(
                    phone=phone_number, id_code=id_code
                )
            )
        raise MobileIDError("Unknown response format")

    def authenticate(
        self, id_code: str, phone_number: str, message: str = None, language: str = None, hash_type: str = HASH_SHA256
    ):
        """Initiate an authentication session

        https://github.com/SK-EID/MID#32-initiating-signing-and-authentication

        Difference between auth and signing is the hash: for auth, it's just a random string of the corresponding size
        (the size of a hash produced by selected algorithm) - 32 for SHA256

        https://github.com/SK-EID/MID#23-creating-the-hash

        :param str id_code: National identity number
        :param str phone_number: User's phone number
        :param str message: Text to display for authentication consent dialog on the mobile device, NOTE: max 20 chars!
        :param str language: choices: ENG, EST, LIT, RUS. Defaults to ENG
        :param str hash_type: Hash algorithm to use when generating a random hash value (choices: HASH_ALGORITHMS)
        :return: session ID
        :rtype: AuthenticateResult
        """
        # Ensure required values are set
        if not (id_code and phone_number):
            # TODO proper validation
            raise ValueError("Both id_code and phone_number are required")

        if not id_code_ee_is_valid(id_code):
            raise InvalidIdCode

        assert hash_type in HASH_ALGORITHMS

        message = str(message or self.DISPLAY_TEXT_AUTH)
        assert len(message) <= 20, f"Display text can not exceed 20 chars: got '{message}'"

        if language not in Languages.ALL:
            language = settings.MOBILE_ID_DEFAULT_LANGUAGE

        random_bytes = secure_random(64)
        hash_value = generate_hash(hash_type, random_bytes)
        hash_value_b64 = base64.b64encode(hash_value)

        endpoint = self.Actions.AUTH

        result = self.invoke(
            endpoint,
            method="POST",
            data={
                "nationalIdentityNumber": id_code,
                "phoneNumber": phone_number,
                "hashType": hash_type,
                "hash": hash_value_b64.decode("utf-8"),
                "language": language,
                # Casting to str to ensure translations are resolved
                "displayText": message,  # NOTE: hard 20-char limit
                "displayTextFormat": "UCS-2",  # the other choice is GSM-7 which is 7-bit
            },
        )

        assert "sessionID" in result, "No session id in {result}".format(result=result)
        return AuthenticateResult(
            session_id=result["sessionID"],
            digest=hash_value,
            hash_type=hash_type,
            verification_code=get_verification_code(hash_value),
        )

    def status(self, session_id: str, digest: bytes, timeout: int = 10000):
        """
        Retrieve auth session result from Mobile-ID backend

        see https://github.com/SK-EID/MID#33-status-of-signing-and-authentication

        :param session_id: session ID, from auth result
        :param digest: hash value that was used to initiate auth
        :param int timeout: Request long poll timeout value in milliseconds (Note: server uses a default
                         if client does not send it)
        :rtype: AuthenticateStatusResult
        """
        data = self._get_session_response(self.Actions.AUTH, session_id, timeout)

        # signature.value (str): Signature value, base64 encoded.
        signature_value = base64.b64decode(data["signature"]["value"])

        # signature.algorithm (str): Signature algorithm, in the form of sha256WithRSAEncryption
        signature_algorithm = data["signature"]["algorithm"]
        assert signature_algorithm[:6].upper() in HASH_ALGORITHMS

        # cert: Certificate value, DER+Base64 encoded
        cert_value = base64.b64decode(data["cert"])

        try:
            pyasice.verify(cert_value, signature_value, digest, signature_algorithm[:6], prehashed=True)
        except pyasice.SignatureVerificationError as e:
            raise SignatureVerificationError from e

        return AuthenticateStatusResult(
            certificate=cert_value,
            signature=signature_value,
            signature_algorithm=signature_algorithm,
        )

    def sign(
        self,
        id_code: str,
        phone_number: str,
        signed_data: bytes,
        message: str = None,
        language: str = None,
        hash_type: str = HASH_SHA256,
    ):
        """Initiate a signature session.

        Differences from authentication session:
        - endpoint
        - using signed data instead of a random string

        https://github.com/SK-EID/MID#32-initiating-signing-and-authentication

        :param str id_code: National identity number
        :param str phone_number: Client's phone number
        :param bytes signed_data: Binary data to sign
        :param str message: Text to display on the mobile device, NOTE: max 20 chars!
        :param str language: choices: ENG, EST, LIT, RUS. Defaults to ENG
        :param str hash_type: Hash algorithm used to sign data
        :return SignResult: Result of the request
        """
        if not (id_code and phone_number):
            # TODO proper validation
            raise ValueError("Both id_code and phone_number are required")

        if not id_code_ee_is_valid(id_code):
            raise InvalidIdCode

        hash_type = hash_type.upper()
        assert hash_type in HASH_ALGORITHMS

        message = str(message or self.DISPLAY_TEXT_SIGN)
        assert len(message) <= 20, f"Display text can not exceed 20 chars: got '{message}'"

        if language not in Languages.ALL:
            language = Languages.ENG

        content_hash = generate_hash(hash_type, signed_data)
        hash_value_b64 = base64.b64encode(content_hash)

        result = self.invoke(
            self.Actions.SIGN,
            method="POST",
            data={
                "nationalIdentityNumber": id_code,
                "phoneNumber": phone_number,
                "hashType": hash_type,
                "hash": hash_value_b64.decode("utf-8"),
                "language": language,
                # Casting to str to ensure translations are resolved
                "displayText": message,
                "displayTextFormat": "UCS-2",  # the other choice is GSM-7 which is 7-bit
            },
        )

        return SignResult(
            session_id=result["sessionID"],
            digest=content_hash,
            verification_code=get_verification_code(content_hash),
        )

    def sign_status(self, session_id: str, certificate: bytes, signed_digest: bytes, timeout=10000):
        """Retrieve signing session result from Mobile-ID backend

        The certificate is missing in the response, so
        to verify the signature you must pass it on from the authentication process.

        see https://github.com/SK-EID/MID#33-status-of-signing-and-authentication

        :param session_id: session ID from I{sign} Result
        :param certificate: the certificate used to sign data
        :param signed_digest: the digest of data to sign
        :param int timeout: Request long poll timeout value in milliseconds (Note: server uses a default
                         if client does not send it)
        :rtype: SignStatusResult
        """
        data = self._get_session_response(self.Actions.SIGN, session_id, timeout)

        signature = base64.b64decode(data["signature"]["value"])
        signature_algorithm = data["signature"]["algorithm"]
        assert signature_algorithm[:6].upper() in HASH_ALGORITHMS

        try:
            pyasice.verify(certificate, signature, signed_digest, signature_algorithm[:6], prehashed=True)
        except pyasice.SignatureVerificationError as e:
            raise SignatureVerificationError from e

        return SignStatusResult(
            signature=signature,
            signature_algorithm=signature_algorithm,
            certificate=certificate,
        )

    # ============
    # Internals
    # ============

    def _get_session_response(self, action, session_id, timeout=None):
        """Perform a request to session status.

        :param action: authentication or signature
        :param session_id:
        :param timeout:
        :return:
        """
        endpoint = self.Actions.SESSION_STATUS.format(action=action, session_id=session_id)

        data = self.poll_session(session_id, endpoint_url=endpoint, timeout=timeout)

        # result (str): End result of the transaction.
        # This structure is different from Smart ID so can't efficiently put it into BaseSKService.poll_session()
        end_result = data["result"]

        if end_result != EndResults.OK:
            if end_result == EndResults.TIMEOUT:
                raise UserTimeout
            elif end_result == EndResults.USER_CANCELLED:
                raise CanceledByUser
            elif end_result == EndResults.NOT_MID_CLIENT:
                raise UserNotRegistered
            # Fail hard, if endResult is something unknown to us
            if end_result not in EndResults.ALL:
                raise MobileIDError(f"Unexpected result '{end_result}' reported")

            raise UpstreamServiceError(f"Service returned {end_result}", service=self.NAME)

        return data
