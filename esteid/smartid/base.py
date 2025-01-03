import base64
import logging
from time import sleep, time

import requests

import pyasice

from ..base_service import BaseSKService
from ..constants import HASH_ALGORITHMS, HASH_SHA256
from ..exceptions import ActionInProgress, CanceledByUser
from ..exceptions import EsteidError as SmartIDError
from ..exceptions import (
    PermissionDenied,
    SignatureVerificationError,
    UpstreamServiceError,
    UserNotRegistered,
    UserTimeout,
)
from ..util import generate_hash, secure_random
from ..validators import validate_id_code
from .constants import CERTIFICATE_LEVEL_QUALIFIED, CERTIFICATE_LEVELS, EndResults
from .types import AuthenticateResult, AuthenticateStatusResult, SignResult, SignStatusResult
from .utils import get_verification_code


logger = logging.getLogger(__name__)


class SmartIDService(BaseSKService):
    """Smart-ID Authentication and signing

    Based on https://github.com/SK-EID/smart-id-documentation

    Test api root: https://sid.demo.sk.ee/smart-id-rp/v1
    Production api root: https://rp-api.smart-id.com/v1

    Fixme:
        - Add more logging
    """

    DISPLAY_TEXT_AUTH = "Authenticate"
    DISPLAY_TEXT_SIGN = "Sign"

    NAME = "Smart ID"

    class Actions:
        AUTH = "/authentication/etsi/PNO{country}-{id_code}"
        SIGN_BY_DOCUMENT = "/signature/document/{document}"
        SELECT_CERTIFICATE = "/certificatechoice/etsi/PNO{country}-{id_code}"
        SELECT_CERTIFICATE_BY_DOCUMENT = "/certificatechoice/document/{document_number}"
        SESSION_STATUS = "/session/{session_id}"

    def authenticate(
        self,
        id_code,
        country,
        certificate_level=CERTIFICATE_LEVEL_QUALIFIED,
        message=None,
        hash_type=HASH_SHA256,
        random_bytes=None,
    ):
        """Initiate an authentication session

        see https://github.com/SK-EID/smart-id-documentation#44-authentication-session

        :param str id_code: National identity number
        :param str country: Country as an uppercase ISO 3166-1 alpha-2 code (choices: Countries.ALL)
        :param str certificate_level: Level of certificate requested (choices: CERTIFICATE_LEVELS)
        :param str message: Text to display for authentication consent dialog on the mobile device
        :param str hash_type: Hash algorithm to use when generating a random hash value (choices: HASH_ALGORITHMS)
        :param bytes random_bytes: Random bytes to use for the hash value (optional). If not provided, will be generated

        :return AuthenticateResult: Result of the request
        """
        # Ensure required values are set
        validate_id_code(id_code, country)
        assert certificate_level in CERTIFICATE_LEVELS
        assert hash_type in HASH_ALGORITHMS

        random_bytes = secure_random(64) if random_bytes is None else random_bytes
        hash_value = generate_hash(hash_type, random_bytes)
        hash_value_b64 = base64.b64encode(hash_value).decode()

        endpoint = self.Actions.AUTH.format(country=country.upper(), id_code=id_code)

        data = {
            "certificateLevel": certificate_level,
            "hashType": hash_type,
            "hash": hash_value_b64,
            # Casting to str to ensure translations are resolved
            "displayText": str(message or self.DISPLAY_TEXT_AUTH),
            # Don't use nonce to so we can rely on idempotent behaviour
            #
            # From the docs:
            #
            # Whenever a RP session creation request (POST to certificatechoice/, signature/, authentication/) is
            # repeated inside a given timeframe with exactly the same parameters, session ID of an existing
            # session can be returned as a result.
            #
            # This allows to retry RP POST requests in case of communication errors. Retry timeframe is 15 seconds.
            #
            # When requestor wants, it can override the idempotent behaviour inside of this timeframe using an
            # optional "nonce" parameter present for all POST requests. Normally, that parameter can be omitted.
            # 'nonce': None,
        }

        try:
            result = self.invoke(
                endpoint,
                method="POST",
                data=data,
            )

        except UpstreamServiceError as e:
            self._handle_specific_errors(e)
            raise

        return AuthenticateResult(
            session_id=result["sessionID"],
            hash_type=hash_type,
            hash_value=hash_value,
            hash_value_b64=hash_value_b64,
            verification_code=get_verification_code(hash_value),
        )

    def status(self, session_id, hash_value, timeout=10000):
        """Retrieve session result from Smart-ID backend

        see https://github.com/SK-EID/smart-id-documentation#46-session-status

        :param session_id: session ID, from I{authenticate} Result
        :param hash_value: hash value that was sent to I{authenticate}
        :param int timeout: Request long poll timeout value in milliseconds (Note: server uses a default
                         if client does not send it)
        :rtype: AuthenticateStatusResult
        """
        data = self._get_session_response(session_id, timeout)

        # result.documentNumber (str): Document number, can be used in further signature and authentication
        #                              requests to target the same device. Note: Only available if
        #                              result.endResult is END_RESULT_OK
        document_number = data["result"]["documentNumber"]

        # signature.value (str): Signature value, base64 encoded.
        signature_value = base64.b64decode(data["signature"]["value"])
        # signature.algorithm (str): Signature algorithm, in the form of sha256WithRSAEncryption
        signature_algorithm = data["signature"]["algorithm"]
        assert signature_algorithm[:6].upper() in HASH_ALGORITHMS

        # cert: Only available if result.endResult is OK
        # cert.value (str): Certificate value, DER+Base64 encoded
        cert_b64 = data["cert"]["value"]
        cert_value = base64.b64decode(cert_b64)

        # cert.certificateLevel (str): Level of Smart-ID certificate:
        #                              ADVANCED - Used for Smart-ID basic.
        #                              QUALIFIED - Used for Smart-ID.
        # Note: Not really sure how this affects the data inside the certificate
        certificate_level = data["cert"]["certificateLevel"]

        try:
            pyasice.verify(cert_value, signature_value, hash_value, signature_algorithm[:6], prehashed=True)
        except pyasice.SignatureVerificationError as e:
            raise SignatureVerificationError from e

        return AuthenticateStatusResult(
            document_number=document_number,
            certificate=cert_value,
            certificate_b64=cert_b64,
            certificate_level=certificate_level,
        )

    def sign_by_document_number(
        self,
        document_number: str,
        signed_data: bytes,
        certificate_level=CERTIFICATE_LEVEL_QUALIFIED,
        message=None,
        hash_type=HASH_SHA256,
    ) -> SignResult:
        """Initiate a signature session by document number.

        This method is preferred over signing by id_code/country, and requires a prior authentication to get the
          document number, and also selecting a signing certificate.

        see https://github.com/SK-EID/smart-id-documentation#2310-signing-session

        :param document_number: Document number, obtained from auth session
        :param signed_data: Binary data to sign
        :param certificate_level: Level of certificate requested (choices: CERTIFICATE_LEVELS)
        :param str message: Text to display for authentication consent dialog on the mobile device
        :param str hash_type: Hash algorithm used to sign data
        :return SignResult: Result of the request
        """
        # Ensure required values are set
        assert document_number
        assert signed_data
        assert certificate_level in CERTIFICATE_LEVELS
        assert hash_type
        hash_type = hash_type.upper()
        assert hash_type in HASH_ALGORITHMS

        content_hash = generate_hash(hash_type, signed_data)
        hash_value_b64 = base64.b64encode(content_hash)

        endpoint = self.Actions.SIGN_BY_DOCUMENT.format(document=document_number)

        try:
            result = self.invoke(
                endpoint,
                method="POST",
                data={
                    "certificateLevel": certificate_level,
                    "hashType": hash_type,
                    "hash": hash_value_b64.decode("ascii"),
                    # Casting to str to ensure translations are resolved
                    "displayText": str(message or self.DISPLAY_TEXT_SIGN),
                },
            )

        except UpstreamServiceError as e:
            self._handle_specific_errors(e)
            raise

        return SignResult(
            session_id=result["sessionID"],
            digest=content_hash,
            verification_code=get_verification_code(content_hash),  # YES we hash the hash.
        )

    def sign_status(self, session_id, digest: bytes, timeout: int = 1000):
        """Retrieve signing session result from Smart-ID backend

        see https://github.com/SK-EID/smart-id-documentation#46-session-status

        :param session_id: session ID from I{sign} Result
        :param digest: the hash of the signed data
        :param int timeout: Request long poll timeout value in milliseconds (Note: server uses a default
                         if client does not send it)
        :rtype: SignStatusResult
        """
        data = self._get_session_response(session_id, timeout)

        cert_value = base64.b64decode(data["cert"]["value"])
        signature = base64.b64decode(data["signature"]["value"])
        signature_algorithm = data["signature"]["algorithm"]
        assert signature_algorithm[:6].upper() in HASH_ALGORITHMS

        pyasice.verify(cert_value, signature, digest, signature_algorithm[:6], prehashed=True)

        return SignStatusResult(
            document_number=data["result"]["documentNumber"],
            signature=signature,
            signature_algorithm=data["signature"]["algorithm"],
            certificate=cert_value,
            certificate_level=data["cert"]["certificateLevel"],
        )

    def select_signing_certificate(self, id_code, country, certificate_level=CERTIFICATE_LEVEL_QUALIFIED) -> tuple:
        """Obtain a certificate that will be used for signing.

        This method is REQUIRED prior to signing with `sign()`. Otherwise it's possible that `authenticate()` would
          return a different cert, and the XAdES signature would not be valid.

        :param id_code:
        :param country:
        :param certificate_level:
        :return: tuple[bytes, str] - ASN.1 (DER) certificate and document number
        """
        validate_id_code(id_code, country)
        endpoint = self.Actions.SELECT_CERTIFICATE.format(country=country.upper(), id_code=id_code)

        result = self.invoke(
            endpoint,
            method="POST",
            data={
                "certificateLevel": certificate_level,
            },
        )

        session_id = result["sessionID"]

        start_time = int(time())
        while True:
            # Note: Normally the session response is returned quickly to the first polling request.
            # In case this doesn't happen, we allow polling for 60 seconds with a 3-second interval.
            # These numbers are arbitrary but since they only serve as contingency fallback,
            # making constants out of them seems redundant.
            try:
                data = self._get_session_response(session_id, 1000)
                break
            except ActionInProgress as e:
                now = int(time())
                if now > start_time + 60:
                    raise UpstreamServiceError(
                        "Failed to get a certificate response within 60 seconds",
                        service=self.NAME,  # pylint: disable=no-member
                    ) from e
                sleep(3)

        document_number = data["result"]["documentNumber"]
        certificate = base64.b64decode(data["cert"]["value"])
        return certificate, document_number

    # ============
    # Internals
    # ============

    def _get_session_response(self, session_id, timeout):
        """Perform a request to session status.

        :param session_id:
        :param timeout:
        :return:
        """
        data = self.poll_session(session_id, endpoint_url=self.Actions.SESSION_STATUS, timeout=timeout)

        # result.endResult (str): End result of the transaction.
        # This structure is different from Mobile ID so can't efficiently put it into BaseSKService.poll_session()
        end_result = data["result"]["endResult"]

        if end_result != EndResults.OK:
            if end_result == EndResults.TIMEOUT:
                raise UserTimeout
            if end_result == EndResults.USER_REFUSED:
                raise CanceledByUser

            # Fail hard, if endResult is something unknown to us
            if end_result not in EndResults.ALL:
                raise SmartIDError(f"Unexpected end result {end_result}")

            raise UpstreamServiceError(end_result, service=self.NAME)  # pylint: disable=no-member

        return data

    def _handle_specific_errors(self, exc: UpstreamServiceError):
        """
        Handles some SmartID-specific errors
        """
        cause = getattr(exc, "__cause__", None)
        if isinstance(cause, requests.HTTPError):
            response = cause.response
            # From the docs:
            #
            # HTTP error code 403 - Relying Party has no permission to issue the request. This may happen when:
            #  Relying Party has no permission to invoke operations on accounts with ADVANCED certificates.
            if response.status_code == 403:
                raise PermissionDenied("Certificate level ADVANCED not allowed") from exc

            # From the docs:
            #
            # HTTP error code 404 - object described in URL was not found,
            # essentially meaning that the user does not have account in Smart-ID system.
            if response.status_code == 404:
                raise UserNotRegistered from exc

            # Log the HTTP response
            logger.exception(
                "The %s service returned an error %s at %s. Response:\n %s",
                self.NAME,  # pylint: disable=no-member
                response.status_code,
                response.url,
                response.text,
            )
