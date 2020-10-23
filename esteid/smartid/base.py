import base64
from uuid import UUID

import requests

import pyasice

from ..constants import HASH_ALGORITHMS, HASH_SHA256
from ..exceptions import ActionFailed, ActionNotCompleted
from ..exceptions import EsteidError as SmartIDError
from ..exceptions import (
    IdentityCodeDoesNotExist,
    InvalidCredentials,
    OfflineError,
    PermissionDenied,
    SessionDoesNotExist,
    SignatureVerificationError,
    UnsupportedClientImplementation,
)
from ..util import generate_hash, secure_random
from .constants import (
    CERTIFICATE_LEVEL_ADVANCED,
    CERTIFICATE_LEVEL_QUALIFIED,
    CERTIFICATE_LEVELS,
    COUNTRIES,
    END_RESULT_CODES,
    END_RESULT_DOCUMENT_UNUSABLE,
    END_RESULT_OK,
    END_RESULT_TIMEOUT,
    END_RESULT_USER_REFUSED,
    STATE_RUNNING,
    STATES,
)
from .types import AuthenticateResult, AuthenticateStatusResult, SignResult, SignStatusResult
from .utils import get_verification_code


class SmartIDService(object):
    """Smart-ID Authentication and signing

    Based on https://github.com/SK-EID/smart-id-documentation

    Test api root: https://sid.demo.sk.ee/smart-id-rp/v1
    Production api root: https://rp-api.smart-id.com/v1

    Fixme:
        - Add more logging
    """

    MESSAGES = {
        "display_text": "Log in with Smart-ID",
        "permission_denied": "No permission to issue the request",
        "permission_denied_advanced": "No permission to issue the request (set certificate_level to {})",
        "no_identity_code": "Identity {} was not found in Smart-ID system",
        "no_session_code": "Session {} does not exist",
        "action_not_completed": "Action for session {} has not completed yet",
        "unexpected_state": "Unexpected state {}",
        "unexpected_end_result": "Unexpected end result {}",
        "signature_mismatch": "Signature mismatch",
        "timed_out": "Connection timed out, retry later",
        "invalid_credentials": "Authentication failed: Check rp_uuid and verify the ip of the "
        "server has been added to the service contract",
        "unsupported_client": "The client is not supported",
        "maintenance": "System is under maintenance, retry later",
        "proxy_error": "Proxy error {}, retry later",
        "http_error": "Invalid response code(status_code: {0}, body: {1})",
        "invalid_signature_algorithm": "Invalid signature algorithm {}",
    }

    END_RESULT_MESSAGES = {
        END_RESULT_OK: "Successfully authenticated with Smart-ID",
        END_RESULT_USER_REFUSED: "User refused the Smart-ID request",
        END_RESULT_TIMEOUT: "Smart-ID request timed out",
        END_RESULT_DOCUMENT_UNUSABLE: "Smart-ID document is not usable. Please check your Smart-ID application or "
        "contact Smart-ID support",
    }

    TEST_API_ROOT = "https://sid.demo.sk.ee/smart-id-rp/v1"
    API_ROOT = "https://rp-api.smart-id.com/v1"

    def __init__(self, rp_uuid, rp_name, api_root=None):
        self.rp_uuid = rp_uuid  # type: UUID
        self.rp_name = rp_name  # type: str
        self.api_root = api_root or self.TEST_API_ROOT

        self.is_test = self.api_root == self.TEST_API_ROOT

        self.session = requests.Session()

    def authenticate(
        self, id_code, country, certificate_level=CERTIFICATE_LEVEL_QUALIFIED, message=None, hash_type=HASH_SHA256
    ):
        """Initiate an authentication session

        see https://github.com/SK-EID/smart-id-documentation#44-authentication-session

        :param str id_code: National identity number
        :param str country: Country as an uppercase ISO 3166-1 alpha-2 code (choices: SMARTID_COUNTRIES)
        :param str certificate_level: Level of certificate requested (choices: CERTIFICATE_LEVELS)
        :param str message: Text to display for authentication consent dialog on the mobile device
        :param str hash_type: Hash algorithm to use when generating a random hash value (choices: HASH_ALGORITHMS)
        :return AuthenticateResult: Result of the request
        """
        # Ensure required values are set
        assert id_code
        assert country in COUNTRIES
        assert certificate_level in CERTIFICATE_LEVELS
        assert hash_type in HASH_ALGORITHMS

        random_bytes = secure_random(64)
        hash_value = generate_hash(hash_type, random_bytes)

        endpoint = "/authentication/pno/{country}/{id_code}".format(country=country, id_code=id_code)

        data = {
            "certificateLevel": certificate_level,
            "hashType": hash_type,
            "hash": base64.b64encode(hash_value).decode(),
            # Casting to str to ensure translations are resolved
            "displayText": str(message or self.msg("display_text")),
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
                data=self.rp_params(data),
            )

        except requests.HTTPError as e:
            # From the docs:
            #
            # HTTP error code 403 - Relying Party has no permission to issue the request. This may happen when:
            #  Relying Party has no permission to invoke operations on accounts with ADVANCED certificates.
            if e.response.status_code == 403:
                if certificate_level == CERTIFICATE_LEVEL_ADVANCED:
                    raise PermissionDenied(self.msg("permission_denied_advanced").format(CERTIFICATE_LEVEL_QUALIFIED))

                raise PermissionDenied(self.msg("permission_denied"))

            # From the docs:
            #
            # HTTP error code 404 - object described in URL was not found, essentially meaning that the user does not
            # have account in Smart-ID system.
            elif e.response.status_code == 404:
                raise IdentityCodeDoesNotExist(self.msg("no_identity_code").format(id_code))

            raise

        return AuthenticateResult(
            session_id=result["sessionID"],
            hash_type=hash_type,
            hash_value=hash_value,
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
        cert_value = base64.b64decode(data["cert"]["value"])

        # cert.certificateLevel (str): Level of Smart-ID certificate:
        #                              ADVANCED - Used for Smart-ID basic.
        #                              QUALIFIED - Used for Smart-ID.
        # Note: Not really sure how this affects the data inside the certificate
        certificate_level = data["cert"]["certificateLevel"]

        try:
            pyasice.verify(cert_value, signature_value, hash_value, signature_algorithm[:6], prehashed=True)
        except pyasice.SignatureVerificationError:
            raise SignatureVerificationError(self.msg("signature_mismatch"))

        return AuthenticateStatusResult(
            document_number=document_number,
            certificate=cert_value,
            certificate_level=certificate_level,
        )

    def sign(
        self,
        id_code,
        country,
        signed_data,
        certificate_level=CERTIFICATE_LEVEL_QUALIFIED,
        message=None,
        hash_type=HASH_SHA256,
    ):
        """Initiate a signature session.

        Should not be used in favor of `sign_by_document_number()`.

        see https://github.com/SK-EID/smart-id-documentation#45-signing-session

        :param str id_code: National identity number
        :param str country: Country as an uppercase ISO 3166-1 alpha-2 code (choices: SMARTID_COUNTRIES)
        :param bytes signed_data: Binary data to sign
        :param str certificate_level: Level of certificate requested (choices: CERTIFICATE_LEVELS)
        :param str message: Text to display for authentication consent dialog on the mobile device
        :param str hash_type: Hash algorithm used to sign data
        :return SignResult: Result of the request
        """
        assert id_code
        assert country in COUNTRIES

        endpoint = "/signature/pno/{country}/{id_code}".format(country=country, id_code=id_code)
        try:
            return self._sign(endpoint, signed_data, certificate_level, message, hash_type)
        except requests.HTTPError as e:
            # From the docs:
            #
            # HTTP error code 404 - object described in URL was not found, essentially meaning that the user does not
            # have account in Smart-ID system.
            if e.response.status_code == 404:
                raise IdentityCodeDoesNotExist(self.msg("no_identity_code").format(id_code))
            raise

    def sign_by_document_number(
        self,
        document_number,
        signed_data,
        certificate_level=CERTIFICATE_LEVEL_QUALIFIED,
        message=None,
        hash_type=HASH_SHA256,
    ) -> SignResult:
        """Initiate a signature session by document number.

        This method is preferred over signing by id_code/country, and requires a prior authentication to get the
          document number, and also selecting a signing certificate.

        see https://github.com/SK-EID/smart-id-documentation#45-signing-session

        :param str document_number: Document number, obtained from auth session
        :param str signed_data: Binary data to sign
        :param str certificate_level: Level of certificate requested (choices: CERTIFICATE_LEVELS)
        :param str message: Text to display for authentication consent dialog on the mobile device
        :param str hash_type: Hash algorithm used to sign data
        :return SignResult: Result of the request
        """
        assert document_number

        endpoint = "/signature/document/{document}".format(document=document_number)
        return self._sign(endpoint, signed_data, certificate_level, message, hash_type)

    def _sign(self, endpoint, signed_data, certificate_level, message, hash_type) -> SignResult:
        """Initiate a signing session

        see https://github.com/SK-EID/smart-id-documentation#45-signing-session

        :return SignResult: Result of the request
        """
        # Ensure required values are set
        assert signed_data
        assert certificate_level in CERTIFICATE_LEVELS
        assert hash_type
        hash_type = hash_type.upper()
        assert hash_type in HASH_ALGORITHMS

        content_hash = generate_hash(hash_type, signed_data)
        hash_value_b64 = base64.b64encode(content_hash)

        try:
            result = self.invoke(
                endpoint,
                method="POST",
                data=self.rp_params(
                    {
                        "certificateLevel": certificate_level,
                        "hashType": hash_type,
                        "hash": hash_value_b64.decode("ascii"),
                        # Casting to str to ensure translations are resolved
                        "displayText": str(message or self.msg("display_text")),
                    }
                ),
            )

        except requests.HTTPError as e:
            # From the docs:
            #
            # HTTP error code 403 - Relying Party has no permission to issue the request. This may happen when:
            #  Relying Party has no permission to invoke operations on accounts with ADVANCED certificates.
            if e.response.status_code == 403:
                if certificate_level == CERTIFICATE_LEVEL_ADVANCED:
                    raise PermissionDenied(self.msg("permission_denied_advanced").format(CERTIFICATE_LEVEL_QUALIFIED))

                raise PermissionDenied(self.msg("permission_denied"))
            raise

        return SignResult(
            session_id=result["sessionID"],
            digest=content_hash,
            verification_code=get_verification_code(content_hash),  # YES we hash the hash.
        )

    def sign_status(self, session_id, digest: bytes, timeout: int = 10000):
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

    def select_signing_certificate(
        self, id_code=None, country=None, document_number=None, certificate_level=CERTIFICATE_LEVEL_QUALIFIED
    ):
        """Obtain a certificate that will be used for signing.

        This method is REQUIRED prior to signing with `sign()`. Otherwise it's possible that `authenticate()` would
          return a different cert, and the XAdES signature would not be valid.

        :param id_code:
        :param country:
        :param document_number:
        :param certificate_level:
        :return: bytes - ASN.1 (DER) certificate
        """

        assert document_number or (id_code and country in COUNTRIES)

        if document_number:
            endpoint = "/certificatechoice/document/{document}".format(document=document_number)
        else:
            endpoint = "/certificatechoice/pno/{country}/{id_code}".format(country=country, id_code=id_code)

        try:
            result = self.invoke(
                endpoint,
                method="POST",
                data=self.rp_params(
                    {
                        "certificateLevel": certificate_level,
                    }
                ),
            )

        except (requests.ConnectionError, requests.Timeout):
            raise OfflineError(self.msg("timed_out"))

        except requests.HTTPError:
            raise

        session_id = result["sessionID"]

        data = self._get_session_response(session_id, 10000)
        return base64.b64decode(data["cert"]["value"])

    # ============
    # Internals
    # ============

    def close_session(self):  # pragma: no cover
        pass

    def rp_params(self, data):
        """

        :param dict data:
        """
        data.update(
            {
                "relyingPartyUUID": str(self.rp_uuid),
                "relyingPartyName": self.rp_name,
            }
        )

        return data

    def api_url(self, endpoint):
        return "{api_root}{endpoint}".format(api_root=self.api_root, endpoint=endpoint)

    def invoke(self, endpoint, method="GET", query=None, data=None, headers=None):  # pylint: disable-msg=R0913
        query = query or {}

        request_headers = {
            "Content-Type": "application/json",
        }

        if headers:
            request_headers.update(headers)

        req = requests.Request(
            method=method,
            url=self.api_url(endpoint),
            params=query,
            json=data,
            headers=request_headers,
        )
        prepared = req.prepare()

        try:
            # Attempt to fulfill the request
            response = self.session.send(prepared)

            # ensure we don't mask errors
            response.raise_for_status()

        except (requests.ConnectionError, requests.Timeout):
            raise OfflineError(self.msg("timed_out"))

        except requests.HTTPError as e:
            status_code = e.response.status_code
            if status_code == 401:
                raise InvalidCredentials(self.msg("invalid_credentials"))

            # 480 The client (i.e. client-side implementation of this API) is old and not
            #  supported any more. Relying Party must contact customer support.
            elif status_code == 480:
                raise UnsupportedClientImplementation(self.msg("unsupported_client"))

            # 580 System is under maintenance, retry later.
            # see https://github.com/SK-EID/smart-id-documentation#413-http-status-code-usage
            elif status_code == 580:
                raise OfflineError(self.msg("maintenance"))

            # Raise proxy errors as OfflineError
            elif status_code in [502, 503, 504]:
                raise OfflineError(self.msg("proxy_error").format(status_code))

            # HTTPErrors for everything else
            raise requests.HTTPError(
                self.msg("http_error").format(status_code, e.response.content), request=e.request, response=e.response
            )

        try:
            return response.json()
        except ValueError:
            raise SmartIDError("Failed to parse response: {}".format(response.content))

    def msg(self, code):
        return self.MESSAGES[code]

    def end_result_msg(self, end_result):
        return self.END_RESULT_MESSAGES[end_result]

    def _get_session_response(self, session_id, timeout):
        """Perform a request to session status.

        :param session_id:
        :param timeout:
        :return:
        """
        endpoint = "/session/{session_id}".format(session_id=session_id)

        try:
            data = self.invoke(
                endpoint,
                query={
                    "timeoutMs": timeout,
                },
            )

        except requests.HTTPError as e:
            if e.response.status_code == 404:
                raise SessionDoesNotExist(self.msg("no_session_code").format(session_id))

            raise

        state = data["state"]
        if state == STATE_RUNNING:
            raise ActionNotCompleted(self.msg("action_not_completed").format(session_id))

        # Documentation states that the state can only be RUNNING or COMPLETE
        # Fail hard if we encounter unknown states
        if state not in STATES:
            raise SmartIDError(self.msg("unexpected_state").format(state))

        # result.endResult (str): End result of the transaction.
        end_result = data["result"]["endResult"]

        if end_result != END_RESULT_OK:
            # Fail hard, if endResult is something unknown to us
            if end_result not in END_RESULT_CODES:
                raise SmartIDError(self.msg("unexpected_end_result").format(end_result))

            raise ActionFailed(end_result, self.end_result_msg(end_result))

        return data
