import base64
from uuid import UUID

import requests

import pyasice

from ..constants import HASH_ALGORITHMS, HASH_SHA256
from ..exceptions import ActionFailed, ActionNotCompleted
from ..exceptions import EsteidError as MobileIDError
from ..exceptions import (
    InvalidCredentials,
    OfflineError,
    SessionDoesNotExist,
    SignatureVerificationError,
    UserNotRegistered,
)
from ..util import generate_hash, secure_random
from .constants import EndResults, Languages, STATE_RUNNING, STATES
from .types import AuthenticateResult, AuthenticateStatusResult, SignResult, SignStatusResult
from .utils import get_verification_code


class MobileIDService:
    """Mobile-ID Authentication and signing

    Based on https://github.com/SK-EID/MID

    Test api root: https://tsp.demo.sk.ee/mid-api
    Production api root: https://mid.sk.ee/mid-api

    Fixme:
        - Add more logging
    """

    MESSAGES = {
        "display_text": "Mobile-ID login",
        "permission_denied": "No permission to issue the request",
        "permission_denied_advanced": "No permission to issue the request (set certificate_level to {})",
        "no_identity_code": "Identity {} was not found in Mobile-ID system",
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
        EndResults.OK: "Successfully authenticated with Mobile-ID",
        EndResults.USER_CANCELLED: "User canceled the Mobile-ID request",
        EndResults.TIMEOUT: "Mobile-ID request timed out",
        EndResults.NOT_MID_CLIENT: "Not a Mobile-ID client",
    }

    class Actions:
        AUTH = "/authentication"
        SIGN = "/signature"
        SESSION_STATUS = "{action_type}/session/{session_id}"

    def __init__(self, rp_uuid: UUID, rp_name: str, api_root: str):
        self.rp_uuid = rp_uuid
        self.rp_name = rp_name
        self.api_root = api_root

        self.session = requests.Session()

    def get_certificate(self, id_code: str, phone_number: str) -> bytes:
        """
        Gets a user certificate that would be used for signing.

        Also checks if the user with these
        """
        if not (id_code and phone_number):
            # TODO proper validation
            raise ValueError("Both id_code and phone_number are required")

        endpoint = "/certificate"

        result = self.invoke(
            endpoint,
            method="POST",
            data=self.rp_params({"phoneNumber": phone_number, "nationalIdentityNumber": id_code}),
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
        assert hash_type in HASH_ALGORITHMS

        message = str(message or self.msg("display_text"))
        assert len(message) <= 20, f"Display text can not exceed 20 chars: got '{message}'"

        if language not in Languages.ALL:
            language = Languages.ENG

        random_bytes = secure_random(64)
        hash_value = generate_hash(hash_type, random_bytes)
        hash_value_b64 = base64.b64encode(hash_value)

        endpoint = self.Actions.AUTH

        result = self.invoke(
            endpoint,
            method="POST",
            data=self.rp_params(
                {
                    "nationalIdentityNumber": id_code,
                    "phoneNumber": phone_number,
                    "hashType": hash_type,
                    "hash": hash_value_b64.decode("utf-8"),
                    "language": language,
                    # Casting to str to ensure translations are resolved
                    "displayText": message,  # NOTE: hard 20-char limit
                    "displayTextFormat": "UCS-2",  # the other choice is GSM-7 which is 7-bit
                }
            ),
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
            raise SignatureVerificationError(self.msg("signature_mismatch")) from e

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

        hash_type = hash_type.upper()
        assert hash_type in HASH_ALGORITHMS

        message = str(message or self.msg("display_text"))
        assert len(message) <= 20, f"Display text can not exceed 20 chars: got '{message}'"

        if language not in Languages.ALL:
            language = Languages.ENG

        content_hash = generate_hash(hash_type, signed_data)
        hash_value_b64 = base64.b64encode(content_hash)

        result = self.invoke(
            self.Actions.SIGN,
            method="POST",
            data=self.rp_params(
                {
                    "nationalIdentityNumber": id_code,
                    "phoneNumber": phone_number,
                    "hashType": hash_type,
                    "hash": hash_value_b64.decode("utf-8"),
                    "language": language,
                    # Casting to str to ensure translations are resolved
                    "displayText": str(message or self.msg("display_text")),  # NOTE: 20-char limit
                    "displayTextFormat": "UCS-2",  # the other choice is GSM-7 which is 7-bit
                }
            ),
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
            raise SignatureVerificationError(self.msg("signature_mismatch")) from e

        return SignStatusResult(
            signature=signature,
            signature_algorithm=signature_algorithm,
            certificate=certificate,
        )

    # ============
    # Internals
    # ============
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

    def invoke(self, endpoint, method="GET", query=None, data=None, headers=None):
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
                raise InvalidCredentials(self.msg("invalid_credentials")) from e

            elif status_code == 400:
                raise MobileIDError(f"Bad Request. Response:\n{e.response.text}") from e

            # 580 System is under maintenance, retry later.
            # see https://github.com/SK-EID/smart-id-documentation#413-http-status-code-usage
            # (Note: Though not documented, Mobile ID also returns this occasionally.)
            elif status_code == 580:
                raise OfflineError(self.msg("maintenance")) from e

            # Raise proxy errors as OfflineError
            elif status_code in [502, 503, 504]:
                raise OfflineError(self.msg("proxy_error").format(status_code)) from e

            # HTTPErrors for everything else
            raise requests.HTTPError(
                self.msg("http_error").format(status_code, e.response.content), request=e.request, response=e.response
            )

        try:
            return response.json()
        except ValueError:
            raise MobileIDError("Failed to parse response: {}".format(response.content))

    def msg(self, code):
        return self.MESSAGES[code]

    def end_result_msg(self, end_result):
        return self.END_RESULT_MESSAGES[end_result]

    def _get_session_response(self, action, session_id, timeout=None):
        """Perform a request to session status.

        :param action: authentication or signature
        :param session_id:
        :param timeout:
        :return:
        """
        endpoint = "{action}/session/{session_id}".format(action=action, session_id=session_id)

        try:
            data = self.invoke(
                endpoint,
                query={
                    "timeoutMs": timeout,
                },
            )

        except requests.HTTPError as e:
            if e.response.status_code == 404:
                raise SessionDoesNotExist(self.msg("no_session_code").format(session_id)) from e

            raise

        state = data["state"]
        if state == STATE_RUNNING:
            raise ActionNotCompleted(self.msg("action_not_completed").format(session_id))

        # Documentation states that the state can only be RUNNING or COMPLETE
        # Fail hard if we encounter unknown states
        if state not in STATES:
            raise MobileIDError(self.msg("unexpected_state").format(state))

        # result (str): End result of the transaction.
        end_result = data["result"]

        if end_result != EndResults.OK:
            # Fail hard, if endResult is something unknown to us
            if end_result not in EndResults.ALL:
                raise MobileIDError(self.msg("unexpected_end_result").format(end_result))

            raise ActionFailed(end_result, self.end_result_msg(end_result))

        return data
