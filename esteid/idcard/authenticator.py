import base64
import logging
import uuid

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_der_x509_certificate, NameOID
from esteid_certificates import get_certificate
from oscrypto.asymmetric import Certificate as OsCryptoCertificate

from pyasice.ocsp import OCSP

from .. import settings
from ..authentication import Authenticator
from ..authentication.types import AuthenticationResult
from ..constants import HASH_SHA256
from ..exceptions import ActionInProgress, InvalidIdCode, InvalidParameter, InvalidParameters
from ..types import CertificateHolderInfo
from ..util import generate_hash, get_request_session_method, secure_random
from .types import LibraryAuthenticateResponse


logger = logging.getLogger(__name__)


class IdCardAuthenticator(Authenticator):
    certificate: bytes

    hash_type: str

    _certificate_handle: "OsCryptoCertificate"

    def setup(self, initial_data: dict = None):
        # no setup required for web-eid based authentication
        pass

        self.hash_type = initial_data.get("algorithm", HASH_SHA256) or HASH_SHA256

    def authenticate(self):
        """This is called by the front-end during the start of the authentication process

        The method generates a challenge nonce and returns it to the front-end to be used in the
        web-eid `authenticate` call.
        """

        random_bytes = secure_random(64)
        hash_value = generate_hash(self.hash_type, random_bytes)
        hash_value_b64 = base64.b64encode(hash_value).decode()

        self.save_session_data(
            session_id=uuid.uuid4().hex,
            hash_value_b64=hash_value_b64,
        )

        raise ActionInProgress(
            data={
                "nonce": hash_value_b64,
            }
        )

    def poll(self, initial_data: dict = None) -> AuthenticationResult:
        hash_value_b64 = self.session_data.hash_value_b64

        if not isinstance(initial_data, dict):
            raise InvalidParameters("Missing required parameters")

        auth_response = LibraryAuthenticateResponse(**initial_data)

        try:
            auth_response.is_valid()
        except (InvalidIdCode, InvalidParameter):
            # Just to be explicit
            raise
        except ValueError as e:
            raise InvalidParameters("Invalid parameters") from e

        certificate = load_der_x509_certificate(auth_response.certificate_bytes, default_backend())

        # This method:
        #
        # - validates the signature matches the certificate and the original nonce
        # - indirectly validates the certificate (by loading it with cryptography)
        auth_response.validate_signature(certificate, self.origin, hash_value_b64.encode())

        # Now we verify the certificate validity via OCSP. This ensures we comply with the following parts of the spec:
        #
        # - validate the certificate
        # - validate the certificate expiry via OCSP
        # - validate that the current time falls within the authentication certificate's validity period
        # - validates that the authentication certificate does not contain any disallowed policies
        # - validates that the authentication certificate is signed by a trusted certificate authority
        # - validates that the purpose of the authentication certificate's key usage is client authentication

        try:
            issuer_common_name = certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except AttributeError:
            issuer_common_name = certificate.asn1.issuer.native["common_name"]

        issuer_cert = get_certificate(issuer_common_name)

        ocsp = OCSP(settings.OCSP_URL, get_session=get_request_session_method())
        ocsp.validate(auth_response.certificate_bytes, issuer_cert, auth_response.signature_bytes)

        # Finally we construct a holder info object from the certificate, so we can return the user's details in an
        # authentication result
        cert_holder_info = CertificateHolderInfo.from_certificate(auth_response.certificate_bytes)

        return AuthenticationResult(
            country=cert_holder_info.country,
            id_code=cert_holder_info.id_code,
            given_name=cert_holder_info.given_name,
            surname=cert_holder_info.surname,
            certificate_b64=auth_response.unverifiedCertificate,
        )
