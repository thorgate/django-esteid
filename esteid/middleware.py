import logging
import warnings

from esteid_certificates import get_certificate_file_name

from esteid import settings
from esteid.util import parse_legacy_dn, parse_rfc_dn

from .ocsp import OCSPVerifier


try:
    from django.utils.deprecation import MiddlewareMixin
except ImportError:  # Django < 1.10
    # Works perfectly for everyone using MIDDLEWARE_CLASSES
    MiddlewareMixin = object


logger = logging.getLogger(__name__)


ERROR_NO_DN = 3000
ERROR_INVALID_DN = 3001


class BaseIdCardMiddleware(MiddlewareMixin):
    """Base class for receiving authentication info from ID card.

    Note that this requires cooperation from the web server (eg Apache / Nginx) - the server must request client
    certificate and pass it on in specific HTTP headers.
    You should use one of the subclasses that's preconfigured for a specific server.

    The middleware also performs certificate validation check via OCSP if certificate and issuer headers are known and
    specified.

    If authentication information is present and valid, it's added to the request's `id_auth` attribute as dict
    containing at least the following items:

    - `serialNumber` - personal identification code, e.g. `37504170511`
    - `C` - country code, e.g. `EE`
    - `CN` - full name and personal id code, e.g. `SMITH,JOHN,37504170511`
    - `GN` - first name (given name), e.g. 'JOHN'
    - `SN` - last name (surname), e.g. 'SMITH'

    If authentication fails, the request will have `id_err` attribute with value of the error code.

    Documentation (In Estonian):
    https://eid.eesti.ee/index.php/Kasutaja_tuvastamine_veebis#Veebiserveri_konfigureerimine
    """

    DN_HEADER_NAME = None
    CERTIFICATE_HEADER_NAME = None
    ISSUER_HEADER_NAME = None

    # If any of these is not present in client DN, the authentication fails
    REQUIRED_DN_FIELDS = {
        "serialNumber",
        "C",
        "CN",
        "GN",
        "SN",
    }

    def process_request(self, request):
        assert self.DN_HEADER_NAME, "%s doesn't set DN_HEADER_NAME attribute" % self.__class__.__name__

        # Get the subject DN from header
        client_dn = request.META.get(self.DN_HEADER_NAME, None)
        if client_dn is None:
            setattr(request, "id_err", ERROR_NO_DN)
            return

        id_auth = self.parse_client_dn(client_dn)
        if not self.REQUIRED_DN_FIELDS.issubset(id_auth.keys()):
            logger.info("BaseIdCardMiddleware: required DN fields missing, client DN is %s", client_dn)
            setattr(request, "id_err", ERROR_INVALID_DN)
            return

        setattr(request, "id_auth", id_auth)

        if self.CERTIFICATE_HEADER_NAME is not None and self.ISSUER_HEADER_NAME is not None:
            issuer = request.META.get(self.ISSUER_HEADER_NAME, None)
            certificate = request.META.get(self.CERTIFICATE_HEADER_NAME, None)
            if issuer and certificate:
                certificate = self.prepare_certificate(certificate)
                setattr(request, "id_cert", certificate)

                # OCSP check
                issuer = self.parse_client_dn(issuer)
                response = self.verify_ocsp(certificate, issuer)

                # Code 0 means success, everything else is error
                if response != 0:
                    logger.info("BaseIdCardMiddleware: OCSP verification returned %s", response)
                    delattr(request, "id_auth")
                    # Pad OCSP error codes with 4000
                    setattr(request, "id_err", 4000 + response)

    def prepare_certificate(self, certificate):
        """ Use this in case the certificate value in HTTP header needs formatting. """
        return certificate

    def parse_client_dn(self, dn):
        """ Use either parse_legacy_dn or parse_rfc_dn depending on the format your proxy server users. """
        return parse_legacy_dn(dn)

    @classmethod
    def get_ocsp_url(cls):
        """Get ocsp responder certificate path

        Note: This is a separate method to allow easier overwriting via subclassing

        :return:str
        """
        return settings.OCSP_URL

    @classmethod
    def get_ocsp_responder_certificate_path(cls):
        """Get ocsp responder certificate path

        Note: This is a separate method to allow easier overwriting via subclassing

        :return:str
        """
        certificate_path = getattr(settings, "ESTEID_OCSP_RESPONDER_CERTIFICATE_PATH", None)
        test_cert_name = "TEST of SK OCSP RESPONDER 2011"
        live_cert_name = "sk-ocsp-responder-certificates"
        # Preserve compatibility
        if certificate_path == "TEST_of_SK_OCSP_RESPONDER_2011.pem":
            return get_certificate_file_name(test_cert_name)
        if certificate_path == "sk-ocsp-responder-certificates.pem":
            return get_certificate_file_name(live_cert_name)

        return test_cert_name if settings.ESTEID_DEMO else live_cert_name

    @classmethod
    def verify_ocsp(cls, certificate, issuer):
        """Runs OCSP verification and returns error code - 0 means success"""

        return OCSPVerifier(certificate, issuer, cls.get_ocsp_url(), cls.get_ocsp_responder_certificate_path()).verify()


class ApacheIdCardMiddleware(BaseIdCardMiddleware):
    """ID card middleware configured for Apache server

    Requires standard SSL_CLIENT_S_DN, SSL_CLIENT_I_DN and SSL_CLIENT_CERT headers.
    """

    DN_HEADER_NAME = "HTTP_SSL_CLIENT_S_DN"
    ISSUER_HEADER_NAME = "HTTP_SSL_CLIENT_I_DN"
    CERTIFICATE_HEADER_NAME = "HTTP_SSL_CLIENT_CERT"

    def prepare_certificate(self, certificate):
        return certificate.replace(" ", "\n").replace("\nCERTIFICATE-----", " CERTIFICATE-----")

    def parse_client_dn(self, dn):
        return parse_rfc_dn(dn)


class NginxIdCardMiddleware(BaseIdCardMiddleware):
    """ID card middleware configured for Nginx server

    Note that Nginx middleware does NOT perform validation (OCSP) checks for the received certificate.
    """

    DN_HEADER_NAME = "HTTP_X_CLIENT"


class IdCardMiddleware(NginxIdCardMiddleware):
    """ Deprecated - use ApacheIdCardMiddleware or NginxIdCardMiddleware """

    def __init__(self, *args, **kwargs):
        warnings.warn(
            "IdCardMiddleware is deprecated - use ApacheIdCardMiddleware or NginxIdCardMiddleware",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(*args, **kwargs)
