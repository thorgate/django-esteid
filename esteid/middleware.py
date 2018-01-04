import logging

from django.utils.cache import patch_vary_headers

from esteid.helpers import parse_legacy_dn, parse_rfc_dn
from . import config
from .ocsp import OCSPVerifier


try:
    from django.utils.deprecation import MiddlewareMixin
except ImportError:  # Django < 1.10
    # Works perfectly for everyone using MIDDLEWARE_CLASSES
    MiddlewareMixin = object


logger = logging.getLogger(__name__)


ERROR_NO_DN = 3000
ERROR_INVALID_DN = 3001


class MultiHostMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # Choose which subhost to use (if any):
        host = request.META["HTTP_HOST"]
        if host[-3:] == ":80":
            host = host[:-3]  # ignore default port number, if present

        request.subhost_name = 'default'
        for host_name, host_config in config.get_hosts().items():
            if host.startswith(host_name) or host == host_config.get('hostname'):
                request.subhost_name = host_name
                request.urlconf = host_config.get('urlconf')

    def process_response(self, request, response):
        if getattr(request, "urlconf", None):
            patch_vary_headers(response, ('Host',))

        return response


class BaseIdCardMiddleware(MiddlewareMixin):
    # This allows one to easily change the DN format used (legacy, rfc)

    DN_HEADER_NAME = None
    CERTIFICATE_HEADER_NAME = None
    ISSUER_HEADER_NAME = None

    REQUIRED_DN_FIELDS = {
        'serialNumber',
        'C',
        'CN',
        'GN',
        'SN',
    }

    def process_request(self, request):
        assert self.DN_HEADER_NAME, "%s doesn't set DN_HEADER_NAME attribute" % self.__class__.__name__

        # Get the subject DN from header
        client_dn = request.META.get(self.DN_HEADER_NAME, None)
        if client_dn is None:
            setattr(request, 'id_err', ERROR_NO_DN)
            return

        id_auth = self.parse_client_dn(client_dn)
        if not self.REQUIRED_DN_FIELDS.issubset(id_auth.keys()):
            logger.info("BaseIdCardMiddleware: required DN fields missing, client DN is %s", client_dn)
            setattr(request, 'id_err', ERROR_INVALID_DN)
            return

        setattr(request, 'id_auth', id_auth)

        if self.CERTIFICATE_HEADER_NAME is not None and self.ISSUER_HEADER_NAME is not None:
            issuer = request.META.get(self.ISSUER_HEADER_NAME, None)
            certificate = request.META.get(self.CERTIFICATE_HEADER_NAME, None)
            if issuer and certificate:
                certificate = self.prepare_certificate(certificate)
                setattr(request, 'id_cert', certificate)

                # OCSP check
                issuer = self.parse_client_dn(issuer)
                response = self.verify_ocsp(certificate, issuer)

                # Code 0 means success, everything else is error
                if response != 0:
                    logger.info("BaseIdCardMiddleware: OCSP verification returned %s", response)
                    delattr(request, 'id_auth')
                    setattr(request, 'id_err', response)

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
        return config.ocsp_url()

    @classmethod
    def get_ocsp_responder_certificate_path(cls):
        """Get ocsp responder certificate path

        Note: This is a separate method to allow easier overwriting via subclassing

        :return:str
        """
        return config.ocsp_responder_certificate_path()

    @classmethod
    def verify_ocsp(cls, certificate, issuer):
        """ Runs OCSP verification and returns error code - 0 means success
        """

        return OCSPVerifier(certificate, issuer,
                            cls.get_ocsp_url(),
                            cls.get_ocsp_responder_certificate_path()).verify()


class ApacheIdCardMiddleware(BaseIdCardMiddleware):
    """ ID card middleware configured for Apache server

    Requires standard SSL_CLIENT_S_DN, SSL_CLIENT_I_DN and SSL_CLIENT_CERT headers.
    """

    DN_HEADER_NAME = 'HTTP_SSL_CLIENT_S_DN'
    ISSUER_HEADER_NAME = 'HTTP_SSL_CLIENT_I_DN'
    CERTIFICATE_HEADER_NAME = 'HTTP_SSL_CLIENT_CERT'

    def prepare_certificate(self, certificate):
        return certificate.replace(' ', '\n').replace('\nCERTIFICATE-----', ' CERTIFICATE-----')

    def parse_client_dn(self, dn):
        return parse_rfc_dn(dn)


class NginxIdCardMiddleware(BaseIdCardMiddleware):
    DN_HEADER_NAME = 'HTTP_X_CLIENT'

    # TODO: Set to a valid value once we add certificates support
    CERTIFICATE_HEADER_NAME = None


class IdCardMiddleware(NginxIdCardMiddleware):
    """ Deprecated - use ApacheIdCardMiddleware or NginxIdCardMiddleware """
