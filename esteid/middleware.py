from django.utils.cache import patch_vary_headers

from esteid.helpers import parse_legacy_dn
from . import config
from .ocsp import OCSPVerifier


try:
    from django.utils.deprecation import MiddlewareMixin
except ImportError:  # Django < 1.10
    # Works perfectly for everyone using MIDDLEWARE_CLASSES
    MiddlewareMixin = object


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


class IdCardMiddleware(MiddlewareMixin):
    # This allows one to easily change the DN format used (legacy, rfc)
    parse_x_client = parse_legacy_dn

    def process_request(self, request):
        x_client = request.META.get('HTTP_X_CLIENT', None)

        if x_client is not None:
            response = self.verify_ocsp(request)

            if response != 0:
                setattr(request, 'id_err', response)

            else:
                setattr(request, 'id_auth', self.parse_x_client(x_client) if x_client else None)

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
    def verify_ocsp(cls, request):
        issuer = request.META.get('HTTP_X_ISSUER', None)
        certificate = request.META.get('HTTP_X_CLIENTCERT', None)
        return OCSPVerifier(certificate, issuer,
                            cls.get_ocsp_url(),
                            cls.get_ocsp_responder_certificate_path()).verify()
