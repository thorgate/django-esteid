import binascii
import json
import logging
from pathlib import Path

from django.http import HttpRequest, HttpResponse
from django.template import RequestContext
from django.template.engine import Template
from django.views.generic.base import View
from esteid_certificates import get_certificate
from oscrypto.asymmetric import Certificate, load_certificate

import pyasice
from pyasice.ocsp import OCSP

from esteid import settings
from esteid.authentication.types import AuthenticationResult
from esteid.exceptions import EsteidError, InvalidParameter
from esteid.types import CertificateHolderInfo


logger = logging.getLogger(__name__)


class BaseIdCardAuthenticationView(View):
    """
    Receives client authentication data from the webserver through headers.

    It's mandatory to pass down the client certificate in one of the following manners:
    * the `X-Client-Cert` header - the preferred option for nginx
    * a so-called ENV variable `SSL_CLIENT_CERT`, which is provided by Apache.

    The certificate is verified at first reception and saved to session.

    The web server may also provide other client and issuer headers, but those are not crucial
    because the certificate contains all of them.
    """

    CERTIFICATE_HEADER_NAME = "HTTP_X_CLIENT_CERT"
    CERTIFICATE_ENV_NAME = "HTTP_SSL_CLIENT_CERT"

    TEMPLATE_SUCCESS = "iframe.html"
    TEMPLATE_FAILURE = "iframe-error.html"
    TEMPLATE_DIRECTORY = Path(__file__).parent / "templates"

    _certificate_handle: Certificate

    def on_auth_success(self, request: HttpRequest, auth_result: AuthenticationResult):
        """
        A hook to execute when authentication and OCSP validation were successful.
        """
        pass

    def authenticate(self, headers: dict) -> AuthenticationResult:
        """
        Receives a user certificate from the web server in PEM format
        """
        certificate_pem = headers.get(self.CERTIFICATE_HEADER_NAME) or headers.get(self.CERTIFICATE_ENV_NAME)
        if not certificate_pem:
            raise InvalidParameter("Missing required header 'X-Client-Cert'", param="certificate")

        certificate = "".join(
            [
                line
                for line in certificate_pem.split("\n")
                if line and "-" not in line  # removes both -----BEGIN and -----END CERTIFICATE-----
            ]
        )

        try:
            certificate = binascii.a2b_base64(certificate)
        except ValueError as e:
            raise InvalidParameter("Failed to decode `certificate` from PEM format", param="certificate") from e

        try:
            self._certificate_handle = load_certificate(certificate)
        except ValueError as e:
            raise InvalidParameter(
                "Failed to recognize `certificate` as a supported certificate format", param="certificate"
            ) from e

        cert_holder_info = CertificateHolderInfo.from_certificate(self._certificate_handle)

        return AuthenticationResult(
            country=cert_holder_info.country,
            id_code=cert_holder_info.id_code,
            given_name=cert_holder_info.given_name,
            surname=cert_holder_info.surname,
            certificate_b64=binascii.b2a_base64(certificate).decode(),
        )

    def get(self, request: HttpRequest, *args, **kwargs):
        try:
            auth_result = self.authenticate(request.META)
            self.validate_certificate_ocsp(self._certificate_handle)
        except EsteidError as e:
            logger.exception("Authentication error")
            template_file = self.TEMPLATE_FAILURE
            errors = e.get_user_error()
            http_status = e.status
            context = {"error": errors, "error_json": json.dumps(errors)}
        except pyasice.ocsp.OCSPError:
            logger.exception("OCSP validation error")
            template_file = self.TEMPLATE_FAILURE
            errors = {
                "error": "OCSPError",
                "message": "Certificate validation failed",
            }
            http_status = 409
            context = {"error": errors, "error_json": json.dumps(errors)}
        except Exception:
            logger.exception("Internal server error")
            template_file = self.TEMPLATE_FAILURE
            errors = {
                "error": "InternalError",
                "message": "Internal Error. Please contact the administrator",
            }
            http_status = 409
            context = {"error": errors, "error_json": json.dumps(errors)}
        else:
            template_file = self.TEMPLATE_SUCCESS
            context = {"auth_result": auth_result, "auth_result_json": json.dumps(auth_result)}
            http_status = 200

            self.on_auth_success(request, auth_result)

        with open(self.TEMPLATE_DIRECTORY / template_file) as f:
            template = Template(f.read())

        context = RequestContext(request, context)
        return HttpResponse(template.render(context), content_type="text/html; charset=utf-8", status=http_status)

    @staticmethod
    def validate_certificate_ocsp(certificate: Certificate):
        """
        Raises `pyasice.ocsp.OCSPError` on failure.

        Note: for Esteid, even the demo OCSP service validates real ID card certificates finely.
        """
        issuer_name = certificate.asn1.issuer.native["common_name"]
        issuer_cert = get_certificate(issuer_name)

        ocsp_url = settings.OCSP_URL

        ocsp = OCSP(ocsp_url)
        ocsp.validate(certificate, issuer_cert, signature=b"")  # give an empty bytes so it satisfies type checking