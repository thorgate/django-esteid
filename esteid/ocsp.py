import logging
import os
import subprocess
import warnings
from tempfile import NamedTemporaryFile

from django.utils.encoding import force_bytes, force_text
from esteid_certificates import get_certificate_file_name, UnknownCertificateError


warnings.warn("This module is deprecated. Please use the new signing API", DeprecationWarning)


logger = logging.getLogger(__name__)


class OCSPVerifier(object):
    def __init__(self, certificate, issuer, ocsp_url, va_file_path):
        self.certificate = certificate
        self.issuer = issuer
        if isinstance(self.issuer, str):
            self.issuer = self.parse_issuer(issuer)

        self.ocsp_url = ocsp_url
        self.va_file_path = va_file_path

    def verify(self):
        if not self.certificate:
            return 1

        if not self.issuer:
            return 2

        issuer_cn = self.issuer.get("CN", None)
        if not issuer_cn:
            return 3

        try:
            issuer_cert_filename = get_certificate_file_name(issuer_cn)
        except UnknownCertificateError:
            return 4

        # Save cert to a temporary file
        cert_file = NamedTemporaryFile(delete=False)
        cert_file.write(force_bytes(self.certificate.replace("\t", "")))
        cert_file.close()

        # Run openssl ocsp verify command
        args = [
            "openssl",
            "ocsp",
            "-issuer %s" % issuer_cert_filename,
            "-cert %s" % cert_file.name,
            "-url %s" % self.ocsp_url,
            "-VAfile %s" % self.va_file_path,
        ]

        try:
            output = subprocess.check_output(" ".join(args), stderr=subprocess.STDOUT, shell=True)
            output = force_text(output)

            if ": good" in output:
                result = 0

            elif ": revoked" in output:
                result = 6

            else:
                logger.info("openssl ocsp: unknown output: %s", output)
                result = 7

        except subprocess.CalledProcessError as e:
            logger.error("openssl ocsp: failed with output: %s", e.output)
            result = 5

        # delete temporary file
        os.unlink(cert_file.name)

        return result

    @classmethod
    def parse_issuer(cls, issuer):
        res = {}
        issuer = issuer.strip().strip("/").split("/")

        for part in issuer:
            part = part.split("=")
            res[part[0]] = part[1]

        return res
