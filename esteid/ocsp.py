import os
import subprocess
import logging

from tempfile import NamedTemporaryFile

from django.utils.encoding import force_bytes, force_text

from . import config


class OCSPVerifier(object):
    CERT_PATH = os.path.join(os.path.dirname(__file__), 'certs')

    ISSUER_CERTS = {
        "ESTEID-SK 2007": "ESTEID-SK_2007.pem",
        "ESTEID-SK 2011": "ESTEID-SK_2011.pem",
        "ESTEID-SK 2015": "ESTEID-SK_2015.pem",
    }

    OCSP_URLS = {
        'TEST': 'http://demo.sk.ee/ocsp',
        'LIVE': 'http://ocsp.sk.ee',
    }

    VA_FILES = {
        'TEST': 'TEST_OCSP_2011.pem',
        'LIVE': 'sk-ocsp-responder-certificates.pem',
    }

    def __init__(self, certificate, issuer):
        self.certificate = certificate
        self.issuer = self.parse_issuer(issuer)

    def verify(self):
        if not self.certificate:
            return 1

        if not self.issuer:
            return 2

        issuer_cn = self.issuer.get('CN', None)
        if not issuer_cn:
            return 3

        if issuer_cn not in self.ISSUER_CERTS:
            return 4

        # Save cert to a temporary file
        cert_file = NamedTemporaryFile(delete=False)
        cert_file.write(force_bytes(self.certificate.replace('\t', '')))
        cert_file.close()

        # Run openssl ocsp verify command
        args = [
            'openssl', 'ocsp',
            '-issuer %s' % os.path.join(self.CERT_PATH, self.ISSUER_CERTS[issuer_cn]),
            '-cert %s' % cert_file.name,
            '-url %s' % self.OCSP_URLS[config.client_type()],
            '-VAfile %s' % os.path.join(self.CERT_PATH, self.VA_FILES[config.client_type()]),
        ]

        try:
            output = subprocess.check_output(' '.join(args), stderr=subprocess.STDOUT, shell=True)
            output = force_text(output)

            if ': good' in output:
                result = 0

            elif ': revoked' in output:
                result = 6

            else:
                result = 7

        except subprocess.CalledProcessError as e:
            logging.error('Output was: %s', e.output)
            result = 5

        # delete temporary file
        os.unlink(cert_file.name)

        return result

    @classmethod
    def parse_issuer(cls, issuer):
        res = {}
        issuer = issuer.strip().strip('/').split('/')

        for part in issuer:
            part = part.split('=')
            res[part[0]] = part[1]

        return res
