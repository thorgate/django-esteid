import os
import subprocess
import logging

from tempfile import NamedTemporaryFile

from django.utils.encoding import force_bytes, force_text


logger = logging.getLogger(__name__)


class OCSPVerifier(object):
    CERT_PATH = os.path.join(os.path.dirname(__file__), 'certs')

    ISSUER_CERTS = {
        # Test certs
        'TEST of SK OCSP RESPONDER 2011': 'TEST_OCSP_2011.pem',
        'TEST of EID-SK 2011': 'TEST_of_EID-SK_2011.pem',
        'TEST of EID-SK 2016': 'TEST_of_EID-SK_2016.pem',
        'TEST of ESTEID-SK 2011': 'TEST_of_ESTEID-SK_2011.pem',
        'TEST of ESTEID-SK 2015': 'TEST_of_ESTEID-SK_2015.pem',
        'TEST of KLASS3-SK 2010': 'TEST_of_KLASS3-SK_2010.pem',
        'TEST of KLASS3-SK 2016': 'TEST_of_KLASS3-SK_2016.pem',

        # Live certs
        'ESTEID-SK 2007': 'ESTEID-SK_2007.pem',
        'ESTEID-SK 2011': 'ESTEID-SK_2011.pem',
        'ESTEID-SK 2015': 'ESTEID-SK_2015.pem',
        'EID-SK 2011': 'EID-SK_2011.pem',
        'EID-SK 2016': 'EID-SK_2016.pem',
        'KLASS3-SK 2010': 'KLASS3-SK_2010_EECCRCA.pem',
        'KLASS3-SK 2016': 'KLASS3-SK_2016_EECCRCA_SHA384.pem',
    }

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

        issuer_cn = self.issuer.get('CN', None)
        if not issuer_cn:
            return 3

        issuer_cert_filename = self.get_issuer_cert_filename(issuer_cn)
        if issuer_cert_filename is None:
            return 4

        # Save cert to a temporary file
        cert_file = NamedTemporaryFile(delete=False)
        cert_file.write(force_bytes(self.certificate.replace('\t', '')))
        cert_file.close()

        # Run openssl ocsp verify command
        args = [
            'openssl', 'ocsp',
            '-issuer %s' % issuer_cert_filename,
            '-cert %s' % cert_file.name,
            '-url %s' % self.ocsp_url,
            '-VAfile %s' % self.va_file_path,
        ]

        try:
            output = subprocess.check_output(' '.join(args), stderr=subprocess.STDOUT, shell=True)
            output = force_text(output)

            if ': good' in output:
                result = 0

            elif ': revoked' in output:
                result = 6

            else:
                logger.info('openssl ocsp: unknown output: %s', output)
                result = 7

        except subprocess.CalledProcessError as e:
            logger.error('openssl ocsp: failed with output: %s', e.output)
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

    def get_issuer_cert_filename(self, issuer_cn):
        filename = self.ISSUER_CERTS.get(issuer_cn, None)
        if filename is None:
            return None

        return os.path.join(self.CERT_PATH, filename)
