# coding: utf-8
from __future__ import unicode_literals
import hashlib

from oscrypto import asymmetric

from asn1crypto.algos import DigestInfo
from asn1crypto.core import Boolean, OctetString
from asn1crypto.ocsp import OCSPRequest, OCSPResponse, TBSRequest, TBSRequestExtension, TBSRequestExtensionId
from asn1crypto.x509 import Certificate

import requests

from .exceptions import BDoc2Error


class SKHackedTBSRequestExtension(TBSRequestExtension):
    """A workaround class for MobiilID compatibility

    The jdigidoc library used in the SK service fails to validate an OCSP request
    made up with the original TBSRequestExtension because it expects a plain OctetString in the value field.
    This does not break validation with newer libraries including digidoc-tool
    """
    _fields = [
        ('extn_id', TBSRequestExtensionId),
        ('critical', Boolean, {'default': False}),
        ('extn_value', OctetString),  # This replaces ParsableOctetString
    ]


class OCSPError(BDoc2Error):
    pass


class OCSP(object):
    """
    Certificate validation request via the OCSP protocol, using the asn1crypto/ocspbuilder stack.

    Perform certificate validation:

        ocsp = OCSP()
        ocsp.validate(subject_cert, issuer_cert, signature)

    Check an arbitrary response:

        ocsp = OCSP.load(der_encoded_binary_data)
    """
    DEMO_URL = 'http://demo.sk.ee/ocsp'
    PROD_URL = 'http://ocsp.sk.ee/'

    REQUEST_CONTENT_TYPE = 'application/ocsp-request'
    RESPONSE_CONTENT_TYPE = 'application/ocsp-response'

    def __init__(self, url=None):
        """
        """
        self.url = self.PROD_URL if url is None else url
        self.ocsp_response = None

    def validate(self, subject_cert, issuer_cert, signature):
        """
        A correct OCSP request for BDOC-TM shall contain a DER-encoded "Hash value of the binary value of
        the signature along with hash algorithm identifier" in the `nonce` field. Yet at the moment, apparently
        the OCSP service doesn't qualify for time-mark BDOCs so this is probably not significant

        Provide certificates as asn1crypto.x509.Certificate object, oscrypto.asymmetric.Certificate object,
          a buffer (bytes) in PEM or DER format, or a path to a certificate file.

        :param issuer_cert: a certificate object, a buffer or a path to file
        :param subject_cert: a certificate object, a buffer or a path to file
        :param bytes signature: required for BDOC-TM format
        :return:
        """
        ocsp_request = self.build_ocsp_request(subject_cert, issuer_cert, signature)

        try:
            response = requests.post(
                self.url,
                data=ocsp_request.dump(),
                headers={'Content-Type': self.REQUEST_CONTENT_TYPE, 'Connection': 'close'}
            )
            response.raise_for_status()
        except requests.ConnectionError:
            raise OCSPError("Failed to connect to OCSP service at {}".format(self.url))
        except requests.HTTPError as e:
            raise OCSPError("Bad response from OCSP service at {}: {}".format(self.url, e))

        assert response.status_code == 200  # this wouldn't tell anything yet
        assert response.headers['Content-Type'] == self.RESPONSE_CONTENT_TYPE

        ocsp_response = OCSPResponse.load(response.content)
        ocsp_status = ocsp_response['response_status'].native
        if ocsp_status != 'successful':
            raise OCSPError("OCSP validation failed: certificate is %s" % ocsp_status)

        self.ocsp_request = ocsp_request
        self.ocsp_response = ocsp_response
        return ocsp_response

    def get_responder_certs(self):
        """Get OCSP responder certificates embedded in the response

        :return: Tuple[asn1crypto.x509.Certificate]
        """
        return tuple(self.ocsp_response.basic_ocsp_response['certs'])

    def get_encapsulated_response(self):
        """Get a DER-encoded OCSP response"""
        return self.ocsp_response.dump()

    @classmethod
    def load(cls, binary_data):
        me = cls()
        me.ocsp_response = OCSPResponse.load(binary_data)
        return me

    @classmethod
    def build_ocsp_request(cls, subject_cert, issuer_cert, signature=None):
        if not isinstance(issuer_cert, (Certificate, asymmetric.Certificate)):
            issuer_cert = asymmetric.load_certificate(issuer_cert)
        if not isinstance(subject_cert, (Certificate, asymmetric.Certificate)):
            subject_cert = asymmetric.load_certificate(subject_cert)

        extensions = None
        if signature is not None:
            nonce = cls.build_nonce(signature)
            extensions = [SKHackedTBSRequestExtension({
                'extn_id': 'nonce',
                'critical': False,
                'extn_value': nonce.dump(),
            })]

        tbs_request = cls.build_tbs_request(subject_cert.asn1, issuer_cert.asn1, tbs_request_extensions=extensions)
        ocsp_request = OCSPRequest({
            'tbs_request': tbs_request,
            'optional_signature': None,
        })
        return ocsp_request

    @classmethod
    def build_nonce(cls, signature):
        digest = hashlib.sha256(signature).digest()
        obj = DigestInfo({
            'digest_algorithm': {
                'algorithm': 'sha256',
            },
            'digest': digest,
        })
        return obj

    @classmethod
    def build_tbs_request(cls, subject_cert, issuer_cert, tbs_request_extensions=None, request_extensions=None,
                          _key_hash_algo='sha1'):
        """Build a TBSRequest entry for OCSPRequest

        :param asn1crypto.x509.Certificate subject_cert:
        :param asn1crypto.x509.Certificate issuer_cert:
        :param Optional[list] tbs_request_extensions:
        :param Optional[list] request_extensions:
        :param string _key_hash_algo:
        :return:
        """
        return TBSRequest({
            'request_list': [
                {
                    'req_cert': {
                        'hash_algorithm': {
                            'algorithm': _key_hash_algo
                        },
                        'issuer_name_hash': getattr(subject_cert.issuer, _key_hash_algo),
                        'issuer_key_hash': getattr(issuer_cert.public_key, _key_hash_algo),
                        'serial_number': subject_cert.serial_number,
                    },
                    'single_request_extensions': request_extensions,
                }
            ],
            'request_extensions': tbs_request_extensions,
        })
