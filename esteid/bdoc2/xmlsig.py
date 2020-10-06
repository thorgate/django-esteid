import base64
import copy
import hashlib
import logging
import os
from typing import Union

from oscrypto.asymmetric import load_certificate, Certificate
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime

from lxml import etree

from esteid import certs
from .ocsp import OCSP
from .signature_verifier import verify

logger = logging.getLogger(__name__)


def get_utc_time():
    # For testing purposes, as we can't patch a datetime object
    return datetime.utcnow()


class XmlSignature(object):
    """
    Usage:

        # Create a signature XAdES structure
        sig = XmlSignature.create() \
            .add_document('test.pdf', b'PDF data', 'application/pdf') \
            .set_certificate(file_or_binary_data) \
            .update_signed_info()

        # Get the actual signature from e.g. smartid, out of scope
        signature_value = sign(id_code, sig.digest())

        # Get OCSP and TSA confirmation
        from .utils import finalize_signature
        finalize_signature(sig, lt_ts=True)

        result_xml = sig.add_signature(signature_value) \
            .verify() \
            .add_ocsp_response(ocsp) \
            .add_timestamp_response(ocsp) \
            .dump()
    """
    SIGNATURE_TEMPLATE = os.path.join(os.path.dirname(__file__), 'templates', 'signature.xml')
    NAMESPACES = {
        'asic': 'http://uri.etsi.org/02918/v1.2.1#',
        'ds': 'http://www.w3.org/2000/09/xmldsig#',
        'xades': 'http://uri.etsi.org/01903/v1.3.2#',
    }

    C14N_METHODS = (
        'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',  # this is the REQUIRED c14n algorithm [xmldsig]
        'http://www.w3.org/2001/10/xml-exc-c14n#',
        'http://www.w3.org/2006/12/xml-c14n11',
    )

    DIGEST_ALGORITHMS = {
        'sha256': 'http://www.w3.org/2001/04/xmlenc#sha256',
    }

    SIGNED_PROPERTIES_TYPE = (
        # Standards are ambiguous about this:
        'http://uri.etsi.org/01903#SignedProperties',  # BDOC 2.1.2 mandates this
        'http://uri.etsi.org/01903/v1.1.1#SignedProperties',  # and this is as per https://www.w3.org/TR/XAdES/
    )

    NEW_SIGNATURE_ID = u'S1'  # This is arbitrary but used a few times in the XAdES structure.
    ROOT_CA_CERT = 'EE_Certification_Centre_Root_CA.pem'
    TEST_ROOT_CA_CERT = 'TEST_of_EE_Certification_Centre_Root_CA.pem'

    def __init__(self, xml_or_binary_data):
        if isinstance(xml_or_binary_data, (etree._Element, etree._ElementTree)):
            self.xml = xml_or_binary_data
        else:
            parser = etree.XMLParser(remove_blank_text=True, remove_comments=True)
            try:
                self.xml = etree.XML(xml_or_binary_data, parser=parser)
            except ValueError:
                logger.exception("Failed to load XML document: %s", xml_or_binary_data)
                raise

        if self.xml.tag != '{%s}XAdESSignatures' % self.NAMESPACES['asic']:
            raise ValueError("Expecting an 'asic:XAdESSignatures' root node")

        data_objects_props_node = self._get_node('ds:SignedInfo')
        doc_entries = data_objects_props_node.findall('ds:Reference[@Type=""]', namespaces=self.NAMESPACES)
        self.doc_ids = [doc_entry.attrib['Id'] for doc_entry in doc_entries]

        self._certificate: Certificate = None

    @classmethod
    def create(cls):
        """Create a XAdES structure from the accompanying template"""
        with open(cls.SIGNATURE_TEMPLATE, 'rb') as f:
            xml_sig = cls(f.read().replace(b'{SIGNATURE_ID}', cls.NEW_SIGNATURE_ID.encode('ascii')))
            xml_sig.doc_ids = []
            return xml_sig

    def get_signed_time(self):
        return self._get_node('xades:SigningTime').text

    def get_certificate(self):
        if not self._certificate:
            cert_asn1 = self.get_certificate_value()
            if cert_asn1:
                self._certificate = load_certificate(cert_asn1)
        return self._certificate

    def get_certificate_value(self):
        cert_node = self._get_node('ds:X509Certificate')
        if cert_node is None or not cert_node.text:
            return None
        return base64.b64decode(cert_node.text)

    def set_certificate(self, subject_cert: Union[bytes, Certificate]):
        """Set the certificate that would be used for signing

        :param subject_cert: bytes, file name (Python 3.4+), asn1crypto.x509.Certificate objects
        :return:
        """
        if not isinstance(subject_cert, Certificate):
            subject_cert = load_certificate(subject_cert)

        self._certificate = subject_cert

        cert_asn1 = subject_cert.asn1
        der_encoded_cert = cert_asn1.dump()
        serial_number = (u'%d' % cert_asn1.serial_number).encode('ascii')

        cert_node = self._get_node('ds:X509Certificate')
        cert_node.text = base64.b64encode(der_encoded_cert)

        cert_props = self._get_node('xades:SigningCertificate')
        cert_props.find('.//ds:DigestValue', namespaces=self.NAMESPACES).text = base64.b64encode(cert_asn1.sha256)
        cert_props.find('.//ds:X509SerialNumber', namespaces=self.NAMESPACES).text = serial_number

        # No idea what value is possible, but rfc4514 is most common, so get it from a cryptography object
        x509_cert = x509.load_der_x509_certificate(der_encoded_cert, default_backend())
        cert_props.find('.//ds:X509IssuerName', namespaces=self.NAMESPACES).text = x509_cert.issuer.rfc4514_string()

        return self

    def add_document(self, file_name, binary_data, mime_type, hash_type='sha256'):
        """Add a document for signing

        :param file_name: the file name to display in the container
        :param mime_type: the document's mime type
        :param binary_data: the document's contents
        :param hash_type: the hash function to use for digesting
        :return:
        """
        if hash_type not in self.DIGEST_ALGORITHMS:
            raise ValueError('Unknown hash type: %s' % hash_type)

        digest_fn = getattr(hashlib, hash_type)
        doc_hash = digest_fn(binary_data).digest()

        signed_info = self._get_node('ds:SignedInfo')
        first_ref_entry = signed_info.find('.//ds:Reference[@Type=""]', namespaces=self.NAMESPACES)
        doc_id = first_ref_entry.attrib['Id']

        doc_props = self._get_node('xades:SignedDataObjectProperties')
        first_doc_entry = doc_props.find('.//xades:DataObjectFormat[@ObjectReference="#%s"]' % doc_id,
                                         namespaces=self.NAMESPACES)

        if self.doc_ids:
            next_num = len(self.doc_ids) + 1

            # generate new Id attribute
            while True:
                new_doc_id = 'r-id-{}'.format(next_num)
                if new_doc_id not in self.doc_ids:
                    break
                next_num += 1

            # Instead of manually creating elements, just copy the structure
            new_ref_entry = copy.deepcopy(first_ref_entry)
            signed_info.append(new_ref_entry)

            new_doc_entry = copy.deepcopy(first_doc_entry)
            doc_props.append(new_doc_entry)
        else:
            new_doc_id = doc_id.format(DOCUMENT_NUMBER=1)
            new_doc_entry = first_doc_entry
            new_ref_entry = first_ref_entry

        self.doc_ids.append(new_doc_id)
        new_ref_entry.attrib['Id'] = new_doc_id
        new_ref_entry.attrib['URI'] = file_name
        new_ref_entry.find('.//ds:DigestMethod', namespaces=self.NAMESPACES).attrib['Algorithm'] = self.DIGEST_ALGORITHMS[hash_type]
        new_ref_entry.find('.//ds:DigestValue', namespaces=self.NAMESPACES).text = base64.b64encode(doc_hash)

        new_doc_entry.attrib['ObjectReference'] = '#%s' % new_doc_id
        new_doc_entry.find('.//xades:MimeType', namespaces=self.NAMESPACES).text = mime_type

        return self

    def update_signed_info(self):
        """Calculate the digest over SignedProperties and embed it in SignedInfo"""

        sp_ref_node = next(
            self.xml.find('.//ds:SignedInfo/ds:Reference[@Type="%s"]' % ref_type, namespaces=self.NAMESPACES)
            for ref_type in self.SIGNED_PROPERTIES_TYPE
        )

        # Get a transform/c14n algorithm
        # This is very obscure in the standard:
        # https://www.w3.org/TR/2002/REC-xmldsig-core-20020212/#sec-ReferenceProcessingModel
        try:
            c14n_alg = sp_ref_node.find('.//ds:Transform').attrib['Algorithm']
        except:  # noqa: E722
            c14n_alg = None

        signed_props_node = self._get_node('xades:SignedProperties')
        time_node = signed_props_node.find('.//xades:SigningTime', namespaces=self.NAMESPACES)
        # Add a UTC timestamp. Can't use isoformat() as it adds +00:00 and microseconds
        #  which can break the parser elsewhere
        time_node.text = get_utc_time().strftime('%Y-%m-%dT%H:%M:%SZ')

        signed_props_c14n = self.canonicalize(signed_props_node, c14n_alg)
        # TODO select algorithm based on DigestMethod // update DigestMethod
        signed_props_hash = hashlib.sha256(signed_props_c14n).digest()
        sp_ref_node.find('.//ds:DigestValue', namespaces=self.NAMESPACES).text = base64.b64encode(signed_props_hash)

        return self

    def signed_data(self):
        sign_info_node = self._get_node('ds:SignedInfo')
        return self.canonicalize(sign_info_node)

    def digest(self):
        return hashlib.sha256(self.signed_data()).digest()

    def get_signature_value(self):
        sig_value_node = self._get_node('ds:SignatureValue')
        return base64.b64decode(sig_value_node.text)

    def add_signature_value(self, signature):
        """Insert the base64-encoded value of a signature obtained from a signing service

        NOTE: the signature method should be known in advance, as it's part of the SignedInfo structure over which
          the signature is calculated.

        :param signature: Binary signature
        :return:
        """
        sig_value_node = self._get_node('ds:SignatureValue')
        sig_value_node.text = base64.b64encode(signature)
        return self

    def add_root_ca_cert(self, cert_file):
        """Add a root CA cert from file.

        :param cert_file: can be one of self.ROOT_CA_CERT, self.TEST_ROOT_CA_CERT, or an absolute path
        """
        certs_node = self._get_node('xades:CertificateValues')
        ca_node = etree.Element('{%s}EncapsulatedX509Certificate' % self.NAMESPACES['xades'])
        ca_node.attrib['Id'] = (u'%s-ROOT-CA-CERT' % self.NEW_SIGNATURE_ID).encode('ascii')
        with open(os.path.join(certs.CERT_PATH, cert_file), 'rb') as f:
            root_cert = load_certificate(f.read())
        ca_node.text = base64.b64encode(root_cert.asn1.dump())
        certs_node.append(ca_node)
        return self

    def add_ocsp_response(self, ocsp_response, embed_ocsp_certificate=False):
        """
        Embed the OCSP response and certificates

        :param OCSP ocsp_response:
        :param bool embed_ocsp_certificate: Whether to add ocsp certificate to the xml. This is needed when the OCSP service in use
            does not embed the certificate in its response.
        :return: self
        """
        ocsp_response_node = self._get_node('xades:EncapsulatedOCSPValue')
        ocsp_response_node.text = base64.b64encode(ocsp_response.get_encapsulated_response())

        if embed_ocsp_certificate:
            ocsp_certs_node = self._get_node('xades:CertificateValues')
            ocsp_certs = ocsp_response.get_responder_certs()
            cert_node = ocsp_certs_node.find('.//xades:EncapsulatedX509Certificate', namespaces=self.NAMESPACES)
            cert_node.text = base64.b64encode(ocsp_certs[0].dump())
            cert_node.attrib['Id'] = 'S1-Responder-cert-1'

            for i, next_cert in enumerate(ocsp_certs[1:]):
                cert_node = copy.deepcopy(cert_node)
                cert_node.text = base64.b64encode(ocsp_certs[next_cert].dump())
                cert_node.attrib['Id'] = 'S1-Responder-cert-%d' % i
                ocsp_certs_node.append(cert_node)

        return self

    def get_ocsp_response(self):
        ocsp_response_node = self._get_node('xades:EncapsulatedOCSPValue')
        return OCSP.load(base64.b64decode(ocsp_response_node.text))

    def get_timestamp_response(self):
        sig_value_node = self._get_node('ds:SignatureValue')
        method = self.get_c14n_method('xades:SignatureTimeStamp')
        return self.canonicalize(sig_value_node, method)

    def add_timestamp_response(self, tsr):
        ts_value_node = self._get_node('xades:EncapsulatedTimeStamp')
        ts_value_node.text = base64.b64encode(tsr.dump())
        return self

    def remove_timestamp_node(self):
        ts_value_node = self._get_node('xades:SignatureTimeStamp')
        ts_value_node.getparent().remove(ts_value_node)
        return self

    def dump(self):
        return b'<?xml version="1.0" encoding="UTF-8"?>' + etree.tostring(self.xml)

    def verify(self):
        hash_algo = 'sha256'  # TODO get from where it's appropriate
        cert = self.get_certificate_value()
        signature = self.get_signature_value()
        signed_data = self.signed_data()
        verify(cert, signature, signed_data, hash_algo)
        return self

    def get_c14n_method(self, parent_node='ds:SignedInfo'):
        """Get a c14n method used within a specific context given by `parent_node`

        The default context is the SignedInfo node. Also encountered in SignatureTimestamp

        :param parent_node:
        :return:
        """
        method_node = self._get_node('{}/ds:CanonicalizationMethod'.format(parent_node))
        if method_node is not None:
            method = method_node.attrib['Algorithm']
            if method not in self.C14N_METHODS:
                raise ValueError("Unknown c14n method: {}".format(method))
        else:
            method = self.C14N_METHODS[0]
        return method

    def canonicalize(self, node, method=None):
        if method is not None:
            assert method in self.C14N_METHODS
        else:
            method = self.get_c14n_method()
        exclusive = 'xml-exc-c14n' in method
        return etree.tostring(node, method='c14n', exclusive=exclusive)

    def _get_node(self, tag_name):
        return self.xml.find('.//{}'.format(tag_name), namespaces=self.NAMESPACES)
