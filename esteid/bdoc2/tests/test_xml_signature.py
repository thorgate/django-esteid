import base64
import hashlib
from datetime import datetime

import pytest

from lxml import etree
from unittest.mock import patch
from oscrypto.asymmetric import Certificate, load_certificate

from ... import certs
from .. import xmlsig
from ..xmlsig import XmlSignature


def test_xmlsig_create():
    xml_signature = XmlSignature.create()

    assert xml_signature.xml.tag == '{%(asic)s}XAdESSignatures' % xml_signature.NAMESPACES

    signature_node = xml_signature.xml.find('./ds:Signature', namespaces=xml_signature.NAMESPACES)
    assert signature_node is not None
    assert signature_node.attrib['Id'] == xml_signature.NEW_SIGNATURE_ID

    assert xml_signature.doc_ids == []


def test_xmlsig_load_ok():
    with open(XmlSignature.SIGNATURE_TEMPLATE, 'rb') as f:
        xml_signature = XmlSignature(f.read())

    assert xml_signature.xml.tag == '{%(asic)s}XAdESSignatures' % xml_signature.NAMESPACES

    signature_node = xml_signature.xml.find('./ds:Signature', namespaces=xml_signature.NAMESPACES)
    assert signature_node is not None
    assert signature_node.attrib['Id'] == '{SIGNATURE_ID}'

    assert xml_signature.doc_ids == ['r-id-{DOCUMENT_NUMBER}']


def test_xmlsig_load_error():
    with pytest.raises(etree.XMLSyntaxError):
        XmlSignature(b'not xml')

    with pytest.raises(ValueError):
        XmlSignature(b'<some>xml</some>')

    with pytest.raises(ValueError):
        XmlSignature(etree.XML(b'<some>xml</some>'))


def test_xmlsig_signing_time():
    xml_signature = XmlSignature.create()

    assert xml_signature.get_signed_time() == '{SIGNATURE_TIMESTAMP}'

    with patch.object(xmlsig, 'get_utc_time', lambda: datetime(2000, 1, 1, 0, 0, 0)):
        xml_signature.update_signed_info()

    assert xml_signature.get_signed_time() == '2000-01-01T00:00:00Z'


def test_xmlsig_certificate():
    xml_signature = XmlSignature.create()

    assert xml_signature.get_certificate_value() is None
    assert xml_signature.get_certificate() is None

    cert = load_certificate(certs.get_certificate('TEST of EID-SK 2016'))

    xml_signature.set_certificate(cert)

    assert xml_signature.get_certificate_value() == cert.asn1.dump()
    assert isinstance(xml_signature.get_certificate(), Certificate)


def test_xmlsig_documents():
    xml_signature = XmlSignature.create()
    assert xml_signature.doc_ids == []

    xml_signature.add_document('test.txt', b'test', 'text/plain')
    digest = base64.b64encode(hashlib.sha256(b'test').digest()).decode('ascii')

    assert xml_signature.doc_ids == ['r-id-1']
    assert xml_signature._get_node('ds:Reference[@Id="r-id-1"]').attrib['URI'] == 'test.txt'
    assert xml_signature._get_node('ds:Reference[@Id="r-id-1"]/ds:DigestValue').text == digest
    assert xml_signature._get_node('xades:DataObjectFormat[@ObjectReference="#r-id-1"]'
                                   '/xades:MimeType').text == 'text/plain'

    xml_signature.add_document('test2.pdf', b'test PDF', 'application/pdf')
    digest = base64.b64encode(hashlib.sha256(b'test PDF').digest()).decode('ascii')

    assert xml_signature.doc_ids == ['r-id-1', 'r-id-2']
    assert xml_signature._get_node('ds:Reference[@Id="r-id-2"]').attrib['URI'] == 'test2.pdf'
    assert xml_signature._get_node('ds:Reference[@Id="r-id-2"]/ds:DigestValue').text == digest
    assert xml_signature._get_node('xades:DataObjectFormat[@ObjectReference="#r-id-2"]'
                                   '/xades:MimeType').text == 'application/pdf'
