from oscrypto.asymmetric import load_certificate

from esteid import certs
from .container import BDoc2File
from .exceptions import NoFilesToSign
from .ocsp import OCSP
from .tsa import TSA
from .xmlsig import XmlSignature


def prepare_signature(user_certificate: bytes, container: BDoc2File, is_demo=False) -> XmlSignature:
    """Generate the XAdES signature structure

    :param user_certificate: the DER-encoded certificate
    :param container: The BDoc2 container to operate on
    :param bool is_demo: Whether to use the demo root certificate. For ID card signatures, this should be left false
    """
    if not container.has_data_files():
        raise NoFilesToSign(f"Container `{container}` contains no files to sign")

    # Generate a XAdES signature
    xml_sig = XmlSignature.create()

    for file_name, content, mime_type in container.iter_data_files():
        xml_sig.add_document(file_name, content, mime_type)

    xml_sig.set_certificate(user_certificate) \
        .add_root_ca_cert(XmlSignature.TEST_ROOT_CA_CERT if is_demo else XmlSignature.ROOT_CA_CERT) \
        .update_signed_info()

    return xml_sig


def finalize_signature(xml_signature, lt_ts=False, is_demo=False):
    """Finalize the XAdES signature in accordance with LT-TM profile, or LT-TS profile if `lt_ts` is True

    :param XmlSignature xml_signature:
    :param bool lt_ts: Whether to make the signature compliant with LT-TS and perform a TSA request
    :param bool is_demo: Whether to use the demo services instead of the production. For ID card signatures,
                         this should be left false.
    """
    subject_cert = xml_signature.get_certificate()
    issuer_cn = subject_cert.asn1.issuer.native['common_name']
    issuer_cert = load_certificate(certs.get_certificate_file_name(issuer_cn))

    # Get an OCSP status confirmation
    ocsp = OCSP(url=OCSP.DEMO_URL if is_demo else None)
    ocsp.validate(subject_cert, issuer_cert, xml_signature.get_signature_value())

    # Embed the OCSP response
    xml_signature.add_ocsp_response(ocsp)

    if lt_ts:
        # Get a signature TimeStamp
        tsa = TSA(url=TSA.DEMO_URL if is_demo else None)
        tsr = tsa.get_timestamp(xml_signature.get_timestamp_response())
        xml_signature.add_timestamp_response(tsr)
    else:
        xml_signature.remove_timestamp_node()
