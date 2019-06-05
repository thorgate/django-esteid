from oscrypto.asymmetric import load_certificate

from esteid import certs
from .ocsp import OCSP
from .tsa import TSA


def finalize_signature(xml_signature, lt_ts=False, is_demo=False):
    """Finalize the XAdES signature in accordance with LT-TM profile, or LT-TS profile if `lt_ts` is True

    :param XmlSignature xml_signature:
    :param bool lt_ts: Whether to make the signature compliant with LT-TS and perform a TSA request
    :param bool is_demo: Whether to use the demo services instead of the production
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
