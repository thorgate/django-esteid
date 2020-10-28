"""
Compatibility utilities that provide signed container info
in the same format as the DDS service did.
"""
import base64
import hashlib

from pyasice import Container, XmlSignature

from esteid.types import ResponderCertificate, SignedDocInfo


def signature_info(xml_signature: XmlSignature):
    subject_cert = xml_signature.get_certificate()
    cert_asn1 = subject_cert.asn1
    personal = cert_asn1.subject.native
    validity = cert_asn1.native["tbs_certificate"]["validity"]
    signing_time = xml_signature.get_signing_time()

    return {
        "id": xml_signature._get_node("ds:Signature").attrib["Id"],
        "signing_time": signing_time,
        "status": True,
        "signature_production_place": None,
        "signer": {
            "certificate": {
                "issuer": xml_signature._get_node("xades:SigningCertificate//ds:X509IssuerName").text,
                "issuer_serial": xml_signature._get_node("xades:SigningCertificate//ds:X509SerialNumber").text,
                "policies": [],
                "subject": personal["common_name"],
                "valid_from": validity["not_before"].strftime("%Y-%m-%dT%H:%M:%SZ"),
                "valid_to": validity["not_after"].strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            "full_name": "%s %s" % (personal["given_name"], personal["surname"]),
            "id_code": personal["serial_number"].split("-")[-1],
        },
        "confirmation": {
            # if ever needed
            "produced_at": signing_time,
            "responder_id": "OCSP",
            # TODO: create an API to extract the data from xml_signature and cover by tests.
            # Currently it is accessible as a wrapped asn1crypto.x509.Certificate by smth like:
            # xml_signature.get_responder_certs()[0].native['tbs_certificate']
            # individual fields: ocsp_cert['issuer'] etc
            "responder_certificate": ResponderCertificate(
                issuer="", valid_from="", valid_to="", issuer_serial="", subject=""
            ),
        },
        "signer_role": [{"certified": 0, "role": None}],
    }


def container_info(bdoc_container: Container, full=True):
    if full:
        data_files_info = [
            {
                "digestType": "sha256",
                "digestValue": base64.b64encode(hashlib.sha256(content).digest()).decode(),
                "filename": name,
                "id": name,
                "mimeType": mimetype,
                "contentType": mimetype,
                "size": len(content),
            }
            for name, content, mimetype in bdoc_container.iter_data_files()
        ]
    else:
        data_files_info = [
            {
                "filename": name,
            }
            for name in bdoc_container.data_file_names
        ]
    return SignedDocInfo.from_dict(
        {
            "dataFileInfo": data_files_info,
            "format": "BDOC",
            "signature_info": [signature_info(signature) for signature in bdoc_container.iter_signatures()],
            "version": "2.1",
        }
    )
