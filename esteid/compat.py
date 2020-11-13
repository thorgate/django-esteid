"""
Compatibility utilities that provide signed container info
in the same format as the DDS service did.
"""
import base64
import hashlib

import attr

from pyasice import Container, XmlSignature

from esteid.types import ResponderCertificate, SignedDocInfo, Signer


def signature_info(xml_signature: XmlSignature):
    subject_cert = xml_signature.get_certificate()
    ocsp_cert = xml_signature.get_ocsp_response().get_responder_certs()[0]
    signing_time = xml_signature.get_signing_time()

    return {
        "id": xml_signature._get_node("ds:Signature").attrib["Id"],
        "signing_time": signing_time,
        "status": True,
        "signature_production_place": None,
        "signer": attr.asdict(Signer.from_certificate(subject_cert)),
        "confirmation": {
            # if ever needed
            "produced_at": signing_time,
            "responder_id": "OCSP",
            "responder_certificate": ResponderCertificate.from_certificate(ocsp_cert),
        },
        "signer_role": [{"certified": 0, "role": None}],
    }


def container_info(bdoc_container: Container, full=True):
    if full:
        data_files_info = [
            {
                "digest_type": "sha256",
                "digest_value": base64.b64encode(hashlib.sha256(content).digest()).decode(),
                "filename": name,
                "id": name,
                "mime_type": mimetype,
                "content_type": mimetype,
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
            "data_file_info": data_files_info,
            "signature_info": [signature_info(signature) for signature in bdoc_container.iter_signatures()],
        }
    )
