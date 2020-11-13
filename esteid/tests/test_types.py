import json

import pytest

import attr
import oscrypto.asymmetric
from django.core.serializers.json import DjangoJSONEncoder

import pyasice

from esteid.compat import container_info
from esteid.types import Certificate, DataFileInfo, SignedDocInfo, Signer


def test_signeddocinfo_from_dict(signed_doc_dict):
    # smoketest for signed doc parsing
    instance = SignedDocInfo.from_dict(signed_doc_dict)

    assert instance.format == "BDOC"
    assert instance.version == "2.1"

    assert instance.data_file_info == [
        DataFileInfo.from_dict(
            {
                "contentType": "HASHCODE",
                "digestType": "sha256",
                "digestValue": "Mmb3rosrMXMY86F4P+Pj0VQEQnpDquhEarJ00RelWXE=",
                "filename": "something.pdf",
                "id": "something.pdf",
                "mime_type": "application/pdf",
                "size": 27216,
            }
        )
    ]


def test_signeddocinfo_from_container(signed_container_file):
    with pyasice.Container(signed_container_file) as container:
        data = container_info(container)

    assert data.format == "BDOC"
    assert data.version == "2.1"
    assert data.mime_type == pyasice.Container.MIME_TYPE

    assert len(data.signature_info) == 1
    assert data.signature_info[0].signing_time
    assert data.signature_info[0].signer.id_code == "60001019906"

    assert len(data.data_file_info) == 1
    assert data.data_file_info[0].filename == "test.txt"


@pytest.mark.parametrize("cert_type", ["bytes", "asn1", "oscrypto"])
def test_certificate_from_cert(static_certificate, cert_type):
    if cert_type == "bytes":
        cert = static_certificate
    else:
        cert = oscrypto.asymmetric.load_certificate(static_certificate)
        if cert_type == "asn1":
            cert = cert.asn1

    cert_data = Certificate.from_certificate(cert)
    assert cert_data.issuer_serial == "116050271893176812114901422365303754679"
    assert cert_data.issuer == (
        "Common Name: TEST of NQ-SK 2016, "
        "Organization Identifier: NTREE-10747013, "
        "Organization: AS Sertifitseerimiskeskus, Country: EE"
    )
    assert cert_data.valid_from.isoformat() == "2017-02-02T09:14:37+00:00"
    assert cert_data.valid_to.isoformat() == "2022-02-01T21:59:59+00:00"
    assert cert_data.subject == "SMART-ID,HELLO,PNOEE-11702020200"


@pytest.mark.parametrize("cert_type", ["bytes", "asn1", "oscrypto"])
def test_signer_data_from_oscrypto_cert(static_certificate, cert_type):
    if cert_type == "bytes":
        cert = static_certificate
    else:
        cert = oscrypto.asymmetric.load_certificate(static_certificate)
        if cert_type == "asn1":
            cert = cert.asn1

    signer_data = Signer.from_certificate(cert)
    assert signer_data.full_name == "HELLO SMART-ID"
    assert signer_data.id_code == "11702020200"
    assert isinstance(signer_data.certificate, Certificate)


def test_signer_data_to_json(static_certificate):
    signer_data = Signer.from_certificate(static_certificate)

    output = json.dumps(attr.asdict(signer_data), cls=DjangoJSONEncoder)
    assert Signer.from_dict(json.loads(output)) == signer_data
