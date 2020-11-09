import pyasice

from esteid.compat import container_info
from esteid.types import DataFileInfo, SignedDocInfo


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
