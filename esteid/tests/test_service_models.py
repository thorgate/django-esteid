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
