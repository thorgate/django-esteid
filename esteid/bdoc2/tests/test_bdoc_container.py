import os
from tempfile import NamedTemporaryFile

import pytest

from ..container import BDoc2File, BDoc2FileError
from ..xmlsig import XmlSignature


@pytest.fixture
def temporary_file():
    f = NamedTemporaryFile(delete=False)

    yield f.name

    os.unlink(f.name)


def test_bdoc_data_files(temporary_file):
    bdoc_file = BDoc2File()
    assert list(bdoc_file.iter_data_files()) == []

    with pytest.raises(BDoc2FileError):
        bdoc_file.save()

    bdoc_file.add_file('test.txt', b'this is a test', 'text/plain')
    bdoc_file.save(temporary_file)

    bdoc_file = BDoc2File(temporary_file)
    assert list(bdoc_file.iter_data_files()) == [('test.txt', b'this is a test', 'text/plain')]

    bdoc_file.add_file('test2.txt', b'another test', 'text/plain')
    assert bdoc_file.data_file_names == ['test.txt', 'test2.txt']

    bdoc_file.save()

    bdoc_file = BDoc2File(temporary_file)
    assert bdoc_file.data_file_names == ['test.txt', 'test2.txt']

    assert list(bdoc_file.iter_data_files()) == [
        ('test.txt', b'this is a test', 'text/plain'),
        ('test2.txt', b'another test', 'text/plain'),
    ]

    with bdoc_file.open_file('test.txt') as f:
        assert f.read() == b'this is a test'

    with bdoc_file.open_file('test2.txt') as f:
        assert f.read() == b'another test'


def test_bdoc_signatures(temporary_file):
    bdoc_file = BDoc2File()
    bdoc_file.add_file('test.txt', b'this is a test', 'text/plain')

    assert list(bdoc_file.iter_signatures()) == []

    xml_sig = XmlSignature.create().add_signature_value(b'signature')
    bdoc_file.add_signature(xml_sig).save(temporary_file)

    assert bdoc_file._enumerate_signatures() == ['META-INF/signatures1.xml']
    assert [sig.get_signature_value() for sig in bdoc_file.iter_signatures()] == [b'signature']

    # Open anew
    bdoc_file = BDoc2File(temporary_file)
    assert bdoc_file._enumerate_signatures() == ['META-INF/signatures1.xml']
    assert [sig.get_signature_value() for sig in bdoc_file.iter_signatures()] == [b'signature']

    xml_sig = XmlSignature.create().add_signature_value(b'signature2')
    bdoc_file.add_signature(xml_sig).save()

    bdoc_file = BDoc2File(temporary_file)
    assert bdoc_file._enumerate_signatures() == ['META-INF/signatures1.xml', 'META-INF/signatures2.xml']
    assert [sig.get_signature_value() for sig in bdoc_file.iter_signatures()] == [b'signature', b'signature2']


def test_bdoc_signature_numbers(temporary_file):
    bdoc_file = BDoc2File()
    bdoc_file.add_file('test.txt', b'this is a test', 'text/plain')
    bdoc_file._zip_file.writestr('META-INF/signatures111.xml', b'dummy')
    xml_sig = XmlSignature.create().add_signature_value(b'signature')
    bdoc_file.add_signature(xml_sig).save(temporary_file)

    assert bdoc_file._enumerate_signatures() == ['META-INF/signatures111.xml', 'META-INF/signatures112.xml']
