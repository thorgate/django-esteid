import pytest

from esteid.digidocservice.service import PreviouslyCreatedContainer, DigiDocException


def test_add_datafile_fails_if_container_exists_in_session(digidoc_service):
    digidoc_service.container = PreviouslyCreatedContainer()

    with pytest.raises(DigiDocException) as exc_info:
        digidoc_service.add_datafile('x', 'text/plain', '', 0, b'')

    assert 'Cannot add files to PreviouslyCreatedContainer' in str(exc_info.value)


def test_create_signed_document_fails_if_container_exists_in_session(digidoc_service):
    digidoc_service.container = PreviouslyCreatedContainer()

    with pytest.raises(DigiDocException) as exc_info:
        digidoc_service.create_signed_document()

    assert 'PreviouslyCreatedContainer already in session' in str(exc_info.value)


@pytest.mark.parametrize('format_identifier', [
    'FAKE',
    'ASIC',
])
def test_create_signed_document_fails_if_wrong_format(format_identifier, digidoc_service):
    with pytest.raises(ValueError) as exc_info:
        digidoc_service.create_signed_document(format_identifier)

    assert 'File format should be one of' in str(exc_info.value)
