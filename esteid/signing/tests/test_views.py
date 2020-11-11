from unittest.mock import Mock

import pytest

from esteid.exceptions import AlreadySignedByUser
from esteid.types import Signer as SignerData

from ..views import SignViewMixin


@pytest.fixture()
def signatory_id_code(signed_container):
    signature = next(signed_container.iter_signatures())
    subject_cert = signature.get_certificate()
    signatory = SignerData.from_certificate(subject_cert)
    return signatory.id_code


@pytest.mark.parametrize(
    "container,allow_sign_many,result",
    [
        pytest.param(None, True, None, id="No container, allowed - OK"),
        pytest.param(None, False, None, id="No container, not allowed - OK"),
        pytest.param(True, True, None, id="Container, allowed - OK"),
        pytest.param(True, False, AlreadySignedByUser, id="Container, not allowed - ERROR"),
    ],
)
def test_signing_views_check_eligibility(
    signatory_id_code, container, allow_sign_many, result, signed_container, override_esteid_settings
):
    if container:
        container = signed_container

    signer = Mock(id_code=signatory_id_code)
    signer_not_signatory = Mock(id_code="12345678912")
    view = SignViewMixin()

    with override_esteid_settings(ESTEID_ALLOW_ONE_PARTY_SIGN_TWICE=allow_sign_many):
        # Signing by a different party should always succeed
        view.check_eligibility(signer_not_signatory, container)

        if result is AlreadySignedByUser:
            with pytest.raises(AlreadySignedByUser):
                view.check_eligibility(signer, container)
        else:
            view.check_eligibility(signer, container)
