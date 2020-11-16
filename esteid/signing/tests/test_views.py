import json
from http import HTTPStatus
from unittest.mock import Mock, patch

import pytest

from pyasice import Container

from esteid.exceptions import (
    ActionInProgress,
    AlreadySignedByUser,
    CanceledByUser,
    EsteidError,
    InvalidParameters,
    OfflineError,
    UpstreamServiceError,
    UserNotRegistered,
)
from esteid.types import Signer as SignerData

from ..views import SignViewMixin


@pytest.fixture()
def signatory_id_code(signed_container):
    signature = next(signed_container.iter_signatures())
    subject_cert = signature.get_certificate()
    signatory = SignerData.from_certificate(subject_cert)
    return signatory.id_code


@pytest.fixture()
def signer_class():
    signer_class = Mock(name="signer class")
    signer_class.start_session.return_value = signer_class()
    signer_class.load_session.return_value = signer_class()
    return signer_class


@pytest.fixture()
def signing_view(signer_class):
    the_view = SignViewMixin()
    with patch.object(the_view, "select_signer_class", return_value=signer_class), patch.object(
        the_view, "get_container", return_value=Container()
    ), patch.object(the_view, "check_eligibility"):
        yield the_view


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


def test_signing_views_canceled_by_user(signing_view, signer_class):
    signer_class().finalize.side_effect = CanceledByUser

    with patch.object(signing_view, "handle_user_cancel"):
        result = signing_view.patch(Mock())

        signing_view.handle_user_cancel.assert_called_once()

        assert result.status_code == CanceledByUser.status
        assert json.loads(result.content) == {
            "status": "error",
            "error": "CanceledByUser",
            "message": str(CanceledByUser.default_message),
        }


@pytest.mark.parametrize(
    "error",
    [
        OfflineError(service="service"),
        UpstreamServiceError(service="service"),
    ],
)
def test_signing_views_esteid_error_handling_finalize(error: EsteidError, signing_view, signer_class):
    signer_class().finalize.side_effect = error

    result = signing_view.patch(Mock())

    assert result.status_code == error.status
    assert json.loads(result.content) == {
        "status": "error",
        "error": error.__class__.__name__,
        "message": str(error.default_message).format(service="service"),
    }


def test_signing_views_exception_handling_finalize(signing_view, signer_class):
    signer_class().finalize.side_effect = Exception("unhandled")

    result = signing_view.patch(Mock())

    assert result.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
    assert json.loads(result.content) == {
        "status": "error",
        "error": "Internal error",
        "message": "Internal server error",
    }


def test_signing_views_action_in_progress(signing_view, signer_class):
    progress_data = {"verification_code": 1111}
    signer_class().finalize.side_effect = ActionInProgress("In progress", data=progress_data)

    result = signing_view.patch(Mock())

    assert result.status_code == ActionInProgress.status == HTTPStatus.ACCEPTED
    assert json.loads(result.content) == {"status": "pending", **progress_data}


@pytest.mark.parametrize(
    "error",
    [
        InvalidParameters(),
        OfflineError(service="service"),
        UserNotRegistered(),
        UpstreamServiceError(service="service"),
    ],
)
def test_signing_views_esteid_error_handling_prepare(error: EsteidError, signing_view, signer_class):
    signer_class().prepare.side_effect = error

    result = signing_view.post(Mock())

    signing_view.check_eligibility.assert_called_once_with(signer_class(), signing_view.get_container())

    assert result.status_code == error.status
    assert json.loads(result.content) == {
        "status": "error",
        "error": error.__class__.__name__,
        "message": str(error.default_message).format(service="service"),  # .format(): unused arguments are ignored
    }


def test_signing_views_exception_handling_prepare(signing_view, signer_class):
    signer_class().prepare.side_effect = Exception("unhandled")

    result = signing_view.post(Mock())

    assert result.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
    assert json.loads(result.content) == {
        "status": "error",
        "error": "Internal error",
        "message": "Internal server error",
    }
