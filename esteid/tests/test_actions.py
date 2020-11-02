from unittest.mock import patch

import pytest

from .. import actions
from ..types import DataFile


@pytest.fixture()
def a_view():
    class AView:
        request = None

        def get_files(self):
            return [DataFile("test.txt", "text/plain", None, 5, b"test!")]

        def get_bdoc_container_file(self):
            return None

    return AView()


@patch.object(actions, "delete_esteid_session")
def test_idcard_prepare_action(_, a_view):
    assert actions.IdCardPrepareAction.do_action(a_view) == {
        "success": False,
        "code": "BAD_CERTIFICATE",
    }


@patch.object(actions, "get_esteid_session")
def test_idcard_finish_action(_, a_view):
    assert actions.IdCardFinishAction.do_action(a_view) == {
        "success": False,
        "code": "BAD_SIGNATURE",
    }
