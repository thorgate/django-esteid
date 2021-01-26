from time import time
from unittest.mock import patch

import pytest

from esteid.exceptions import EsteidError, SigningSessionDoesNotExist, SigningSessionExists
from esteid.signing import Signer


@pytest.fixture()
def test_session_data():
    return Signer.SessionData(
        digest_b64="MQ==",
        timestamp=11111,
        temp_container_file="temp_container_file",
        temp_signature_file="temp_signature_file",
    )


@patch.object(Signer, "SIGNING_METHODS", {})
def test_signer_register_subclass():
    def create_signer():
        class TestSigner(Signer):
            pass

        return TestSigner

    signer_class = create_signer()

    assert Signer.SIGNING_METHODS == {"test": signer_class}

    # Asserts that the signer class has not been registered yet, which is not true
    with pytest.raises(AssertionError):
        create_signer()


@patch.object(Signer, "SIGNING_METHODS", {})
def test_signer_select():
    class MySigner(Signer):
        pass

    assert Signer.select_signer("my") is MySigner
    with pytest.raises(EsteidError):
        Signer.select_signer("nonexistent")


def test_signer_init__initial_true(test_session_data):

    # Empty session: OK
    session = {}
    signer = Signer(session, initial=True)

    assert signer.session_data == {}
    assert signer.session is session
    assert session == {}

    # Wrong data, session is reset
    wrong_data = dict(test_session_data)
    wrong_data.pop("timestamp")
    session = {Signer._SESSION_KEY: wrong_data}
    signer = Signer(session, initial=True)

    assert signer.session_data == {}
    assert signer.session is session
    assert session == {}

    # Expired session data, session is reset
    session = {Signer._SESSION_KEY: dict(test_session_data)}
    signer = Signer(session, initial=True)

    assert signer.session_data == {}
    assert signer.session is session
    assert session == {}

    # Some (unvalidated) session data present, not expired => error
    session = {Signer._SESSION_KEY: {"timestamp": int(time()), "key": "value"}}
    with pytest.raises(SigningSessionExists):
        Signer(session, initial=True)

    # Correct session data present, not expired => error
    session = {Signer._SESSION_KEY: {**test_session_data, "timestamp": int(time()), "key": "value"}}
    with pytest.raises(SigningSessionExists):
        Signer(session, initial=True)


def test_signer_init__initial_false(test_session_data):

    # Wrong data: empty session
    session = {}
    with pytest.raises(SigningSessionDoesNotExist):
        Signer(session, initial=False)

    # Wrong data: No timestamp field
    wrong_data = dict(test_session_data)
    wrong_data.pop("timestamp")
    session = {Signer._SESSION_KEY: wrong_data}
    with pytest.raises(SigningSessionDoesNotExist):
        Signer(session, initial=False)

    # Expired session
    session = {Signer._SESSION_KEY: {**test_session_data, "key": "value"}}
    with pytest.raises(SigningSessionDoesNotExist):
        Signer(session, initial=False)

    # Session unexpired and valid => All ok
    timestamp = int(time()) - Signer.SESSION_VALIDITY_TIMEOUT + 1
    session = {Signer._SESSION_KEY: {**test_session_data, "timestamp": timestamp}}
    signer = Signer(session, initial=False)

    assert signer.session_data == {**test_session_data, "timestamp": timestamp}
    assert signer.session is session
