from time import time
from unittest.mock import patch

import pytest

from esteid.authentication import Authenticator
from esteid.authentication.types import SessionData
from esteid.exceptions import EsteidError, SigningSessionDoesNotExist, SigningSessionExists


@pytest.fixture()
def test_session_data():
    return SessionData(timestamp=11111, session_id="test", hash_value_b64="MQ==")  # a very old timestamp


@patch.object(Authenticator, "AUTHENTICATION_METHODS", {})
def test_authenticator_register_subclass():
    def create_authenticator():
        class TestAuthenticator(Authenticator):
            pass

        return TestAuthenticator

    authenticator_class = create_authenticator()

    assert Authenticator.AUTHENTICATION_METHODS == {"test": authenticator_class}

    # Asserts that the authenticator class has not been registered yet, which is not true
    with pytest.raises(AssertionError):
        create_authenticator()


@patch.object(Authenticator, "AUTHENTICATION_METHODS", {})
def test_authenticator_select():
    class MyAuthenticator(Authenticator):
        pass

    assert Authenticator.select_authenticator("my") is MyAuthenticator
    with pytest.raises(EsteidError):
        Authenticator.select_authenticator("nonexistent")


def test_authenticator_init__initial_true(test_session_data):

    # Empty session: OK
    session = {}
    authenticator = Authenticator(session, initial=True)

    assert authenticator.session_data == {}
    assert authenticator.session is session
    assert session == {}

    # Wrong data, session is reset
    wrong_data = dict(test_session_data)
    wrong_data.pop("timestamp")
    session = {Authenticator._SESSION_KEY: wrong_data}
    authenticator = Authenticator(session, initial=True)

    assert authenticator.session_data == {}
    assert authenticator.session is session
    assert session == {}

    # Expired session data, session is reset
    session = {Authenticator._SESSION_KEY: {**test_session_data}}
    authenticator = Authenticator(session, initial=True)

    assert authenticator.session_data == {}
    assert authenticator.session is session
    assert session == {}

    # Some (unvalidated) session data present, not expired => error
    session = {Authenticator._SESSION_KEY: {"timestamp": int(time()), "key": "value"}}
    with pytest.raises(SigningSessionExists):
        Authenticator(session, initial=True)

    # Correct session data present, not expired => error
    session = {Authenticator._SESSION_KEY: {**test_session_data, "timestamp": int(time()), "key": "value"}}
    with pytest.raises(SigningSessionExists):
        Authenticator(session, initial=True)


def test_authenticator_init__initial_false(test_session_data):

    # Wrong data: empty
    session = {}
    with pytest.raises(SigningSessionDoesNotExist):
        Authenticator(session, initial=False)

    # Wrong data: No timestamp field
    wrong_data = dict(test_session_data)
    wrong_data.pop("timestamp")
    session = {Authenticator._SESSION_KEY: wrong_data}
    with pytest.raises(SigningSessionDoesNotExist):
        Authenticator(session, initial=False)

    # Expired session
    session = {Authenticator._SESSION_KEY: test_session_data}
    with pytest.raises(SigningSessionDoesNotExist):
        Authenticator(session, initial=False)

    # Session unexpired and valid => All ok
    timestamp = int(time()) - Authenticator.SESSION_VALIDITY_TIMEOUT + 1
    session = {Authenticator._SESSION_KEY: {**test_session_data, "timestamp": timestamp, "key": "value"}}
    authenticator = Authenticator(session, initial=False)

    assert authenticator.session_data == {**test_session_data, "timestamp": timestamp, "key": "value"}
    assert authenticator.session is session
