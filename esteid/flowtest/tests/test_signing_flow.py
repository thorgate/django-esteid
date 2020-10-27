import base64
import binascii
import json
import os
from unittest.mock import patch
from urllib.parse import urlencode

import pytest

from django.contrib.sessions.backends import db
from django.test import Client
from django.urls import reverse

from esteid.flowtest.views import SigningTestView
from esteid.signing import Signer


@pytest.fixture()
def datafiles():
    return {"test.txt": {"content": base64.b64encode(b"text").decode(), "content_type": "text/plain"}}


@pytest.mark.parametrize("urlconf", ("sign-my", "sign-rest-my"))
@pytest.mark.parametrize("content_type", ("application/json", "application/x-www-form-urlencoded"))
def test_my_signing_flow(urlconf, content_type, datafiles):
    assert "my" in Signer.SIGNING_METHODS

    url = reverse(urlconf)

    client = Client()

    session = {}

    # This is a SUPER obvious way to work with test sessions.
    with patch.object(db, "SessionStore", return_value=session):
        session["__ddoc_files"] = datafiles

        if content_type == "application/json":
            data = json.dumps({})
        else:
            data = None
        response = client.post(url, data, content_type)

        assert response.status_code == 200
        assert response.json() == {
            "status": SigningTestView.Status.SUCCESS,
            "verification_code": "1234",
        }
        assert session[Signer._SESSION_KEY]["digest_b64"] == base64.b64encode(b"test").decode()
        temp_container_file = session[Signer._SESSION_KEY]["temp_container_file"]
        assert os.path.exists(temp_container_file)

        response = client.patch(url, data, content_type)
        assert response.status_code == 200
        assert response.json() == {
            "status": SigningTestView.Status.SUCCESS,
        }

        assert Signer._SESSION_KEY not in session, "Failed to clean up session"
        assert not os.path.exists(temp_container_file), "Failed to clean up files"


@pytest.mark.parametrize("urlconf", ("sign-mypost", "sign-rest-mypost"))
@pytest.mark.parametrize("content_type", ("application/json", "application/x-www-form-urlencoded"))
def test_my_post_signing_flow(urlconf, content_type, datafiles):
    assert "mypost" in Signer.SIGNING_METHODS

    url = reverse(urlconf)

    client = Client()

    session = {}
    with patch.object(db, "SessionStore", return_value=session):
        session["__ddoc_files"] = datafiles

        data = {"certificate": binascii.b2a_hex(b"test").decode()}
        if content_type == "application/json":
            data = json.dumps(data)
        else:
            data = urlencode(data)

        response = client.post(url, data, content_type)

        assert response.status_code == 200
        assert response.json() == {
            "status": SigningTestView.Status.SUCCESS,
            "verification_code": "1234",
        }
        assert session[Signer._SESSION_KEY]["digest_b64"] == base64.b64encode(b"test").decode()
        temp_container_file = session[Signer._SESSION_KEY]["temp_container_file"]
        assert os.path.exists(temp_container_file)

        data = {"signature_value": binascii.b2a_hex(b"test").decode()}
        if content_type == "application/json":
            data = json.dumps(data)
        else:
            data = urlencode(data)

        response = client.patch(url, data, content_type)
        assert response.status_code == 200
        assert response.json() == {
            "status": SigningTestView.Status.SUCCESS,
        }
        assert Signer._SESSION_KEY not in session, "Failed to clean up session"
        assert not os.path.exists(temp_container_file), "Failed to clean up files"
