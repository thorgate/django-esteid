import base64

import pytest

from ..types import InterimSessionData


@pytest.mark.parametrize(
    "value,result",
    [
        pytest.param(
            None,
            TypeError(""),
            id="not a dict",
        ),
        pytest.param(
            {},
            ValueError("Missing required key digest_b64"),
            id="empty dict",
        ),
        pytest.param(
            {"digest_b64": "", "temp_signature_file": "", "temp_container_file": "", "timestamp": 0},
            None,
            id="empty values",
        ),
        pytest.param(
            {"digest_b64": "dGVzdA==", "temp_signature_file": "asdf", "temp_container_file": "asdf", "timestamp": 0},
            None,
            id="non-empty values",
        ),
    ],
)
def test_signing_types_session_data(value, result):
    if isinstance(result, Exception):
        with pytest.raises(type(result)):
            InterimSessionData(value).is_valid()
    else:
        data = InterimSessionData(value)
        assert data.is_valid()
        assert data.digest == base64.b64decode(value["digest_b64"])
        assert data.temp_container_file == value["temp_container_file"]
        assert data.temp_signature_file == value["temp_signature_file"]
