import base64
import pathlib

import pytest

from django.core.files import File

from ..types import DataFile, InterimSessionData


TEST_TXT = "test.txt"
TEST_TXT_CONTENT = b"Hello"


@pytest.fixture()
def test_txt(tmp_path):
    # Can't pass fixtures to parametrize() so we need a well-known file name for a parameterized test.
    # tmp_path is pytest's builtin fixture with a temporary path as a pathlib.Path object
    with open(tmp_path / TEST_TXT, "wb") as f:
        f.write(TEST_TXT_CONTENT)

    yield open(tmp_path / TEST_TXT, "rb")


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


@pytest.mark.parametrize(
    "params,result",
    [
        pytest.param(
            {},
            TypeError("required positional argument.+wraps"),
            id="empty params",
        ),
        pytest.param(
            {"wraps": ..., "file_name": TEST_TXT},
            TypeError("Expected a Django File or path to file"),
            id="wraps not a string",
        ),
        pytest.param(
            {"wraps": TEST_TXT},
            TEST_TXT_CONTENT,
            id="wraps a string",
        ),
        pytest.param(
            {"wraps": TEST_TXT, "file_name": "other.name"},
            TEST_TXT_CONTENT,
            id="wraps a string, gets file_name",
        ),
        pytest.param(
            {"wraps": TEST_TXT, "file_name": "other.name", "content": b"test", "mime_type": "text/plain"},
            b"test",
            id="wraps a string, all arguments",
        ),
        pytest.param(
            {"wraps": pathlib.PurePath(TEST_TXT)},
            TEST_TXT_CONTENT,
            id="wraps a PurePath",
        ),
        pytest.param(
            {"wraps": pathlib.PosixPath(TEST_TXT), "file_name": "other.name"},
            TEST_TXT_CONTENT,
            id="wraps a PosixPath",
        ),
        pytest.param(
            {"wraps": pathlib.Path(TEST_TXT), "file_name": "other.name", "content": b"test", "mime_type": "text/plain"},
            b"test",
            id="wraps a Path, all arguments",
        ),
        pytest.param(
            {"wraps": File},
            TEST_TXT_CONTENT,
            id="wraps a File",
        ),
        pytest.param(
            {"wraps": File, "file_name": "other.name"},
            TEST_TXT_CONTENT,
            id="wraps a File, alternative file name",
        ),
        pytest.param(
            {"wraps": File, "file_name": "other.name", "content": b"test", "mime_type": "text/plain"},
            b"test",
            id="wraps a File, all arguments",
        ),
    ],
)
def test_signing_types_data_file(params: dict, result, tmp_path, test_txt):
    if isinstance(result, Exception):
        with pytest.raises(type(result), match=result.args[0]):
            DataFile(**params)

    else:
        # some preparations
        if params["wraps"] is File:
            params["wraps"] = File(test_txt)
        else:
            params["wraps"] = str(tmp_path / TEST_TXT)

        datafile = DataFile(**params)
        assert datafile.wrapped_file == params["wraps"]
        assert datafile.content == params.get("content")
        assert datafile.file_name == (params.get("file_name") or TEST_TXT)
        assert datafile.mime_type == params.get("mime_type", "application/octet-stream")

        data = datafile.read()
        assert data == result
