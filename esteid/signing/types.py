import base64
import os
from pathlib import PurePath
from typing import Union

from django.core.files import File

from esteid.types import PredictableDict


class DataFile:
    """
    Interface for file objects that are added to signed containers.

    Constructor accepts a path to file (a string or a pathlib *Path) or a django File.

    Additional arguments include:
    - `mime_type`, defaults to "application/octet-stream";
    - `content` if for any reason the wrapped file's content should be ignored (it won't be read in this case);
    - `file_name`: a custom (base)name of the file as it would appear in the container.

    The container cares about 3 attributes:
    * file name (base name only)
        - taken from
    * mime type
    * the content, for calculating hash; `content` is obtained through a call to `read()`.
    """

    def __init__(
        self, wraps: Union[str, File, PurePath], mime_type: str = None, content: bytes = None, file_name: str = None
    ):
        if not isinstance(wraps, (str, File, PurePath)):
            raise TypeError(f"Invalid argument. Expected a Django File or path to file, got {type(wraps).__name__}")

        self.wrapped_file = wraps
        self.file_name = file_name or (os.path.basename(wraps if isinstance(wraps, str) else wraps.name))
        self.content = content

        # Can use the content_type attribute for UploadedFile
        self.mime_type = mime_type or getattr(wraps, "content_type", "application/octet-stream")

    def read(self):
        if self.content is None:
            if isinstance(self.wrapped_file, (str, PurePath)):
                with open(self.wrapped_file, "rb") as f:
                    self.content = f.read()
            else:
                # ... This doesn't work in Django 1.11 because the `open()` method returns None in that version.
                # with self.wrapped_file.open("rb") as f:
                with self.wrapped_file as f:
                    f.open("rb")
                    self.content = f.read()
        return self.content


class InterimSessionData(PredictableDict):
    """
    Wrapper for temporary data stored between container preparation and finalization requests
    """

    digest_b64: str  # stores digest as a base64 encoded string, to allow JSON serialization
    temp_container_file: str
    temp_signature_file: str
    timestamp: int

    @property
    def digest(self):
        return base64.b64decode(self.digest_b64)

    @digest.setter
    def digest(self, value: bytes):
        self.digest_b64 = base64.b64encode(value).decode()
