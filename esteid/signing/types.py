import base64
import os
from pathlib import PurePath
from typing import Union

from django.core.files import File


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


class PredictableDict(dict):
    """
    Allows attribute-style access to values of a dict.

    Define necessary attributes as type annotations on your subclass:

        class Z(PredictableDict):
            required_attr: str
            optional_attr: Optional[str]

    and you will get nice attribute-style access with type hints.

    Validate the presence of all required attributes and type-check all attributes with:

        Z(required_attr="test").is_valid()

    Subclasses inherit annotated attributes and can override them, just like normal class attributes.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__dict__ = self

    def is_valid(self, raise_exception=True):
        for attr_name, attr_type in self._get_annotations().items():
            # type -> (type, )
            # Union[T, S] -> U.__args__ == (T, S)
            valid_types = getattr(attr_type, "__args__", (attr_type,))

            try:
                val = self[attr_name]
            except KeyError as e:
                # No error for optional fields.
                if type(None) in valid_types:
                    # Optional[T] == Union[T, NoneType]
                    continue

                if not raise_exception:
                    return False
                raise ValueError(f"Missing required key {attr_name}") from e

            if type(val) not in valid_types:
                if not raise_exception:
                    return False
                raise ValueError(f"Wrong type {type(val)} for key {attr_name}")

        return True

    @classmethod
    def _get_annotations(cls):
        """Collects annotations from all parent classes according to inheritance rules."""
        annotations = {}
        for klass in reversed(cls.__mro__):
            overrides = getattr(klass, "__annotations__", None)
            if overrides:
                annotations.update(overrides)
        return annotations


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
