import os
from tempfile import NamedTemporaryFile
from time import time
from typing import BinaryIO, Dict, List, Type, Union

from pyasice import Container, XmlSignature

from .exceptions import SigningError, SigningSessionDoesNotExist, SigningSessionExists
from .types import DataFile, InterimSessionData


class Signer:
    """
    Abstract pluggable signer.

    Receives initial parameters from a view (or any other caller), based on which
    it selects the concrete Signer subclass.

    The concrete Signer:
    * does the necessary preparation of container/signature
      for the files provided by the view;
    * calls the associated services as necessary, to obtain the signature;
    * finalizes the container.

    The concrete Signer is also associated with an initial parameters type,
    a session storage type, ... - akin to DRF serializers.

    The only requirement to a concrete signer class is that it
    inherit from the Signer class and register itself
    by being imported. The registration is done by `__init_subclass__()`.

    The signer class' name, lowercase, without `signer` suffix, will be the signing method name.
    """

    SIGNING_METHODS: Dict[str, Type["Signer"]] = {}

    # The session data class, configurable to match the necessary session data profile
    SessionData = InterimSessionData

    # Instance variable that holds session data
    session_data: InterimSessionData

    # This can be shared by subclasses, unless it's desired to be able to sign by different methods at once
    # (which is probably useless from the user point of view)
    _SESSION_KEY = f"{__name__}.session"

    # timeout in seconds, after which a fresh session can be started even if old session data is present.
    SESSION_VALIDITY_TIMEOUT = 1  # 60 * 2

    # Abstract Methods

    def prepare(self, container_file=None, files: List[DataFile] = None) -> dict:
        """
        Abstract method. Prepares the container, either from an existing one or from files.

        Returns a dict of data to display to user, if necessary: e.g. verification code.

        Preparing the container means creating a temporary container file, and a temporary XML signature,
        which requires a user certificate. Getting this certificate is the responsibility of the Signer class.

        Note 1: if `container` exists, it should be used regardless of whether `files` are also passed.
        Note 2: if `container` exists, it should be copied to a temporary file, so that if during the signing process
                the original container file gets modified, we would still be signing the original one.

        See also the `open_container()` method.
        """
        raise NotImplementedError

    def finalize(self, data=None) -> BinaryIO:
        """
        Abstract method. Checks the signing process status and finalizes the container when complete.

        Can accept data as necessary (e.g. when signing with ID card, it receives `signature_value`).
        Returns a handle to the final container. This can be e.g. an open file, or BytesIO.
        Raises Pending, Canceled, etc.
        """
        raise NotImplementedError

    # Customizable methods

    def setup(self, initial_data: dict = None):
        """Customize this to receive and check any data prior to `prepare()`"""
        pass

    def save_session_data(self, *, digest: bytes, container: Container, xml_sig: XmlSignature):
        """
        Saves the interim session data along with a timestamp that is used to determine session validity.

        Can be extended to accept additional arguments
        """
        data_obj = self.session_data

        data_obj.digest = digest
        data_obj.timestamp = int(time())

        with NamedTemporaryFile(delete=False) as temp_signature_file:
            temp_signature_file.write(xml_sig.dump())
        data_obj.temp_signature_file = temp_signature_file.name

        with NamedTemporaryFile("wb", delete=False) as temp_container_file:
            temp_container_file.write(container.finalize().getbuffer())
        data_obj.temp_container_file = temp_container_file.name

        self.session[self._SESSION_KEY] = dict(data_obj)

    # Methods that probably do not need overriding

    def load_session_data(self, session) -> InterimSessionData:
        try:
            session_data = self.SessionData(session[self._SESSION_KEY])
        except (KeyError, TypeError):
            session_data = self.SessionData()
        self.session_data = session_data
        return session_data

    def __init__(self, session, initial=False):
        """
        Initializes the necessary session data.

        Takes a session object, e.g. django request.session,
        and a flag that tells whether to start new session or attempt to load an existing one
        """
        session_data = self.load_session_data(session)
        if initial:
            if session_data:
                try:
                    timestamp = session_data.timestamp
                except AttributeError:
                    timestamp = 0

                if not timestamp or time() < timestamp + self.SESSION_VALIDITY_TIMEOUT:
                    raise SigningSessionExists("Another signing session already in progress")

                # clear the old session data. This incurs no DB overhead:
                # Django issues the actual DB query only in the process_response phase.
                self._cleanup_session(session)
        else:
            if not session_data:
                raise SigningSessionDoesNotExist("No active signing session found")

            try:
                session_data.is_valid()
            except ValueError as e:
                raise SigningSessionDoesNotExist("Invalid signing session") from e
        self.session = session

    def cleanup(self):
        """
        Cleans temporary signing session data and files.
        """
        return self._cleanup_session(self.session)

    @classmethod
    def start_session(cls, signing_method, session, initial_data) -> "Signer":
        """
        Initializes a fresh signing session.
        """
        signer_class = cls.select_signer(signing_method)
        signer = signer_class(session, initial=True)
        signer.setup(initial_data)
        return signer

    @classmethod
    def load_session(cls, signing_method, session) -> "Signer":
        """
        Continues (loads) an existing signing session from the `session` object
        """
        signer_class = cls.select_signer(signing_method)
        return signer_class(session)

    @classmethod
    def _cleanup_session(cls, session):
        data = session.pop(cls._SESSION_KEY, None)
        if not data:
            return

        try:
            data = cls.SessionData(data)
        except TypeError:
            return

        try:
            os.remove(data.temp_container_file)
        except (AttributeError, FileNotFoundError):
            pass

        try:
            os.remove(data.temp_signature_file)
        except (AttributeError, FileNotFoundError):
            pass

    @staticmethod
    def open_container(container_file: Union[str, BinaryIO] = None, files: List[DataFile] = None) -> Container:
        if container_file:
            if isinstance(container_file, str):
                container = Container.open(container_file)
            else:
                container = Container(container_file)
        elif files:
            container = Container()
            for f in files:
                container.add_file(f.file_name, f.read(), f.mime_type)
        else:
            raise ValueError("Either container path or list of files must be present and not empty")
        return container

    # "Magic" registration of subclasses

    @staticmethod
    def select_signer(signing_method) -> Type["Signer"]:
        try:
            signer_class = Signer.SIGNING_METHODS[signing_method]
        except KeyError as e:
            raise SigningError(f"Failed to load signer: method `{signing_method}` not registered") from e
        return signer_class

    def __init_subclass__(cls):
        """Registers subclasses automatically"""
        method = cls.__name__.lower()
        if method.endswith("signer"):
            method = method[:-6]
        assert method not in Signer.SIGNING_METHODS, f"A Signer for {method} is already registered"

        Signer.SIGNING_METHODS[method] = cls
