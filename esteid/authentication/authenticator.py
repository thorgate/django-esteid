import logging
from time import time
from typing import Dict, Optional, Type

from esteid.authentication.types import AuthenticationResult, SessionData
from esteid.exceptions import EsteidError, SigningSessionDoesNotExist, SigningSessionExists


logger = logging.getLogger(__name__)


class Authenticator:
    """
    Abstract pluggable authenticator.

    Receives initial parameters from a view (or any other caller), based on which
    it selects the concrete Authenticator subclass.

    The concrete Authenticator calls the associated services as necessary,
      to obtain the authentication data.

    The concrete Authenticator is also associated with an initial parameters type,
    a session storage type, ... - akin to DRF serializers.

    The only requirement to a concrete authenticator class is that it
    inherit from the Authenticator class and register itself
    by being imported. The registration is done by `__init_subclass__()`.

    The authenticator class' name, lowercase, without `authenticator` suffix, will be the authentication method name.
    """

    AUTHENTICATION_METHODS: Dict[str, Type["Authenticator"]] = {}

    _SESSION_KEY = f"{__name__}.session"

    # timeout in seconds, after which a fresh session can be started even if old session data is present.
    SESSION_VALIDITY_TIMEOUT = 60 * 2

    session_data: SessionData

    # Abstract methods

    def authenticate(self) -> Optional[AuthenticationResult]:
        """
        Initiate the authentication process.

        If the init request succeeded, raises an ActionInProgress error
        with the corresponding data such as verification code.

        Note: For a theoretical case when authentication happens immediately, we leave an opportunity
        that this method returns AuthenticationResult.
        """
        raise NotImplementedError

    def poll(self) -> AuthenticationResult:
        """
        Polls status of the authentication process.

        If authentication succeeded, returns an AuthenticationResult.
        Otherwise, raises an ActionInProgress error with the corresponding data such as verification code.
        """
        raise NotImplementedError

    # Customizable methods

    def setup(self, initial_data: dict = None):
        """Customize this to receive and check any data prior to `prepare()`"""
        pass

    # Session management.
    # NOTE: this part is largely a copy-paste from signing.

    def save_session_data(self, *, session_id, hash_value_b64):
        """
        Saves the session data between initialization and polling requests
        """
        session_data = self.session_data or SessionData()

        session_data.session_id = session_id
        session_data.hash_value_b64 = hash_value_b64
        session_data.timestamp = int(time())

        self.session[self._SESSION_KEY] = dict(session_data)

    def load_session_data(self, session) -> SessionData:
        try:
            session_data = session[self._SESSION_KEY]
        except KeyError:
            session_data = {}

        try:
            session_data = SessionData(session_data)
        except TypeError:
            session_data = SessionData()
            self._cleanup_session(session)

        # Not doing session data validation here, because
        # an instance of another type may need different data
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

                if time() < timestamp + self.SESSION_VALIDITY_TIMEOUT:
                    raise SigningSessionExists("Another authentication session already in progress")

                # session expired => create a fresh data store
                session_data = SessionData()

                # wipe the old data from session.
                self._cleanup_session(session)
        else:
            if not session_data:
                raise SigningSessionDoesNotExist("No active authentication session found")

            try:
                session_data.is_valid()
            except ValueError as e:
                raise SigningSessionDoesNotExist("Invalid authentication session") from e

            if time() > session_data.timestamp + self.SESSION_VALIDITY_TIMEOUT:
                raise SigningSessionDoesNotExist("This authentication session has expired")

        self.session = session
        self.session_data = session_data

    def cleanup(self):
        """
        Cleans temporary authentication session data and files.
        """
        return self._cleanup_session(self.session)

    @classmethod
    def start_session(cls, session, initial_data) -> "Authenticator":
        """
        Initializes a fresh authentication session.
        """
        signer = cls(session, initial=True)
        signer.setup(initial_data)
        return signer

    @classmethod
    def load_session(cls, session) -> "Authenticator":
        """
        Continues (loads) an existing authentication session from the `session` object
        """
        return cls(session, initial=False)

    @classmethod
    def _cleanup_session(cls, session):
        session.pop(cls._SESSION_KEY, None)

    # "Magic" registration of subclasses

    @staticmethod
    def select_authenticator(authentication_method: str) -> Type["Authenticator"]:
        try:
            authenticator_class = Authenticator.AUTHENTICATION_METHODS[authentication_method]
        except KeyError as e:
            raise EsteidError(f"Failed to load signer: method `{authentication_method}` not registered") from e
        return authenticator_class

    @classmethod
    def get_method_name(cls):
        method = cls.__name__.lower()
        if method.endswith("authenticator"):
            method = method[: -len("authenticator")]
        return method

    def __init_subclass__(cls):
        """Registers subclasses automatically"""
        method = cls.get_method_name()
        assert (
            method not in Authenticator.AUTHENTICATION_METHODS
        ), f"An Authenticator for {method} is already registered"

        Authenticator.AUTHENTICATION_METHODS[method] = cls
