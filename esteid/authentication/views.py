import logging
from http import HTTPStatus
from typing import Optional, Type, TYPE_CHECKING

from django.contrib.auth import HASH_SESSION_KEY, login, SESSION_KEY
from django.http import HttpRequest, JsonResponse

from esteid.exceptions import ActionInProgress
from esteid.mixins import DjangoRestCompatibilityMixin, SessionViewMixin

from .authenticator import Authenticator
from .types import AuthenticationResult


try:
    from rest_framework.exceptions import ValidationError as DRFValidationError
except ImportError:
    # If rest framework is not installed, create a stub class so the isinstance check is always false
    class DRFValidationError:
        pass


if TYPE_CHECKING:
    # Make type checkers aware of request.session attribute which is missing on the HttpRequest class
    from django.contrib.sessions import base_session

    class RequestType(HttpRequest):
        session: base_session.AbstractBaseSession
        data: dict


logger = logging.getLogger(__name__)


def get_origin(request):
    origin = f"{request.scheme}://{request.get_host()}"

    return origin


class AuthenticationViewMixin(SessionViewMixin):
    # these come from the `url()` definition as in `View.as_view(authentication_method='...')`, either one is enough
    authentication_method: str = None
    authenticator: Type[Authenticator] = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._authenticator_instance: Optional[Authenticator] = None

    def on_auth_success(self, request, data: AuthenticationResult):
        """
        A hook to make use of the authentication data once the process is complete.

        May be used to store the data into session, authenticate a user etc.
        """
        pass

    @classmethod
    def login(cls, request, user, backend=None):
        # This should prevent session key rotation in login. Key rotation must be prevented, as in some cases
        # the request where authentication actually happens will never be delivered to FE due to network error.
        #
        # esteid-helper retries in this case, but if session cookie was changed and lost there is nothing
        # we can do.
        #
        # See condition in login()
        if request.session.get(SESSION_KEY) is None:
            request.session[SESSION_KEY] = user.pk
            session_auth_hash = ""
            if hasattr(user, "get_session_auth_hash"):
                session_auth_hash = user.get_session_auth_hash()
            if session_auth_hash:
                request.session[HASH_SESSION_KEY] = session_auth_hash
        login(request, user, backend)

    def success_response(self, request, data: AuthenticationResult):
        """Customizable response on success"""
        return JsonResponse({**data, "status": self.Status.SUCCESS})

    def select_authenticator_class(self) -> Type["Authenticator"]:
        if self.authenticator is not None:
            return self.authenticator
        return Authenticator.select_authenticator(self.authentication_method)

    def dispatch(self, request, *args, **kwargs):
        try:
            if request.session.session_key is None:
                return JsonResponse(
                    {
                        "status": self.Status.ERROR,
                        "error": "DjangoSessionHasChanged",
                        # This error message is unlikely to reach the end user and is more for a developer,
                        # esteid-helper will retry on Gone status
                        "message": "Unable to log you in, likely due to network error. Please try again",
                        # If you are a developer reading this, you need to check login() method and possibly
                        # override it to ensure that the session key doesn't get cycled.
                        #
                        # This happens when key is cycled but due to network error updated session cookie is
                        # not delivered to the FE and FE keeps using the old session key.
                    },
                    status=HTTPStatus.GONE,
                )
        except AttributeError:
            pass

        try:
            return super().dispatch(request, *args, **kwargs)
        finally:
            if self._authenticator_instance is not None:
                if self._authenticator_instance.session_data.is_valid(raise_exception=False):
                    self._authenticator_instance.save_session_data()

    def handle_user_cancel(self):
        if self._authenticator_instance is not None:
            self._authenticator_instance.session_data.status = self.Status.CANCELLED

    def handle_error(self):
        if self._authenticator_instance is not None:
            self._authenticator_instance.session_data.status = self.Status.ERROR

    def get_nonce(self, request) -> Optional[bytes]:
        return None

    def start_session(self, request: "RequestType", *args, **kwargs):
        """
        Initiates an authentication session.
        """

        auth_class = self.select_authenticator_class()
        self._authenticator_instance = auth_class.start_session(
            request.session, request.data, origin=get_origin(request)
        )

        try:
            self._authenticator_instance.session_data.result = self._authenticator_instance.authenticate(
                random_bytes=self.get_nonce(request)
            )
        except ActionInProgress as e:
            # return SUCCESS to indicate that the upstream service successfully accepted the request
            return JsonResponse({"status": self.Status.SUCCESS, **e.data}, status=e.status)

        # Handle a theoretical case of immediate authentication
        self.on_auth_success(request, self._authenticator_instance.session_data.result)
        self._authenticator_instance.session_data.status = self.Status.SUCCESS
        return self.success_response(request, self._authenticator_instance.session_data.result)

    def finish_session(self, request: "RequestType", *args, **kwargs):
        """
        Checks the status of an authentication session
        """
        authenticator_class = self.select_authenticator_class()
        self._authenticator_instance = authenticator_class.load_session(request.session, origin=get_origin(request))

        if (
            self._authenticator_instance.session_data.status != self.Status.PENDING
            and self._authenticator_instance.session_data.result is not None
        ):
            # Return cached data, if available
            return JsonResponse(
                {
                    "status": self._authenticator_instance.session_data.status,
                    **self._authenticator_instance.session_data.result,
                },
                status=self.Status.http_status_for_status(self._authenticator_instance.session_data.status),
            )

        try:
            self._authenticator_instance.session_data.result = self._authenticator_instance.poll(request.data)
        except ActionInProgress as e:
            return JsonResponse({"status": self.Status.PENDING, **e.data}, status=e.status)

        self.on_auth_success(request, self._authenticator_instance.session_data.result)
        self._authenticator_instance.session_data.status = self.Status.SUCCESS
        return self.success_response(request, self._authenticator_instance.session_data.result)

    def handle_delete_request(self, request):
        authenticator_class = self.select_authenticator_class()
        authenticator = authenticator_class.load_session(request.session, origin=get_origin(request))

        authenticator.cleanup()


class AuthenticationViewRestMixin(AuthenticationViewMixin):
    """
    To be used with rest-framework's APIView.
    """

    def delete(self, request, *args, **kwargs):
        self.handle_delete_request(request)

        return JsonResponse({"status": self.Status.CANCELLED})


class AuthenticationViewDjangoMixin(DjangoRestCompatibilityMixin, AuthenticationViewMixin):
    """
    To be used with plain Django class-based views (No rest-framework).

    Adds `data` attribute to the request with the POST or JSON data.
    """

    def delete(self, request, *args, **kwargs):
        self.handle_delete_request(request)

        return JsonResponse({"status": self.Status.CANCELLED})
