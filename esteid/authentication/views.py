import logging
from typing import Type, TYPE_CHECKING

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


class AuthenticationViewMixin(SessionViewMixin):
    # these come from the `url()` definition as in `View.as_view(authentication_method='...')`, either one is enough
    authentication_method: str = None
    authenticator: Type[Authenticator] = None

    def on_auth_success(self, request, data: AuthenticationResult):
        """
        A hook to make use of the authentication data once the process is complete.

        May be used to store the data into session, authenticate a user etc.
        """
        pass

    def success_response(self, request, data: AuthenticationResult):
        """Customizable response on success"""
        return JsonResponse({**data, "status": self.Status.SUCCESS})

    def select_authenticator_class(self) -> Type["Authenticator"]:
        if self.authenticator is not None:
            return self.authenticator
        return Authenticator.select_authenticator(self.authentication_method)

    def start_session(self, request: "RequestType", *args, **kwargs):
        """
        Initiates an authentication session.
        """

        auth_class = self.select_authenticator_class()
        authenticator = auth_class.start_session(request.session, request.data)

        do_cleanup = True

        try:
            result = authenticator.authenticate()

        except ActionInProgress as e:
            do_cleanup = False
            # return SUCCESS to indicate that the upstream service successfully accepted the request
            return JsonResponse({"status": self.Status.SUCCESS, **e.data}, status=e.status)

        else:
            # Handle a theoretical case of immediate authentication
            self.on_auth_success(request, result)
            return JsonResponse({**result, "status": self.Status.SUCCESS})

        finally:
            if do_cleanup:
                authenticator.cleanup()

    def finish_session(self, request: "RequestType", *args, **kwargs):
        """
        Checks the status of an authentication session
        """
        authenticator_class = self.select_authenticator_class()
        authenticator = authenticator_class.load_session(request.session)

        do_cleanup = True

        try:
            result = authenticator.poll()

        except ActionInProgress as e:
            do_cleanup = False
            return JsonResponse({"status": self.Status.PENDING, **e.data}, status=e.status)

        else:
            self.on_auth_success(request, result)
            return self.success_response(request, result)

        finally:
            if do_cleanup:
                authenticator.cleanup()


class AuthenticationViewRestMixin(AuthenticationViewMixin):
    """
    To be used with rest-framework's APIView.
    """


class AuthenticationViewDjangoMixin(DjangoRestCompatibilityMixin, AuthenticationViewMixin):
    """
    To be used with plain Django class-based views (No rest-framework).

    Adds `data` attribute to the request with the POST or JSON data.
    """
