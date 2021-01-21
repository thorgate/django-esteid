import logging
from http import HTTPStatus
from typing import Type, TYPE_CHECKING

from django.core.exceptions import ValidationError as DjangoValidationError
from django.http import Http404, HttpRequest, JsonResponse
from django.utils.translation import gettext

from esteid.exceptions import ActionInProgress, CanceledByUser, EsteidError, InvalidParameters
from esteid.mixins import DjangoRestCompatibilityMixin

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


class AuthenticationViewMixin:
    class Status:
        ERROR = "error"
        PENDING = "pending"
        SUCCESS = "success"

    # this comes from the `url()` definition as in `View.as_view(authentication_method='...')`
    authentication_method: str = None

    def on_auth_complete(self, request, data: AuthenticationResult):
        """
        A hook to make use of the authentication data once the process is complete.

        May be used to store the data into session, authenticate a user etc.
        """
        pass

    def select_authenticator_class(self) -> Type["Authenticator"]:
        return Authenticator.select_authenticator(self.authentication_method)

    def start_session(self, request: "RequestType", *args, **kwargs):
        """
        Initiates an authentication session.

        Potentially, can result in an immediate authentication.
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

        finally:
            if do_cleanup:
                authenticator.cleanup()

        self.on_auth_complete(request, result)

        return JsonResponse({**result, "status": self.Status.SUCCESS})

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

        finally:
            if do_cleanup:
                authenticator.cleanup()

        self.on_auth_complete(request, result)

        return JsonResponse({**result, "status": self.Status.SUCCESS})

    def report_error(self, e: EsteidError):
        return JsonResponse({"status": self.Status.ERROR, **e.get_user_error()}, status=e.status)

    def handle_user_cancel(self):
        pass

    def handle_errors(self, e: Exception, stage="start"):
        if isinstance(e, EsteidError):
            if isinstance(e, CanceledByUser):
                self.handle_user_cancel()

            # Do not log user input related errors
            if not isinstance(e, InvalidParameters):
                logger.exception("Failed to %s signing session.", stage)
            return self.report_error(e)

        if isinstance(e, (Http404, DRFValidationError)):
            raise e

        if isinstance(e, DjangoValidationError):
            return JsonResponse(
                {"status": self.Status.ERROR, "error": e.__class__.__name__, "message": str(e)},
                status=HTTPStatus.CONFLICT,
            )

        logger.exception("Failed to %s signing session.", stage)
        return JsonResponse(
            {"status": self.Status.ERROR, "error": "Internal error", "message": gettext("Internal server error")},
            status=HTTPStatus.INTERNAL_SERVER_ERROR,
        )

    def post(self, request, *args, **kwargs):
        """
        Handles session start requests
        """
        try:
            return self.start_session(request, *args, **kwargs)
        except Exception as e:
            return self.handle_errors(e, stage="start")

    def patch(self, request, *args, **kwargs):
        """
        Handles session finish requests
        """
        try:
            return self.finish_session(request, *args, **kwargs)
        except Exception as e:
            return self.handle_errors(e, stage="finish")


class AuthenticationViewRestMixin(AuthenticationViewMixin):
    """
    To be used with rest-framework's APIView.
    """


class AuthenticationViewDjangoMixin(DjangoRestCompatibilityMixin, AuthenticationViewMixin):
    """
    To be used with plain Django class-based views (No rest-framework).

    Adds `data` attribute to the request with the POST or JSON data.
    """

    def post(self, request: "RequestType", *args, **kwargs):
        """
        Handles session start requests
        """
        request.data = self.parse_request(request)
        return super().start_session(request, *args, **kwargs)

    def patch(self, request: "RequestType", *args, **kwargs):
        """
        Handles session finish requests
        """
        request.data = self.parse_request(request)
        return super().finish_session(request, *args, **kwargs)
