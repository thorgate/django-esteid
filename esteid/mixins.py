import json
import logging
from http import HTTPStatus
from typing import Callable, TYPE_CHECKING

from django.core.exceptions import ValidationError as DjangoValidationError
from django.http import Http404, HttpRequest, JsonResponse, QueryDict
from django.utils.translation import gettext

from esteid.exceptions import CanceledByUser, EsteidError, InvalidParameters


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


class SessionViewMixin:
    """
    Provides POST and PATCH method handlers for auth/signing session management.

    Also does common error handling.
    """

    class Status:
        ERROR = "error"
        PENDING = "pending"
        SUCCESS = "success"

    start_session: Callable
    finish_session: Callable

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


class DjangoRestCompatibilityMixin(SessionViewMixin):
    """
    Enables Django view to accept JSON request bodies the same way as Rest Framework views.
    """

    def post(self, request: "RequestType", *args, **kwargs):
        """
        Handles session start requests
        """
        request.data = self.parse_request(request)
        return super().post(request, *args, **kwargs)

    def patch(self, request: "RequestType", *args, **kwargs):
        """
        Handles session finish requests
        """
        request.data = self.parse_request(request)
        return super().patch(request, *args, **kwargs)

    @staticmethod
    def parse_request(request):
        """
        Parses PATCH/POST request bodies as JSON or urlencoded, and assigns `request.data`.

        Rationale:
        * Compatibility with REST Framework.
        * Allow JSON.
        * Django's request.POST only works for POST, not PATCH etc.
        """
        try:
            if request.content_type == "application/x-www-form-urlencoded":
                return QueryDict(request.body).dict()
            if request.content_type == "application/json":
                data = json.loads(request.body)
                if isinstance(data, dict):
                    return data
                raise InvalidParameters("Failed to parse request data as dict")
        except InvalidParameters:
            raise
        except Exception as e:
            raise InvalidParameters(
                f"Failed to parse the request body according to content type {request.content_type}"
            ) from e
        raise InvalidParameters(f"Unsupported request content type {request.content_type}")
