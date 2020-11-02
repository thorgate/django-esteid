import json
import logging
from http import HTTPStatus
from typing import BinaryIO, TYPE_CHECKING, Union

from django.http import HttpRequest, JsonResponse, QueryDict

import pyasice

from esteid.exceptions import ActionInProgress, EsteidError, InvalidParameters, SigningSessionError

from .signer import Signer


if TYPE_CHECKING:
    # Make type checkers aware of request.session attribute which is missing on the HttpRequest class
    from django.contrib.sessions import base_session

    class RequestType(HttpRequest):
        session: base_session.AbstractBaseSession
        data: dict


logger = logging.getLogger(__name__)


class SignViewMixin:
    class Status:
        ERROR = "error"
        PENDING = "pending"
        SUCCESS = "success"

    # this comes from the `url()` definition as in `View.as_view(signing_method='...')`
    signing_method: str = None

    def get_container(self, *args, **kwargs) -> Union[str, BinaryIO]:
        """
        Returns (path to|file handle of) the container to sign, if it exists prior to signing

        A string value is treated as a file path.
        A file handle is anything that provides a `read()` method that returns bytes.
        """
        raise NotImplementedError

    def save_container(self, container: pyasice.Container, *args, **kwargs):
        """
        Receives a container instance, expected to save the file contents as appropriate.

        Example with Django's UploadedFile:

            instance = self.get_object()
            # Be sure to call `container_info(container)` before `container.finalize()`
            instance.container_info = esteid.compat.container_info(container)
            instance.container = UploadedFile(container.finalize(), "signed_document.doc", container.MIME_TYPE)
            instance.save()

        """
        raise NotImplementedError

    def get_files_to_sign(self, *args, **kwargs) -> list:
        """
        Returns list of files to sign, unless there is a pre-created container
        """
        raise NotImplementedError

    def get_success_response(self, *args, **kwargs):
        """
        Generates a success response when the signing process is complete (in `finalize()`)

        Can be customized to return additional data, such as links to download the container
        """
        return JsonResponse({"status": self.Status.SUCCESS})

    def start_session(self, request: "RequestType", *args, **kwargs):
        """
        Initiates a signing session
        """

        try:
            signer = Signer.start_session(self.signing_method, request.session, request.data)
        except InvalidParameters as e:
            return JsonResponse({"status": self.Status.ERROR, **e.get_user_error()}, status=e.status)
        except SigningSessionError as e:
            logger.exception("Failed to start session")
            return JsonResponse({"status": self.Status.ERROR, **e.get_user_error()}, status=e.status)

        try:
            container = self.get_container(*args, **kwargs)
        except NotImplementedError:
            container = None

        if not container:
            files_to_sign = self.get_files_to_sign(*args, **kwargs)
        else:
            files_to_sign = None

        try:
            response_to_user = signer.prepare(container, files_to_sign)

        except EsteidError as e:
            return JsonResponse({"status": self.Status.ERROR, **e.get_user_error()}, status=e.status)

        except Exception:
            logger.exception("Failed to prepare signature.")
            return JsonResponse(
                {"status": self.Status.ERROR, "error": "Internal error"}, status=HTTPStatus.INTERNAL_SERVER_ERROR
            )

        return JsonResponse({**response_to_user, "status": self.Status.SUCCESS})

    def finish_session(self, request: "RequestType", *args, **kwargs):
        """
        Checks the status of a signing session and attempts to finalize signing
        """
        signer = Signer.load_session(self.signing_method, request.session)
        do_cleanup = True

        try:
            container = signer.finalize(getattr(request, "data", None))
            self.save_container(container, *args, **kwargs)

        except ActionInProgress as e:
            do_cleanup = False
            return JsonResponse({"status": self.Status.PENDING, **e.data}, status=e.status)

        except EsteidError as e:
            return JsonResponse({"status": self.Status.ERROR, **e.get_user_error()}, status=e.status)

        except Exception:
            logger.exception("Failed to finalize signature.")
            return JsonResponse(
                {"status": self.Status.ERROR, "error": "Internal error"}, status=HTTPStatus.INTERNAL_SERVER_ERROR
            )

        finally:
            if do_cleanup:
                signer.cleanup()

        return self.get_success_response(*args, **kwargs)


class SignViewRestMixin(SignViewMixin):
    """
    To be used with rest-framework's APIView
    """

    def post(self, request, *args, **kwargs):
        """
        Handles session start requests
        """
        return self.start_session(request, *args, **kwargs)

    def patch(self, request, *args, **kwargs):
        """
        Handles session finish requests
        """
        return self.finish_session(request, *args, **kwargs)


class SignViewDjangoMixin(SignViewMixin):
    """
    To be used with plain Django class-based views (No rest-framework)
    """

    def post(self, request: "RequestType", *args, **kwargs):
        """
        Handles session start requests
        """
        request.data = self.parse_request(request)
        return self.start_session(request, *args, **kwargs)

    def patch(self, request: "RequestType", *args, **kwargs):
        """
        Handles session finish requests
        """
        request.data = self.parse_request(request)
        return self.finish_session(request, *args, **kwargs)

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
