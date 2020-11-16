import json
import logging
from http import HTTPStatus
from typing import BinaryIO, Type, TYPE_CHECKING, Union

from django.core.exceptions import ValidationError as DjangoValidationError
from django.http import Http404, HttpRequest, JsonResponse, QueryDict
from django.utils.translation import gettext

import pyasice

from esteid import settings
from esteid.exceptions import ActionInProgress, AlreadySignedByUser, CanceledByUser, EsteidError, InvalidParameters
from esteid.types import Signer as SignerData

from .signer import Signer


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


class SignViewMixin:
    class Status:
        ERROR = "error"
        PENDING = "pending"
        SUCCESS = "success"

    # this comes from the `url()` definition as in `View.as_view(signing_method='...')`
    signing_method: str = None

    def get_container(self, *args, **kwargs) -> Union[str, BinaryIO, pyasice.Container]:
        """
        Returns [path to|file handle of] the container to sign, if it exists prior to signing

        A string value is treated as a file path.
        A file handle is anything that provides a `read()` method that returns bytes.
        """
        raise NotImplementedError

    def save_container(self, container: pyasice.Container, *args, **kwargs):
        """
        Receives a container instance, expected to save the file contents as appropriate.

        Example with Django's UploadedFile:

            from esteid.compat import container_info
            instance = self.get_object()
            # Be sure to call `container_info(container)` before `container.finalize()`
            instance.container_info = container_info(container)
            instance.container = UploadedFile(container.finalize(), "signed_document.doc", container.MIME_TYPE)
            # OR:
            # buffer = container.finalize().getbuffer()
            # instance.container = SimpleUploadedFile("signed_document.doc", buffer, container.MIME_TYPE)
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

    def check_eligibility(self, signer: Signer, container: pyasice.Container = None):
        """
        Performs a check whether a signing party is eligible to sign the container.

        Override it in subclasses as necessary:
        """
        if container is None or settings.ESTEID_ALLOW_ONE_PARTY_SIGN_TWICE:
            return

        signatories = []
        for signature in container.iter_signatures():
            subject_cert = signature.get_certificate()
            signatory = SignerData.from_certificate(subject_cert)
            signatories.append(signatory.id_code)

        if signer.id_code in signatories:
            raise AlreadySignedByUser

    def select_signer_class(self) -> Type["Signer"]:
        return Signer.select_signer(self.signing_method)

    def start_session(self, request: "RequestType", *args, **kwargs):
        """
        Initiates a signing session
        """

        signer_class = self.select_signer_class()
        signer = signer_class.start_session(request.session, request.data)

        try:
            container = self.get_container(*args, **kwargs)
        except NotImplementedError:
            container = None

        if not container:
            files_to_sign = self.get_files_to_sign(*args, **kwargs)
        else:
            files_to_sign = None
            if not isinstance(container, pyasice.Container):
                if isinstance(container, str):
                    container = pyasice.Container.open(container)
                else:
                    container = pyasice.Container(container)

        self.check_eligibility(signer, container)

        response_to_user = signer.prepare(container, files_to_sign)

        return JsonResponse({**response_to_user, "status": self.Status.SUCCESS})

    def finish_session(self, request: "RequestType", *args, **kwargs):
        """
        Checks the status of a signing session and attempts to finalize signing
        """
        signer_class = self.select_signer_class()
        signer = signer_class.load_session(request.session)

        do_cleanup = True

        try:
            container = signer.finalize(getattr(request, "data", None))
            self.save_container(container, *args, **kwargs)

        except ActionInProgress as e:
            do_cleanup = False
            return JsonResponse({"status": self.Status.PENDING, **e.data}, status=e.status)

        finally:
            if do_cleanup:
                signer.cleanup()

        return self.get_success_response(*args, **kwargs)

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
            raise

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


class SignViewRestMixin(SignViewMixin):
    """
    To be used with rest-framework's APIView.
    """


class SignViewDjangoMixin(SignViewMixin):
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
