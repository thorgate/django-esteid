import logging
from typing import BinaryIO, Type, TYPE_CHECKING, Union

from django.http import HttpRequest, JsonResponse

import pyasice

from esteid import settings
from esteid.exceptions import ActionInProgress, AlreadySignedByUser
from esteid.mixins import DjangoRestCompatibilityMixin, SessionViewMixin
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


class SignViewMixin(SessionViewMixin):
    # these come from the `url()` definition as in `View.as_view(signing_method='...')`, either one is enough
    signer_class: Type[Signer] = None
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
        if self.signer_class is not None:
            return self.signer_class
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


class SignViewRestMixin(SignViewMixin):
    """
    To be used with rest-framework's APIView.
    """


class SignViewDjangoMixin(DjangoRestCompatibilityMixin, SignViewMixin):
    """
    To be used with plain Django class-based views (No rest-framework).

    Adds `data` attribute to the request with the POST or JSON data.
    """
