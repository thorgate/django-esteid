import base64
import logging
from tempfile import NamedTemporaryFile

from django.http import HttpResponse, HttpResponseRedirect
from django.views.generic import TemplateView, View

from pyasice import Container

from .actions import (
    IdCardFinishAction,
    IdCardPrepareAction,
    MobileIdSignAction,
    MobileIdStatusAction,
    SmartIdSignAction,
    SmartIdStatusAction,
)
from .generic import ApiView, GenericDigitalSignViewMixin, SignStatusViewMixin
from .types import DataFile


logger = logging.getLogger(__name__)


class SKTestView(TemplateView):
    template_name = "esteid/test.html"

    def get_context_data(self, **kwargs):
        context = super(SKTestView, self).get_context_data(**kwargs)

        try:
            files = self.request.session["__ddoc_files"]

        except KeyError:
            files = {}

        context.update(
            {
                "files": files,
            }
        )

        return context

    def post(self, request, *args, **kwargs):
        """This method is only for testing and can
        be used to add some files to the session.

        actions:

            - add_file
            - remove_file
        """
        try:
            files = request.session["__ddoc_files"]

        except KeyError:
            files = {}

        action = request.POST.get("action", "add_file")

        if action == "remove_file":
            file_name = request.POST.get("file_name", "")

            n_files = {}
            for key, file in files.items():
                if key != file_name:
                    n_files[key] = file

            files = n_files

        else:
            for key, file in request.FILES.items():
                file_name = file.name

                idx = 1
                while file_name in files.keys():
                    file_name = "%d_%s" % (idx, file_name)
                    idx += 1

                files[file_name] = dict(
                    content=base64.b64encode(file.read()).decode(),
                    content_type=file.content_type,
                    size=file.size,
                )

        request.session["__ddoc_files"] = files

        return HttpResponseRedirect(".")


class TestFilesMixin(GenericDigitalSignViewMixin):
    def get_files(self):
        files = []

        for file_name, file in self.request.session["__ddoc_files"].items():
            files.append(
                DataFile(
                    file_name=file_name,
                    mimetype=file["content_type"],
                    content_type=file["content_type"],
                    size=file["size"],
                    content=base64.b64decode(file["content"]),
                )
            )

        return files


class TestSignStatusViewMixin(SignStatusViewMixin):
    """Gets the status of signing and finalizes the process if necessary."""

    def post(self, request, *args, **kwargs):
        result = super().post(request, *args, **kwargs)

        if result["success"]:
            container: Container = result.pop("container", None)

            if container:
                with NamedTemporaryFile("wb", delete=False) as f:
                    f.write(container.finalize().getbuffer())

                request.session["__ddoc_container_file"] = f.name
                logger.debug("Saved container to temp file %s", f.name)

        return result


class TestMobileIdSignView(TestFilesMixin, ApiView):
    def post(self, request, *args, **kwargs):
        return MobileIdSignAction.do_action(
            self,
            id_code=request.POST.get("id_code", ""),
            phone_number=request.POST.get("phone_nr", ""),
            language=request.POST.get("language", None),
        )


class TestMobileIdStatusView(TestSignStatusViewMixin, ApiView):
    ACTION_CLASS = MobileIdStatusAction


class TestSmartIdSignView(TestFilesMixin, ApiView):
    def post(self, request, *args, **kwargs):
        return SmartIdSignAction.do_action(
            self,
            id_code=request.POST.get("id_code", ""),
            language=request.POST.get("language", None),
        )


class TestSmartIdStatusView(TestSignStatusViewMixin, ApiView):
    ACTION_CLASS = SmartIdStatusAction


class TestDownloadContainerView(View):
    def get(self, request, *args, **kwargs):
        request.session.pop("__ddoc_files", None)

        container_file = request.session.pop("__ddoc_container_file", None)
        logging.info("Got container temp file name '%s'", container_file)
        file_contents = None
        if container_file:
            try:
                with open(container_file, "rb") as f:
                    file_contents = f.read()
            except FileNotFoundError:
                pass

        if not file_contents:
            response = HttpResponse("Error: no container file found", status=409)
        else:
            # Download the file
            response = HttpResponse(file_contents, content_type=Container.MIME_TYPE)
            response["Content-Disposition"] = "attachment; filename=" + "signed.bdoc"
        return response


class TestIdCardSignView(TestFilesMixin, ApiView):
    def post(self, request, *args, **kwargs):
        return IdCardPrepareAction.do_action(self, certificate=request.POST["certificate"])


class TestIdCardFinishView(TestSignStatusViewMixin, ApiView):
    ACTION_CLASS = IdCardFinishAction

    def build_action_kwargs(self, request):
        return dict(signature_value=request.POST["signature_value"])


class AuthenticationView(TemplateView):
    template_name = "esteid/authenticate.html"

    def __init__(self, *args, **kwargs):
        self.id_auth = None
        self.id_err = None

    def dispatch(self, request, *args, **kwargs):
        self.id_auth = getattr(request, "id_auth", None)
        self.id_err = getattr(request, "id_err", None)

        return super(AuthenticationView, self).dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(AuthenticationView, self).get_context_data(**kwargs)

        self.request.session["id_auth"] = self.id_auth
        context["id_auth"] = self.id_auth
        context["id_err"] = self.id_err

        return context
