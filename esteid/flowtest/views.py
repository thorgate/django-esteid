import base64
from tempfile import NamedTemporaryFile

from django.views.generic import DetailView, View
from rest_framework.views import APIView

from pyasice import Container

from esteid.authentication import AuthenticationViewDjangoMixin, AuthenticationViewRestMixin
from esteid.signing import DataFile, SignViewDjangoMixin, SignViewRestMixin

# Register our signers
from ..authentication.types import AuthenticationResult
from ..idcard import IdCardSigner  # noqa
from ..idcard import BaseIdCardAuthenticationView
from ..mobileid import MobileIdSigner  # noqa
from ..smartid import SmartIdSigner  # noqa
from .signer import MyPostSigner, MySigner  # noqa


class BaseMethods:
    def get_files_to_sign(self, *args, **kwargs):
        files = self.request.session.get("__ddoc_files")
        if files:
            return [
                DataFile(
                    file_name,
                    content=base64.b64decode(file["content"]),
                    mime_type=file["content_type"],
                )
                for file_name, file in files.items()
            ]

        return []

    def save_container(self, container: Container, *args, **kwargs):
        with NamedTemporaryFile("wb", delete=False) as f:
            f.write(container.finalize().getbuffer())
        self.request.session["__ddoc_container_file"] = f.name


class SigningTestView(BaseMethods, SignViewDjangoMixin, DetailView):
    pass


class SigningTestRestView(BaseMethods, SignViewRestMixin, APIView):
    pass


class IDCardAuthTestView(BaseIdCardAuthenticationView):
    def on_auth_success(self, request, auth_result: AuthenticationResult):
        pass


class AuthTestView(AuthenticationViewDjangoMixin, View):
    def on_auth_success(self, request, data: AuthenticationResult):
        pass


class AuthTestRestView(AuthenticationViewRestMixin, APIView):
    def on_auth_success(self, request, data: AuthenticationResult):
        pass
