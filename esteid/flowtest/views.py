import base64
from tempfile import NamedTemporaryFile

from django.views.generic import DetailView
from rest_framework.views import APIView

from pyasice import Container

from esteid.signing import DataFile, SignViewDjangoMixin, SignViewRestMixin

# Register our signers
from ..idcard import IdCardSigner  # noqa
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
