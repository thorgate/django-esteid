from typing import List

from django.http import HttpRequest, JsonResponse
from django.views import View

from .actions import BaseAction
from .types import DataFile


class GenericDigitalSignViewMixin(object):
    request: HttpRequest

    def get_files(self) -> List[DataFile]:
        """
        This should be implemented on view level, and should return a list of files that should be digitally signed.

        Will be ignored if `get_bdoc_container_file()` returns not None
        """
        return []

    def get_bdoc_container_file(self) -> str:
        """
        Returns path to a container that should be digitally signed.

        If there is a container, then get_files() will be ignored, and a new signature will be added to the container.
        """
        pass


class ApiView(View):
    def dispatch(self, request, *args, **kwargs):
        response = super().dispatch(request, *args, **kwargs)
        if isinstance(response, (dict, list, tuple)):
            return JsonResponse(response)

        return response


class SignStatusViewMixin:
    """Gets the status of signing and finalizes the process if necessary."""

    ACTION_CLASS: BaseAction

    def build_action_kwargs(self, request):
        return {}

    def post(self, request, *args, **kwargs):
        action_kwargs = self.build_action_kwargs(request)
        return self.ACTION_CLASS.do_action(self, **action_kwargs)

    def get(self, request, *args, **kwargs):
        return self.post(request, *args, **kwargs)
