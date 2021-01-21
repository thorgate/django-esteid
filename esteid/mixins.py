import json

from django.http import QueryDict

from .exceptions import InvalidParameters


class DjangoRestCompatibilityMixin:
    """
    Provides a method enabling Django view to accept JSON request bodies the same way as Rest Framework views.
    """

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
