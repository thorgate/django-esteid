import json

from django.core.serializers.json import DjangoJSONEncoder
from django.http.response import HttpResponse


class JSONResponse(HttpResponse):
    def __init__(self, content, cls=None, status=200):
        if cls is None:
            cls = DjangoJSONEncoder

        super(JSONResponse, self).__init__(json.dumps(content, cls=cls), content_type='application/json', status=status)
