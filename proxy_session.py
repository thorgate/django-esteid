import json
from base64 import b64decode, b64encode
from django.conf import settings

import requests


class ProxiedSession(requests.Session):
    """A session that sends requests through a proxy

    WARNING: ONLY USE FOR LOCAL TESTING NOT FOR SERVICES EXPOSED TO THE WORLD!

    See esteid-proxy/README.md for more information
    """

    def send(self, request, **kwargs):
        # Use a proxy for the request, so we create a new one and put all the params inside the body
        PROXY_URL = "http://localhost:8001"

        new_request = requests.Request(
            method="POST",
            url=PROXY_URL,
            json={
                "httpMethod": request.method,
                "url": request.url,
                "headers": dict(request.headers),
                "body": b64encode(request.body).decode("utf-8") if request.body else None,
            },
            headers={
                "proxy-token": str(getattr(settings, "ESTEID_PROXY_TOKEN", "yolo")),
                "Content-Type": "application/json",
            },
        )
        new_request = new_request.prepare()

        result = super().send(new_request, **kwargs)

        print("RESULT", result.status_code)

        return result


def proxied_get_request_session():
    return ProxiedSession()
