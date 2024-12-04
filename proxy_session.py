import json
from base64 import b64decode, b64encode

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
                "proxy-token": "yolo",
                "Content-Type": "application/json",
            },
        )
        new_request = new_request.prepare()

        result = super().send(new_request, **kwargs)

        print("RESULT", result.status_code)

        return result

        data = result.json()
        full_body = json.loads(data["body"])
        status_code = full_body["status"]

        body = b64decode(full_body["body"])
        headers = full_body["headers"]
        reason = full_body["message"]

        final_resp = requests.Response()
        final_resp.status_code = status_code
        final_resp.headers = headers
        final_resp.reason = reason
        final_resp._content = body
        final_resp._content
        final_resp.encoding = "utf-8"

        return final_resp


def proxied_get_request_session():
    return ProxiedSession()
