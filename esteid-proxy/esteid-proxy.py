from base64 import b64decode, b64encode
import json
import os
import traceback
from typing import Any, Dict
from urllib.parse import parse_qs, unquote_plus, quote_plus

import requests
from requests import RequestException

ALLOWED_URLS = os.environ["ALLOWED_URLS"].split(",")
ANY_ALLOWED = "*" in ALLOWED_URLS

TOKEN = os.environ["TOKEN"]

session = requests.Session()


def handle_request(headers, data):
    # Important to remove the Host header before forwarding the request
    if headers.get("Host"):
        headers.pop("Host")

    if headers.get("host"):
        headers.pop("host")

    req_token = headers.get("proxy-token", "")

    if req_token != TOKEN:
        print("Invalid token.", req_token, TOKEN)
        return {"statusCode": 529, "body": "bad"}

    http_method = data["httpMethod"]
    body = b64decode(data["body"]) if data["body"] is not None else None
    target_url = data["url"]
    headers = data["headers"]

    if not ANY_ALLOWED and not any([target_url.startswith(url) for url in ALLOWED_URLS]):
        print(f"Invalid url {target_url}.")
        return {"statusCode": 529, "body": "misconfigured url"}

    try:
        req = requests.Request(
            method=http_method,
            url=target_url,
            data=body,
            headers=headers,
        )
        prepared = req.prepare()

        resp = session.send(prepared)

        resp.raise_for_status()

        return FastAPIResponse(content=resp.content, status_code=resp.status_code, headers=resp.headers)
                               
        #                        {
        #     "statusCode": resp.status_code,
        #     "body": resp.text,
        #     "headers": dict(resp.headers),
        # }
    except RequestException as e:
        print("Connection failed.")

        return FastAPIResponse(content=e.response.text, status_code=e.response.status_code, headers=dict(e.response.headers))

        return {
            "statusCode": e.response.status_code,
            "body": e.response.text,
            "headers": dict(e.response.headers),

            # "body": json.dumps(
            #     {
            #         "status": ,
            #         "message": e.response.reason,
            #         "headers": dict(e.response.headers),
            #         "body": b64encode(e.response.text.encode("utf-8")).decode("utf-8"),
            #     }
            # ),
        }
    except Exception as e:
        print("Something went wrong.")
        print(e)
        traceback.print_exc()
        return {"statusCode": 529, "body": "internal server error"}


from fastapi import FastAPI, Request as FastAPIRequest, Response as FastAPIResponse


app = FastAPI()

@app.post("/")
async def root(request: FastAPIRequest):
    print("Request received.")

    headers = dict(request.headers)
    body = await request.json()

    return handle_request(headers, body)

