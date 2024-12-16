# esteid-proxy

A simple fastapi proxy server to test out the id card signing and authentication against a live service. This is required since the live server is often behind a proxy and we don't want to have our internal vpn IP in one of the client contracts.

Deploy this to one of your servers thats whitelisted in SK.ee side and use a ssh tunnel to access it. Finally set up a custom requests.Session for esteid library. This way the connection will be made using the proxy server IP so you wont get a nasty 403 error.

## install and run

```bash
poetry install --no-root
# note: set ALLOWED_URLS and TOKEN environment variables
poetry run fastapi dev esteid-proxy.py --port 8001
```

Alternatively, you can run the proxy in docker, using the makefile. This is useful on older servers
that may not have python 3.8 available.

```
make
```

## setup ssh tunnel

```bash
ssh -L 8001:localhost:8001 user@server
```

## use custom session

Add these to a `local_settings.py` file (create one if it doesn't exist) in the same directory as the `test_settings.py` file:

```python
ESTEID_DEMO = False

MOBILE_ID_SERVICE_NAME = "real service name"
MOBILE_ID_SERVICE_UUID = "real service uuid"

ESTEID_GET_REQUEST_SESSION = "proxy_session.proxied_get_request_session"
ESTEID_PROXY_TOKEN = "token that the proxy server outputs if you run it with make, and which you must set explicitly otherwise"
```
