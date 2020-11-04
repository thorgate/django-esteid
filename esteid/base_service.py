import logging
from typing import Union
from uuid import UUID

import requests

from .exceptions import (
    ActionInProgress,
    BadRequest,
    EsteidError,
    InvalidCredentials,
    OfflineError,
    SessionDoesNotExist,
    UnsupportedClientImplementation,
    UpstreamServiceError,
)


logger = logging.getLogger(__name__)


class BaseSKService:
    """Base class for SK Authentication and signing services"""

    NAME: str

    class ProcessingStates:
        # Documentation states that the state can only be RUNNING or COMPLETE
        # see https://github.com/SK-EID/smart-id-documentation#464-response-structure
        # and https://github.com/SK-EID/MID#335-response-structure
        RUNNING = "RUNNING"
        COMPLETE = "COMPLETE"

        ALL = (
            RUNNING,
            COMPLETE,
        )

    _REQUEST_HEADERS = {
        "Content-Type": "application/json",
    }

    def __init__(self, rp_uuid: Union[UUID, str], rp_name: str, api_root: str):
        if not isinstance(rp_uuid, UUID):
            try:
                UUID(rp_uuid)
            except (TypeError, ValueError) as e:
                raise EsteidError("rp_uuid expected to be a valid UUID") from e
        self.rp_uuid = str(rp_uuid)
        self.rp_name = rp_name
        self.api_root = api_root

        self.session = requests.Session()

    def rp_params(self, data: dict):
        return {
            **data,
            "relyingPartyUUID": self.rp_uuid,
            "relyingPartyName": self.rp_name,
        }

    def api_url(self, endpoint):
        return "{api_root}{endpoint}".format(api_root=self.api_root, endpoint=endpoint)

    def invoke(self, endpoint, method="GET", query=None, data=None):
        query = query or {}

        if method != "GET":
            data = self.rp_params(data or {})

        req = requests.Request(
            method=method,
            url=self.api_url(endpoint),
            params=query,
            json=data,
            headers=self._REQUEST_HEADERS,
        )
        prepared = req.prepare()

        try:
            # Attempt to fulfill the request
            response = self.session.send(prepared)

            # ensure we don't mask errors
            response.raise_for_status()

        except (requests.ConnectionError, requests.Timeout, ConnectionError) as e:
            logger.exception("Failed to get a response from %s.", req.url)
            raise OfflineError(service=self.NAME) from e

        except requests.HTTPError as e:
            status_code = e.response.status_code
            if status_code == 401:
                logger.exception("API authentication failure at %s: %s", req.url, e.response.text)
                raise InvalidCredentials from e

            elif status_code == 400:
                logger.exception("Bad Request to %s. Response:\n%s", req.url, e.response.text)
                raise BadRequest from e

            elif status_code == 480:
                logger.exception("Service reported Unsupported Client at %s. Response:\n%s", req.url, e.response.text)
                raise UnsupportedClientImplementation(service=self.NAME) from e

            # 580 System is under maintenance, retry later.
            # see https://github.com/SK-EID/smart-id-documentation#413-http-status-code-usage
            # (Note: Though not documented, Mobile ID also returns this occasionally.)
            elif status_code == 580:
                logger.exception("Service %s on maintenance.", self.NAME)
                raise OfflineError("Maintenance", service=self.NAME) from e

            # Raise proxy errors as OfflineError
            elif status_code in [502, 503, 504]:
                logger.exception("Service %s not available (HTTP %s).", req.url, status_code)
                raise OfflineError(f"Proxy error: {status_code}", service=self.NAME) from e

            # UpstreamServiceError for everything else. The caller can use `exc.__cause__` to get the original HTTPError
            # Do not log these errors here, because they can be related to user input, depending on the endpoint.
            raise UpstreamServiceError(f"Service {self.NAME} returned an unidentified error", service=self.NAME) from e

        try:
            return response.json()
        except ValueError as e:
            logger.exception("Failed to parse %s response as JSON:\n%s", req.url, response.content)
            raise UpstreamServiceError("Failed to parse response as JSON", service=self.NAME) from e

    def poll_session(self, session_id, endpoint_url, timeout=None) -> dict:
        """
        Polls session status with a specified timeout and returns the received result.

        The timeout defaults to 500ms to avoid extremely long blocking. If it is done asynchronously via Celery,
        it can be increased as per the docs below.

        https://github.com/SK-EID/MID#334-long-polling
        https://github.com/SK-EID/smart-id-documentation#46-session-status
        """
        endpoint_url = endpoint_url.format(session_id=session_id)
        try:
            data = self.invoke(
                endpoint_url,
                query={
                    "timeoutMs": timeout or 500,
                },
            )

        except UpstreamServiceError as e:
            cause = getattr(e, "__cause__", None)
            if isinstance(cause, requests.HTTPError):
                response = cause.response
                if response.status_code == 404:
                    raise SessionDoesNotExist(session_id) from e

                logger.exception(
                    "The %s service returned an error %s at %s. Response:\n %s",
                    self.NAME,
                    response.status_code,
                    endpoint_url,
                    response.text,
                )
            else:
                logger.exception("Unidentified error at %s.", endpoint_url)
            raise

        state = data["state"]
        if state == self.ProcessingStates.RUNNING:
            raise ActionInProgress(session_id)

        if state != self.ProcessingStates.COMPLETE:
            logger.exception("Unrecognized state %s at %s", state, endpoint_url)
            raise UpstreamServiceError(service=self.NAME)

        return data
