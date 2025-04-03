import typing as t
from http import HTTPStatus

from esteid.types import PredictableDict


class AuthenticationResult(PredictableDict):
    country: str
    id_code: str
    given_name: str
    surname: str
    certificate_b64: str


class SessionData(PredictableDict):
    """
    Wrapper for temporary data stored between authentication polling requests.

    Contains the upstream service's session ID and the hash value used to calculate the authentication signature,
     along with a timestamp that is used to determine session validity timeout.
    """

    timestamp: int
    session_id: str
    hash_value_b64: str
    status: str
    result: t.Optional[AuthenticationResult]


class Status:
    ERROR = "error"
    PENDING = "pending"
    SUCCESS = "success"
    CANCELLED = "cancelled"

    @classmethod
    def http_status_for_status(cls, status: str) -> HTTPStatus:
        return {
            cls.ERROR: HTTPStatus.GONE,
            cls.PENDING: HTTPStatus.ACCEPTED,
            cls.SUCCESS: HTTPStatus.OK,
            cls.CANCELLED: HTTPStatus.CONFLICT,
        }.get(status, HTTPStatus.INTERNAL_SERVER_ERROR)
