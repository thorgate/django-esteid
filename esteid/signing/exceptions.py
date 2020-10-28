from http import HTTPStatus


class SigningError(Exception):
    """A generic signing error"""

    status = HTTPStatus.INTERNAL_SERVER_ERROR

    def __str__(self):
        return f"{self.__class__.__name__}: {super().__str__()}"


class InvalidSigningMethod(SigningError):
    """If the method is invalid, it's probably not the user's fault. Any better way to indicate?"""

    status = HTTPStatus.METHOD_NOT_ALLOWED


class InvalidParameter(SigningError):
    """Invalid initialization parameters received from the request"""

    status = HTTPStatus.BAD_REQUEST


class SigningSessionError(SigningError):
    """Base class for signing session errors"""

    status = HTTPStatus.CONFLICT


class SigningSessionExists(SigningSessionError):
    """A signing session already exists while not expected to exist (when initializing)"""


class SigningSessionDoesNotExist(SigningSessionError):
    """A signing session does not exist while expected to exist"""


class ActionInProgress(SigningError):
    """
    Raised when a request to the service is still in pending status,
    or when it is necessary to move on to the next step while passing some data on to the user
    (like after successful auth, we initiate a signing request and display verification code)
    """

    status = HTTPStatus.ACCEPTED

    def __init__(self, message=None, data: dict = None):
        super().__init__(message)
        self.data = data or {}


class UpstreamServiceError(SigningError):
    """Request to the upstream service failed"""
