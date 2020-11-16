from http import HTTPStatus

from django.utils.translation import gettext_lazy as _


class EsteidError(Exception):
    """
    A generic Esteid error.

    Provides an interface for displaying a translated message to the user.

    Note: by default, any message passed as a first positional argument is ignored, because it only
    serves for better logging. The User Interface should display a verbose error message
    in case of a user-caused error so that user can take action accordingly. Errors caused by service malfunction
    are likely not informative to a user without malicious intent.

    If the default message contains {key} placeholders, the exception is supposed to be
    raised with kwargs, these will be passed on to <translated default message>.format(**kwargs).
    """

    status = HTTPStatus.INTERNAL_SERVER_ERROR

    default_message = _("Something went wrong")

    kwargs: dict

    def __init__(self, message=None, **kwargs):
        super().__init__(message)
        self.kwargs = kwargs

    def get_message(self):
        return str(self.default_message).format(**self.kwargs)

    def get_user_error(self):
        return {
            "error": self.__class__.__name__,  # error code that can be bound to JS translations
            # TODO review errors and add translations
            "message": self.get_message(),
        }


class ActionInProgress(EsteidError):
    """
    Raised when a request to the service is still in pending status,
    or when it is necessary to move on to the next step while passing some data on to the user
    (like after successful auth, we initiate a signing request and display verification code)
    """

    status = HTTPStatus.ACCEPTED

    default_message = _("Operation is in progress.")

    def __init__(self, message=None, data: dict = None):
        super().__init__(message)
        self.data = data or {}


# *** Misc errors resulting from misconfiguration or upstream service malfunction ***


class UpstreamServiceError(EsteidError):
    """A failure reported by upstream service which is not caused by user.

    Takes a `service` kwarg, e.g. Mobile ID / Smart ID
    """

    status = HTTPStatus.SERVICE_UNAVAILABLE

    default_message = _("The {service} service reported a failure.")

    def __init__(self, message=None, *, service, **kwargs):
        super().__init__(message)
        self.kwargs = {"service": service, **kwargs}


class OfflineError(UpstreamServiceError):
    default_message = _("The {service} service is unavailable at the moment. Please try again later.")


class PermissionDenied(UpstreamServiceError):
    """
    If a SmartID user has a certificate of level ADVANCED, it may be impossible to perform operations.
    """

    default_message = _("Operation with user certificate level ADVANCED not allowed.")

    def __init__(self, message=None, **kwargs):
        kwargs.setdefault("service", "smartid")
        super().__init__(message, **kwargs)


class UnsupportedClientImplementation(UpstreamServiceError):
    pass


# *** Errors that can not be determinably attributed to a service


class InvalidCredentials(EsteidError):
    pass


class BadRequest(EsteidError):
    pass


class SessionDoesNotExist(EsteidError):
    pass


class SignatureVerificationError(EsteidError):
    pass


# *** Signing Session errors ***


class SigningSessionError(EsteidError):
    """Base class for signing session errors"""

    status = HTTPStatus.CONFLICT


class SigningSessionExists(SigningSessionError):
    """A signing session already exists while not expected to exist (when initializing)"""

    default_message = _("A signing session is already in progress.")


class SigningSessionDoesNotExist(SigningSessionError):
    """A signing session does not exist while expected to exist"""

    default_message = _("No signing session found.")


# *** Errors caused by user action or inaction


class InvalidParameters(EsteidError):
    """Invalid initialization parameters received from the request."""

    status = HTTPStatus.BAD_REQUEST

    default_message = _("Invalid parameters.")


class InvalidParameter(InvalidParameters):
    """Invalid initialization parameter PARAM received from the request.

    Takes a `param` kwarg
    """

    default_message = _("Invalid value for parameter {param}.")

    def __init__(self, message=None, *, param, **kwargs):
        super().__init__(message)
        self.kwargs = {**kwargs, "param": param}


class InvalidIdCode(InvalidParameter):
    """Invalid ID code (format or checksum don't match)"""

    default_message = _("Invalid ID code.")

    def __init__(self, message=None, *, param="id_code", **kwargs):
        super().__init__(message, param=param, **kwargs)


class UserNotRegistered(EsteidError):
    """User not registered in the service."""

    status = HTTPStatus.CONFLICT

    default_message = _("User not registered in the service.")


class CanceledByUser(EsteidError):
    """User canceled the operation."""

    status = HTTPStatus.CONFLICT

    default_message = _("The signing operation was canceled by the user.")


class UserTimeout(EsteidError):
    """Failed to get PIN code from user within the interval specified by the service.

    For Mobile ID, this is about 2 minutes.
    https://github.com/SK-EID/MID#338-session-end-result-codes
    https://github.com/SK-EID/smart-id-documentation#5-session-end-result-codes
    """

    status = HTTPStatus.CONFLICT

    default_message = _("The signing operation timed out.")


class AlreadySignedByUser(InvalidParameters):
    """The container has been already signed by the same party.

    The class is based on InvalidParameters so that such errors are not logged.
    """

    status = HTTPStatus.CONFLICT

    default_message = _("The container has been already signed by the user.")
