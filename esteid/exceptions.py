class EsteidError(Exception):
    pass


class UserNotRegistered(EsteidError):
    pass


class InvalidCredentials(EsteidError):
    pass


class OfflineError(EsteidError):
    pass


class SessionDoesNotExist(EsteidError):
    pass


class PermissionDenied(EsteidError):
    pass


class IdentityCodeDoesNotExist(EsteidError):
    pass


class ActionNotCompleted(EsteidError):
    pass


class SignatureVerificationError(EsteidError):
    pass


class InvalidSignatureAlgorithm(SignatureVerificationError):
    pass


class UnsupportedClientImplementation(EsteidError):
    pass


class ActionFailed(EsteidError):
    def __init__(self, result_code, msg):
        self.result_code = result_code

        super(ActionFailed, self).__init__(msg)
