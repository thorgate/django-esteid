class MobileIDError(Exception):
    pass


class UserNotRegistered(MobileIDError):
    pass


class InvalidCredentials(MobileIDError):
    pass


class OfflineError(MobileIDError):
    pass


class SessionDoesNotExist(MobileIDError):
    pass


class PermissionDenied(MobileIDError):
    pass


class IdentityCodeDoesNotExist(MobileIDError):
    pass


class ActionNotCompleted(MobileIDError):
    pass


class SignatureVerificationError(MobileIDError):
    pass


class InvalidSignatureAlgorithm(SignatureVerificationError):
    pass


class ActionFailed(MobileIDError):
    def __init__(self, result_code, msg):
        self.result_code = result_code

        super(ActionFailed, self).__init__(msg)
