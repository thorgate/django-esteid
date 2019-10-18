
class SmartIDError(Exception):
    pass


class InvalidCredentials(SmartIDError):
    pass


class UnsupportedClientImplementation(SmartIDError):
    pass


class OfflineError(SmartIDError):
    pass


class SessionDoesNotExist(SmartIDError):
    pass


class PermissionDenied(SmartIDError):
    pass


class IdentityCodeDoesNotExist(SmartIDError):
    pass


class ActionNotCompleted(SmartIDError):
    pass


class SignatureVerificationError(SmartIDError):
    pass


class InvalidSignatureAlgorithm(SignatureVerificationError):
    pass


class ActionFailed(SmartIDError):
    def __init__(self, result_code, msg):
        self.result_code = result_code

        super(ActionFailed, self).__init__(msg)
