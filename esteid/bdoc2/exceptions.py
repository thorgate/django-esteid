class BDoc2Error(Exception):
    """
    A generic exception that can happen while dealing with BDoc 2 files/signatures
    """
    pass


class NoFilesToSign(BDoc2Error):
    pass


class SignatureVerificationError(BDoc2Error):
    pass


class InvalidSignatureAlgorithm(SignatureVerificationError):
    pass
