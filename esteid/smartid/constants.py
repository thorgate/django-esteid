from esteid.constants import Countries  # noqa


CERTIFICATE_LEVEL_QUALIFIED = "QUALIFIED"
CERTIFICATE_LEVEL_ADVANCED = "ADVANCED"

CERTIFICATE_LEVELS = (
    CERTIFICATE_LEVEL_QUALIFIED,
    CERTIFICATE_LEVEL_ADVANCED,
)


class EndResults:
    """
    https://github.com/SK-EID/smart-id-documentation#5-session-end-result-codes
    """

    OK = "OK"  # session was completed successfully
    USER_REFUSED = "USER_REFUSED"  # user refused the session
    TIMEOUT = "TIMEOUT"  # there was a timeout, i.e. end user did not confirm or he operation within given time-frame
    DOCUMENT_UNUSABLE = "DOCUMENT_UNUSABLE"  # for some reason, this RP request cannot be completed

    ALL = (OK, DOCUMENT_UNUSABLE, TIMEOUT, USER_REFUSED)
