# Documentation states that the state can only be RUNNING or COMPLETE
# see https://github.com/SK-EID/smart-id-documentation#464-response-structure
STATE_RUNNING = "RUNNING"
STATE_COMPLETE = "COMPLETE"

STATES = (
    STATE_RUNNING,
    STATE_COMPLETE,
)


class EndResults:
    """Taken FWIW from the docs"""

    OK = "OK"
    TIMEOUT = "TIMEOUT"
    NOT_MID_CLIENT = "NOT_MID_CLIENT"
    USER_CANCELLED = "USER_CANCELLED"
    SIGNATURE_HASH_MISMATCH = "SIGNATURE_HASH_MISMATCH"
    PHONE_ABSENT = "PHONE_ABSENT"
    DELIVERY_ERROR = "DELIVERY_ERROR"
    SIM_ERROR = "SIM_ERROR"

    ALL = (
        OK,
        TIMEOUT,
        NOT_MID_CLIENT,
        USER_CANCELLED,
        SIGNATURE_HASH_MISMATCH,
        PHONE_ABSENT,
        DELIVERY_ERROR,
        SIM_ERROR,
    )


class Languages:
    ENG = "ENG"
    EST = "EST"
    LIT = "LIT"
    RUS = "RUS"

    ALL = (ENG, EST, LIT, RUS)
