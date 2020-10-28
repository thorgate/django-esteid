COUNTRY_ESTONIA = "EE"
COUNTRY_LATVIA = "LV"
COUNTRY_LITHUANIA = "LT"

COUNTRIES = (
    COUNTRY_ESTONIA,
    COUNTRY_LATVIA,
    COUNTRY_LITHUANIA,
)

CERTIFICATE_LEVEL_QUALIFIED = "QUALIFIED"
CERTIFICATE_LEVEL_ADVANCED = "ADVANCED"

CERTIFICATE_LEVELS = (
    CERTIFICATE_LEVEL_QUALIFIED,
    CERTIFICATE_LEVEL_ADVANCED,
)

# Documentation states that the state can only be RUNNING or COMPLETE
# see https://github.com/SK-EID/smart-id-documentation#464-response-structure
STATE_RUNNING = "RUNNING"
STATE_COMPLETE = "COMPLETE"

STATES = (
    STATE_RUNNING,
    STATE_COMPLETE,
)

# OK - session was completed successfully
END_RESULT_OK = "OK"

# USER_REFUSED - user refused the session
END_RESULT_USER_REFUSED = "USER_REFUSED"

# USER_TIMEOUT - there was a timeout, i.e. end user did not confirm or
#  refuse the operation within given time-frame
END_RESULT_TIMEOUT = "TIMEOUT"

# DOCUMENT_UNUSABLE - for some reason, this RP request cannot be completed
END_RESULT_DOCUMENT_UNUSABLE = "DOCUMENT_UNUSABLE"

# see https://github.com/SK-EID/smart-id-documentation#5-session-end-result-codes
END_RESULT_CODES = (
    END_RESULT_OK,
    END_RESULT_USER_REFUSED,
    END_RESULT_TIMEOUT,
    END_RESULT_DOCUMENT_UNUSABLE,
)
