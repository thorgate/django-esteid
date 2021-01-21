from esteid.types import PredictableDict


class SessionData(PredictableDict):
    """
    Wrapper for temporary data stored between authentication polling requests
    """

    timestamp: int
    session_id: str
    hash_value_b64: str


class AuthenticationResult(PredictableDict):
    id_code: str
    given_name: str
    surname: str
    certificate_b64: str
