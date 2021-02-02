import base64
import logging

from esteid.exceptions import ActionInProgress, InvalidIdCode, InvalidParameters

from ..authentication import Authenticator
from ..authentication.types import AuthenticationResult
from ..types import CertificateHolderInfo
from .i18n import TranslatedSmartIDService
from .types import UserInput


logger = logging.getLogger(__name__)


class SmartIdAuthenticator(Authenticator):
    id_code: str
    country: str

    def setup(self, initial_data: dict = None):
        """
        Receives user input via POST: `id_code`, `country`
        """
        if not isinstance(initial_data, dict):
            raise InvalidParameters("Missing required parameters")

        user_input = UserInput(**initial_data)

        try:
            user_input.is_valid()
        except InvalidIdCode:
            # Just to be explicit
            raise
        except ValueError as e:
            raise InvalidParameters from e

        self.id_code = user_input.id_code
        self.country = user_input.country

    def authenticate(self):
        service = TranslatedSmartIDService.get_instance()

        auth_initial_result = service.authenticate(self.id_code, self.country)

        self.save_session_data(
            session_id=auth_initial_result.session_id, hash_value_b64=auth_initial_result.hash_value_b64
        )

        raise ActionInProgress(
            data={
                "verification_code": auth_initial_result.verification_code,
            }
        )

    def poll(self) -> AuthenticationResult:
        session_id = self.session_data.session_id
        hash_value_b64 = self.session_data.hash_value_b64

        service = TranslatedSmartIDService.get_instance()

        # raises ActionInProgress if not received a final result
        auth_result = service.status(session_id, hash_value=base64.b64decode(hash_value_b64))

        cert_holder_info = CertificateHolderInfo.from_certificate(auth_result.certificate)

        return AuthenticationResult(
            country=cert_holder_info.country,
            id_code=cert_holder_info.id_code,
            given_name=cert_holder_info.given_name,
            surname=cert_holder_info.surname,
            certificate_b64=auth_result.certificate_b64,
        )
