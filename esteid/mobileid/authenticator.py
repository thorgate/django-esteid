import base64
import logging

from esteid.exceptions import ActionInProgress, InvalidIdCode, InvalidParameter, InvalidParameters

from ..authentication import Authenticator
from ..authentication.types import AuthenticationResult
from ..types import CertificateHolderInfo
from .i18n import TranslatedMobileIDService
from .types import UserInput


logger = logging.getLogger(__name__)


class MobileIdAuthenticator(Authenticator):
    phone_number: str
    id_code: str
    language: str

    def setup(self, initial_data: dict = None):
        """
        Receives user input via POST: `id_code`, `phone_number`, `language`
        """
        if not isinstance(initial_data, dict):
            raise InvalidParameters("Missing required parameters")

        user_input = UserInput(**initial_data)

        try:
            user_input.is_valid()
        except (InvalidIdCode, InvalidParameter):
            # Just to be explicit
            raise
        except ValueError as e:
            raise InvalidParameters("Invalid parameters") from e

        self.id_code = user_input.id_code
        self.phone_number = user_input.phone_number
        self.language = user_input.language

    def authenticate(self):
        service = TranslatedMobileIDService.get_instance()

        auth_initial_result = service.authenticate(self.id_code, self.phone_number, language=self.language)

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

        service = TranslatedMobileIDService.get_instance()

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
