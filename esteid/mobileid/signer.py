import logging
import re
from typing import List, Optional

from pyasice import Container, XmlSignature

from esteid import settings
from esteid.constants import Languages
from esteid.exceptions import ActionInProgress, InvalidIdCode, InvalidParameter, InvalidParameters
from esteid.signing import DataFile, Signer
from esteid.signing.types import InterimSessionData, PredictableDict

from ..util import id_code_ee_is_valid
from .i18n import TranslatedMobileIDService


logger = logging.getLogger(__name__)


PHONE_NUMBER_REGEXP = re.compile(r"^\+37[02]\d{7,8}$")  # Mobile ID supports Estonian and Lithuanian phones


class UserInput(PredictableDict):
    phone_number: str
    id_code: str
    language: Optional[str]

    def is_valid(self, raise_exception=True):
        result = super().is_valid(raise_exception=raise_exception)
        if result:
            if not (self.phone_number and re.match(PHONE_NUMBER_REGEXP, self.phone_number)):
                raise InvalidParameter(param="phone_number")
            if not id_code_ee_is_valid(self.id_code):
                raise InvalidIdCode
            if not (self.get("language") and self.language in Languages.ALL):
                self.language = settings.MOBILE_ID_DEFAULT_LANGUAGE
        return result


class MobileIdSessionData(InterimSessionData):
    session_id: str


class MobileIdSigner(Signer):
    phone_number: str
    id_code: str
    language: str

    SessionData = MobileIdSessionData
    session_data: MobileIdSessionData

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

    def prepare(self, container=None, files: List[DataFile] = None) -> dict:
        container = self.open_container(container, files)

        service = TranslatedMobileIDService.get_instance()

        certificate = service.get_certificate(self.id_code, self.phone_number)

        xml_sig = container.prepare_signature(certificate)

        sign_session = service.sign(self.id_code, self.phone_number, xml_sig.signed_data(), language=self.language)

        self.save_session_data(
            digest=sign_session.digest,
            container=container,
            xml_sig=xml_sig,
            session_id=sign_session.session_id,
        )

        return {
            "verification_code": sign_session.verification_code,
        }

    def finalize(self, data: dict = None) -> Container:
        digest = self.session_data.digest
        session_id = self.session_data.session_id

        temp_signature_file = self.session_data.temp_signature_file
        temp_container_file = self.session_data.temp_container_file

        with open(temp_signature_file, "rb") as f:
            xml_sig = XmlSignature(f.read())

        service = TranslatedMobileIDService.get_instance()

        try:
            status = service.sign_status(session_id, xml_sig.get_certificate_value(), digest)
        except ActionInProgress:
            # Just to be explicit about the InProgress status
            raise

        xml_sig.set_signature_value(status.signature)

        self.finalize_xml_signature(xml_sig)

        container = Container.open(temp_container_file)
        container.add_signature(xml_sig)

        return container

    def save_session_data(self, *, digest: bytes, container: Container, xml_sig: XmlSignature, session_id: str):
        data_obj = self.session_data
        data_obj.session_id = session_id

        super().save_session_data(digest=digest, container=container, xml_sig=xml_sig)
