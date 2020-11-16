import logging
from typing import List, Optional

import pyasice
from pyasice import Container, XmlSignature

from esteid.exceptions import ActionInProgress, InvalidIdCode, InvalidParameters
from esteid.signing import DataFile, Signer
from esteid.signing.types import InterimSessionData, PredictableDict

from .base import validate_id_code
from .constants import Countries
from .i18n import TranslatedSmartIDService


logger = logging.getLogger(__name__)


class UserInput(PredictableDict):
    id_code: str
    country: Optional[str]

    def is_valid(self, raise_exception=True):
        """
        Raises InvalidIdCode or ValueError
        """
        result = super().is_valid(raise_exception=raise_exception)
        if result:
            if not (self.get("country") and self.country in Countries.ALL):
                self.country = Countries.ESTONIA

            validate_id_code(self.id_code, self.country)

        return result


class SmartIdSessionData(InterimSessionData):
    session_id: str


class SmartIdSigner(Signer):
    id_code: str
    country: str

    SessionData = SmartIdSessionData
    session_data: SmartIdSessionData

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

    def prepare(self, container: Container = None, files: List[DataFile] = None) -> dict:
        container = self.open_container(container, files)

        service = TranslatedSmartIDService.get_instance()

        certificate, document_number = service.select_signing_certificate(self.id_code, self.country)

        xml_sig = container.prepare_signature(certificate)

        sign_session = service.sign_by_document_number(document_number, xml_sig.signed_data())

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
            xml_sig = pyasice.XmlSignature(f.read())

        service = TranslatedSmartIDService.get_instance()

        try:
            status = service.sign_status(session_id, digest)
        except ActionInProgress:
            # Just to be explicit about the InProgress status
            raise

        container = pyasice.Container.open(temp_container_file)

        xml_sig.set_signature_value(status.signature)

        self.finalize_xml_signature(xml_sig)

        container.add_signature(xml_sig)

        return container

    def save_session_data(self, *, digest: bytes, container: Container, xml_sig: XmlSignature, session_id: str):
        data_obj = self.session_data
        data_obj.session_id = session_id

        super().save_session_data(digest=digest, container=container, xml_sig=xml_sig)
