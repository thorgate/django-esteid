import binascii
import logging
from typing import List

from django.conf import settings
from esteid_certificates import get_certificate

import pyasice

from esteid import constants
from esteid.signing import DataFile, Signer
from esteid.signing.exceptions import InvalidParameter


ESTEID_DEMO = getattr(settings, "ESTEID_DEMO", True)
ESTEID_USE_LT_TS = getattr(settings, "ESTEID_USE_LT_TS", True)

OCSP_URL = getattr(settings, "ESTEID_OCSP_URL", constants.OCSP_DEMO_URL if ESTEID_DEMO else constants.OCSP_LIVE_URL)
TSA_URL = getattr(settings, "ESTEID_TSA_URL", constants.TSA_DEMO_URL if ESTEID_DEMO else constants.TSA_LIVE_URL)


logger = logging.getLogger(__name__)


class IdCardSigner(Signer):
    certificate: bytes

    def setup(self, initial_data: dict = None):
        """
        Receives a user certificate from the front end
        """
        try:
            certificate_hex = initial_data["certificate"]
        except (TypeError, KeyError) as e:
            raise InvalidParameter("Missing required parameter 'certificate'") from e

        try:
            certificate = binascii.a2b_hex(certificate_hex)
        except (TypeError, ValueError) as e:
            raise InvalidParameter("Failed to decode parameter `certificate` from hex-encoding") from e

        self.certificate = certificate

    def prepare(self, container_file=None, files: List[DataFile] = None) -> dict:
        container = self.open_container(container_file, files)
        xml_sig = container.prepare_signature(self.certificate)

        # Note: uses default digest algorithm (sha256)
        signed_digest = xml_sig.digest()

        self.save_session_data(digest=signed_digest, container=container, xml_sig=xml_sig)

        return {
            # hex-encoded digest to be consumed by the hwcrypto.js library
            "digest": binascii.b2a_hex(signed_digest).decode(),
        }

    def finalize(self, data: dict = None) -> pyasice.Container:
        try:
            signature_value = data["signature_value"]
        except (TypeError, KeyError) as e:
            raise InvalidParameter("Missing required parameter 'signature_value'") from e

        try:
            signature_value = binascii.a2b_hex(signature_value)
        except (TypeError, ValueError) as e:
            raise InvalidParameter("Failed to decode parameter `signature_value` from hex-encoding") from e

        temp_signature_file = self.session_data.temp_signature_file
        temp_container_file = self.session_data.temp_container_file
        digest = self.session_data.digest

        with open(temp_signature_file, "rb") as f:
            xml_sig = pyasice.XmlSignature(f.read())

        pyasice.verify(xml_sig.get_certificate_value(), signature_value, digest, prehashed=True)

        container = pyasice.Container.open(temp_container_file)

        xml_sig.set_signature_value(signature_value)

        issuer_cert = get_certificate(xml_sig.get_certificate_issuer_common_name())

        try:
            pyasice.finalize_signature(xml_sig, issuer_cert, lt_ts=ESTEID_USE_LT_TS, ocsp_url=OCSP_URL, tsa_url=TSA_URL)
        except pyasice.Error:
            logger.exception("Signature confirmation service error")

        container.add_signature(xml_sig)

        return container
