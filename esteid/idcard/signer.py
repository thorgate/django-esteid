import binascii
import logging
from typing import List

import pyasice

from esteid.exceptions import InvalidParameter, SignatureVerificationError
from esteid.signing import DataFile, Signer


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
            raise InvalidParameter("Missing required parameter 'certificate'", param="certificate") from e

        try:
            certificate = binascii.a2b_hex(certificate_hex)
        except (TypeError, ValueError) as e:
            raise InvalidParameter(
                "Failed to decode parameter `certificate` from hex-encoding", param="certificate"
            ) from e

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
            raise InvalidParameter("Missing required parameter 'signature_value'", param="signature_value") from e

        try:
            signature_value = binascii.a2b_hex(signature_value)
        except (TypeError, ValueError) as e:
            raise InvalidParameter(
                "Failed to decode parameter `signature_value` from hex-encoding", param="signature_value"
            ) from e

        temp_signature_file = self.session_data.temp_signature_file
        temp_container_file = self.session_data.temp_container_file
        digest = self.session_data.digest

        with open(temp_signature_file, "rb") as f:
            xml_sig = pyasice.XmlSignature(f.read())

        try:
            pyasice.verify(xml_sig.get_certificate_value(), signature_value, digest, prehashed=True)
        except pyasice.SignatureVerificationError as e:
            raise SignatureVerificationError from e

        container = pyasice.Container.open(temp_container_file)

        xml_sig.set_signature_value(signature_value)

        self.finalize_xml_signature(xml_sig)

        container.add_signature(xml_sig)

        return container
