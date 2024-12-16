import base64
import binascii
import logging
from typing import List

from oscrypto.asymmetric import Certificate as OsCryptoCertificate
from oscrypto.asymmetric import load_certificate

import pyasice

from esteid.exceptions import InvalidParameter, SignatureVerificationError
from esteid.signing import DataFile, Signer
from esteid.types import CertificateHolderInfo

from .. import settings


logger = logging.getLogger(__name__)


class IdCardSigner(Signer):
    certificate: bytes

    _certificate_handle: "OsCryptoCertificate"

    @property
    def id_code(self) -> str:
        try:
            certificate_handle = self._certificate_handle
        except AttributeError as e:
            if settings.ESTEID_ID_CARD_VERBOSE_ERRORS:
                logger.exception("Attribute id_code not available: certificate not provided")
            raise AttributeError("Attribute id_code not available: certificate not provided") from e

        cert_holder_info = CertificateHolderInfo.from_certificate(certificate_handle)
        return cert_holder_info.id_code

    @classmethod
    def _load_from_base64(self, data: str):
        try:
            certificate_bin = base64.b64decode(data)
        except binascii.Error:
            raise ValueError("Invalid base64 string") from e
        return load_certificate(certificate_bin)

    @classmethod
    def _load_from_hex(self, data: str):
        certificate_bin = bytes(bytearray.fromhex(data))
        return load_certificate(certificate_bin)

    def setup(self, initial_data: dict = None):
        """
        Receives a user certificate from the front end
        """
        try:
            certificate_hex = initial_data["certificate"]
        except (TypeError, KeyError) as e:
            if settings.ESTEID_ID_CARD_VERBOSE_ERRORS:
                logger.exception(
                    "Missing required parameter 'certificate'. Data: %r",
                    initial_data
                )
            raise InvalidParameter("Missing required parameter 'certificate'", param="certificate") from e

        try:
            self._certificate_handle = self._load_from_hex(certificate_hex)
        except ValueError:
            try:
                self._certificate_handle = self._load_from_base64(certificate_hex)
            except ValueError:
                if settings.ESTEID_ID_CARD_VERBOSE_ERRORS:
                    logger.exception(
                        "Failed to recognize `certificate` as a supported certificate format. "
                        "Certificate representation: %r",
                        certificate_hex,
                    )
                raise InvalidParameter(
                    "Failed to recognize `certificate` as a supported certificate format", param="certificate"
                ) from e

        self.certificate = self._certificate_handle.asn1.dump()

    def prepare(self, container: pyasice.Container = None, files: List[DataFile] = None) -> dict:
        container = self.open_container(container, files)
        xml_sig = container.prepare_signature(self.certificate)

        # Note: uses default digest algorithm (sha256)
        signed_digest = xml_sig.digest()

        self.save_session_data(digest=signed_digest, container=container, xml_sig=xml_sig)

        return {
            # hex-encoded digest to be consumed by the web-eid.js library
            "digest": base64.b64encode(signed_digest).decode("utf-8"),
        }

    def finalize(self, data: dict = None) -> pyasice.Container:
        try:
            signature_value = data["signature_value"]
        except (TypeError, KeyError) as e:
            if settings.ESTEID_ID_CARD_VERBOSE_ERRORS:
                logger.exception(
                    "Missing required parameter 'signature_value'. "
                    "Data: %r",
                    data,
                )
            raise InvalidParameter("Missing required parameter 'signature_value'", param="signature_value") from e

        try:
            signature_value = base64.b64decode(signature_value)
        except binascii.Error as e:
            if settings.ESTEID_ID_CARD_VERBOSE_ERRORS:
                logger.exception(
                    "Failed to decode parameter `signature_value` from DER encoding. "
                    "Signature value: %r",
                    signature_value,
                )
            raise InvalidParameter(
                "Failed to decode parameter `signature_value` from DER encoding", param="signature_value"
            ) from e

        temp_signature_file = self.session_data.temp_signature_file
        temp_container_file = self.session_data.temp_container_file
        digest = self.session_data.digest

        with open(temp_signature_file, "rb") as f:
            xml_sig = pyasice.XmlSignature(f.read())

        try:
            pyasice.verify(xml_sig.get_certificate_value(), signature_value, digest, prehashed=True)
        except pyasice.SignatureVerificationError as e:
            if settings.ESTEID_ID_CARD_VERBOSE_ERRORS:
                logger.exception(
                    "Signature verification error."
                )
            raise SignatureVerificationError from e

        container = pyasice.Container.open(temp_container_file)

        xml_sig.set_signature_value(signature_value)

        self.finalize_xml_signature(xml_sig)

        container.add_signature(xml_sig)

        return container
