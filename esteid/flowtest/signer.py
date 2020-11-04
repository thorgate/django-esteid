from typing import List

from pyasice import XmlSignature

from esteid.exceptions import InvalidParameter
from esteid.signing import Container, DataFile, Signer


class MySigner(Signer):
    def prepare(self, container_file=None, files: List[DataFile] = None) -> dict:
        container = self.open_container(container_file, files)
        xml_sig = XmlSignature.create()

        self.save_session_data(digest=b"test", container=container, xml_sig=xml_sig)

        return {"verification_code": "1234"}

    def finalize(self, data=None) -> Container:
        return Container.open(self.session_data.temp_container_file)


class MyPostSigner(MySigner):
    """
    Requires POST method parameters to init and finalize
    """

    def setup(self, initial_data: dict = None):
        try:
            initial_data["certificate"]
        except (TypeError, KeyError):
            raise InvalidParameter(param="certificate")

    def finalize(self, data=None) -> Container:
        try:
            data["signature_value"]
        except (TypeError, KeyError):
            raise InvalidParameter(param="signature_value")

        return super().finalize()
