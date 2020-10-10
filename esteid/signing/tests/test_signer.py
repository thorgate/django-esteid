from unittest.mock import patch

import pytest

from esteid.signing import Signer
from esteid.signing.exceptions import SigningError


@patch.object(Signer, "SIGNING_METHODS", {})
def test_signer_register_subclass():
    def create_signer():
        class TestSigner(Signer):
            pass

        return TestSigner

    signer_class = create_signer()

    assert Signer.SIGNING_METHODS == {"test": signer_class}

    with pytest.raises(AssertionError):
        create_signer()


@patch.object(Signer, "SIGNING_METHODS", {})
def test_signer_select():
    class MySigner(Signer):
        pass

    assert Signer.select_signer("my") is MySigner
    with pytest.raises(SigningError):
        Signer.select_signer("nonexistent")
