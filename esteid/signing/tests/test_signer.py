from unittest.mock import patch

import pytest

from esteid.exceptions import EsteidError
from esteid.signing import Signer


@patch.object(Signer, "SIGNING_METHODS", {})
def test_signer_register_subclass():
    def create_signer():
        class TestSigner(Signer):
            pass

        return TestSigner

    signer_class = create_signer()

    assert Signer.SIGNING_METHODS == {"test": signer_class}

    # Asserts that the signer class has not been registered yet, which is not true
    with pytest.raises(AssertionError):
        create_signer()


@patch.object(Signer, "SIGNING_METHODS", {})
def test_signer_select():
    class MySigner(Signer):
        pass

    assert Signer.select_signer("my") is MySigner
    with pytest.raises(EsteidError):
        Signer.select_signer("nonexistent")
