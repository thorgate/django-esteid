import uuid

import pytest

from esteid.base_service import BaseSKService
from esteid.exceptions import EsteidError


def test_base_service_accepts_parameters():
    rp_uuid = uuid.uuid4()
    assert BaseSKService(rp_uuid, "name", "url").rp_uuid == str(rp_uuid)
    assert BaseSKService(str(rp_uuid), "name", "url").rp_uuid == str(rp_uuid)

    with pytest.raises(EsteidError, match="valid UUID"):
        BaseSKService("not uuid", "name", "url")
