import base64
import hashlib
from unittest.mock import patch

import pytest
from Crypto.Math.Numbers import Integer
from Crypto.Util.asn1 import DerSequence
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import load_der_x509_certificate

from ..signature_verifier import verify_cryptography


def der_to_x962(signature):
    der_seq = DerSequence().decode(signature, strict=True)
    r_prime, s_prime = Integer(der_seq[0]), Integer(der_seq[1])
    buf = []
    for num in (s_prime, r_prime):
        for _ in range(66):  # each prime should be exactly 66 bytes for the 521-bit EC
            lowest_byte = num & 0xFF
            buf.append(int(lowest_byte))
            num >>= 8
    return bytes(reversed(buf))


@pytest.fixture()
def signed_data():
    return b'Just some data to sign'


@pytest.fixture()
def private_key_ec():
    return ec.generate_private_key(
        ec.SECP521R1(),
        default_backend()
    )


@pytest.fixture()
def certificate_ec(private_key_ec):
    """
    Can also build a real certificate:
    https://cryptography.io/en/latest/x509/reference/#x-509-certificate-builder

    :param private_key_ec:
    :return:
    """
    cert_b64 = """
    MIIGLzCCBBegAwIBAgIQHFA4RWeWjGFbbE2rV10IxzANBgkqhkiG9w0BAQsFADBrMQswCQYDVQQGEwJF
    RTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEXMBUGA1UEYQwOTlRSRUUtMTA3NDcw
    MTMxHzAdBgNVBAMMFlRFU1Qgb2YgRVNURUlELVNLIDIwMTUwHhcNMTgwODA5MTQyMDI3WhcNMjIxMjEx
    MjE1OTU5WjCB1TELMAkGA1UEBhMCRUUxGzAZBgNVBAoMEkVTVEVJRCAoTU9CSUlMLUlEKTEXMBUGA1UE
    CwwOYXV0aGVudGljYXRpb24xPTA7BgNVBAMMNE/igJlDT05ORcW9LcWgVVNMSUsgVEVTVE5VTUJFUixN
    QVJZIMOETk4sNjAwMDEwMTk5MDYxJzAlBgNVBAQMHk/igJlDT05ORcW9LcWgVVNMSUsgVEVTVE5VTUJF
    UjESMBAGA1UEKgwJTUFSWSDDhE5OMRQwEgYDVQQFEws2MDAwMTAxOTkwNjBZMBMGByqGSM49AgEGCCqG
    SM49AwEHA0IABHYleZg39CkgQGU8z8b8ehctBEnaGlducij6eTETeOj2LpEwLedMS1pCfNEZAJjDwAZ2
    DJMBgB05QHrrvzersUKjggItMIICKTAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDB0BgNVHSAEbTBr
    MF8GCisGAQQBzh8DAQMwUTAvBggrBgEFBQcCARYjaHR0cHM6Ly93d3cuc2suZWUvcmVwb3NpdG9vcml1
    bS9DUFMwHgYIKwYBBQUHAgIwEhoQT25seSBmb3IgVEVTVElORzAIBgYEAI96AQIwNwYDVR0RBDAwLoEs
    bWFyeS5hbm4uby5jb25uZXotc3VzbGlrLnRlc3RudW1iZXJAZWVzdGkuZWUwHQYDVR0OBBYEFJ3eqIvc
    J/uIUPi7T7xHWlzOZM/oMB8GA1UdIwQYMBaAFEnA8kQ5ZdWbRjsNOGCDsdYtKIamMIGDBggrBgEFBQcB
    AQR3MHUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE1MEUGCCsGAQUF
    BzAChjlodHRwczovL3NrLmVlL3VwbG9hZC9maWxlcy9URVNUX29mX0VTVEVJRC1TS18yMDE1LmRlci5j
    cnQwYQYIKwYBBQUHAQMEVTBTMFEGBgQAjkYBBTBHMEUWP2h0dHBzOi8vc2suZWUvZW4vcmVwb3NpdG9y
    eS9jb25kaXRpb25zLWZvci11c2Utb2YtY2VydGlmaWNhdGVzLxMCRU4wNAYDVR0fBC0wKzApoCegJYYj
    aHR0cHM6Ly9jLnNrLmVlL3Rlc3RfZXN0ZWlkMjAxNS5jcmwwDQYJKoZIhvcNAQELBQADggIBAETuCyUS
    VOJip0hqcodC3v9FAg7JTH1zUEmkfwuETv96TFG9kD+BE61DN9PMQSwVmHEKJarklCtPwlj2z279Zv2X
    qNR0akjI+mpBbmkl8FGz+sC9MpDaeCM+fpo3+vsu/YLVwTtrmeJsVPBI5b56sgXvL8EJ++Nt/F0Uq4i+
    UUsIhZAcek7XD2G6tUF8vYj7BcSgd7MhxE1GwVnDBitE29TWNCEJGAE4a3LyRqj6ZUdm06Y4+duCBV4w
    +io57LT9qF64oz0RLz+HyErRsHk+70b/+uASTYitZVNVav+fvo5z6gcG4vzZHIQ5lYlzt4/UgV/dud23
    00+n6XzDxazW9aYhdDQUGbHlV2p/O/o9azh0qdikThJObvmHlJH4Ym1+yScUFcGHBn4ERDOVdd2gUf2f
    WVWCbC8M+GhYEY7g+Uq+X8lBlcT69ZEJlZmg5OXfxjL+d+770YIJR5Tpd9xSTxbVEdXo1o04riI1x+P8
    yQ+rr5ZHd9528WHfLI2rvnVmF5ZIcMapsNALZf0q8IAizIS5XYVEpAKT2rfLS2L+eWIxh5M7rszg1rC1
    9WeLQdSX1vMCQT7C/UxGQOz1em0F4xfk3wxCShrInMA4NJnazzST/6pOrPw3cgov35Eo58izraw/YAIm
    iXBCEqA8GcszbnYgdB6A+dMgUh8sAeA/dXrl
    """
    cert = load_der_x509_certificate(base64.b64decode(cert_b64), default_backend())

    with patch.object(cert, 'public_key') as fake_public_key:
        fake_public_key.return_value = private_key_ec.public_key()
        yield cert


def test_verify_data(private_key_ec, certificate_ec, signed_data):
    signature = private_key_ec.sign(signed_data, ec.ECDSA(hashes.SHA256()))

    assert certificate_ec.public_key().public_numbers() == private_key_ec.public_key().public_numbers()

    private_key_ec.public_key().verify(signature, signed_data, ec.ECDSA(hashes.SHA256()))

    verify_cryptography(certificate_ec, der_to_x962(signature), signed_data)
    assert "No exception was raised by the previous call"


def test_verify_hash(private_key_ec, certificate_ec, signed_data):
    signature = private_key_ec.sign(signed_data, ec.ECDSA(hashes.SHA256()))

    assert certificate_ec.public_key().public_numbers() == private_key_ec.public_key().public_numbers()

    private_key_ec.public_key().verify(signature, signed_data, ec.ECDSA(hashes.SHA256()))

    prehash = hashlib.sha256(signed_data).digest()

    verify_cryptography(certificate_ec, der_to_x962(signature), prehash, prehashed=True)
    assert "No exception was raised by the previous call"
