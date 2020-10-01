from Crypto.Util.asn1 import DerSequence
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.x509 import Certificate, load_der_x509_certificate

from Crypto import Hash
from Crypto.Math.Numbers import Integer
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS, PKCS1_v1_5


from .exceptions import BDoc2Error


class SignatureVerificationError(BDoc2Error):
    pass


class InvalidSignatureAlgorithm(SignatureVerificationError):
    pass


def x962_to_der(signature):
    """
    Convert binary signature (X9.62 format) into a DER encoded one
    """
    num_length = len(signature) // 2
    r_prime, s_prime = [
        Integer.from_bytes(x)
        for x in (signature[:num_length], signature[num_length:])
    ]

    return DerSequence([r_prime, s_prime]).encode()


def verify_cryptodome(certificate, signature, data, hash_algo='SHA256'):
    """Verify RSA and EC signatures with the pycryptodome library (DEPRECATED)

    :param bytes certificate: DER-encoded certificate
    :param bytes signature:
    :param bytes data: the original signed data
    :param hash_algo:
    :return:
    """
    hash_algo = hash_algo.upper()
    if hash_algo not in ('SHA256', 'SHA384', 'SHA512'):
        raise InvalidSignatureAlgorithm(hash_algo)

    try:
        # old versions of pycryptodome (~ 3.7)
        hasher = getattr(Hash, hash_algo)
    except AttributeError:
        # Newer versions of pycryptodome (3.9) implement algorithms as modules
        m = __import__('Crypto.Hash', None, None, fromlist=[hash_algo])
        hasher = getattr(m, hash_algo)

    digest = hasher.new(data)

    try:
        key = RSA.import_key(certificate)
        verifier = PKCS1_v1_5.new(key)

    except ValueError:
        key = ECC.import_key(certificate)
        verifier = DSS.new(key, 'deterministic-rfc6979')
        try:
            # returns False on SUCCESS
            verifier.verify(digest, signature)
        except ValueError:  # YES, ValueError
            raise SignatureVerificationError()

    else:
        # And here, wow, it just returns true/false
        if not verifier.verify(digest, signature):
            raise SignatureVerificationError()


def verify_cryptography(certificate, signature, data, hash_algo='SHA256', prehashed=False):
    """Verify RSA and EC signatures with the cryptography library

    :param Union[bytes, Certificate] certificate:
    :param bytes signature:
    :param bytes data: the original signed data, or its hash
    :param hash_algo:
    :param prehashed: True if `data` is a hash of original signed data instead
    :return:
    """
    if not isinstance(certificate, Certificate):
        certificate = load_der_x509_certificate(certificate, default_backend())

    hash_algo = hash_algo.upper()
    if hash_algo not in ('SHA256', 'SHA384', 'SHA512'):
        raise InvalidSignatureAlgorithm(hash_algo)

    hasher = getattr(hashes, hash_algo)
    chosen_hash = hasher()
    if prehashed:
        chosen_hash = Prehashed(chosen_hash)

    public_key = certificate.public_key()

    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                x962_to_der(signature),
                data,
                ec.ECDSA(chosen_hash)
            )
        else:
            public_key.verify(
                signature,
                data,
                padding.PKCS1v15(),
                chosen_hash
            )
    except InvalidSignature:
        raise SignatureVerificationError()


verify = verify_cryptography