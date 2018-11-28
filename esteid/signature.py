from Crypto.PublicKey import ECC
from Crypto.PublicKey import RSA
from Crypto.Signature import DSS, PKCS1_v1_5


class PrehashedMessageData(object):
    """
    Since ECC.verify expects an hash but mobile id does verification without hashing we need
     to use a Hashlib compatible wrapper class for our data
    """
    def __init__(self, data):
        super(PrehashedMessageData, self).__init__()

        self._data = data

    def update(self, data):
        self._data = data

    def digest(self):
        return self._data


def verify_mid_signature(certificate_data, sp_challenge, response_challenge, signature):
    """ Verify mobile id Authentication signature is valid

    :param certificate_data: binary certificate data, from 'CertificateData' field
    :param sp_challenge: binary challenge sent via 'SPChallenge' field
    :param response_challenge: response challenge, from 'Challenge' field
    :param signature: response signature
    :return:
    """

    if not response_challenge.startswith(sp_challenge):
        return False

    try:
        key = RSA.importKey(certificate_data)
        verifier = PKCS1_v1_5.new(key)

    except ValueError:
        key = ECC.import_key(certificate_data)
        verifier = DSS.new(key, 'deterministic-rfc6979')

    digest = PrehashedMessageData(response_challenge)

    try:
        verifier.verify(digest, signature)

        return True

    except ValueError:
        return False
