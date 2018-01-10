import os

from django.conf import settings


def wsdl_url():
    """Url of the DigidocService wsdl

    Test: https://tsp.demo.sk.ee/dds.wsdl
    Live: https://digidocservice.sk.ee/dds.wsdl

    :return: str
    """
    return getattr(settings, 'DIGIDOC_SERVICE_WSDL_URL', 'https://tsp.demo.sk.ee/dds.wsdl')


def service_name():
    return getattr(settings, 'DIGIDOC_SERVICE_NAME', 'Testimine')


def mobile_message():
    return getattr(settings, 'DIGIDOC_SERVICE_MESSAGE', 'Testimine')


def get_hosts():
    return getattr(settings, 'HOSTS', {})


def ocsp_url():
    """OCSP server url

    Test: http://demo.sk.ee/ocsp
    Live: http://ocsp.sk.ee

    :return: str
    """
    return getattr(settings, 'ESTEID_OCSP_URL', 'http://demo.sk.ee/ocsp')


def ocsp_responder_certificate_path():
    """Get ocsp responder certificate path

    Test: TEST_of_SK_OCSP_RESPONDER_2011.pem
    Live: sk-ocsp-responder-certificates.pem

    Note: These files are distributed under esteid/certs

    :return:
    """
    certificate_path = getattr(settings, 'ESTEID_OCSP_RESPONDER_CERTIFICATE_PATH', 'TEST_of_SK_OCSP_RESPONDER_2011.pem')

    if certificate_path in ['TEST_of_SK_OCSP_RESPONDER_2011.pem', 'sk-ocsp-responder-certificates.pem']:
        return os.path.join(os.path.dirname(__file__), 'certs', certificate_path)

    return certificate_path
