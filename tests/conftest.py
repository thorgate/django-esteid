import os
import sys

from zeep import Transport
from zeep.cache import InMemoryCache

from esteid import config
from esteid.digidocservice.service import DigiDocService

BASE_DIR = os.path.dirname(__file__)

sys.path.append(os.path.join(BASE_DIR, '..'))


def get_random_file():
    return os.urandom(4096)


def get_digidoc_service():
    return DigiDocService(wsdl_url=config.wsdl_url(),
                          service_name='Testimine',
                          transport=Transport(cache=InMemoryCache()))
