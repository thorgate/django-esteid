from django.conf import settings


def client_type():
    return getattr(settings, 'DIGIDOC_SERVICE_HOST', 'TEST')

def service_name():
    return getattr(settings, 'DIGIDOC_SERVICE_NAME', 'Testimine')

def mobile_message():
    return getattr(settings, 'DIGIDOC_SERVICE_MESSAGE', 'Testimine')

def get_hosts():
    return getattr(settings, 'HOSTS', {})
