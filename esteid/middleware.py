from django.utils.cache import patch_vary_headers

from . import config

class MultiHostMiddleware(object):
    def process_request(self, request):
        # Choose which subhost to use (if any):
        host = request.META["HTTP_HOST"]
        if host[-3:] == ":80":
            host = host[:-3] # ignore default port number, if present

        request.subhost_name = 'default'
        for host_name, host_config in config.get_hosts().items():
            if host.startswith(host_name) or host == host_config.get('hostname'):
                request.subhost_name = host_name
                request.urlconf = host_config.get('urlconf')

    def process_response(self, request, response):
        if getattr(request, "urlconf", None):
            patch_vary_headers(response, ('Host',))

        return response
