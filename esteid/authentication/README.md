# esteid authentication

The idea: have a clear, extensible API that is easy to integrate.

Solution: One view, [Pluggable authenticators](#pluggable-authenticator) (not 100% achievable, see below)

## Contents
* [Quickstart](#quickstart)
* [Testing](#testing-authentication-with-the-library)
* [Implementation details](#implementation-details)

## Quickstart

```python
# views.py - Pure Django
from django.views.generic import View
from esteid.authentication import AuthenticationViewDjangoMixin

class MyAuthView(AuthenticationViewDjangoMixin, View):
    pass

# Or: views.py - Rest Framework
from rest_framework.views import APIView
from esteid.authentication import AuthenticationViewRestMixin

class MyRestAuthView(AuthenticationViewRestMixin, APIView):
    def on_auth_success(self, request, data):
        request.session['username'] = f"{data.given_name} {data.surname}"

# urls.py
from django.urls.conf import path, re_path

from esteid.authentication import Authenticator
# Import all the necessary signers (a.k.a registration)
from esteid.idcard import BaseIdCardAuthenticationView
from esteid.mobileid import MobileIdAuthenticator
from esteid.smartid import SmartIdAuthenticator
from .views import MyAuthView


class MyIdCardAuthenticationView(BaseIdCardAuthenticationView):
    """A special view that handles ID Card authentication"""
    def on_auth_success(self, request, data):
        """For instance, save the authentication data to session"""
        request.session['username'] = f"{data.given_name} {data.surname}"
    

assert Authenticator.AUTHENTICATION_METHODS == {
    'mobileid': MobileIdAuthenticator,
    'smartid': SmartIdAuthenticator,
}

urlpatterns = [
    re_path(rf"^/authenticate/{method}/", 
            MyAuthView.as_view(authentication_method=method), 
            name=f"auth-{method}")
    for method in Authenticator.AUTHENTICATION_METHODS
]
urlpatterns += [
    path(rf"^/authenticate/idcard/", 
            MyAuthView.as_view(authentication_method=method), 
            name=f"auth-{method}")
    for method in Authenticator.AUTHENTICATION_METHODS
]
```

## Testing Authentication with the Library

To test SmartID and MobileID:

* Install, if necessary, and activate the library's virtualenv
* Start the server locally: `./manage.py runserver 8765`
* Open the [auth testing page](http://127.0.0.1:8765/new-auth/)

To test ID card authentication, please refer to the [ID Card test app](../../idcard_auth_test). 

## Implementation details

### Pluggable Authenticator

The outline of the flow implementation is the Dependency Inversion pattern: 
instead of the view explicitly calling an implementation, 
the view interacts with an Authenticator class, which loads a pluggable implementation
based on the method selected by user.

### ID Card Authentication specific notes

For ID Card, the authentication process is quite different from the SmartID/MobileID process.
REST API can not be used. 
See the corresponding [README](../idcard/README.md) for the details.
