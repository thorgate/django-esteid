# esteid authentication

The idea: have a clear, extensible API that is easy to integrate.

Solution: One view, [Pluggable authenticators](#pluggable-authenticator) (not 100% achievable, see below)

## Contents
* [Quickstart](#quickstart)
* [Testing](#testing-authentication-with-the-library)
* [Implementation details](#implementation-details)

## Quickstart

```python
# views_mixin.py
class MyAuthMixin:
    def on_auth_success(self, request, data):
        """For instance, save the authentication data to session"""
        request.session['username'] = f"{data.given_name} {data.surname}"


# views.py - Pure Django
from django.views.generic import View
from esteid.authentication import AuthenticationViewDjangoMixin

class MyAuthView(MyAuthMixin, AuthenticationViewDjangoMixin, View):
    pass

# Or: views.py - Rest Framework
from rest_framework.views import APIView
from esteid.authentication import AuthenticationViewRestMixin

class MyRestAuthView(MyAuthMixin, AuthenticationViewRestMixin, APIView):
    pass

# urls.py
from django.urls.conf import path, re_path

from esteid.idcard import BaseIdCardAuthenticationView
from esteid.mobileid import MobileIdAuthenticator
from esteid.smartid import SmartIdAuthenticator
from .views import MyAuthView


class MyIdCardAuthenticationView(MyAuthMixin, BaseIdCardAuthenticationView):
    """A special view that handles ID Card authentication"""
    
urlpatterns = [
    re_path(rf"^/authenticate/{auth_class.get_method_name()}/", 
            MyAuthView.as_view(authenticator=auth_class), 
            name=f"auth-{auth_class.get_method_name()}")
    for auth_class in [MobileIdAuthenticator, SmartIdAuthenticator]
]
urlpatterns += [
    path(rf"^/authenticate/id-card/", MyAuthView.as_view(), name=f"auth-idcard")
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
