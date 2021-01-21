# esteid authentication

The idea: have a clear, extensible API that is easy to integrate.

Solution: One view, [Pluggable authenticators](#pluggable-authenticator)

## Contents
* [Quickstart](#quickstart)
* [Integration with projects](#integration-with-projects)
  * [Error handling and logging](#error-handling-and-logging)
  * [File types](#file-types)
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
    def on_auth_complete(self, request, data):
        request.session.username = f"{data.given_name} {data.surname}"

# urls.py
from django.urls.conf import re_path

from esteid.authentication import Authenticator
# Import all the necessary signers (a.k.a registration)
from esteid.idcard import IdCardAuthenticator
from esteid.mobileid import MobileIdAuthenticator
from esteid.smartid import SmartIdAuthenticator
from .views import MyAuthView


assert Authenticator.AUTHENTICATION_METHODS == {
    'idcard': IdCardAuthenticator,
    'mobileid': MobileIdAuthenticator,
    'smartid': SmartIdAuthenticator,
}

urlpatterns = [
    re_path(rf"^/authenticate/{method}/", 
            MyAuthView.as_view(authentication_method=method), 
            name=f"auth-{method}")
    for method in Authenticator.AUTHENTICATION_METHODS
]
```

### Error handling and logging

All exceptions that happen during authentication are handled by the view mixin's method `handle_errors()`.


## Implementation details

### Pluggable Authenticator

The outline of the flow implementation is the Dependency Inversion pattern: 
instead of the view explicitly calling an implementation, 
the view interacts with an Authenticator class, which loads a pluggable implementation
based on the method selected by user.

### Authentication method-specific notes

For ID Card, the authentication process does not require calling any external services. Therefore, 
the whole authentication flow consists of a single request and an immediate response.
