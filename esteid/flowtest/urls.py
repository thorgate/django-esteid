from django.conf.urls import url

from esteid.authentication import Authenticator
from esteid.mobileid import MobileIdAuthenticator  # noqa
from esteid.signing import Signer
from esteid.smartid import SmartIdAuthenticator  # noqa

from .views import AuthTestRestView, AuthTestView, SigningTestRestView, SigningTestView


# Signing

urlpatterns = [
    url(f"^sign/{method}/", SigningTestView.as_view(signing_method=method), name=f"sign-{method}")
    for method in Signer.SIGNING_METHODS
]

urlpatterns += [
    url(f"^sign-rest/{method}/", SigningTestRestView.as_view(signing_method=method), name=f"sign-rest-{method}")
    for method in Signer.SIGNING_METHODS
]

# Authentication

urlpatterns += [
    url(f"^authenticate/{method}/", AuthTestView.as_view(authentication_method=method), name=f"auth-{method}")
    for method in Authenticator.AUTHENTICATION_METHODS
]

urlpatterns += [
    url(
        f"^authenticate-rest/{method}/",
        AuthTestRestView.as_view(authentication_method=method),
        name=f"auth-rest-{method}",
    )
    for method in Authenticator.AUTHENTICATION_METHODS
]
