from django.conf.urls import url

from esteid.mobileid import MobileIdAuthenticator  # noqa
from esteid.signing import Signer
from esteid.smartid import SmartIdAuthenticator  # noqa

from .views import AuthTestRestView, AuthTestView, IDCardAuthTestView, SigningTestRestView, SigningTestView


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
    url(
        f"^authenticate/{auth_class.get_method_name()}/",
        AuthTestView.as_view(authenticator=auth_class),
        name=f"auth-{auth_class.get_method_name()}",
    )
    for auth_class in [MobileIdAuthenticator, SmartIdAuthenticator]
]

urlpatterns += [
    url(
        f"^authenticate-rest/{auth_class.get_method_name()}/",
        AuthTestRestView.as_view(authenticator=auth_class),
        name=f"auth-rest-{auth_class.get_method_name()}",
    )
    for auth_class in [MobileIdAuthenticator, SmartIdAuthenticator]
]

urlpatterns += [
    # See idcard/README.md as to why this view is special.
    url("^authenticate-id-card/", IDCardAuthTestView.as_view(), name="auth-idcard")
]
