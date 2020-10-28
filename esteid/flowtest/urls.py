from django.conf.urls import url

from esteid.signing import Signer

from .views import SigningTestRestView, SigningTestView


urlpatterns = [
    url(f"^sign/{method}/", SigningTestView.as_view(signing_method=method), name=f"sign-{method}")
    for method in Signer.SIGNING_METHODS
]

urlpatterns += [
    url(f"^sign-rest/{method}/", SigningTestRestView.as_view(signing_method=method), name=f"sign-rest-{method}")
    for method in Signer.SIGNING_METHODS
]
