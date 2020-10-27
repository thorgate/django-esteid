import os

from django.conf import settings
from django.conf.urls import include, url
from django.conf.urls.static import static

import esteid.flowtest.urls

from .views import (
    SKTestView,
    TestDownloadContainerView,
    TestIdCardFinishView,
    TestIdCardSignView,
    TestMobileIdSignView,
    TestMobileIdStatusView,
    TestSmartIdSignView,
    TestSmartIdStatusView,
)


urlpatterns = []

# In a project, the URLs can be included if settings.DEBUG is on.
# In tests, settings.DEBUG is False for unknown reasons, so we check that the root urlconf points at this file.
if settings.DEBUG or settings.ROOT_URLCONF == __name__:
    urlpatterns += [
        url("^$", SKTestView.as_view(), name="sk_test"),
        # NOTE: compare the template test-new.html to test.html locally to see JS changes.
        url(r"^new/", SKTestView.as_view(template_name="esteid/test-new.html"), name="sk_test_new"),
        url(r"^download/", TestDownloadContainerView.as_view(), name="download_signed_container"),
        url(r"^id/start/", TestIdCardSignView.as_view(), name="test_id_start"),
        url(r"^id/finish/", TestIdCardFinishView.as_view(), name="test_id_finish"),
        url(r"^mid/start/", TestMobileIdSignView.as_view(), name="test_mid_start"),
        url(r"^mid/status/", TestMobileIdStatusView.as_view(), name="test_mid_status"),
        url(r"^smartid/start/", TestSmartIdSignView.as_view(), name="test_smartid_start"),
        url(r"^smartid/status/", TestSmartIdStatusView.as_view(), name="test_smartid_status"),
        url(r"^flowtest/", include(esteid.flowtest.urls)),
    ]

    urlpatterns += static(settings.STATIC_URL, document_root=os.path.dirname(__file__) + "/static/")
