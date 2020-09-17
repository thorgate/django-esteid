import os

from django.conf import settings
from django.conf.urls import url
from django.conf.urls.static import static
from django.urls.conf import path

from .views import (
    SKTestView,
    TestDownloadContainerView,
    TestIdCardFinishView,
    TestIdCardSignView,
    TestMobileIdSignView,
    TestMobileIdStatusView,
)


urlpatterns = []

if settings.DEBUG:
    urlpatterns += [
        path("", SKTestView.as_view(), name="sk_test"),
        url(r"^id/start/", TestIdCardSignView.as_view(), name="test_id_start"),
        url(r"^id/finish/", TestIdCardFinishView.as_view(), name="test_id_finish"),
        url(r"^id/done/", TestDownloadContainerView.as_view(), name="test_id_finalize"),
        url(r"^mid/start/", TestMobileIdSignView.as_view(), name="test_mid_start"),
        url(r"^mid/status/", TestMobileIdStatusView.as_view(), name="test_mid_status"),
        url(r"^mid/done/", TestDownloadContainerView.as_view(), name="test_mid_finalize"),
    ]

    urlpatterns += static(settings.STATIC_URL, document_root=os.path.dirname(__file__) + "/static/")
