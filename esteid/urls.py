import os

from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import TemplateView

import esteid.flowtest.urls


try:
    from django.urls import include, re_path
except ImportError:  # noqa
    from django.conf.urls import include, url as re_path

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
        re_path("^$", SKTestView.as_view(), name="sk_test"),
        # NOTE: compare the template test-new.html to test.html locally to see JS changes.
        re_path(r"^new/", SKTestView.as_view(template_name="esteid/test-new.html"), name="sk_test_new"),
        re_path(r"^new-auth/", TemplateView.as_view(template_name="esteid/auth-new.html"), name="sk_test_auth_new"),
        re_path(r"^download/", TestDownloadContainerView.as_view(), name="download_signed_container"),
        re_path(r"^id/start/", TestIdCardSignView.as_view(), name="test_id_start"),
        re_path(r"^id/finish/", TestIdCardFinishView.as_view(), name="test_id_finish"),
        re_path(r"^mid/start/", TestMobileIdSignView.as_view(), name="test_mid_start"),
        re_path(r"^mid/status/", TestMobileIdStatusView.as_view(), name="test_mid_status"),
        re_path(r"^smartid/start/", TestSmartIdSignView.as_view(), name="test_smartid_start"),
        re_path(r"^smartid/status/", TestSmartIdStatusView.as_view(), name="test_smartid_status"),
        re_path(r"^flowtest/", include(esteid.flowtest.urls)),
    ]

    urlpatterns += static(settings.STATIC_URL, document_root=os.path.dirname(__file__) + "/static/")
