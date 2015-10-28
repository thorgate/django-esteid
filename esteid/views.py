import base64
import re

from django.http import HttpResponse, HttpResponseRedirect
from django.utils.encoding import force_text, force_bytes
from django.views.generic import TemplateView, View

from .digidocservice.service import DataFile
from .generic import (MobileIdSignViewMixin, MobileIdStatusViewMixin, DigidocCompleteViewMixin, IdCardPrepareViewMixin,
                      IdCardFinishViewMixin)


class SKTestView(TemplateView):
    template_name = 'esteid/test.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        try:
            files = self.request.session['__ddoc_files']

        except KeyError:
            files = {}

        context.update({
            'files': files,
        })

        return context

    def post(self, request, *args, **kwargs):
        """ This method is only for testing and can
            be used to add some files to the session.

            actions:

                - add_file: Add another file
                - remove_file: Add another file
        """
        try:
            files = request.session['__ddoc_files']

        except KeyError:
            files = {}

        action = request.POST.get('action', 'add_file')

        if action == 'remove_file':
            file_name = request.POST.get('file_name', '')

            n_files = {}
            for key, file in files.items():
                if key != file_name:
                    n_files[key] = file

            files = n_files

        else:
            for key, file in request.FILES.items():
                file_name = file.name

                idx = 1
                while file_name in files.keys():
                    file_name = '%d_%s' % (idx, file_name)
                    idx += 1

                files[file_name] = dict(
                    content=force_text(base64.b64encode(file.read())),
                    content_type=file.content_type,
                    size=file.size,
                )

        request.session['__ddoc_files'] = files

        return HttpResponseRedirect('.')


class TestFilesMixin(object):
    def get_files(self):
        files = []

        for file_name, file in self.request.session['__ddoc_files'].items():
            files.append(
                DataFile(
                    file_name=file_name,
                    mimetype=file['content_type'],
                    content_type=None,
                    size=file['size'],
                    content=base64.b64decode(force_bytes(file['content'])),
                )
            )

        return files


class TestMobileIdSignView(TestFilesMixin, MobileIdSignViewMixin, View):
    def build_action_kwargs(self):
        return dict(
            id_code=self.request.POST.get('id_code', ''),
            phone_nr=self.request.POST.get('phone_nr', ''),
            language=self.request.POST.get('language', None),
        )


class TestMobileIdStatusView(TestFilesMixin, MobileIdStatusViewMixin, View):
    pass


class TestDownloadContainerView(TestFilesMixin, DigidocCompleteViewMixin, View):
    def get(self, request, *args, **kwargs):
        # Get the file data
        the_file = self.do_action(*args, **kwargs)

        # Destroy digidoc session
        self.destroy_digidoc_session()

        # Clear active files
        try:
            del request.session['__ddoc_files']

        except KeyError:
            pass

        # Download the file
        response = HttpResponse(the_file, content_type='application/vnd.bdoc-1.0')
        response['Content-Disposition'] = 'attachment; filename=' + 'signed.bdoc'
        return response


class TestIdCardSignView(TestFilesMixin, IdCardPrepareViewMixin, View):
    def build_action_kwargs(self):
        return {
            'certificate': self.request.POST.get('certificate', ''),
            'token_id': self.request.POST.get('token_id', ''),
        }


class TestIdCardFinishView(TestFilesMixin, IdCardFinishViewMixin, View):
    def build_action_kwargs(self):
        return {
            'signature_id': self.request.POST.get('signature_id', ''),
            'signature_value': self.request.POST.get('signature_value', ''),
        }


class AuthenticationView(TemplateView):
    template_name = 'esteid/authenticate.html'

    def __init__(self, *args, **kwargs):
        self.id_auth = None
        self.id_err = None

    def dispatch(self, request, *args, **kwargs):
        self.id_auth = getattr(request, 'id_auth', None)
        self.id_err = getattr(request, 'id_err', None)

        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        self.request.session['id_auth'] = self.id_auth
        context['id_auth'] = self.id_auth
        context['id_err'] = self.id_err

        return context
