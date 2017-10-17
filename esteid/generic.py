from . import config
from .actions import (IdCardPrepareAction, IdCardFinishAction, SignCompleteAction, MobileIdSignAction,
                      MobileIdStatusAction, BaseAction, MobileIdAuthenticateAction,
                      MobileIdAuthenticateStatusAction)
from .digidocservice.service import DigiDocService, DigiDocError
from .response import JSONResponse


class GenericDigitalSignViewMixin(object):
    autostart_digidoc_session = True

    DIGIDOC_SESSION_KEY = '__ddoc_session'
    DIGIDOC_SESSION_DATA_KEY = '__ddoc_session_data'

    def get_files(self):
        """ This should be implemented on view level, and should return a list
            of files that should be digitally signed
        """
        return []

    def set_digidoc_session(self, session_code):
        """ Stores the new session token so it is remembered across requests.

        """
        self.request.session[self.DIGIDOC_SESSION_KEY] = session_code

    def set_digidoc_session_data(self, key, value):
        session_data = self.request.session.get(self.DIGIDOC_SESSION_DATA_KEY, {})
        session_data.update({key: value})

        self.request.session[self.DIGIDOC_SESSION_DATA_KEY] = session_data

    def get_digidoc_session_data(self, key):
        session_data = self.request.session.get(self.DIGIDOC_SESSION_DATA_KEY, {})

        return session_data.get(key, None)

    def get_digidoc_session(self):
        """ This method returns the active digidoc session
            associated with the active request.

            DigiDocService session is stored in request.session[I{DIGIDOC_SESSION_KEY}]
        """

        return self.request.session.get(self.DIGIDOC_SESSION_KEY)

    def destroy_digidoc_session(self):
        """ Closes DigiDocService session and clears request.session[I{DIGIDOC_SESSION_KEY}]
        """

        # cleanup data too
        self.destroy_digidoc_session_data()

        try:
            session = self.request.session[self.DIGIDOC_SESSION_KEY]

            if session:
                try:
                    service = self.flat_service()
                    service.session_code = session
                    service.close_session()

                except DigiDocError:
                    pass

            del self.request.session[self.DIGIDOC_SESSION_KEY]

        except KeyError:
            pass

    def destroy_digidoc_session_data(self):
        # Ensure hanging references to the data are cleared and then remove it from session
        self.request.session.get(self.DIGIDOC_SESSION_DATA_KEY, {}).clear()
        self.request.session.pop(self.DIGIDOC_SESSION_DATA_KEY, {})

    def flat_service(self):
        return DigiDocService(
            wsdl_url=config.wsdl_url(),
            service_name=config.service_name(),
            mobile_message=config.mobile_message(),
        )

    def start_session_kwargs(self):
        return {
            'b_hold_session': True,
        }

    def get_service(self):
        if hasattr(self, 'stored_service'):
            return self.stored_service

        service = self.flat_service()
        session = self.get_digidoc_session()

        if session:
            service.session_code = session

        else:
            if self.autostart_digidoc_session:
                if service.start_session(**self.start_session_kwargs()):
                    # Clear session data to avoid data leakage
                    self.destroy_digidoc_session_data()

                    # Store the new session identifier
                    self.set_digidoc_session(service.session_code)

        setattr(self, 'stored_service', service)
        return service


class BaseMobileIdAuthenticateViewMixin(GenericDigitalSignViewMixin):
    # MobileAuthenticate starts session automatically and does not accept Sesscode
    autostart_digidoc_session = False


class BaseDigitalSignViewMixin(GenericDigitalSignViewMixin):
    CATCH_POST = True
    ACTION_CLASS = None

    def post(self, request, *args, **kwargs):
        if self.CATCH_POST:
            return JSONResponse(self.do_action(*args, **kwargs))

        return super(BaseDigitalSignViewMixin, self).post(request, *args, **kwargs)

    def build_action_kwargs(self):
        return {}

    def do_action(self, *args, **kwargs):
        if not self.ACTION_CLASS or not issubclass(self.ACTION_CLASS, BaseAction):
            raise NotImplementedError

        return self.ACTION_CLASS.do_action(self, action_kwargs=self.build_action_kwargs())


class IdCardPrepareViewMixin(BaseDigitalSignViewMixin):
    ACTION_CLASS = IdCardPrepareAction


class IdCardFinishViewMixin(BaseDigitalSignViewMixin):
    ACTION_CLASS = IdCardFinishAction


class DigidocCompleteViewMixin(BaseDigitalSignViewMixin):
    """ This action gets the signed document from this DigiDocService session
        and then closes it. It's up to the user what he/she wants to do with it.
    """
    CATCH_POST = False
    ACTION_CLASS = SignCompleteAction


class MobileIdSignViewMixin(BaseDigitalSignViewMixin):
    ACTION_CLASS = MobileIdSignAction


class MobileIdStatusViewMixin(BaseDigitalSignViewMixin):
    ACTION_CLASS = MobileIdStatusAction


class MobileIdAuthenticateViewMixin(BaseDigitalSignViewMixin, BaseMobileIdAuthenticateViewMixin):
    ACTION_CLASS = MobileIdAuthenticateAction


class MobileIdAuthenticateStatusViewMixin(BaseDigitalSignViewMixin):
    ACTION_CLASS = MobileIdAuthenticateStatusAction
