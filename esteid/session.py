import os
from typing import List

from pyasice import Container

from esteid.types import DataFile


SESSION_KEY = "__esteid_session"


class EsteidSessionError(Exception):
    pass


def get_esteid_session(request):
    return request.session.get(SESSION_KEY, {})


def start_esteid_session(request):
    delete_esteid_session(request)
    return {}


def update_esteid_session(request, **kwargs):
    session = request.session
    data = session.get(SESSION_KEY, {})
    data.update(kwargs)
    session[SESSION_KEY] = data  # Django session object requires setting keys explicitly


def delete_esteid_session(request):
    session_data = request.session.pop(SESSION_KEY, {})

    temp_signature_file = session_data.get("temp_signature_file")
    if temp_signature_file:
        try:
            os.unlink(temp_signature_file)
        except OSError:
            pass

    temp_container_file = session_data.get("temp_container_file")
    if temp_container_file:
        try:
            os.unlink(temp_container_file)
        except OSError:
            pass


def open_container(container_path: str = None, files_to_sign: List[DataFile] = None):
    """Open an existing BDoc container, or create a container with files to sign"""
    if container_path:
        # Take files from an existing container, ignore files_to_sign
        container = Container.open(container_path)
    elif files_to_sign:
        container = Container()
        for data_file in files_to_sign:
            container.add_file(data_file.file_name, data_file.content, data_file.mimetype)
    else:
        raise ValueError("No files to sign")  # this is a 500 error because it's not the user's fault

    return container
