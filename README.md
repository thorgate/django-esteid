# django-esteid

[![pypi Status](https://badge.fury.io/py/django-esteid.png)](https://badge.fury.io/py/django-esteid)
[![Build Status](https://travis-ci.org/thorgate/django-esteid.svg?branch=master)](https://travis-ci.org/thorgate/django-esteid)

Django-esteid is a package that provides Esteid based authentication for your Django applications.

Quickstart
----------

Install Django esteid:

    pip install django-esteid

Add django-esteid to installed apps:

    INSTALLED_APPS = [
        # ...
        'esteid',
        # ...
    ]

Then use it in a project:

    import esteid

Requirements
------------

This package requires libzip to be installed on the machine. This is needed because we are using it through ctypes
for BDOC format writing. Using the native zip implementation that python provides, proved to be quite difficult
since DigiDocService did not accept that file as a valid BDOC.
