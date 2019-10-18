# django-esteid

[![pypi Status](https://badge.fury.io/py/django-esteid.png)](https://badge.fury.io/py/django-esteid)
[![Build Status](https://travis-ci.org/thorgate/django-esteid.svg?branch=master)](https://travis-ci.org/thorgate/django-esteid)

Django-esteid is a package that provides Esteid based authentication for your Django applications.

## Quickstart

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

## SmartID

Detailed docs are [here](esteid/smartid/README.md).

**Note:***

Currently containers with a SmartID-generated signature are not compatible with MobiilID/ID-Card.
This means, such a signature is valid, but adding another signature to the same container
by means of MobiilID/ID-Card DigiDoc Service API will fail. 

This is the limitation of DigiDoc Service (which uses old versions of 
respective libraries) and can not be resolved except by moving to the new REST API for MobiilID. 

Adding a SmartID signature to a container with a previously generated SmartID signature, 
as well as a MobiilID/ID-Card generated one, works without restrictions.

(Same note is included in the [SmartID readme](esteid/smartid/README.md).)
