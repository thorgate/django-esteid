#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys

import esteid

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

version = esteid.__version__

if sys.argv[-1] == 'publish':
    os.system('python setup.py sdist upload')
    print("You probably want to also tag the version now:")
    print("  git tag -a %s -m 'version %s'" % (version, version))
    print("  git push --tags")
    sys.exit()

readme = open('README.md').read()

setup(
    name='django-esteid',
    version=version,
    description="""Django-esteid is a package that provides Esteid based authentication for your Django applications.""",
    long_description=readme,
    author='Thorgate',
    author_email='jyrno@thorgate.eu',
    url='https://github.com/thorgate/django-esteid',
    packages=[
        'esteid',
    ],
    include_package_data=True,
    install_requires=[
        'lxml>=3.4',
        'suds-jurko==0.6'
    ],
    license="BSD",
    zip_safe=False,
    keywords='esteid django',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
    ],
)
