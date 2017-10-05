.PHONY: help clean clean-build clean-pyc lint test test-all test-full coverage

help:
	@echo "clean-build - remove build artifacts"
	@echo "clean-pyc - remove Python file artifacts"
	@echo "lint - check style with flake8"
	@echo "test - run tests quickly with the default Python"
	@echo "test-all - run tests on every Python version with tox"
	@echo "test-full - shorthand for test lint coverage"
	@echo "coverage - check code coverage quickly with the default Python"

clean: clean-build clean-pyc

clean-build:
	rm -fr build/
	rm -fr dist/
	rm -fr *.egg-info

clean-pyc:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +

lint:
	flake8 esteid tests

test:
	py.test

test-all:
	tox

test-full: test lint coverage

coverage:
	py.test --cov-config .coveragerc --cov=esteid --cov-report html --cov-report term-missing
