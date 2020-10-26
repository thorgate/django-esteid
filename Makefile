PROJECT := esteid
VENV := ./venv/bin
export PATH := $(VENV):$(PATH)

.PHONY:
help:
	@echo "Available commands:"
	@echo "  venv - create virtualenv"
	@echo "  clean-build - remove build artifacts"
	@echo "  clean-pyc - remove Python file artifacts"
	@echo "  fmt - format code with black & isort"
	@echo "  lint - check code style"
	@echo "  test - run tests quickly with the default Python"
	@echo "  test-all - run tests on every Python version with tox"
	@echo "  test-full - shorthand for 'lint coverage'"
	@echo "  coverage - check code coverage quickly with the default Python"

.PHONY:
venv:
	python -m venv venv
	pip install -r requirements-dev.txt

.PHONY:
clean: clean-build clean-pyc

.PHONY:
clean-build:
	rm -fr build/
	rm -fr dist/
	rm -fr *.egg-info

.PHONY:
clean-pyc:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -rf {} +

.PHONY:
lint:
	black --check $(PROJECT)
	isort --check-only --project=$(PROJECT) $(PROJECT)
	flake8 $(PROJECT)

.PHONY:
test:
	PYTHONPATH=. pytest

.PHONY:
test-all:
	tox

.PHONY:
test-full: lint coverage

.PHONY:
coverage:
	PYTHONPATH=. pytest --cov=$(PROJECT) --cov-report html --cov-report term-missing

.PHONY:
fmt:
	black $(PROJECT)
	isort --project=$(PROJECT) $(PROJECT)
