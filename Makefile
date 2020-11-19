PROJECT := esteid
VENV := ./.venv
export PATH := $(VENV)/bin:$(PATH)
LOCALES := en et lt ru

.PHONY:
help:  ## Show this help.
	@echo "Usage: make TARGET."
	@echo "** Available TARGETs: **"
	@sed -ne '/@sed/!s/## //p' $(MAKEFILE_LIST)

.PHONY:
venv: .venv  ## Create virtualenv in $(VENV)

.venv:  ## Create virtualenv in ./venv or $(VENV)
	python -m venv --prompt=django-esteid $(VENV)
	pip install -r requirements-dev.txt

.PHONY:
clean: clean-build clean-pyc  ## Clean build artifacts and pyc files

.PHONY:
clean-build:  ## Clean build artifacts
	rm -fr build/
	rm -fr dist/
	rm -fr *.egg-info

.PHONY:
clean-pyc:  ## Clean pyc files
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -rf {} +

.PHONY:
lint:  ## Run python linters
	black --check .
	isort --check-only --project=$(PROJECT) .
	flake8 $(PROJECT)

.PHONY:
test:  ## Run all python tests in the current virtual env
	PYTHONPATH=. pytest

.PHONY:
test-one-fail:  ## Run python tests in the current virtual env until first failure
	PYTHONPATH=. pytest -x

.PHONY:
test-all:  ## Run tests in all environments with tox
	tox

.PHONY:
test-full: lint coverage  ## Run linters, tests, and coverage

.PHONY:
coverage:  ## Run coverage
	PYTHONPATH=. pytest --cov=$(PROJECT) --cov-report html --cov-report term-missing

.PHONY:
fmt:  ## Format python code
	black .
	isort --project=$(PROJECT) .

.PHONY:
i18n-collect:  ## Collect translatable strings
	@cd esteid && \
	for locale in $(LOCALES); do \
		mkdir -p locale/$$locale/LC_MESSAGES \
		&& ../manage.py makemessages -l $$locale -e py; \
	done

.PHONY:
i18n-compile:  ## Compile translatable strings
	cd esteid && ../manage.py compilemessages
