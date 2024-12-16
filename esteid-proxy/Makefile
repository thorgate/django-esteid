.DEFAULT_GOAL := run
TOKEN ?= $(shell openssl rand -hex 12)
export TOKEN
ALLOWED_URLS ?= "*"
export ALLOWED_URLS

.PHONY:
build:
	@docker build --tag esteid-proxy .

.PHONY:
run: build
	@echo "Secret token: $${TOKEN}"
	@echo "Allowed URLs: $${ALLOWED_URLS}"
	@docker run -p 8001:8001 -e TOKEN=$${TOKEN} -e ALLOWED_URLS=$${ALLOWED_URLS} esteid-proxy
