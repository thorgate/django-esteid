FROM python:3.8-alpine
WORKDIR /app
RUN apk add gcc musl-dev libffi-dev
RUN pip install -U pip setuptools
RUN pip install poetry
COPY ./poetry.lock /app/poetry.lock
COPY ./pyproject.toml /app/pyproject.toml
COPY ./README.md /app/README.md
COPY ./esteid-proxy.py /app/esteid-proxy.py
ENV POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_VIRTUALENVS_CREATE=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache
RUN poetry install --no-root && rm -rf $POETRY_CACHE_DIR
EXPOSE 8001
CMD ["poetry", "run", "fastapi", "run", "esteid-proxy.py", "--port", "8001"]
