FROM python:3.13.7-slim-bookworm@sha256:adafcc17694d715c905b4c7bebd96907a1fd5cf183395f0ebc4d3428bd22d92d

ENV PYTHONDBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_CACHE_DIR=/tmp/uv \
    UV_NO_PROGRESS=1

RUN pip install --no-cache-dir uv==0.12.4

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project

COPY src ./src
COPY tests ./tests
COPY scripts ./scripts
COPY pyproject.toml uv.lock README.md compose.yaml Dockerfile ./
RUN uv sync --frozen && chmod +x scripts/*.sh

USER 65532:65532
CMD ["uv", "run", "--no-sync", "uvicorn", "claimjumper.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
