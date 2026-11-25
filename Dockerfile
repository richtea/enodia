# enodia: Python 3.13.18 slim (Debian trixie), pinned by digest.
# uv 0.13.7, pinned by digest. Used only in the builder stage.
FROM ghcr.io/astral-sh/uv:0.13.10@sha256:a3ea1357342c1a4bf9a0c53a3deb1b55379aefa037338d8113d5771efa01774f AS uv

FROM python:3.13-slim-trixie@sha256:1b5c0692836eae9b028cc352d7146872f36939aa1fb0de24d3ef6df307b956c9 AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_NO_CACHE=1

WORKDIR /app
COPY pyproject.toml uv.lock ./
# Every dependency, including transitive ones, is pinned by hash in uv.lock. Dependencies are installed in their own
# layer first so that a source change does not reinstall them.
RUN --mount=from=uv,source=/uv,target=/bin/uv \
    uv sync --locked --no-dev --no-install-project
COPY src ./src
# Install the gateway itself as a regular (non-editable) package, so the runtime image needs only the venv.
RUN --mount=from=uv,source=/uv,target=/bin/uv \
    uv sync --locked --no-dev --no-editable

FROM python:3.13-slim-trixie@sha256:1b5c0692836eae9b028cc352d7146872f36939aa1fb0de24d3ef6df307b956c9

LABEL org.opencontainers.image.title="enodia" \
      org.opencontainers.image.description="OAuth resource-server gateway for MCP servers that only support a static bearer token" \
      org.opencontainers.image.source="https://github.com/richtea/enodia" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH" \
    CONFIG_FILE=/etc/enodia/config.toml

WORKDIR /app
# Nothing runs pip at runtime, and its vendored packages (urllib3, msgpack, ...) only add vulnerability findings.
RUN python -m pip uninstall --yes --no-cache-dir pip

COPY --from=builder /app/.venv /app/.venv

USER 1000:1000
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["enodia", "--healthcheck"]
ENTRYPOINT ["enodia"]
