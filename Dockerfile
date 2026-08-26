# syntax=docker/dockerfile:1.7

FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

WORKDIR /build

# Install declared runtime dependencies in a layer that only changes when the
# project metadata changes. BuildKit's cache remains outside the final image.
COPY pyproject.toml ./
RUN --mount=type=cache,target=/root/.cache/pip \
    python -c 'import pathlib, tomllib; data = tomllib.loads(pathlib.Path("pyproject.toml").read_text()); pathlib.Path("/tmp/requirements.txt").write_text("\n".join(data["project"]["dependencies"]) + "\n")' \
    && python -m venv /opt/autosoc-venv \
    && /opt/autosoc-venv/bin/pip install -r /tmp/requirements.txt

COPY README.md ./
COPY src/ ./src/
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m pip install "hatchling>=1.27" \
    && python -m pip wheel --no-deps --no-build-isolation \
        --wheel-dir /tmp/wheels . \
    && /opt/autosoc-venv/bin/pip install --no-deps /tmp/wheels/autosoc-*.whl


FROM python:3.12-slim AS runtime

ARG APP_UID=1000
ARG APP_GID=1000

ENV PATH=/opt/autosoc-venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TMPDIR=/tmp \
    AUTOSOC_DATA_DIR=/app/data \
    AUTOSOC_ENABLE_LIVE_PROVIDERS=false \
    AUTOSOC_RATE_LIMIT_PER_MINUTE=60

RUN set -eux; \
    case "${APP_UID}:${APP_GID}" in \
        *[!0-9:]*|:*|*:) echo "APP_UID and APP_GID must be numeric" >&2; exit 1 ;; \
    esac; \
    [ "${APP_UID}" -gt 0 ] && [ "${APP_GID}" -gt 0 ]; \
    ! getent passwd "${APP_UID}" >/dev/null; \
    if ! getent group "${APP_GID}" >/dev/null; then \
        groupadd --gid "${APP_GID}" autosoc; \
    fi; \
    useradd --uid "${APP_UID}" --gid "${APP_GID}" --create-home \
        --home-dir /home/autosoc --shell /usr/sbin/nologin autosoc; \
    install -d -o "${APP_UID}" -g "${APP_GID}" -m 0750 \
        /app /app/data /app/data/remediation

WORKDIR /app

COPY --from=builder /opt/autosoc-venv /opt/autosoc-venv

USER autosoc

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3).read()"]

STOPSIGNAL SIGTERM

CMD ["uvicorn", "autosoc.web.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
