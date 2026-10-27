# Base images are pinned by digest. Build: docker build -t one-time-vault .
FROM ghcr.io/astral-sh/uv:0.11.14@sha256:1025398289b62de8269e70c45b91ffa37c373f38118d7da036fb8bb8efc85d97 AS uv

FROM python:3.12-slim@sha256:12316debbfb86890f6b2d825820612741ba527ad5a44e3902759141d572bfe8f
COPY --from=uv /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never PYTHONUNBUFFERED=1
WORKDIR /app

# Dependencies first, so the layer is reused when only the code changes.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-dev --no-install-project

COPY src ./src
RUN uv sync --locked --no-dev

RUN useradd --system --no-create-home vault
USER vault
EXPOSE 8000

# --no-proxy-headers: the app does its own client IP logic (OTV_TRUSTED_HOPS).
CMD ["/app/.venv/bin/uvicorn", "--factory", "--no-proxy-headers", "--host", "0.0.0.0", "--port", "8000", "one_time_vault.app:app_from_env"]
