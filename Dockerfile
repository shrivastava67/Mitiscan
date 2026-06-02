# syntax=docker/dockerfile:1.7
# ---- builder ----
FROM python:3.14-slim-bookworm AS builder
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /src

# OS deps for weasyprint at build time
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential libpango-1.0-0 libpangoft2-1.0-0 libcairo2 \
      libffi-dev libxml2 libjpeg62-turbo libpng16-16 shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml requirements.txt README.md LICENSE ./
COPY core ./core
COPY gui ./gui
COPY modules ./modules
COPY templates ./templates
COPY mitiscan.py ./mitiscan.py

RUN pip install --prefix=/install --no-deps -r requirements.txt \
 && pip install --prefix=/install --no-deps .

# ---- runtime ----
FROM python:3.14-slim-bookworm AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/usr/local/bin:/home/mitiscan/.local/bin:${PATH}" \
    HOME=/home/mitiscan

# Runtime libs for weasyprint
RUN apt-get update && apt-get install -y --no-install-recommends \
      libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libffi8 \
      libxml2 libjpeg62-turbo libpng16-16 shared-mime-info tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin mitiscan

COPY --from=builder /install /usr/local

WORKDIR /app
COPY --chown=mitiscan:mitiscan . /app

USER mitiscan
VOLUME ["/app/mitiscan_outputs"]

# OCI image labels
LABEL org.opencontainers.image.title="Mitiscan" \
      org.opencontainers.image.description="Automated VAPT platform" \
      org.opencontainers.image.source="https://github.com/shrivastava67/Mitiscan" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="Mitiscan contributors"

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD mitiscan --check-deps >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "mitiscan"]
CMD ["--check-deps"]
