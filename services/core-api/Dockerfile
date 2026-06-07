# Production image for the Blackbirch core-api service.
# Build context is this directory (services/core-api).
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Runtime deps only (no pytest/httpx). cryptography & psycopg2 ship manylinux
# wheels, so no compiler needed. psycopg2-binary enables the Postgres driver;
# dnspython enables live DNS/SPF/DMARC lookups in the external analyzer.
RUN pip install \
    "fastapi>=0.110" \
    "uvicorn[standard]>=0.27" \
    "sqlmodel>=0.0.16" \
    "cryptography>=42.0" \
    "psycopg2-binary>=2.9" \
    "dnspython>=2.6"

# App source
COPY app ./app
COPY collectors ./collectors

# Run as non-root
RUN useradd --create-home --uid 10001 appuser && chown -R appuser /app
USER appuser

EXPOSE 8000

# Simple liveness probe target is GET /healthz
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
