FROM python:3.13-slim

WORKDIR /app

# Install dependencies
COPY pyproject.toml ./
COPY src/ ./src/
COPY policy.json ./policy.json
RUN pip install --no-cache-dir -e . && pip install --no-cache-dir gunicorn

# Non-root user
RUN useradd -m appuser
USER appuser

EXPOSE 8000
ENV PORT=8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

CMD ["gunicorn", "kirogate.services.gateway_app:app", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "4", \
     "--worker-class", "uvicorn.workers.UvicornWorker", \
     "--timeout", "30"]
