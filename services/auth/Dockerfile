FROM python:3.13-slim

WORKDIR /app

# Install dependencies
COPY pyproject.toml ./
COPY src/ ./src/
RUN pip install --no-cache-dir -e . && pip install --no-cache-dir gunicorn

# Non-root user
RUN useradd -m appuser
USER appuser

EXPOSE 8001
ENV PORT=8001

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8001/health')"

CMD ["gunicorn", "kirogate.services.auth_app:app", \
     "--bind", "0.0.0.0:8001", \
     "--workers", "2", \
     "--worker-class", "uvicorn.workers.UvicornWorker", \
     "--timeout", "30"]
