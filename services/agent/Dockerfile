FROM python:3.13-slim

WORKDIR /app

# Install dependencies
COPY pyproject.toml ./
COPY src/ ./src/
RUN pip install --no-cache-dir -e . && pip install --no-cache-dir gunicorn

# Non-root user
RUN useradd -m appuser
USER appuser

EXPOSE 8002
ENV PORT=8002

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8002/health')"

CMD ["gunicorn", "agent_policy_gateway.services.agent_app:app", \
     "--bind", "0.0.0.0:8002", \
     "--workers", "2", \
     "--worker-class", "uvicorn.workers.UvicornWorker", \
     "--timeout", "120"]
