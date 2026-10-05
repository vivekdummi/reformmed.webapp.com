FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY dashboard_manager.py .

# Run as an unprivileged user (the containers use host networking, so an
# RCE as root would be root on the host network namespace).
RUN useradd --system --uid 10001 --no-create-home app
USER app

# Default command (will be overridden by docker-compose)
CMD ["python", "main.py"]
