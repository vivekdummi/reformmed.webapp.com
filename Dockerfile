FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1

# Run as an unprivileged user (the containers use host networking, so an
# RCE as root would be root on the host network namespace).
RUN useradd --system --uid 10001 --no-create-home app
USER app

EXPOSE 5000

# One worker so the in-memory login rate limiter is shared (matches docker-compose).
CMD ["gunicorn", "-w", "1", "--threads", "8", "-b", "0.0.0.0:5000", "--timeout", "90", "app:create_app()"]
