FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create paneluser (UID 1000)
RUN useradd -m -u 1000 paneluser

COPY --chown=paneluser:paneluser . .
RUN mkdir -p /app/data && chown -R paneluser:paneluser /app/data

# Entrypoint that runs as root briefly to fix data dir, then drops to paneluser
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 54325

# NOTE: container starts as root (so entrypoint can chown mounted volume),
# then drops to paneluser inside the entrypoint.
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "54325", "--workers", "1"]
