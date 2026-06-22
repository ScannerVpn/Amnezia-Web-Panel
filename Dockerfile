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

RUN useradd -m -u 1000 paneluser
COPY --chown=paneluser:paneluser . .

RUN mkdir -p /app/data && chown -R paneluser:paneluser /app/data

# Copy and make entrypoint executable
COPY --chown=paneluser:paneluser docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

USER paneluser

EXPOSE 54325

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "54325", "--workers", "1"]
