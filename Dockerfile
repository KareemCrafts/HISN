# HISN v1.0.0 — Docker Image
# For self-hosting on internal networks only.
# Build: docker build -t hisn .
# Run:   docker run -p 5000:5000 -v $(pwd)/data:/app/data hisn

FROM python:3.11-slim

LABEL maintainer="Kareem Alshaer"
LABEL description="HISN — Unified Threat Investigation & Analytics Tool"
LABEL version="1.0.0"

WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY src/ ./src/
COPY setup_data.py .
COPY run_all.py .

# Download detection data
RUN python setup_data.py

# Create required directories
RUN mkdir -p uploads_web uploads_docs logs/samples data reports

# Non-root user for security
RUN useradd -m -u 1000 hisn && chown -R hisn:hisn /app
USER hisn

EXPOSE 5000

ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "src.dashboard.app"]
