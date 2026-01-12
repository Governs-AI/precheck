FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    wget \
    tesseract-ocr \
    libtesseract-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Download spaCy models for Presidio
RUN python -m spacy download en_core_web_sm && \
    python -m spacy download en_core_web_lg

# Verify Presidio installation and download required models
RUN python -c "from presidio_analyzer import AnalyzerEngine; \
    from presidio_anonymizer import AnonymizerEngine; \
    print('✅ Presidio installed successfully'); \
    analyzer = AnalyzerEngine(); \
    print('✅ Presidio Analyzer initialized'); \
    anonymizer = AnonymizerEngine(); \
    print('✅ Presidio Anonymizer initialized')"

# Copy application code
COPY app ./app

# Create non-root user
RUN useradd --create-home --shell /bin/bash app && \
    chown -R app:app /app
USER app

# Expose port
EXPOSE 8080

# Set environment variables
ENV APP_BIND=0.0.0.0:8080
ENV PYTHONPATH=/app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/v1/health || exit 1

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
