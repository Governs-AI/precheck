FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Download spaCy models for Presidio
# English (default, used today by the analyzer)
RUN python -m spacy download en_core_web_sm && \
    python -m spacy download en_core_web_lg

# Multilingual models (GOV-585 / TASKS.md §3.5a).
# These are pre-installed so the image is ready to serve non-English PII
# detection once the NLP engine config is enabled per-org in 3.5b+.
# Kept as a separate layer so the English-only base is still cache-hot for
# builds that don't touch multilingual code.
RUN python -m spacy download es_core_news_sm && \
    python -m spacy download fr_core_news_sm && \
    python -m spacy download de_core_news_sm && \
    python -m spacy download zh_core_web_sm

# Fail the image build if any multilingual model fails to load. This is the
# acceptance check for TASKS.md §3.5a — each model must load without errors in
# the precheck container — and it prints the cold-load time per model so the
# startup cost is visible in CI logs.
COPY scripts/smoke_multilingual_pii.py /tmp/smoke_multilingual_pii.py
RUN python /tmp/smoke_multilingual_pii.py && rm /tmp/smoke_multilingual_pii.py

# Verify Presidio installation and download required models
RUN python -c "from presidio_analyzer import AnalyzerEngine; \
    from presidio_anonymizer import AnonymizerEngine; \
    print('✅ Presidio installed successfully'); \
    analyzer = AnalyzerEngine(); \
    print('✅ Presidio Analyzer initialized'); \
    anonymizer = AnonymizerEngine(); \
    print('✅ Presidio Anonymizer initialized')"

# Copy application code and policy file
COPY app ./app
COPY policy.tool_access.yaml ./

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
    CMD curl -f http://localhost:8080/api/v1/health || exit 1

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
