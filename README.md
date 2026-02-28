# GovernsAI Precheck

[![npm](https://img.shields.io/npm/v/%40governs-ai%2Fsdk?label=npm%20%40governs-ai%2Fsdk)](https://www.npmjs.com/package/@governs-ai/sdk)
[![PyPI](https://img.shields.io/pypi/v/governs-ai-sdk?label=PyPI%20governs-ai-sdk)](https://pypi.org/project/governs-ai-sdk/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Fully Open Source (MIT)** - PII detection and policy evaluation service for AI applications.

This service provides real-time policy evaluation and PII detection/redaction for AI tool usage. You can use it, modify it, and even offer it as a hosted service - no restrictions.

## Features

- **Policy Evaluation**: Real-time evaluation of AI tool usage against configurable policies
- **PII Detection & Redaction**: Advanced PII detection using Microsoft Presidio with regex fallback
- **API Key Authentication**: Secure API key-based authentication
- **Rate Limiting**: Redis-based rate limiting (optional)
- **Database Storage**: SQLAlchemy-based storage with PostgreSQL/SQLite support
- **Docker Support**: Production-ready Docker containerization

## Quick Start

### Local Development

1. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   python -m spacy download en_core_web_sm
   ```

2. **Run the service**:

   ```bash
   python start.py
   # or
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8080
   ```

3. **Test the service**:
   ```bash
   curl -X GET http://localhost:8080/api/v1/health
   ```

### Docker

1. **Build the image**:

   ```bash
   docker build -t governsai-precheck .
   ```

2. **Run the container**:
   ```bash
   docker run -p 8080:8080 governsai-precheck
   ```

## API Endpoints

### Health Check

```http
GET /api/v1/health
```

Returns service status and version information.

### Precheck

```http
POST /api/v1/precheck
X-Governs-Key: your-api-key
Content-Type: application/json

{
  "tool": "web.fetch",
  "scope": "net.external",
  "raw_text": "Please fetch data from https://example.com for user@example.com",
  "tags": ["research"],
  "corr_id": "req-123"
}
```

**Response**:

```json
{
  "decision": "transform",
  "payload": {
    "url": "https://example.com",
    "email": "u***@example.com"
  },
  "reasons": ["pii.redacted:email"],
  "policy_id": "net-redact-presidio",
  "ts": 1703123456
}
```

### Postcheck

```http
POST /api/v1/postcheck
X-Governs-Key: your-api-key
Content-Type: application/json
```

Similar to precheck but for post-execution validation.

## Configuration

The service can be configured via environment variables:

| Variable         | Default                   | Description                      |
| ---------------- | ------------------------- | -------------------------------- |
| `APP_BIND`       | `0.0.0.0:8080`            | Server bind address              |
| `DB_URL`         | `sqlite:///./local.db`    | Database connection URL          |
| `USE_PRESIDIO`   | `true`                    | Enable Presidio PII detection    |
| `PRESIDIO_MODEL` | `en_core_web_sm`          | spaCy model for Presidio         |
| `WEBHOOK_URL`    | `None`                    | Webhook URL for dashboard events |
| `PRECHECK_DLQ`   | `/tmp/precheck.dlq.jsonl` | Dead letter queue file path      |

## PII Detection

The service uses Microsoft Presidio for advanced PII detection with the following capabilities:

- **Email addresses**: Detected and masked
- **Phone numbers**: International format detection and masking
- **Credit cards**: Luhn algorithm validation and masking
- **API keys**: Custom patterns for various API key formats
- **JWT tokens**: Detection and redaction
- **SSN**: US Social Security Number detection
- **IP addresses**: IPv4/IPv6 detection

### Fallback Mode

If Presidio fails to initialize, the service falls back to regex-based detection for basic PII types (email, phone, credit card).

## Webhook Events

The service emits fire-and-forget webhook events for all precheck and postcheck decisions to enable dashboard integration and audit logging.

### Event Structure

```json
{
  "userId": "user123",
  "tool": "web.fetch",
  "scope": "net.external",
  "decision": "transform",
  "policyId": "net-redact-presidio",
  "reasons": ["pii.redacted:email"],
  "payloadHash": "sha256_hash_of_payload",
  "latencyMs": 45,
  "timestamp": 1703123456,
  "correlationId": "req-123",
  "tags": ["research"],
  "direction": "precheck"
}
```

### Configuration

- Set `WEBHOOK_URL` environment variable to enable webhook emission
- Failed webhook deliveries are written to DLQ file (configurable via `PRECHECK_DLQ`)
- Webhook includes retry logic with exponential backoff (0.5s, 1s, 2s)

### Testing

Use the provided webhook test URL for development:

```bash
export WEBHOOK_URL="https://webhook-test.com/1508b1ea2414ed242d2b8abf6ea66616"
```

## Policy Configuration

### Denied Tools

The following tools are automatically denied:

- `python.exec`
- `bash.exec`
- `code.exec`
- `shell.exec`

### Network Tools

Tools with network scope or web/http prefixes trigger PII redaction:

- `web.*`
- `http.*`
- `fetch.*`
- `request.*`
- `net.*` scope

## Development

### Development Setup

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Download spaCy model
python -m spacy download en_core_web_sm
```

### Running Tests

```bash
pytest tests/
```

### Code Formatting

```bash
black app/ tests/
isort app/ tests/
```

### Type Checking

```bash
mypy app/
```

## Deployment Modes

### Cloud Mode

- Bind to `0.0.0.0:8080`
- Use PostgreSQL database
- Use Redis for rate limiting
- Set `PUBLIC_BASE` for external access

### Local Sidecar Mode

- Bind to `127.0.0.1:7071`
- Use SQLite database
- Optional Redis
- Local development setup

## License

**MIT License** - Fully open source, no restrictions.

### What You Can Do:
- ✅ **Use in production** - Deploy for your organization
- ✅ **Host as a service** - Offer "Precheck-as-a-Service" to customers
- ✅ **Modify freely** - Customize for your needs
- ✅ **Bundle with products** - Integrate into your software
- ✅ **No attribution required** - Use without mentioning GovernsAI (though we'd appreciate it!)

### Why MIT?
We want Precheck to become the standard for AI governance. Making it fully open source (not just source-available) means:
- No legal friction for enterprise adoption
- Can be integrated into any project (open or proprietary)
- Community can build on and extend it
- You can run it anywhere, anytime, for any purpose

See [LICENSE](LICENSE) file for full legal text.

## Part of GovernsAI Open-Core

Precheck is the core of the GovernsAI ecosystem:
- **Precheck Service** (this package) - MIT (fully open source)
- **TypeScript SDK** - MIT
- **Browser Extension** - MIT
- **Platform Console** - ELv2 (source-available for self-hosting)

Learn more: [GovernsAI Licensing](https://docs.governsai.com/licensing)
