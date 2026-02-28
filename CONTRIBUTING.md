# Contributing to GovernsAI Precheck

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

## Development

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8080
```

## Validation

```bash
pytest
```

## Pull Request Checklist

- Add or update tests for policy behavior changes.
- Keep API responses backward compatible unless versioned.
- Document new environment variables and defaults.
