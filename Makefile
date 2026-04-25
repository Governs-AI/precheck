.PHONY: install install-dev test load-test format lint type-check clean run docker-build docker-run

# Install production dependencies
install:
	pip install -r requirements.txt
	python -m spacy download en_core_web_sm

# Install development dependencies
install-dev:
	pip install -r requirements-dev.txt
	python -m spacy download en_core_web_sm

# Run tests
test:
	pytest tests/ -v

# Run the k6 load test (requires a running local service and a seeded API key)
load-test:
	@test -n "$(PRECHECK_API_KEY)" || (echo "PRECHECK_API_KEY is required"; exit 1)
	mkdir -p tests/load/artifacts
	k6 run \
		--summary-export tests/load/artifacts/precheck-load-summary.json \
		--out json=tests/load/artifacts/precheck-load-results.json \
		tests/load/precheck_load.js

# Format code
format:
	black app/ tests/
	isort app/ tests/

# Lint code
lint:
	flake8 app/ tests/

# Type checking
type-check:
	mypy app/

# Clean up temporary files
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -f local.db
	rm -f *.dlq.jsonl

# Run the application
run:
	python start.py

# Build Docker image
docker-build:
	docker build -t governsai-precheck .

# Run Docker container
docker-run:
	docker run -p 8080:8080 governsai-precheck

# Development setup
dev-setup: install-dev
	@echo "Development environment ready!"
	@echo "Run 'make run' to start the service"
