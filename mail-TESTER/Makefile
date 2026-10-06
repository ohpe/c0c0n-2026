.PHONY: help install dev run smtp test lint fmt clean docker-build docker-up docker-down

VENV   := .venv
PYTHON := $(VENV)/bin/python
PIP    := $(VENV)/bin/pip
UV     := $(shell command -v uv 2>/dev/null)

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

# ── Setup ─────────────────────────────────────────────────────────

venv: ## Create virtual environment
ifdef UV
	uv venv $(VENV)
else
	python3 -m venv $(VENV)
endif

install: venv ## Install dependencies
ifdef UV
	uv pip install -e ".[dev]"
else
	$(PIP) install -e ".[dev]"
endif

dev: install ## Alias for install (dev setup)

# ── Run ───────────────────────────────────────────────────────────

run: ## Start on port 31337; ask before using a random port if occupied
	$(PYTHON) -m mail_tester.main

run-reload: ## Start with auto-reload on port 31337; ask before using random port
	$(PYTHON) -m mail_tester.main

# ── Quality ───────────────────────────────────────────────────────

test: ## Run tests
	$(PYTHON) -m pytest tests/ -v

lint: ## Run linter (ruff check)
	$(VENV)/bin/ruff check mail_tester/ tests/

fmt: ## Auto-format code (ruff format)
	$(VENV)/bin/ruff format mail_tester/ tests/
	$(VENV)/bin/ruff check --fix mail_tester/ tests/

# ── Docker ────────────────────────────────────────────────────────

docker-build: ## Build Docker image
	docker compose build

docker-up: ## Start containers (detached)
	docker compose up -d

docker-down: ## Stop containers
	docker compose down

docker-logs: ## Tail container logs
	docker compose logs -f mail-tester

# ── Utilities ─────────────────────────────────────────────────────

send-test: ## Send a test email via swaks (requires swaks installed)
	swaks --to test@localhost --from student@example.com \
		--server localhost:$${MAILTESTER_SMTP_PORT:-2525} \
		--header "Subject: Makefile Test"

clean: ## Remove build artifacts and caches
	rm -rf build/ dist/ *.egg-info .ruff_cache .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
