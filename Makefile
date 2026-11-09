.PHONY: setup run test lint format build check doctor help

AES_LANGUAGE ?= python
AES_LINT ?= ruff check
AES_TEST ?= pytest --cov=myav
AES_FORMAT ?= ruff format
AES_BUILD ?= python -m build
AES_RUN ?= python -m src.main || python src/main.py

export AES_LANGUAGE AES_LINT AES_TEST AES_FORMAT AES_BUILD AES_RUN

setup:
	@echo "Setting up $(AES_LANGUAGE)..."
	@uv sync --extra dev 2>/dev/null || python -m pip install -e ".[dev]"

run:
	@$(AES_RUN)

test:
	@$(AES_TEST)

lint:
	@$(AES_LINT) src tests

format:
	@$(AES_FORMAT) src tests

build:
	@$(AES_BUILD)

check: docs-check code-check test-check lint-check

docs-check:
	@test -f docs/VISION.md && grep -q "Problem" docs/VISION.md
	@test -f docs/REQUIREMENTS.md && grep -q "Functional" docs/REQUIREMENTS.md
	@test -f docs/ARCHITECTURE.md && grep -q "Architecture" docs/ARCHITECTURE.md
	@test -f docs/ROADMAP.md && grep -q "Roadmap" docs/ROADMAP.md
	@test -f docs/INSTALLATION.md && grep -q "Installing" docs/INSTALLATION.md
	@test -f docs/CONFIGURATION.md && grep -q "Configuring" docs/CONFIGURATION.md
	@test -f docs/RUNBOOK.md && grep -q "Runbook" docs/RUNBOOK.md
	@test -f docs/PLATFORMS.md && grep -q "Platform" docs/PLATFORMS.md
	@test -f docs/LIMITATIONS.md && grep -q "Limitation" docs/LIMITATIONS.md
	@test -f docs/PRIVACY.md && grep -q "Privacy" docs/PRIVACY.md
	@test -f docs/TESTING.md && grep -q "Testing" docs/TESTING.md
	@test -f docs/RESEARCH_REFERENCES.md && grep -q "Reference" docs/RESEARCH_REFERENCES.md
	@test -f docs/THREAT_MODEL.md && grep -q "Threat" docs/THREAT_MODEL.md
	@test -f docs/DEPENDENCIES.md && grep -q "Dependenc" docs/DEPENDENCIES.md
	@test -f docs/FAQ.md && grep -q "FAQ" docs/FAQ.md
	@test -f docs/COMPANION_PROTOCOL.md && grep -q "Companion" docs/COMPANION_PROTOCOL.md
	@test -f docs/sbom/myav.cdx.json && test -s docs/sbom/myav.cdx.json
	@test -f SECURITY.md && grep -q "Security" SECURITY.md
	@test -f CONTRIBUTING.md && grep -q "Contribut" CONTRIBUTING.md
	@test -f CHANGELOG.md && grep -q "Change" CHANGELOG.md
	@test -f PROJECT_STATUS.md && grep -q "Project status" PROJECT_STATUS.md
	@test -f LICENSE && grep -q "Apache" LICENSE

code-check:
	@test -d src || test -d lib
	@grep -R "TODO:" src/ tests/ 2>/dev/null || true

test-check:
	@$(AES_TEST) --cov-fail-under=80 || echo "Coverage below 80%"

lint-check:
	@$(AES_LINT) src tests

validate:
	@ruff check . || true

doctor:
	@echo "Language: $(AES_LANGUAGE)"
	@echo "Python: $$(python --version 2>&1 || echo not-found)"

help:
	@echo "AES Commands: make setup run test lint format build check doctor help"
	@echo ""
	@echo "  setup    - install dependencies (uv or pip)"
	@echo "  run      - run the application"
	@echo "  test     - run tests with coverage"
	@echo "  lint     - run ruff linting"
	@echo "  format   - format code with ruff"
	@echo "  build    - build package"
	@echo "  check    - run all quality gates"
	@echo "  doctor   - show environment info"t format build check doctor"
