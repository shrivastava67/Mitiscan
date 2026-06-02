.PHONY: help install dev fmt lint typecheck test security audit sbom build clean docker docker-run ci

PY ?= python
PIP ?= pip

help:
	@echo "Targets:"
	@echo "  install     - editable install (runtime only)"
	@echo "  dev         - editable install with dev extras + pre-commit"
	@echo "  fmt         - format with ruff + black"
	@echo "  lint        - ruff check"
	@echo "  typecheck   - mypy"
	@echo "  test        - pytest with coverage"
	@echo "  security    - bandit + pip-audit"
	@echo "  sbom        - CycloneDX SBOM"
	@echo "  build       - sdist + wheel"
	@echo "  docker      - build container image"
	@echo "  docker-run  - run container (GUI requires X11 forward)"
	@echo "  ci          - lint + typecheck + test + security"
	@echo "  clean       - remove build artifacts"

install:
	$(PIP) install -e .

dev:
	$(PIP) install -e ".[dev]"
	pre-commit install

fmt:
	ruff check --fix .
	black .

lint:
	ruff check .

typecheck:
	mypy core gui modules mitiscan.py

test:
	pytest --cov --cov-report=term-missing

security:
	bandit -r core gui modules mitiscan.py -c pyproject.toml
	pip-audit --strict

audit: security

sbom:
	cyclonedx-py requirements -i requirements.txt -o sbom.cdx.json
	@echo "SBOM written to sbom.cdx.json"

build:
	$(PY) -m build

docker:
	docker build -t mitiscan:dev .

docker-run:
	docker run --rm -it mitiscan:dev --check-deps

ci: lint typecheck test security

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage coverage.xml sbom.cdx.json
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
