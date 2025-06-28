# GitLab Runner Controller Makefile
# Secure development, testing, and deployment automation

.PHONY: help install test lint security-scan format clean build docker deploy

# Default target
help: ## Show this help message
	@echo "GitLab Runner Controller - Secure Development Makefile"
	@echo ""
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Python and UV settings
PYTHON := python3.12
UV := uv
VENV := .venv
ACTIVATE := source $(VENV)/bin/activate

# Project settings
PROJECT_NAME := gitlab-runner-controller
VERSION := $(shell grep version pyproject.toml | head -1 | cut -d'"' -f2)
IMAGE_NAME := $(PROJECT_NAME):$(VERSION)

# Test and coverage settings
TEST_PATH := tests/
COV_REPORT := htmlcov/
COV_MIN := 90

# Security settings
BANDIT_CONFIG := pyproject.toml
SAFETY_POLICY := .safety-policy.json

# Development Environment Setup
install: ## Install development dependencies and setup environment
	@echo "🔧 Setting up development environment..."
	$(UV) venv $(VENV)
	$(ACTIVATE) && $(UV) pip install -r requirements-dev.txt
	$(ACTIVATE) && pre-commit install
	@echo "✅ Development environment ready!"

install-prod: ## Install production dependencies only
	@echo "🚀 Installing production dependencies..."
	$(UV) venv $(VENV)
	$(ACTIVATE) && $(UV) pip install -r requirements.txt
	@echo "✅ Production environment ready!"

update: ## Update dependencies to latest versions
	@echo "📦 Updating dependencies..."
	$(ACTIVATE) && $(UV) pip compile requirements.in --upgrade
	$(ACTIVATE) && $(UV) pip compile requirements-dev.in --upgrade
	$(ACTIVATE) && $(UV) pip install -r requirements-dev.txt
	@echo "✅ Dependencies updated!"

# Code Quality and Formatting
format: ## Format code with Black and isort
	@echo "🎨 Formatting code..."
	$(ACTIVATE) && black src/ tests/
	$(ACTIVATE) && isort src/ tests/
	@echo "✅ Code formatting complete!"

lint: ## Run linting checks
	@echo "🔍 Running linting checks..."
	$(ACTIVATE) && black --check src/ tests/
	$(ACTIVATE) && isort --check-only src/ tests/
	$(ACTIVATE) && flake8 src/ tests/
	$(ACTIVATE) && mypy src/
	@echo "✅ Linting checks passed!"

# Testing
test: ## Run all tests with coverage
	@echo "🧪 Running tests with coverage..."
	$(ACTIVATE) && pytest $(TEST_PATH) \
		--cov=src \
		--cov-report=term-missing \
		--cov-report=html:$(COV_REPORT) \
		--cov-report=xml \
		--cov-fail-under=$(COV_MIN) \
		-v
	@echo "✅ Tests completed!"

test-unit: ## Run unit tests only
	@echo "🧪 Running unit tests..."
	$(ACTIVATE) && pytest tests/unit/ -v
	@echo "✅ Unit tests completed!"

test-integration: ## Run integration tests only
	@echo "🧪 Running integration tests..."
	$(ACTIVATE) && pytest tests/integration/ -v
	@echo "✅ Integration tests completed!"

test-security: ## Run security-specific tests
	@echo "🛡️ Running security tests..."
	$(ACTIVATE) && pytest tests/security/ -v
	@echo "✅ Security tests completed!"

test-fast: ## Run tests without coverage for faster feedback
	@echo "⚡ Running fast tests..."
	$(ACTIVATE) && pytest $(TEST_PATH) -x --tb=short
	@echo "✅ Fast tests completed!"

coverage: ## Generate and open coverage report
	@echo "📊 Generating coverage report..."
	$(ACTIVATE) && pytest $(TEST_PATH) --cov=src --cov-report=html:$(COV_REPORT)
	@echo "📖 Opening coverage report..."
	xdg-open $(COV_REPORT)/index.html 2>/dev/null || open $(COV_REPORT)/index.html 2>/dev/null || echo "Coverage report available at $(COV_REPORT)/index.html"

# Security Scanning
security-scan: ## Run comprehensive security scans
	@echo "🔒 Running security scans..."
	$(MAKE) bandit-scan
	$(MAKE) safety-check
	$(MAKE) semgrep-scan
	$(MAKE) trivy-scan
	@echo "✅ Security scans completed!"

bandit-scan: ## Run Bandit security linting
	@echo "🔍 Running Bandit security scan..."
	$(ACTIVATE) && bandit -r src/ -f json -o bandit-report.json || echo "⚠️ Bandit found security issues"
	$(ACTIVATE) && bandit -r src/ -f txt || echo "⚠️ Check bandit-report.json for details"

safety-check: ## Check dependencies for known vulnerabilities
	@echo "🔍 Checking dependencies for vulnerabilities..."
	$(ACTIVATE) && safety check --json --output safety-report.json || echo "⚠️ Safety found vulnerable dependencies"
	$(ACTIVATE) && safety check || echo "⚠️ Check safety-report.json for details"

semgrep-scan: ## Run Semgrep static analysis
	@echo "🔍 Running Semgrep static analysis..."
	$(ACTIVATE) && semgrep --config=auto src/ --json --output=semgrep-report.json || echo "⚠️ Semgrep found issues"
	$(ACTIVATE) && semgrep --config=auto src/ || echo "⚠️ Check semgrep-report.json for details"

trivy-scan: ## Scan for vulnerabilities with Trivy
	@echo "🔍 Running Trivy filesystem scan..."
	trivy fs --security-checks vuln,secret --format json --output trivy-report.json . || echo "⚠️ Trivy found issues"
	trivy fs --security-checks vuln,secret . || echo "⚠️ Check trivy-report.json for details"

# Pre-commit and Git Hooks
pre-commit: ## Run pre-commit hooks on all files
	@echo "🎣 Running pre-commit hooks..."
	$(ACTIVATE) && pre-commit run --all-files
	@echo "✅ Pre-commit checks completed!"

pre-commit-update: ## Update pre-commit hooks
	@echo "📦 Updating pre-commit hooks..."
	$(ACTIVATE) && pre-commit autoupdate
	@echo "✅ Pre-commit hooks updated!"

# Building and Packaging
build: ## Build the package
	@echo "📦 Building package..."
	$(ACTIVATE) && python -m build
	@echo "✅ Package built in dist/"

clean: ## Clean build artifacts and cache files
	@echo "🧹 Cleaning build artifacts..."
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf $(COV_REPORT)/
	rm -rf .mypy_cache/
	rm -rf .pytest_cache/
	rm -rf __pycache__/
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	rm -f bandit-report.json safety-report.json semgrep-report.json trivy-report.json
	@echo "✅ Cleanup completed!"

# Docker Operations
docker-build: ## Build Docker container
	@echo "🐳 Building Docker container..."
	docker build -t $(IMAGE_NAME) .
	docker tag $(IMAGE_NAME) $(PROJECT_NAME):latest
	@echo "✅ Docker container built: $(IMAGE_NAME)"

docker-security-scan: ## Scan Docker image for vulnerabilities
	@echo "🔍 Scanning Docker image for vulnerabilities..."
	trivy image $(IMAGE_NAME) --format json --output docker-trivy-report.json || echo "⚠️ Docker image has vulnerabilities"
	trivy image $(IMAGE_NAME) || echo "⚠️ Check docker-trivy-report.json for details"

docker-run: ## Run Docker container locally
	@echo "🐳 Running Docker container..."
	docker run --rm -it \
		-p 8080:8080 \
		-v $(PWD)/config.yaml:/app/config.yaml:ro \
		$(IMAGE_NAME) \
		--config /app/config.yaml

docker-shell: ## Get shell access to Docker container
	@echo "🐳 Starting shell in Docker container..."
	docker run --rm -it --entrypoint /bin/bash $(IMAGE_NAME)

# Documentation
docs: ## Generate documentation
	@echo "📚 Generating documentation..."
	$(ACTIVATE) && mkdocs build
	@echo "✅ Documentation generated in site/"

docs-serve: ## Serve documentation locally
	@echo "📚 Serving documentation locally..."
	$(ACTIVATE) && mkdocs serve

docs-deploy: ## Deploy documentation to GitHub Pages
	@echo "🚀 Deploying documentation..."
	$(ACTIVATE) && mkdocs gh-deploy

# Configuration and Validation
generate-config: ## Generate sample configuration file
	@echo "⚙️ Generating sample configuration..."
	$(ACTIVATE) && python -m gitlab_runner_controller.cli generate-config
	@echo "✅ Sample configuration generated!"

validate-config: ## Validate configuration file
	@echo "🔍 Validating configuration..."
	$(ACTIVATE) && python -m gitlab_runner_controller.cli validate
	@echo "✅ Configuration validation completed!"

# Development and Debugging
dev: ## Start development server with hot reload
	@echo "🚀 Starting development server..."
	$(ACTIVATE) && python -m gitlab_runner_controller.cli run --log-format console --log-level DEBUG

debug: ## Start in debug mode with enhanced logging
	@echo "🐛 Starting debug mode..."
	$(ACTIVATE) && python -m gitlab_runner_controller.cli run --log-format console --log-level DEBUG --dry-run

# CI/CD Integration
ci-test: ## Run CI/CD pipeline tests
	@echo "🔄 Running CI/CD pipeline tests..."
	$(MAKE) lint
	$(MAKE) security-scan
	$(MAKE) test
	@echo "✅ CI/CD pipeline tests completed!"

ci-security: ## Run CI/CD security checks
	@echo "🔒 Running CI/CD security checks..."
	$(MAKE) bandit-scan
	$(MAKE) safety-check
	$(MAKE) trivy-scan
	@echo "✅ CI/CD security checks completed!"

# Installation and Deployment
install-system: ## Install system-wide (requires sudo)
	@echo "🚀 Installing system-wide..."
	sudo pip install .
	@echo "✅ System installation completed!"

uninstall-system: ## Uninstall system-wide (requires sudo)
	@echo "🗑️ Uninstalling system-wide..."
	sudo pip uninstall -y $(PROJECT_NAME)
	@echo "✅ System uninstallation completed!"

# Kubernetes Operations (requires kubectl and cluster access)
k8s-deploy: ## Deploy to Kubernetes cluster
	@echo "☸️ Deploying to Kubernetes..."
	kubectl apply -f infrastructure/kubernetes/
	@echo "✅ Kubernetes deployment completed!"

k8s-status: ## Check Kubernetes deployment status
	@echo "☸️ Checking Kubernetes deployment status..."
	kubectl get pods -l app=$(PROJECT_NAME)
	kubectl get services -l app=$(PROJECT_NAME)

k8s-logs: ## View Kubernetes pod logs
	@echo "📋 Viewing Kubernetes logs..."
	kubectl logs -l app=$(PROJECT_NAME) --tail=100 -f

k8s-delete: ## Delete Kubernetes deployment
	@echo "🗑️ Deleting Kubernetes deployment..."
	kubectl delete -f infrastructure/kubernetes/
	@echo "✅ Kubernetes deployment deleted!"

# Release Management
version: ## Show current version
	@echo "Current version: $(VERSION)"

bump-patch: ## Bump patch version
	@echo "📈 Bumping patch version..."
	$(ACTIVATE) && bump2version patch
	@echo "✅ Version bumped!"

bump-minor: ## Bump minor version
	@echo "📈 Bumping minor version..."
	$(ACTIVATE) && bump2version minor
	@echo "✅ Version bumped!"

bump-major: ## Bump major version
	@echo "📈 Bumping major version..."
	$(ACTIVATE) && bump2version major
	@echo "✅ Version bumped!"

release: ## Create a new release
	@echo "🚀 Creating release $(VERSION)..."
	$(MAKE) clean
	$(MAKE) ci-test
	$(MAKE) build
	$(MAKE) docker-build
	$(MAKE) docker-security-scan
	git tag -s v$(VERSION) -m "Release v$(VERSION)"
	@echo "✅ Release v$(VERSION) created!"

# Monitoring and Metrics
metrics: ## Display project metrics
	@echo "📊 Project Metrics:"
	@echo "==================="
	@echo "Lines of Code:"
	@find src/ -name "*.py" -exec wc -l {} + | tail -1
	@echo ""
	@echo "Test Coverage:"
	@$(ACTIVATE) && pytest --cov=src --cov-report=term | grep "TOTAL" || echo "Run 'make test' first"
	@echo ""
	@echo "Security Score:"
	@$(ACTIVATE) && bandit -r src/ -f txt | grep "Overall" || echo "Run 'make bandit-scan' first"

health-check: ## Run comprehensive health check
	@echo "🏥 Running health check..."
	@echo "✅ Python version: $(shell $(PYTHON) --version)"
	@echo "✅ UV version: $(shell $(UV) --version)"
	@echo "✅ Virtual environment: $(shell test -d $(VENV) && echo "Present" || echo "Missing")"
	@echo "✅ Pre-commit hooks: $(shell test -f .git/hooks/pre-commit && echo "Installed" || echo "Not installed")"
	@echo "✅ Dependencies: $(shell $(ACTIVATE) && pip check >/dev/null 2>&1 && echo "OK" || echo "Issues found")"
	@echo "🏥 Health check completed!"

# Advanced Development Tools
profile: ## Profile application performance
	@echo "📈 Profiling application performance..."
	$(ACTIVATE) && python -m cProfile -o profile.stats -m gitlab_runner_controller.cli --help
	$(ACTIVATE) && python -c "import pstats; p = pstats.Stats('profile.stats'); p.sort_stats('cumulative'); p.print_stats(20)"
	@echo "✅ Performance profiling completed!"

memory-profile: ## Profile memory usage
	@echo "💾 Profiling memory usage..."
	$(ACTIVATE) && python -m memory_profiler -m gitlab_runner_controller.cli --help
	@echo "✅ Memory profiling completed!"

# Help and Information
info: ## Display project information
	@echo "GitLab Runner Controller"
	@echo "======================="
	@echo "Version: $(VERSION)"
	@echo "Python: $(PYTHON)"
	@echo "Virtual Environment: $(VENV)"
	@echo "Test Path: $(TEST_PATH)"
	@echo "Coverage Report: $(COV_REPORT)"
	@echo "Image Name: $(IMAGE_NAME)"

requirements: ## Display tool requirements
	@echo "Required Tools:"
	@echo "=============="
	@echo "- Python 3.12+"
	@echo "- UV package manager"
	@echo "- Docker (for container operations)"
	@echo "- kubectl (for Kubernetes operations)"
	@echo "- Trivy (for security scanning)"
	@echo "- Git (with GPG signing configured)"

.DEFAULT_GOAL := help
