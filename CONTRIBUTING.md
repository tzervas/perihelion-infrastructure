# Contributing to Private Homelab GitLab Infrastructure

Welcome to the Private Homelab GitLab Infrastructure project! This document provides guidelines for contributing to the project while maintaining our high standards for security, code quality, and operational excellence.

## Table of Contents

- [Development Environment](#development-environment)
- [Security Guidelines](#security-guidelines)
- [Code Standards](#code-standards)
- [Pull Request Process](#pull-request-process)
- [Testing Requirements](#testing-requirements)
- [Documentation Standards](#documentation-standards)
- [Review Process](#review-process)

## Development Environment

### Prerequisites

- **Docker**: Version 24.0.7 or later with rootless configuration
- **Kubernetes**: kubectl and helm for cluster interactions
- **Python**: 3.12+ with UV package manager
- **Git**: Configured with GPG signing
- **Development Tools**: Pre-commit hooks, security scanners

### DevContainer Setup

This project uses devcontainers for secure, isolated development:

```bash
# Clone the repository
git clone https://github.com/tzervas/private-homelab.git
cd private-homelab

# Open in VS Code with devcontainer
code .
# Select "Reopen in Container" when prompted
```

### Local Development Setup

```bash
# Install UV package manager
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create virtual environment
uv venv

# Activate environment
source .venv/bin/activate

# Install development dependencies
uv pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install
```

### GPG Configuration

All commits must be signed with GPG keys:

```bash
# Configure Git with GPG signing
git config --global user.signingkey YOUR_GPG_KEY_ID
git config --global commit.gpgsign true
git config --global tag.gpgSign true

# Verify GPG configuration
git config --list | grep gpg
```

## Security Guidelines

### Secure Development Practices

1. **Never commit secrets**: Use environment variables or Vault for sensitive data
2. **Input validation**: Validate all external inputs using type hints and pydantic models
3. **Principle of least privilege**: Request minimal required permissions
4. **Container security**: Use non-root users and read-only file systems
5. **Network isolation**: Implement proper network policies and firewalls

### Security Scanning Requirements

All code must pass security scans before merging:

```bash
# Run security scans locally
make security-scan

# Individual tool commands
bandit -r src/
safety check
semgrep --config=auto src/
trivy fs .
```

### Vulnerability Management

- **Critical vulnerabilities**: Must be fixed within 24 hours
- **High vulnerabilities**: Must be fixed within 72 hours
- **Medium vulnerabilities**: Must be addressed within 30 days
- **Low vulnerabilities**: Should be addressed within 90 days

## Code Standards

### Python Standards

This project adheres to PEP8 standards with Black formatting:

```bash
# Format code with Black
black src/ tests/

# Type checking with mypy
mypy src/

# Linting with flake8
flake8 src/ tests/

# Security linting with bandit
bandit -r src/
```

### Type Hints

All Python code must include comprehensive type hints:

```python
from typing import Dict, List, Optional, Union
from pydantic import BaseModel

def process_configuration(
    config: Dict[str, Union[str, int]], 
    optional_settings: Optional[List[str]] = None
) -> bool:
    """
    Process configuration with proper type annotations.
    
    Args:
        config: Configuration dictionary with string or integer values
        optional_settings: Optional list of setting names to process
        
    Returns:
        Success status of configuration processing
        
    Raises:
        ValueError: If configuration is invalid
        ConfigurationError: If required settings are missing
    """
    # Implementation here
    return True
```

### Documentation Standards

All functions and classes must include comprehensive docstrings:

```python
class GitLabController:
    """
    Kubernetes controller for managing GitLab runners.
    
    This controller provides intelligent scaling and lifecycle management
    for GitLab CI/CD runners in a Kubernetes environment.
    
    Attributes:
        namespace: Kubernetes namespace for runner deployments
        max_runners: Maximum number of concurrent runners allowed
        scaling_policy: Configuration for auto-scaling behavior
        
    Example:
        >>> controller = GitLabController(
        ...     namespace="gitlab-runners",
        ...     max_runners=50,
        ...     scaling_policy=ScalingPolicy.ADAPTIVE
        ... )
        >>> controller.start()
    """
    
    def __init__(
        self, 
        namespace: str, 
        max_runners: int = 50,
        scaling_policy: ScalingPolicy = ScalingPolicy.ADAPTIVE
    ) -> None:
        """Initialize the GitLab controller with specified configuration."""
        pass
```

### Infrastructure as Code Standards

#### Kubernetes Manifests
- Use resource quotas and limits for all deployments
- Implement proper RBAC with minimal permissions
- Include security contexts with non-root users
- Add network policies for traffic isolation

#### Helm Charts
- Parameterize all configuration values
- Include comprehensive value validation
- Provide clear upgrade/rollback procedures
- Document all template functions and helpers

#### Terraform/Kustomize
- Use remote state with encryption
- Implement proper module versioning
- Include validation rules for resources
- Provide disaster recovery procedures

## Pull Request Process

### Branch Strategy

We use GitFlow with feature branches and mandatory reviews:

```bash
# Create feature branch from main
git checkout -b feature/runner-controller-improvements

# Make changes with signed commits
git commit -S -m "feat(controller): improve runner scaling algorithm

- Implement predictive scaling based on job queue depth
- Add circuit breaker for failed runner launches
- Improve resource utilization efficiency by 25%

Signed-off-by: Tyler Zervas <tyler@example.com>"

# Push branch and create PR
git push origin feature/runner-controller-improvements
```

### Pull Request Requirements

1. **Branch protection**: All changes must go through pull requests
2. **Review requirement**: Minimum 2 reviewer approvals required
3. **CI/CD passing**: All automated tests and security scans must pass
4. **Documentation updates**: Include relevant documentation changes
5. **Breaking changes**: Must include migration guides and version bumps

### Commit Message Format

Follow conventional commit standards with GPG signing:

```
<type>(<scope>): <description>

<body>

<footer>
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `security`

Example:
```
feat(security): implement mutual TLS for inter-service communication

- Add certificate generation for service mesh
- Configure Calico with encryption in transit
- Update network policies for TLS requirements
- Add monitoring for certificate expiration

BREAKING CHANGE: Services now require TLS certificates for communication

Fixes: #123
Signed-off-by: Tyler Zervas <tyler@example.com>
```

## Testing Requirements

### Test Categories

1. **Unit Tests**: Minimum 90% code coverage
2. **Integration Tests**: Service interaction validation
3. **Security Tests**: Vulnerability and compliance scanning
4. **Performance Tests**: Load testing and benchmarking
5. **End-to-End Tests**: Complete workflow validation

### Test Execution

```bash
# Run all tests
make test

# Run specific test categories
make test-unit
make test-integration
make test-security
make test-performance

# Generate coverage report
make coverage
```

### Security Testing

```bash
# Container security scanning
trivy image gitlab-runner-controller:latest

# Infrastructure security testing
terraform plan -var-file=security-test.tfvars
kube-score score deployment.yaml

# Application security testing
bandit -r src/
safety check requirements.txt
```

## Documentation Standards

### Required Documentation

1. **API Documentation**: Auto-generated from code comments
2. **Architecture Diagrams**: Current system topology and data flows
3. **Security Procedures**: Incident response and recovery procedures
4. **Deployment Guides**: Step-by-step installation instructions
5. **Troubleshooting Guides**: Common issues and resolution steps

### Documentation Format

- Use Markdown for all documentation
- Include code examples with proper syntax highlighting
- Provide clear section headers and table of contents
- Add diagrams using Mermaid or PlantUML
- Keep documentation version-controlled with code

## Review Process

### Automated Reviews

The project uses Sourcery AI for automated code reviews:

1. **Code Quality**: Identifies performance and maintainability issues
2. **Security Analysis**: Detects potential security vulnerabilities
3. **Best Practices**: Suggests improvements following industry standards
4. **Documentation**: Checks for missing or incomplete documentation

### Human Review Process

1. **Technical Review**: Focus on architecture, performance, and security
2. **Security Review**: Dedicated security engineer review for sensitive changes
3. **Documentation Review**: Ensure completeness and accuracy of documentation
4. **Operational Review**: Verify deployment and operational procedures

### Review Criteria

- [ ] Code follows established patterns and conventions
- [ ] Security best practices are implemented
- [ ] Tests provide adequate coverage and scenarios
- [ ] Documentation is complete and accurate
- [ ] Performance implications are considered
- [ ] Backward compatibility is maintained (or breaking changes documented)
- [ ] Monitoring and observability are included

### Resolving Review Comments

1. **Address all comments**: Respond to every review comment with resolution
2. **Justify decisions**: Provide clear reasoning for any disagreements
3. **Update documentation**: Reflect any changes in relevant documentation
4. **Re-request review**: Notify reviewers when issues are resolved
5. **Merge criteria**: All discussions must be resolved before merging

## Release Process

### Version Management

- Follow semantic versioning (MAJOR.MINOR.PATCH)
- Tag releases with GPG signatures
- Maintain detailed changelog with security notes
- Document migration procedures for breaking changes

### Release Checklist

- [ ] All tests pass including security scans
- [ ] Documentation is updated and accurate
- [ ] Performance benchmarks meet requirements
- [ ] Security review completed
- [ ] Deployment procedures validated
- [ ] Rollback procedures tested
- [ ] Monitoring and alerting verified

## Getting Help

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and discussions
- **Security Issues**: security@company.com (private channel)
- **Documentation**: Project wiki and inline comments

### Support Levels

1. **Community Support**: Best effort through GitHub issues
2. **Contributor Support**: Priority support for active contributors
3. **Security Issues**: Immediate response for security vulnerabilities
4. **Emergency Support**: Critical system failures affecting operations

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). 

By participating in this project, you agree to:
- Be respectful and inclusive in all interactions
- Focus on constructive feedback and learning
- Prioritize security and quality in all contributions
- Follow established processes and guidelines
- Maintain confidentiality of sensitive information

Thank you for contributing to the Private Homelab GitLab Infrastructure project!
