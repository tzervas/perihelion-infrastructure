# perihelion-infrastructure — Tero Index (Layer 1)

> **Honesty:** Empirical/Declared — lite heading/line heuristic over markdown in perihelion-infrastructure via tero-mcp/scripts/generate_lite_index.py; source files are ground truth. Generated 2026-07-10.
> Use this index to find where to Read, not as authoritative ground truth.

- **Items:** 313
- **Flagged:** 0
- **item_tag:** `Empirical/Declared`
- **Machine index:** [`index.json`](./index.json)
- **Manifest:** [`MANIFEST.toml`](./MANIFEST.toml)

## doc (313 entries)

| Anchor | Kind | Id | Title | File:Line | Status | Summary |
|---|---|---|---|---|---|---|
| `agents` | other | — | AGENTS.md — perihelion-infrastructure | `AGENTS.md:2` | — | Use Tero + cabal-devmelopner for work here. |
| `agents--tero-layer-1-corpus-index` | section | — | Tero (Layer-1 corpus index) | `AGENTS.md:6` | — | Repo has docs/tero-index/index.json (generated/ refreshed via tero-mcp/scripts/generateliteindex.py). |
| `agents--agent-with-context` | other | — | agent with context: | `AGENTS.md:18` | — | uv run --project ../cabal-devmelopner cabal-devmelopner "task description here" --use-tero |
| `agents--working-with-cabal-devmelopner-agent-tool` | section | — | Working with cabal-devmelopner agent tool | `AGENTS.md:24` | — | This project is prepared for integration: |
| `agents--local-checks` | section | — | Local checks | `AGENTS.md:36` | — | Look for: |
| `agents--further-reading` | section | — | Further reading | `AGENTS.md:44` | — | - README.md |
| `agents--hygiene-thin-land-2026-07-09-plan-priority-1` | section | — | Hygiene + thin land (2026-07-09, plan priority 1) | `AGENTS.md:54` | — | Added scripts/check.sh (requirements + pyproject aware via uv/venv/pip, pytest incl security/, advisory black/isort/flake, tero regen modeled on cabal-devmelop… |
| `agents--distribution-semver-appended` | section | — | Distribution + Semver (appended) | `AGENTS.md:60` | — | Semver baseline for this supportive tooling/helper extracted from mycelium (read-only clone at /root/git/isolated/mycelium, perms 555). |
| `contributing` | section | — | Contributing to Private Homelab GitLab Infrastructure | `CONTRIBUTING.md:1` | — | Welcome to the Private Homelab GitLab Infrastructure project! This document provides guidelines for contributing to the project while maintaining our high stan… |
| `contributing--table-of-contents` | section | — | Table of Contents | `CONTRIBUTING.md:5` | — | - [Development Environment](#development-environment) |
| `contributing--development-environment` | section | — | Development Environment | `CONTRIBUTING.md:15` | — | - Docker: Version 24.0.7 or later with rootless configuration |
| `contributing--prerequisites` | section | — | Prerequisites | `CONTRIBUTING.md:17` | — | - Docker: Version 24.0.7 or later with rootless configuration |
| `contributing--devcontainer-setup` | section | — | DevContainer Setup | `CONTRIBUTING.md:25` | — | This project uses devcontainers for secure, isolated development: |
| `contributing--clone-the-repository` | other | — | Clone the repository | `CONTRIBUTING.md:30` | — | git clone https://github.com/tzervas/private-homelab.git |
| `contributing--open-in-vs-code-with-devcontainer` | other | — | Open in VS Code with devcontainer | `CONTRIBUTING.md:34` | — | code . |
| `contributing--select-reopen-in-container-when-prompted` | other | — | Select "Reopen in Container" when prompted | `CONTRIBUTING.md:36` | — | curl -LsSf https://astral.sh/uv/install.sh \| sh |
| `contributing--local-development-setup` | section | — | Local Development Setup | `CONTRIBUTING.md:39` | — | curl -LsSf https://astral.sh/uv/install.sh \| sh |
| `contributing--install-uv-package-manager` | other | — | Install UV package manager | `CONTRIBUTING.md:42` | — | curl -LsSf https://astral.sh/uv/install.sh \| sh |
| `contributing--create-virtual-environment` | other | — | Create virtual environment | `CONTRIBUTING.md:45` | — | uv venv |
| `contributing--activate-environment` | other | — | Activate environment | `CONTRIBUTING.md:48` | — | source .venv/bin/activate |
| `contributing--install-development-dependencies` | other | — | Install development dependencies | `CONTRIBUTING.md:51` | — | uv pip install -r requirements-dev.txt |
| `contributing--install-pre-commit-hooks` | other | — | Install pre-commit hooks | `CONTRIBUTING.md:54` | — | pre-commit install |
| `contributing--gpg-configuration` | section | — | GPG Configuration | `CONTRIBUTING.md:58` | — | All commits must be signed with GPG keys: |
| `contributing--configure-git-with-gpg-signing` | other | — | Configure Git with GPG signing | `CONTRIBUTING.md:63` | — | git config --global user.signingkey YOURGPGKEYID |
| `contributing--verify-gpg-configuration` | other | — | Verify GPG configuration | `CONTRIBUTING.md:68` | — | git config --list \| grep gpg |
| `contributing--security-guidelines` | section | — | Security Guidelines | `CONTRIBUTING.md:72` | — | 1. Never commit secrets: Use environment variables or Vault for sensitive data |
| `contributing--secure-development-practices` | section | — | Secure Development Practices | `CONTRIBUTING.md:74` | — | 1. Never commit secrets: Use environment variables or Vault for sensitive data |
| `contributing--security-scanning-requirements` | section | — | Security Scanning Requirements | `CONTRIBUTING.md:82` | — | All code must pass security scans before merging: |
| `contributing--run-security-scans-locally` | other | — | Run security scans locally | `CONTRIBUTING.md:87` | — | make security-scan |
| `contributing--individual-tool-commands` | other | — | Individual tool commands | `CONTRIBUTING.md:90` | — | bandit -r src/ |
| `contributing--vulnerability-management` | section | — | Vulnerability Management | `CONTRIBUTING.md:97` | — | - Critical vulnerabilities: Must be fixed within 24 hours |
| `contributing--code-standards` | section | — | Code Standards | `CONTRIBUTING.md:104` | — | This project adheres to PEP8 standards with Black formatting: |
| `contributing--python-standards` | section | — | Python Standards | `CONTRIBUTING.md:106` | — | This project adheres to PEP8 standards with Black formatting: |
| `contributing--format-code-with-black` | other | — | Format code with Black | `CONTRIBUTING.md:111` | — | black src/ tests/ |
| `contributing--type-checking-with-mypy` | other | — | Type checking with mypy | `CONTRIBUTING.md:114` | — | mypy src/ |
| `contributing--linting-with-flake8` | other | — | Linting with flake8 | `CONTRIBUTING.md:117` | — | flake8 src/ tests/ |
| `contributing--security-linting-with-bandit` | other | — | Security linting with bandit | `CONTRIBUTING.md:120` | — | bandit -r src/ |
| `contributing--type-hints` | section | — | Type Hints | `CONTRIBUTING.md:124` | — | All Python code must include comprehensive type hints: |
| `contributing--documentation-standards` | section | — | Documentation Standards | `CONTRIBUTING.md:154` | — | All functions and classes must include comprehensive docstrings: |
| `contributing--infrastructure-as-code-standards` | section | — | Infrastructure as Code Standards | `CONTRIBUTING.md:190` | — | - Use resource quotas and limits for all deployments |
| `contributing--kubernetes-manifests` | section | — | Kubernetes Manifests | `CONTRIBUTING.md:192` | — | - Use resource quotas and limits for all deployments |
| `contributing--helm-charts` | section | — | Helm Charts | `CONTRIBUTING.md:198` | — | - Parameterize all configuration values |
| `contributing--terraform-kustomize` | section | — | Terraform/Kustomize | `CONTRIBUTING.md:204` | — | - Use remote state with encryption |
| `contributing--pull-request-process` | section | — | Pull Request Process | `CONTRIBUTING.md:210` | — | We use GitFlow with feature branches and mandatory reviews: |
| `contributing--branch-strategy` | section | — | Branch Strategy | `CONTRIBUTING.md:212` | — | We use GitFlow with feature branches and mandatory reviews: |
| `contributing--create-feature-branch-from-main` | other | — | Create feature branch from main | `CONTRIBUTING.md:217` | — | git checkout -b feature/runner-controller-improvements |
| `contributing--make-changes-with-signed-commits` | other | — | Make changes with signed commits | `CONTRIBUTING.md:220` | — | git commit -S -m "feat(controller): improve runner scaling algorithm |
| `contributing--push-branch-and-create-pr` | other | — | Push branch and create PR | `CONTRIBUTING.md:229` | — | git push origin feature/runner-controller-improvements |
| `contributing--pull-request-requirements` | section | — | Pull Request Requirements | `CONTRIBUTING.md:233` | — | 1. Branch protection: All changes must go through pull requests |
| `contributing--commit-message-format` | section | — | Commit Message Format | `CONTRIBUTING.md:241` | — | Follow conventional commit standards with GPG signing: |
| `contributing--testing-requirements` | section | — | Testing Requirements | `CONTRIBUTING.md:270` | — | 1. Unit Tests: Minimum 90% code coverage |
| `contributing--test-categories` | section | — | Test Categories | `CONTRIBUTING.md:272` | — | 1. Unit Tests: Minimum 90% code coverage |
| `contributing--test-execution` | section | — | Test Execution | `CONTRIBUTING.md:280` | — | make test |
| `contributing--run-all-tests` | other | — | Run all tests | `CONTRIBUTING.md:283` | — | make test |
| `contributing--run-specific-test-categories` | other | — | Run specific test categories | `CONTRIBUTING.md:286` | — | make test-unit |
| `contributing--generate-coverage-report` | other | — | Generate coverage report | `CONTRIBUTING.md:292` | — | make coverage |
| `contributing--security-testing` | section | — | Security Testing | `CONTRIBUTING.md:296` | — | trivy image gitlab-runner-controller:latest |
| `contributing--container-security-scanning` | other | — | Container security scanning | `CONTRIBUTING.md:299` | — | trivy image gitlab-runner-controller:latest |
| `contributing--infrastructure-security-testing` | other | — | Infrastructure security testing | `CONTRIBUTING.md:302` | — | terraform plan -var-file=security-test.tfvars |
| `contributing--application-security-testing` | other | — | Application security testing | `CONTRIBUTING.md:306` | — | bandit -r src/ |
| `contributing--documentation-standards-2` | section | — | Documentation Standards | `CONTRIBUTING.md:311` | — | 1. API Documentation: Auto-generated from code comments |
| `contributing--required-documentation` | section | — | Required Documentation | `CONTRIBUTING.md:313` | — | 1. API Documentation: Auto-generated from code comments |
| `contributing--documentation-format` | section | — | Documentation Format | `CONTRIBUTING.md:321` | — | - Use Markdown for all documentation |
| `contributing--review-process` | section | — | Review Process | `CONTRIBUTING.md:329` | — | The project uses Sourcery AI for automated code reviews: |
| `contributing--automated-reviews` | section | — | Automated Reviews | `CONTRIBUTING.md:331` | — | The project uses Sourcery AI for automated code reviews: |
| `contributing--human-review-process` | section | — | Human Review Process | `CONTRIBUTING.md:340` | — | 1. Technical Review: Focus on architecture, performance, and security |
| `contributing--review-criteria` | section | — | Review Criteria | `CONTRIBUTING.md:347` | — | - [ ] Code follows established patterns and conventions |
| `contributing--resolving-review-comments` | section | — | Resolving Review Comments | `CONTRIBUTING.md:357` | — | 1. Address all comments: Respond to every review comment with resolution |
| `contributing--release-process` | section | — | Release Process | `CONTRIBUTING.md:365` | — | - Follow semantic versioning (MAJOR.MINOR.PATCH) |
| `contributing--version-management` | section | — | Version Management | `CONTRIBUTING.md:367` | — | - Follow semantic versioning (MAJOR.MINOR.PATCH) |
| `contributing--release-checklist` | section | — | Release Checklist | `CONTRIBUTING.md:374` | — | - [ ] All tests pass including security scans |
| `contributing--getting-help` | section | — | Getting Help | `CONTRIBUTING.md:384` | — | - GitHub Issues: Bug reports and feature requests |
| `contributing--communication-channels` | section | — | Communication Channels | `CONTRIBUTING.md:386` | — | - GitHub Issues: Bug reports and feature requests |
| `contributing--support-levels` | section | — | Support Levels | `CONTRIBUTING.md:393` | — | 1. Community Support: Best effort through GitHub issues |
| `contributing--code-of-conduct` | section | — | Code of Conduct | `CONTRIBUTING.md:400` | — | This project adheres to the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/codeofconduct/). |
| `readme` | other | — | 🏗️ Perihelion Infrastructure | `README.md:1` | — | Enterprise-Grade Kubernetes Infrastructure with Security-First GitLab CI/CD Platform |
| `readme--overview` | section | — | 📋 Overview | `README.md:12` | — | Perihelion Infrastructure delivers a comprehensive, production-ready Kubernetes platform featuring secure GitLab CI/CD automation, enterprise monitoring, and d… |
| `readme--platform-features` | section | — | 🎯 Platform Features | `README.md:16` | — | - 🔒 Security-First Architecture: Zero-trust networking, Pod Security Standards, comprehensive RBAC |
| `readme--platform-architecture` | section | — | 🏛️ Platform Architecture | `README.md:27` | — | Perihelion Infrastructure implements a comprehensive Kubernetes platform with: |
| `readme--core-infrastructure-components` | section | — | Core Infrastructure Components | `README.md:31` | — | - Intelligent Auto-Scaling: Dynamic runner provisioning based on queue depth and resource utilization |
| `readme--gitlab-runner-controller` | section | — | 🦊 GitLab Runner Controller | `README.md:33` | — | - Intelligent Auto-Scaling: Dynamic runner provisioning based on queue depth and resource utilization |
| `readme--monitoring-observability-stack` | section | — | 📊 Monitoring & Observability Stack | `README.md:39` | — | - Prometheus: High-availability metrics collection with 30-day retention |
| `readme--security-infrastructure` | section | — | 🔐 Security Infrastructure | `README.md:45` | — | - Network Policies: Default-deny with explicit allowlists for zero-trust networking |
| `readme--supporting-services` | section | — | 📋 Supporting Services | `README.md:51` | — | - Centralized Logging: Fluent Bit log collection with security classification |
| `readme--security-features` | section | — | 🛡️ Security Features | `README.md:57` | — | - Network Segmentation: Strict namespace isolation with network policies |
| `readme--defense-in-depth-architecture` | section | — | Defense-in-Depth Architecture | `README.md:59` | — | - Network Segmentation: Strict namespace isolation with network policies |
| `readme--attack-surface-minimization` | section | — | Attack Surface Minimization | `README.md:65` | — | - Minimal Images: Distroless containers with no unnecessary packages |
| `readme--compliance-monitoring` | section | — | Compliance & Monitoring | `README.md:71` | — | - Security Dashboards: Real-time threat detection and compliance monitoring |
| `readme--project-status` | section | — | 🚀 Project Status | `README.md:77` | — | - GitLab Runner Controller: Full implementation with security hardening |
| `readme--completed-components` | section | — | ✅ Completed Components | `README.md:79` | — | - GitLab Runner Controller: Full implementation with security hardening |
| `readme--in-progress` | section | — | 🔄 In Progress | `README.md:87` | — | - Supporting Services: Vault integration and centralized logging (current branch: feature/supporting-services) |
| `readme--upcoming` | section | — | 📋 Upcoming | `README.md:93` | — | - Production Deployment: Full production rollout with monitoring |
| `readme--quick-start` | section | — | Quick Start | `README.md:99` | — | git clone https://github.com/tzervas/perihelion-auth-manager.git |
| `readme--clone-the-repository` | other | — | Clone the repository | `README.md:102` | — | git clone https://github.com/tzervas/perihelion-auth-manager.git |
| `readme--install-dependencies-with-uv` | other | — | Install dependencies with UV | `README.md:106` | — | uv venv |
| `readme--deploy-with-helm-or-kustomize` | other | — | Deploy with Helm or Kustomize | `README.md:111` | — | helm install perihelion-infrastructure helm/gitlab-runner-controller/ |
| `readme--or` | other | — | OR | `README.md:113` | — | kubectl apply -k k8s/ |
| `readme--documentation` | section | — | Documentation | `README.md:117` | — | - [Implementation Plan](docs/gitlabimplementationplan.md) - Detailed project execution plan |
| `readme--license` | section | — | License | `README.md:125` | — | MIT License - see [LICENSE](LICENSE) file for details. |
| `readme--contributing` | section | — | Contributing | `README.md:129` | — | Please see [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines and development setup instructions. |
| `readme--maintainers` | section | — | Maintainers | `README.md:133` | — | - Tyler Zervas (@tzervas) |
| `readme--security` | section | — | Security | `README.md:137` | — | For security issues, please see our [Security Policy](SECURITY.md) or contact security@company.com. |
| `security` | section | — | Security Policy | `SECURITY.md:1` | — | The Private Homelab GitLab Infrastructure project takes security seriously. This document outlines our security practices, vulnerability reporting procedures,… |
| `security--overview` | section | — | Overview | `SECURITY.md:3` | — | The Private Homelab GitLab Infrastructure project takes security seriously. This document outlines our security practices, vulnerability reporting procedures,… |
| `security--supported-versions` | section | — | Supported Versions | `SECURITY.md:7` | — | We provide security updates for the following versions: |
| `security--security-model` | section | — | Security Model | `SECURITY.md:17` | — | Our security architecture implements multiple layers of protection: |
| `security--defense-in-depth` | section | — | Defense in Depth | `SECURITY.md:19` | — | Our security architecture implements multiple layers of protection: |
| `security--threat-model` | section | — | Threat Model | `SECURITY.md:30` | — | We defend against the following threat vectors: |
| `security--reporting-security-vulnerabilities` | section | — | Reporting Security Vulnerabilities | `SECURITY.md:41` | — | For sensitive security issues, please report privately to: |
| `security--private-disclosure` | section | — | Private Disclosure | `SECURITY.md:43` | — | For sensitive security issues, please report privately to: |
| `security--what-to-include` | section | — | What to Include | `SECURITY.md:51` | — | When reporting a vulnerability, please include: |
| `security--example-report` | section | — | Example Report | `SECURITY.md:61` | — | Subject: [SECURITY] Container Privilege Escalation in Runner Controller |
| `security--security-response-process` | section | — | Security Response Process | `SECURITY.md:89` | — | - Security reports are acknowledged within 24 hours |
| `security--acknowledgment` | section | — | Acknowledgment | `SECURITY.md:91` | — | - Security reports are acknowledged within 24 hours |
| `security--assessment-criteria` | section | — | Assessment Criteria | `SECURITY.md:97` | — | 1. Day 0: Vulnerability reported privately |
| `security--disclosure-timeline` | section | — | Disclosure Timeline | `SECURITY.md:106` | — | 1. Day 0: Vulnerability reported privately |
| `security--security-best-practices` | section | — | Security Best Practices | `SECURITY.md:114` | — | make security-scan |
| `security--for-contributors` | section | — | For Contributors | `SECURITY.md:116` | — | make security-scan |
| `security--secure-development` | section | — | Secure Development | `SECURITY.md:118` | — | make security-scan |
| `security--always-use-security-scanners-before-commits` | other | — | Always use security scanners before commits | `SECURITY.md:121` | — | make security-scan |
| `security--sign-all-commits-with-gpg` | other | — | Sign all commits with GPG | `SECURITY.md:124` | — | git commit -S -m "security: implement input validation" |
| `security--use-pre-commit-hooks-for-security-checks` | other | — | Use pre-commit hooks for security checks | `SECURITY.md:127` | — | pre-commit install |
| `security--code-security` | section | — | Code Security | `SECURITY.md:131` | — | def processuserinput(data: str) -> bool: |
| `security--always-validate-inputs-with-type-hints` | other | — | Always validate inputs with type hints | `SECURITY.md:134` | — | def processuserinput(data: str) -> bool: |
| `security--never-log-sensitive-information` | other | — | Never log sensitive information | `SECURITY.md:149` | — | logger.info(f"Processing request for user {userid}")  # OK |
| `security--use-secrets-management-for-credentials` | other | — | Use secrets management for credentials | `SECURITY.md:153` | — | password = getsecretfromvault("database/password") |
| `security--for-deployments` | section | — | For Deployments | `SECURITY.md:157` | — | securityContext: |
| `security--container-security` | section | — | Container Security | `SECURITY.md:159` | — | securityContext: |
| `security--security-context-for-all-containers` | other | — | Security context for all containers | `SECURITY.md:162` | — | securityContext: |
| `security--resource-limits-to-prevent-dos` | other | — | Resource limits to prevent DoS | `SECURITY.md:175` | — | resources: |
| `security--network-security` | section | — | Network Security | `SECURITY.md:186` | — | apiVersion: networking.k8s.io/v1 |
| `security--default-deny-network-policy` | other | — | Default deny network policy | `SECURITY.md:189` | — | apiVersion: networking.k8s.io/v1 |
| `security--specific-allow-rules-only` | other | — | Specific allow rules only | `SECURITY.md:200` | — | apiVersion: networking.k8s.io/v1 |
| `security--security-tools-and-automation` | section | — | Security Tools and Automation | `SECURITY.md:221` | — | — |
| `security--required-security-tools` | section | — | Required Security Tools | `SECURITY.md:223` | — | — |
| `security--automated-security-scanning` | section | — | Automated Security Scanning | `SECURITY.md:234` | — | name: Security Scan |
| `security--github-actions-security-workflow` | other | — | GitHub Actions security workflow | `SECURITY.md:237` | — | name: Security Scan |
| `security--incident-response` | section | — | Incident Response | `SECURITY.md:266` | — | - Active security breach or compromise |
| `security--security-incident-classification` | section | — | Security Incident Classification | `SECURITY.md:268` | — | - Active security breach or compromise |
| `security--level-1-critical` | section | — | Level 1 - Critical | `SECURITY.md:270` | — | - Active security breach or compromise |
| `security--level-2-high` | section | — | Level 2 - High | `SECURITY.md:275` | — | - Potential security vulnerability exploitation |
| `security--level-3-medium` | section | — | Level 3 - Medium | `SECURITY.md:280` | — | - Security policy violations |
| `security--response-procedures` | section | — | Response Procedures | `SECURITY.md:285` | — | 1. Assess: Determine scope and impact |
| `security--immediate-response-0-1-hour` | section | — | Immediate Response (0-1 hour) | `SECURITY.md:287` | — | 1. Assess: Determine scope and impact |
| `security--investigation-phase-1-24-hours` | section | — | Investigation Phase (1-24 hours) | `SECURITY.md:293` | — | 1. Collect: Gather logs and forensic evidence |
| `security--recovery-phase-24-72-hours` | section | — | Recovery Phase (24-72 hours) | `SECURITY.md:299` | — | 1. Remediate: Apply patches and fixes |
| `security--post-incident-1-2-weeks` | section | — | Post-Incident (1-2 weeks) | `SECURITY.md:305` | — | 1. Review: Conduct post-incident review |
| `security--emergency-contacts` | section | — | Emergency Contacts | `SECURITY.md:311` | — | — |
| `security--compliance-and-auditing` | section | — | Compliance and Auditing | `SECURITY.md:320` | — | We align with the following security standards: |
| `security--compliance-frameworks` | section | — | Compliance Frameworks | `SECURITY.md:322` | — | We align with the following security standards: |
| `security--audit-requirements` | section | — | Audit Requirements | `SECURITY.md:332` | — | - Monthly: Security configuration reviews |
| `security--internal-audits` | section | — | Internal Audits | `SECURITY.md:334` | — | - Monthly: Security configuration reviews |
| `security--external-audits` | section | — | External Audits | `SECURITY.md:339` | — | - Annually: Third-party penetration testing |
| `security--security-metrics` | section | — | Security Metrics | `SECURITY.md:344` | — | We track the following security metrics: |
| `security--security-awareness` | section | — | Security Awareness | `SECURITY.md:354` | — | All contributors must complete: |
| `security--training-requirements` | section | — | Training Requirements | `SECURITY.md:356` | — | All contributors must complete: |
| `security--security-champions` | section | — | Security Champions | `SECURITY.md:365` | — | Each team should have designated security champions responsible for: |
| `security--updates-to-this-policy` | section | — | Updates to This Policy | `SECURITY.md:374` | — | This security policy is reviewed and updated: |
| `security--contact-information` | section | — | Contact Information | `SECURITY.md:387` | — | For questions about this security policy: |
| `roadmap` | note | — | perihelion-infrastructure — Roadmap | `docs/ROADMAP.md:1` | Living (2026-07-09) | Status: Living (2026-07-09) |
| `roadmap--current-state-per-readme-tero` | section | — | Current State (per README + tero) | `docs/ROADMAP.md:10` | — | - GitLab Runner Controller (src/gitlabrunnercontroller/): auto-scaling, hardened |
| `roadmap--hygiene-tero` | section | — | Hygiene + Tero | `docs/ROADMAP.md:21` | — | - scripts/check.sh added (modeled on cabal-devmelopner + search-box; handles requirements.txt + requirements-dev.txt + pyproject, uv/venv, pytest (unit+securit… |
| `roadmap--waves-minimal-hygiene-focus` | section | — | Waves (minimal / hygiene focus) | `docs/ROADMAP.md:30` | — | - [plan.md](../../plan.md) (priority 1 thin + peri py infra) |
| `roadmap--links` | section | — | Links | `docs/ROADMAP.md:39` | — | - [plan.md](../../plan.md) (priority 1 thin + peri py infra) |
| `roadmap--semver-distribution-build-chore-semver-ghcr-distribution-build-appended` | section | — | Semver + Distribution Build (chore/semver-ghcr-distribution-build appended) | `docs/ROADMAP.md:52` | — | - Established baseline from git history + docs (initial pyproject 0.1.0, no prior releases; CONTRIBUTING mandates semver MAJOR.MINOR.PATCH + GPG signed tags +… |
| `gitlabarchitecturecore` | section | — | GitLab Self-Hosted Infrastructure: Architecture and Core Components v3.0 | `docs/gitlab_architecture_core.md:1` | — | This specification defines the foundational architecture and core components for a production-grade GitLab deployment. The system implements a three-tier archi… |
| `gitlabarchitecturecore--executive-summary` | section | — | Executive Summary | `docs/gitlab_architecture_core.md:3` | — | This specification defines the foundational architecture and core components for a production-grade GitLab deployment. The system implements a three-tier archi… |
| `gitlabarchitecturecore--system-architecture-overview` | section | — | System Architecture Overview | `docs/gitlab_architecture_core.md:7` | — | The infrastructure employs a load balancer-centric architecture utilizing defense-in-depth security principles and Infrastructure as Code methodologies. |
| `gitlabarchitecturecore--architectural-pattern` | section | — | Architectural Pattern | `docs/gitlab_architecture_core.md:9` | — | The infrastructure employs a load balancer-centric architecture utilizing defense-in-depth security principles and Infrastructure as Code methodologies. |
| `gitlabarchitecturecore--design-principles` | section | — | Design Principles | `docs/gitlab_architecture_core.md:40` | — | - Separation of Concerns: Each tier maintains distinct responsibilities |
| `gitlabarchitecturecore--load-balancer-configuration` | section | — | Load Balancer Configuration | `docs/gitlab_architecture_core.md:47` | — | The load balancer tier provides high availability and traffic distribution capabilities. |
| `gitlabarchitecturecore--technical-specifications` | section | — | Technical Specifications | `docs/gitlab_architecture_core.md:49` | — | The load balancer tier provides high availability and traffic distribution capabilities. |
| `gitlabarchitecturecore--high-availability-features` | section | — | High Availability Features | `docs/gitlab_architecture_core.md:87` | — | - Active-Passive Clustering: Automatic failover between load balancer instances |
| `gitlabarchitecturecore--gitlab-core-services` | section | — | GitLab Core Services | `docs/gitlab_architecture_core.md:94` | — | The application tier hosts GitLab components with resource allocation optimized for production workloads. |
| `gitlabarchitecturecore--deployment-architecture` | section | — | Deployment Architecture | `docs/gitlab_architecture_core.md:96` | — | The application tier hosts GitLab components with resource allocation optimized for production workloads. |
| `gitlabarchitecturecore--service-dependencies` | section | — | Service Dependencies | `docs/gitlab_architecture_core.md:150` | — | - Database Layer: PostgreSQL cluster with synchronous replication |
| `gitlabarchitecturecore--dynamic-runner-infrastructure` | section | — | Dynamic Runner Infrastructure | `docs/gitlab_architecture_core.md:157` | — | The runner tier provides elastic compute capacity for CI/CD pipeline execution. |
| `gitlabarchitecturecore--runner-pool-configuration` | section | — | Runner Pool Configuration | `docs/gitlab_architecture_core.md:159` | — | The runner tier provides elastic compute capacity for CI/CD pipeline execution. |
| `gitlabarchitecturecore--scaling-behavior` | section | — | Scaling Behavior | `docs/gitlab_architecture_core.md:209` | — | - Demand-Based Scaling: Automatic scaling based on job queue depth |
| `gitlabarchitecturecore--horizontal-pod-autoscaling` | section | — | Horizontal Pod Autoscaling | `docs/gitlab_architecture_core.md:216` | — | horizontalscaling: |
| `gitlabarchitecturecore--scaling-specifications` | section | — | Scaling Specifications | `docs/gitlab_architecture_core.md:218` | — | horizontalscaling: |
| `gitlabarchitecturecore--vertical-pod-autoscaling` | section | — | Vertical Pod Autoscaling | `docs/gitlab_architecture_core.md:263` | — | verticalscaling: |
| `gitlabarchitecturecore--resource-optimization` | section | — | Resource Optimization | `docs/gitlab_architecture_core.md:265` | — | verticalscaling: |
| `gitlabarchitecturecore--configuration-management-structure` | section | — | Configuration Management Structure | `docs/gitlab_architecture_core.md:285` | — | infrastructure/ |
| `gitlabarchitecturecore--gitops-repository-layout` | section | — | GitOps Repository Layout | `docs/gitlab_architecture_core.md:287` | — | infrastructure/ |
| `gitlabarchitecturecore--validation-and-testing` | section | — | Validation and Testing | `docs/gitlab_architecture_core.md:320` | — | healthchecks: |
| `gitlabarchitecturecore--component-health-checks` | section | — | Component Health Checks | `docs/gitlab_architecture_core.md:322` | — | healthchecks: |
| `gitlabarchitecturecore--performance-baselines` | section | — | Performance Baselines | `docs/gitlab_architecture_core.md:343` | — | - Request Latency: P95 latency under 500ms for web requests |
| `gitlabarchitecturecore--dependencies-and-integration-points` | section | — | Dependencies and Integration Points | `docs/gitlab_architecture_core.md:350` | — | - DNS Resolution: Requires valid DNS entries for service discovery |
| `gitlabarchitecturecore--external-dependencies` | section | — | External Dependencies | `docs/gitlab_architecture_core.md:352` | — | - DNS Resolution: Requires valid DNS entries for service discovery |
| `gitlabarchitecturecore--internal-dependencies` | section | — | Internal Dependencies | `docs/gitlab_architecture_core.md:359` | — | - Kubernetes Platform: Requires functional Kubernetes cluster |
| `gitlabimplementationplan` | section | — | GitLab Infrastructure Implementation Task List and Project Plan v3.0 | `docs/gitlab_implementation_plan.md:1` | — | This document provides a comprehensive implementation guide for deploying GitLab infrastructure as specified in the architectural documentation. Tasks are orga… |
| `gitlabimplementationplan--project-overview` | section | — | Project Overview | `docs/gitlab_implementation_plan.md:3` | — | This document provides a comprehensive implementation guide for deploying GitLab infrastructure as specified in the architectural documentation. Tasks are orga… |
| `gitlabimplementationplan--task-management-framework` | section | — | Task Management Framework | `docs/gitlab_implementation_plan.md:7` | — | Task Identification Structure |
| `gitlabimplementationplan--notation-system` | section | — | Notation System | `docs/gitlab_implementation_plan.md:9` | — | Task Identification Structure |
| `gitlabimplementationplan--project-constraints` | section | — | Project Constraints | `docs/gitlab_implementation_plan.md:18` | — | Timeline Parameters |
| `gitlabimplementationplan--phase-1-foundation-infrastructure-p0` | section | — | Phase 1: Foundation Infrastructure [P0] | `docs/gitlab_implementation_plan.md:26` | — | Dependencies: None |
| `gitlabimplementationplan--1.1-system-preparation` | section | — | 1.1 System Preparation | `docs/gitlab_implementation_plan.md:28` | — | Dependencies: None |
| `gitlabimplementationplan--1.1.1-operating-system-hardening-p0` | section | — | 1.1.1 Operating System Hardening [P0] | `docs/gitlab_implementation_plan.md:30` | — | Dependencies: None |
| `gitlabimplementationplan--security-assessment-command` | other | — | Security assessment command | `docs/gitlab_implementation_plan.md:54` | — | lynis audit system --quiet \| grep "Hardening index" |
| `gitlabimplementationplan--expected-output-hardening-index-85-or-higher` | other | — | Expected output: Hardening index : 85 or higher | `docs/gitlab_implementation_plan.md:56` | — | systemctl status auditd firewalld chronyd |
| `gitlabimplementationplan--service-validation` | other | — | Service validation | `docs/gitlab_implementation_plan.md:58` | — | systemctl status auditd firewalld chronyd |
| `gitlabimplementationplan--expected-all-services-active-and-enabled` | other | — | Expected: All services active and enabled | `docs/gitlab_implementation_plan.md:60` | — | Deliverables: |
| `gitlabimplementationplan--1.1.2-container-runtime-installation-p0` | section | — | 1.1.2 Container Runtime Installation [P0] | `docs/gitlab_implementation_plan.md:69` | — | Dependencies: [1.1.1] |
| `gitlabimplementationplan--1.1.3-tls-certificate-infrastructure-p0` | section | — | 1.1.3 TLS Certificate Infrastructure [P0] | `docs/gitlab_implementation_plan.md:101` | — | Dependencies: [1.1.1] |
| `gitlabimplementationplan--phase-2-kubernetes-platform-p0` | section | — | Phase 2: Kubernetes Platform [P0] | `docs/gitlab_implementation_plan.md:134` | — | Dependencies: [1.1.2] |
| `gitlabimplementationplan--2.1-cluster-deployment` | section | — | 2.1 Cluster Deployment | `docs/gitlab_implementation_plan.md:136` | — | Dependencies: [1.1.2] |
| `gitlabimplementationplan--2.1.1-k3s-installation-and-hardening-p0` | section | — | 2.1.1 K3s Installation and Hardening [P0] | `docs/gitlab_implementation_plan.md:138` | — | Dependencies: [1.1.2] |
| `gitlabimplementationplan--2.1.2-storage-provider-configuration-p1` | section | — | 2.1.2 Storage Provider Configuration [P1] | `docs/gitlab_implementation_plan.md:173` | — | Dependencies: [2.1.1] |
| `gitlabimplementationplan--2.1.3-network-infrastructure-p0` | section | — | 2.1.3 Network Infrastructure [P0] | `docs/gitlab_implementation_plan.md:209` | — | Dependencies: [2.1.1] |
| `gitlabimplementationplan--phase-3-load-balancer-infrastructure-p0` | section | — | Phase 3: Load Balancer Infrastructure [P0] | `docs/gitlab_implementation_plan.md:244` | — | Dependencies: [2.1.3] |
| `gitlabimplementationplan--3.1-haproxy-deployment` | section | — | 3.1 HAProxy Deployment | `docs/gitlab_implementation_plan.md:246` | — | Dependencies: [2.1.3] |
| `gitlabimplementationplan--3.1.1-load-balancer-cluster-setup-p0` | section | — | 3.1.1 Load Balancer Cluster Setup [P0] | `docs/gitlab_implementation_plan.md:248` | — | Dependencies: [2.1.3] |
| `gitlabimplementationplan--3.1.2-ssl-termination-configuration-p0` | section | — | 3.1.2 SSL Termination Configuration [P0] | `docs/gitlab_implementation_plan.md:286` | — | Dependencies: [3.1.1, 1.1.3] |
| `gitlabimplementationplan--phase-4-gitops-platform-p0` | section | — | Phase 4: GitOps Platform [P0] | `docs/gitlab_implementation_plan.md:322` | — | Dependencies: [2.1.3] |
| `gitlabimplementationplan--4.1-argocd-implementation` | section | — | 4.1 ArgoCD Implementation | `docs/gitlab_implementation_plan.md:324` | — | Dependencies: [2.1.3] |
| `gitlabimplementationplan--4.1.1-argocd-deployment-p0` | section | — | 4.1.1 ArgoCD Deployment [P0] | `docs/gitlab_implementation_plan.md:326` | — | Dependencies: [2.1.3] |
| `gitlabimplementationplan--4.1.2-repository-structure-creation-p1` | section | — | 4.1.2 Repository Structure Creation [P1] | `docs/gitlab_implementation_plan.md:364` | — | Dependencies: [4.1.1] |
| `gitlabimplementationplan--phase-5-supporting-services-p1` | section | — | Phase 5: Supporting Services [P1] | `docs/gitlab_implementation_plan.md:402` | — | Dependencies: [2.1.2] |
| `gitlabimplementationplan--5.1-secret-management` | section | — | 5.1 Secret Management | `docs/gitlab_implementation_plan.md:404` | — | Dependencies: [2.1.2] |
| `gitlabimplementationplan--5.1.1-hashicorp-vault-deployment-p1` | section | — | 5.1.1 HashiCorp Vault Deployment [P1] | `docs/gitlab_implementation_plan.md:406` | — | Dependencies: [2.1.2] |
| `gitlabimplementationplan--5.1.2-secret-generation-pipeline-p1` | section | — | 5.1.2 Secret Generation Pipeline [P1] | `docs/gitlab_implementation_plan.md:446` | — | Dependencies: [5.1.1] |
| `gitlabimplementationplan--5.2-object-storage` | section | — | 5.2 Object Storage | `docs/gitlab_implementation_plan.md:487` | — | Dependencies: [2.1.2] |
| `gitlabimplementationplan--5.2.1-minio-cluster-deployment-p1` | section | — | 5.2.1 MinIO Cluster Deployment [P1] | `docs/gitlab_implementation_plan.md:489` | — | Dependencies: [2.1.2] |
| `gitlabimplementationplan--phase-6-gitlab-deployment-p0` | section | — | Phase 6: GitLab Deployment [P0] | `docs/gitlab_implementation_plan.md:528` | — | Dependencies: [4.1.2, 5.1.2, 5.2.1] |
| `gitlabimplementationplan--6.1-core-services` | section | — | 6.1 Core Services | `docs/gitlab_implementation_plan.md:530` | — | Dependencies: [4.1.2, 5.1.2, 5.2.1] |
| `gitlabimplementationplan--6.1.1-gitlab-installation-p0` | section | — | 6.1.1 GitLab Installation [P0] | `docs/gitlab_implementation_plan.md:532` | — | Dependencies: [4.1.2, 5.1.2, 5.2.1] |
| `gitlabimplementationplan--6.1.2-runner-controller-development-p0` | section | — | 6.1.2 Runner Controller Development [P0] | `docs/gitlab_implementation_plan.md:579` | — | Dependencies: [6.1.1] |
| `gitlabimplementationplan--phase-7-observability-stack-p1` | section | — | Phase 7: Observability Stack [P1] | `docs/gitlab_implementation_plan.md:617` | — | Dependencies: [6.1.1] |
| `gitlabimplementationplan--7.1-monitoring-infrastructure` | section | — | 7.1 Monitoring Infrastructure | `docs/gitlab_implementation_plan.md:619` | — | Dependencies: [6.1.1] |
| `gitlabimplementationplan--7.1.1-prometheus-and-grafana-setup-p1` | section | — | 7.1.1 Prometheus and Grafana Setup [P1] | `docs/gitlab_implementation_plan.md:621` | — | Dependencies: [6.1.1] |
| `gitlabimplementationplan--7.1.2-log-aggregation-pipeline-p1` | section | — | 7.1.2 Log Aggregation Pipeline [P1] | `docs/gitlab_implementation_plan.md:664` | — | Dependencies: [7.1.1] |
| `gitlabimplementationplan--phase-8-production-readiness-p1` | section | — | Phase 8: Production Readiness [P1] | `docs/gitlab_implementation_plan.md:703` | — | Dependencies: [6.1.2] |
| `gitlabimplementationplan--8.1-testing-and-validation` | section | — | 8.1 Testing and Validation | `docs/gitlab_implementation_plan.md:705` | — | Dependencies: [6.1.2] |
| `gitlabimplementationplan--8.1.1-load-testing-suite-p2` | section | — | 8.1.1 Load Testing Suite [P2] | `docs/gitlab_implementation_plan.md:707` | — | Dependencies: [6.1.2] |
| `gitlabimplementationplan--8.1.2-security-audit-p1` | section | — | 8.1.2 Security Audit [P1] | `docs/gitlab_implementation_plan.md:741` | — | Dependencies: [8.1.1] |
| `gitlabimplementationplan--phase-9-documentation-and-training-p2` | section | — | Phase 9: Documentation and Training [P2] | `docs/gitlab_implementation_plan.md:765` | — | Dependencies: [8.1.2] |
| `gitlabimplementationplan--9.1-documentation-suite` | section | — | 9.1 Documentation Suite | `docs/gitlab_implementation_plan.md:767` | — | Dependencies: [8.1.2] |
| `gitlabimplementationplan--9.1.1-operational-documentation-p2` | section | — | 9.1.1 Operational Documentation [P2] | `docs/gitlab_implementation_plan.md:769` | — | Dependencies: [8.1.2] |
| `gitlabimplementationplan--9.1.2-knowledge-transfer-p2` | section | — | 9.1.2 Knowledge Transfer [P2] | `docs/gitlab_implementation_plan.md:800` | — | Dependencies: [9.1.1] |
| `gitlabimplementationplan--critical-path-analysis` | section | — | Critical Path Analysis | `docs/gitlab_implementation_plan.md:825` | — | The critical path encompasses tasks that directly impact production readiness and project timeline: |
| `gitlabimplementationplan--project-dependencies` | section | — | Project Dependencies | `docs/gitlab_implementation_plan.md:827` | — | The critical path encompasses tasks that directly impact production readiness and project timeline: |
| `gitlabimplementationplan--resource-allocation` | section | — | Resource Allocation | `docs/gitlab_implementation_plan.md:835` | — | Team Composition Requirements: |
| `gitlabimplementationplan--risk-mitigation-strategies` | section | — | Risk Mitigation Strategies | `docs/gitlab_implementation_plan.md:845` | — | Technical Risks: |
| `gitlabimplementationplan--r1.-disaster-recovery-planning-p1` | section | — | R1. Disaster Recovery Planning [P1] | `docs/gitlab_implementation_plan.md:859` | — | Effort: 5 |
| `gitlabimplementationplan--r2.-capacity-planning-p2` | section | — | R2. Capacity Planning [P2] | `docs/gitlab_implementation_plan.md:868` | — | Effort: 3 |
| `gitlabimplementationplan--r3.-compliance-framework-p2` | section | — | R3. Compliance Framework [P2] | `docs/gitlab_implementation_plan.md:877` | — | Effort: 5 |
| `gitlabobservabilityoperations` | section | — | GitLab Observability and Operations v3.0 | `docs/gitlab_observability_operations.md:1` | — | This document establishes comprehensive monitoring, logging, and operational procedures for GitLab infrastructure. The observability framework implements the t… |
| `gitlabobservabilityoperations--observability-architecture` | section | — | Observability Architecture | `docs/gitlab_observability_operations.md:3` | — | This document establishes comprehensive monitoring, logging, and operational procedures for GitLab infrastructure. The observability framework implements the t… |
| `gitlabobservabilityoperations--metrics-collection-infrastructure` | section | — | Metrics Collection Infrastructure | `docs/gitlab_observability_operations.md:7` | — | Prometheus serves as the primary metrics collection and storage system with long-term retention capabilities. |
| `gitlabobservabilityoperations--prometheus-configuration` | section | — | Prometheus Configuration | `docs/gitlab_observability_operations.md:9` | — | Prometheus serves as the primary metrics collection and storage system with long-term retention capabilities. |
| `gitlabobservabilityoperations--custom-metrics-definition` | section | — | Custom Metrics Definition | `docs/gitlab_observability_operations.md:78` | — | custommetrics: |
| `gitlabobservabilityoperations--thanos-long-term-storage` | section | — | Thanos Long-term Storage | `docs/gitlab_observability_operations.md:117` | — | thanos: |
| `gitlabobservabilityoperations--visualization-and-dashboards` | section | — | Visualization and Dashboards | `docs/gitlab_observability_operations.md:150` | — | grafana: |
| `gitlabobservabilityoperations--grafana-configuration` | section | — | Grafana Configuration | `docs/gitlab_observability_operations.md:152` | — | grafana: |
| `gitlabobservabilityoperations--distributed-tracing` | section | — | Distributed Tracing | `docs/gitlab_observability_operations.md:225` | — | jaeger: |
| `gitlabobservabilityoperations--jaeger-implementation` | section | — | Jaeger Implementation | `docs/gitlab_observability_operations.md:227` | — | jaeger: |
| `gitlabobservabilityoperations--application-instrumentation` | section | — | Application Instrumentation | `docs/gitlab_observability_operations.md:270` | — | tracingconfiguration: |
| `gitlabobservabilityoperations--log-aggregation-pipeline` | section | — | Log Aggregation Pipeline | `docs/gitlab_observability_operations.md:293` | — | fluentbit: |
| `gitlabobservabilityoperations--fluent-bit-configuration` | section | — | Fluent Bit Configuration | `docs/gitlab_observability_operations.md:295` | — | fluentbit: |
| `gitlabobservabilityoperations--log-processing-rules` | section | — | Log Processing Rules | `docs/gitlab_observability_operations.md:347` | — | logprocessing: |
| `gitlabobservabilityoperations--alerting-framework` | section | — | Alerting Framework | `docs/gitlab_observability_operations.md:382` | — | alertrules: |
| `gitlabobservabilityoperations--alert-rules-configuration` | section | — | Alert Rules Configuration | `docs/gitlab_observability_operations.md:384` | — | alertrules: |
| `gitlabobservabilityoperations--notification-channels` | section | — | Notification Channels | `docs/gitlab_observability_operations.md:447` | — | alertmanager: |
| `gitlabobservabilityoperations--operational-procedures` | section | — | Operational Procedures | `docs/gitlab_observability_operations.md:499` | — | backupoperations: |
| `gitlabobservabilityoperations--backup-and-recovery-operations` | section | — | Backup and Recovery Operations | `docs/gitlab_observability_operations.md:501` | — | backupoperations: |
| `gitlabobservabilityoperations--incident-response-procedures` | section | — | Incident Response Procedures | `docs/gitlab_observability_operations.md:557` | — | incidentresponse: |
| `gitlabobservabilityoperations--maintenance-procedures` | section | — | Maintenance Procedures | `docs/gitlab_observability_operations.md:610` | — | maintenanceoperations: |
| `gitlabsecuritynetwork` | section | — | GitLab Security and Network Configuration v3.0 | `docs/gitlab_security_network.md:1` | — | This document establishes comprehensive security controls and network isolation policies for GitLab infrastructure deployment. The security model implements de… |
| `gitlabsecuritynetwork--security-architecture-overview` | section | — | Security Architecture Overview | `docs/gitlab_security_network.md:3` | — | This document establishes comprehensive security controls and network isolation policies for GitLab infrastructure deployment. The security model implements de… |
| `gitlabsecuritynetwork--network-security-framework` | section | — | Network Security Framework | `docs/gitlab_security_network.md:7` | — | The network topology segregates components into distinct security zones with controlled communication pathways. |
| `gitlabsecuritynetwork--security-zone-architecture` | section | — | Security Zone Architecture | `docs/gitlab_security_network.md:9` | — | The network topology segregates components into distinct security zones with controlled communication pathways. |
| `gitlabsecuritynetwork--network-policy-implementation` | section | — | Network Policy Implementation | `docs/gitlab_security_network.md:41` | — | Kubernetes network policies enforce microsegmentation at the pod level. |
| `gitlabsecuritynetwork--transport-layer-security` | section | — | Transport Layer Security | `docs/gitlab_security_network.md:118` | — | Comprehensive TLS implementation ensures encrypted communication across all service endpoints. |
| `gitlabsecuritynetwork--ssl-tls-configuration` | section | — | SSL/TLS Configuration | `docs/gitlab_security_network.md:120` | — | Comprehensive TLS implementation ensures encrypted communication across all service endpoints. |
| `gitlabsecuritynetwork--certificate-authority-integration` | section | — | Certificate Authority Integration | `docs/gitlab_security_network.md:160` | — | certificateauthority: |
| `gitlabsecuritynetwork--authentication-and-authorization` | section | — | Authentication and Authorization | `docs/gitlab_security_network.md:185` | — | RBAC implementation provides granular permission management across system components. |
| `gitlabsecuritynetwork--role-based-access-control` | section | — | Role-Based Access Control | `docs/gitlab_security_network.md:187` | — | RBAC implementation provides granular permission management across system components. |
| `gitlabsecuritynetwork--multi-factor-authentication` | section | — | Multi-Factor Authentication | `docs/gitlab_security_network.md:238` | — | authenticationmethods: |
| `gitlabsecuritynetwork--container-security` | section | — | Container Security | `docs/gitlab_security_network.md:266` | — | Implementation of Pod Security Standards ensures container-level security controls. |
| `gitlabsecuritynetwork--pod-security-standards` | section | — | Pod Security Standards | `docs/gitlab_security_network.md:268` | — | Implementation of Pod Security Standards ensures container-level security controls. |
| `gitlabsecuritynetwork--container-image-security` | section | — | Container Image Security | `docs/gitlab_security_network.md:316` | — | imagesecurity: |
| `gitlabsecuritynetwork--secret-management-integration` | section | — | Secret Management Integration | `docs/gitlab_security_network.md:348` | — | HashiCorp Vault provides centralized secret management with dynamic secret generation. |
| `gitlabsecuritynetwork--vault-configuration` | section | — | Vault Configuration | `docs/gitlab_security_network.md:350` | — | HashiCorp Vault provides centralized secret management with dynamic secret generation. |
| `gitlabsecuritynetwork--network-segmentation` | section | — | Network Segmentation | `docs/gitlab_security_network.md:395` | — | firewallconfiguration: |
| `gitlabsecuritynetwork--firewall-rules` | section | — | Firewall Rules | `docs/gitlab_security_network.md:397` | — | firewallconfiguration: |
| `gitlabsecuritynetwork--security-monitoring` | section | — | Security Monitoring | `docs/gitlab_security_network.md:434` | — | auditconfiguration: |
| `gitlabsecuritynetwork--audit-logging` | section | — | Audit Logging | `docs/gitlab_security_network.md:436` | — | auditconfiguration: |
| `gitlabsecuritynetwork--intrusion-detection` | section | — | Intrusion Detection | `docs/gitlab_security_network.md:466` | — | intrusiondetection: |
| `gitlabsecuritynetwork--compliance-framework` | section | — | Compliance Framework | `docs/gitlab_security_network.md:489` | — | compliancecontrols: |
| `gitlabsecuritynetwork--security-controls` | section | — | Security Controls | `docs/gitlab_security_network.md:491` | — | compliancecontrols: |
| `gitlabsecuritynetwork--vulnerability-management` | section | — | Vulnerability Management | `docs/gitlab_security_network.md:522` | — | vulnerabilitymanagement: |
| `gitlabsupportingservices` | section | — | GitLab Supporting Infrastructure Services v3.0 | `docs/gitlab_supporting_services.md:1` | — | This document specifies the supporting infrastructure services required for GitLab platform operation. These services provide data persistence, caching, messag… |
| `gitlabsupportingservices--service-architecture-overview` | section | — | Service Architecture Overview | `docs/gitlab_supporting_services.md:3` | — | This document specifies the supporting infrastructure services required for GitLab platform operation. These services provide data persistence, caching, messag… |
| `gitlabsupportingservices--object-storage-infrastructure` | section | — | Object Storage Infrastructure | `docs/gitlab_supporting_services.md:7` | — | MinIO provides S3-compatible object storage for GitLab artifacts, container registry, and backup storage requirements. |
| `gitlabsupportingservices--minio-distributed-configuration` | section | — | MinIO Distributed Configuration | `docs/gitlab_supporting_services.md:9` | — | MinIO provides S3-compatible object storage for GitLab artifacts, container registry, and backup storage requirements. |
| `gitlabsupportingservices--storage-performance-optimization` | section | — | Storage Performance Optimization | `docs/gitlab_supporting_services.md:78` | — | storageoptimization: |
| `gitlabsupportingservices--distributed-cache-layer` | section | — | Distributed Cache Layer | `docs/gitlab_supporting_services.md:102` | — | Redis provides high-performance caching and session storage for GitLab applications. |
| `gitlabsupportingservices--redis-cluster-configuration` | section | — | Redis Cluster Configuration | `docs/gitlab_supporting_services.md:104` | — | Redis provides high-performance caching and session storage for GitLab applications. |
| `gitlabsupportingservices--cache-optimization` | section | — | Cache Optimization | `docs/gitlab_supporting_services.md:158` | — | cachepolicies: |
| `gitlabsupportingservices--message-queue-infrastructure` | section | — | Message Queue Infrastructure | `docs/gitlab_supporting_services.md:175` | — | NATS provides reliable message queuing for asynchronous processing and event-driven communication. |
| `gitlabsupportingservices--nats-jetstream-configuration` | section | — | NATS JetStream Configuration | `docs/gitlab_supporting_services.md:177` | — | NATS provides reliable message queuing for asynchronous processing and event-driven communication. |
| `gitlabsupportingservices--secret-management-system` | section | — | Secret Management System | `docs/gitlab_supporting_services.md:265` | — | Vault provides centralized secret management with dynamic secret generation and rotation capabilities. |
| `gitlabsupportingservices--hashicorp-vault-deployment` | section | — | HashiCorp Vault Deployment | `docs/gitlab_supporting_services.md:267` | — | Vault provides centralized secret management with dynamic secret generation and rotation capabilities. |
| `gitlabsupportingservices--secret-rotation-strategy` | section | — | Secret Rotation Strategy | `docs/gitlab_supporting_services.md:358` | — | secretrotation: |
| `gitlabsupportingservices--database-infrastructure` | section | — | Database Infrastructure | `docs/gitlab_supporting_services.md:385` | — | PostgreSQL provides the primary data store for GitLab application data. |
| `gitlabsupportingservices--postgresql-high-availability` | section | — | PostgreSQL High Availability | `docs/gitlab_supporting_services.md:387` | — | PostgreSQL provides the primary data store for GitLab application data. |
| `gitlabsupportingservices--service-discovery-and-configuration` | section | — | Service Discovery and Configuration | `docs/gitlab_supporting_services.md:452` | — | Consul provides service discovery and distributed configuration management. |
| `gitlabsupportingservices--consul-integration` | section | — | Consul Integration | `docs/gitlab_supporting_services.md:454` | — | Consul provides service discovery and distributed configuration management. |
| `gitlabsupportingservices--backup-and-recovery-services` | section | — | Backup and Recovery Services | `docs/gitlab_supporting_services.md:508` | — | backupservices: |
| `gitlabsupportingservices--automated-backup-pipeline` | section | — | Automated Backup Pipeline | `docs/gitlab_supporting_services.md:510` | — | backupservices: |
| `gitlabsupportingservices--service-health-monitoring` | section | — | Service Health Monitoring | `docs/gitlab_supporting_services.md:548` | — | healthchecks: |
| `gitlabsupportingservices--health-check-configuration` | section | — | Health Check Configuration | `docs/gitlab_supporting_services.md:550` | — | healthchecks: |

