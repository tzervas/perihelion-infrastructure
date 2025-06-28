# 🏗️ Perihelion Infrastructure

**Enterprise-Grade Kubernetes Infrastructure with Security-First GitLab CI/CD Platform**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/Security-Hardened-green.svg)](./SECURITY.md)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.29+-blue.svg)](https://kubernetes.io/)
[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://python.org/)
[![CI/CD](https://img.shields.io/badge/CI%2FCD-Automated-brightgreen.svg)](./.github/workflows/)
[![Monitoring](https://img.shields.io/badge/Monitoring-Prometheus-orange.svg)](./k8s/monitoring/)

## 📋 Overview

Perihelion Infrastructure delivers a comprehensive, production-ready Kubernetes platform featuring secure GitLab CI/CD automation, enterprise monitoring, and defense-in-depth security. Designed for organizations requiring robust, scalable, and secure development infrastructure.

### 🎯 Platform Features

- **🔒 Security-First Architecture**: Zero-trust networking, Pod Security Standards, comprehensive RBAC
- **📊 Enterprise Monitoring**: Full observability stack with Prometheus, Grafana, and AlertManager
- **🚀 Intelligent CI/CD**: Auto-scaling GitLab runners with advanced queue management
- **🛡️ Attack-Resistant Design**: Multi-layer security with threat detection and response
- **⚡ High Performance**: Optimized resource utilization and efficient scaling algorithms
- **🔄 Production Operations**: Complete GitOps workflow with automated testing and deployment
- **🔐 Secrets Management**: Integrated Vault with External Secrets Operator
- **📝 Centralized Logging**: Secure log aggregation with Fluent Bit and Loki

## 🏛️ Platform Architecture

Perihelion Infrastructure implements a comprehensive Kubernetes platform with:

### Core Infrastructure Components

#### 🦊 GitLab Runner Controller
- **Intelligent Auto-Scaling**: Dynamic runner provisioning based on queue depth and resource utilization
- **Security-Hardened Execution**: Pod Security Standards with restricted profiles
- **Comprehensive Monitoring**: Prometheus metrics with Grafana dashboards
- **Attack Resistance**: Rate limiting, input validation, and anomaly detection

#### 📊 Monitoring & Observability Stack
- **Prometheus**: High-availability metrics collection with 30-day retention
- **Grafana**: Security and CI/CD focused dashboards with automated provisioning
- **AlertManager**: Multi-channel alerting with intelligent routing and escalation
- **Security Monitoring**: Threat detection and compliance monitoring dashboards

#### 🔐 Security Infrastructure
- **Network Policies**: Default-deny with explicit allowlists for zero-trust networking
- **RBAC**: Least-privilege access controls with service account isolation
- **Pod Security Standards**: Restricted profile enforcement with security contexts
- **External Secrets**: Vault integration for secure credential management

#### 📋 Supporting Services
- **Centralized Logging**: Fluent Bit log collection with security classification
- **Secrets Management**: HashiCorp Vault with Kubernetes authentication
- **Certificate Management**: Automated TLS provisioning and rotation
- **Storage**: Persistent volumes with encryption at rest

## 🛡️ Security Features

### Defense-in-Depth Architecture
- **Network Segmentation**: Strict namespace isolation with network policies
- **Pod Security**: Comprehensive security contexts and runtime protection
- **Audit Logging**: Complete activity tracking with long-term retention
- **Threat Detection**: Real-time security monitoring and alerting

### Attack Surface Minimization
- **Minimal Images**: Distroless containers with no unnecessary packages
- **Non-Root Execution**: All containers run as non-privileged users
- **Read-Only Filesystems**: Immutable container runtime environments
- **Capability Dropping**: Removal of all unnecessary Linux capabilities

### Compliance & Monitoring
- **Security Dashboards**: Real-time threat detection and compliance monitoring
- **Automated Scanning**: Container and infrastructure vulnerability assessments
- **Incident Response**: Automated alerting with escalation procedures
- **Compliance Reporting**: Continuous security posture assessment

## 🚀 Project Status

### ✅ Completed Components

- **GitLab Runner Controller**: Full implementation with security hardening
- **Kubernetes Infrastructure**: Comprehensive manifests with Pod Security Standards
- **CI/CD Pipelines**: Automated testing, security scanning, and deployment
- **Monitoring Stack**: Prometheus, Grafana, and AlertManager with dashboards
- **Security Infrastructure**: Network policies, RBAC, and resource quotas

### 🔄 In Progress

- **Supporting Services**: Vault integration and centralized logging (current branch: `feature/supporting-services`)
- **Operational Documentation**: Runbooks and incident response procedures
- **Testing & Validation**: Staging deployment and integration testing

### 📋 Upcoming

- **Production Deployment**: Full production rollout with monitoring
- **Advanced Features**: Enhanced scaling algorithms and performance optimization
- **Security Hardening**: Additional security controls and compliance automation

## Quick Start

```bash
# Clone the repository
git clone https://github.com/tzervas/perihelion-auth-manager.git
cd perihelion-auth-manager

# Install dependencies with UV
uv venv
source .venv/bin/activate
uv pip install -r requirements-dev.txt

# Deploy with Helm or Kustomize
helm install perihelion-infrastructure helm/gitlab-runner-controller/
# OR
kubectl apply -k k8s/
```

## Documentation

- [Implementation Plan](docs/gitlab_implementation_plan.md) - Detailed project execution plan
- [Core Architecture](docs/gitlab_architecture_core.md) - System architecture and component specifications
- [Security & Network](docs/gitlab_security_network.md) - Security controls and network configuration
- [Supporting Services](docs/gitlab_supporting_services.md) - Database, storage, and supporting infrastructure
- [Observability & Operations](docs/gitlab_observability_operations.md) - Monitoring, logging, and operational procedures

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines and development setup instructions.

## Maintainers

- Tyler Zervas (@tzervas)

## Security

For security issues, please see our [Security Policy](SECURITY.md) or contact security@company.com.
