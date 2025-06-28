# Private Homelab GitLab Infrastructure

A secure, production-grade GitLab self-hosted infrastructure designed with defense-in-depth security principles and optimized for high availability, performance, and scalability.

## Project Overview

This project implements a comprehensive GitLab infrastructure deployment featuring:

- **Security-First Design**: Multi-layered security with network segmentation, zero-trust architecture, and comprehensive monitoring
- **High Availability**: Clustered services with automatic failover and disaster recovery capabilities
- **Scalable Architecture**: Dynamic runner pools with auto-scaling based on workload demands
- **Complete Observability**: Comprehensive metrics, logging, and distributed tracing
- **Infrastructure as Code**: GitOps-based deployment with automated CI/CD pipelines

## Architecture Components

### Core Infrastructure
- **Kubernetes Platform**: K3s cluster with hardened security configurations
- **Load Balancing**: HAProxy cluster with SSL termination and session persistence
- **Service Mesh**: Calico CNI with network policies for microsegmentation
- **Storage**: Distributed MinIO object storage with erasure coding

### Security Layer
- **Secret Management**: HashiCorp Vault with dynamic secret generation
- **Certificate Management**: Automated TLS certificate provisioning and rotation
- **Network Security**: Zero-trust network policies with default-deny rules
- **Container Security**: Pod Security Standards with runtime security monitoring

### Supporting Services
- **Database**: PostgreSQL cluster with synchronous replication
- **Caching**: Redis cluster for session storage and application caching
- **Message Queue**: NATS JetStream for reliable event processing
- **Monitoring**: Prometheus + Grafana with long-term storage via Thanos

### GitLab Services
- **GitLab CE**: Core GitLab application with external database and storage
- **Container Registry**: Integrated Docker registry with vulnerability scanning
- **Dynamic Runners**: Kubernetes-based runners with automatic scaling
- **Runner Controller**: Custom controller for intelligent runner management

## Security Features

### Defense in Depth
- Network segmentation with DMZ, application, runner, data, and management zones
- Pod Security Standards enforcement with runtime security monitoring
- Comprehensive audit logging with 7-year retention for compliance
- Intrusion detection system with behavioral analysis

### Attack Surface Reduction
- Minimal container images with no unnecessary packages
- Non-root container execution with read-only file systems
- Capability dropping and seccomp profiles
- Network policies with explicit allow rules only

### Monitoring and Response
- Real-time security event correlation
- Automated incident response playbooks
- Comprehensive vulnerability management pipeline
- Regular security assessments and penetration testing

## Quick Start

```bash
# Clone the repository
git clone https://github.com/tzervas/private-homelab.git
cd private-homelab

# Install dependencies
./scripts/install-dependencies.sh

# Deploy the infrastructure
./scripts/deploy.sh
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
