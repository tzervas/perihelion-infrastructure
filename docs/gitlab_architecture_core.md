# GitLab Self-Hosted Infrastructure: Architecture and Core Components v3.0

## Executive Summary

This specification defines the foundational architecture and core components for a production-grade GitLab deployment. The system implements a three-tier architecture with static load balancers managing dynamic runner pools, optimizing resource utilization while maintaining security boundaries and operational predictability.

## System Architecture Overview

### Architectural Pattern

The infrastructure employs a load balancer-centric architecture utilizing defense-in-depth security principles and Infrastructure as Code methodologies.

```
┌─────────────────────────────────────────────┐
│          External Traffic                    │
└────────────────┬────────────────────────────┘
                 │
┌────────────────▼────────────────────────────┐
│     Load Balancer Tier (Static)             │
│     • HAProxy/MetalLB Cluster               │
│     • SSL Termination                       │
│     • Rate Limiting                         │
└────────────────┬────────────────────────────┘
                 │
┌────────────────▼────────────────────────────┐
│     Application Tier                        │
│     • GitLab Core Services                  │
│     • Runner Controller                     │
│     • Supporting Services                   │
└────────────────┬────────────────────────────┘
                 │
┌────────────────▼────────────────────────────┐
│     Dynamic Runner Pool                     │
│     • Ephemeral Containers                  │
│     • Auto-scaling Groups                   │
│     • Resource Profiles                     │
└─────────────────────────────────────────────┘
```

### Design Principles

- **Separation of Concerns**: Each tier maintains distinct responsibilities
- **Horizontal Scalability**: Components scale independently based on demand
- **Fault Tolerance**: Multiple failure domains prevent single points of failure
- **Security Boundaries**: Network isolation between functional layers

## Load Balancer Configuration

### Technical Specifications

The load balancer tier provides high availability and traffic distribution capabilities.

```yaml
load_balancer:
  topology:
    primary:
      type: "haproxy"
      version: "2.8-lts"
      replicas: 2
      vip: "${infrastructure.ip_address}"
    
  configuration:
    frontends:
      https:
        bind: "*:443 ssl"
        mode: "http"
        max_connections: 10000
        timeout:
          client: 30s
          
    backends:
      gitlab_web:
        algorithm: "leastconn"
        health_check:
          method: "GET"
          path: "/health/readiness"
          interval: 5s
          timeout: 3s
          
      runner_registration:
        algorithm: "source"
        persistence:
          type: "table"
          expire: 3600s
```

### High Availability Features

- **Active-Passive Clustering**: Automatic failover between load balancer instances
- **Session Persistence**: Maintains connection state for runner registration
- **Health Monitoring**: Continuous backend service availability checks
- **Connection Draining**: Graceful handling of maintenance operations

## GitLab Core Services

### Deployment Architecture

The application tier hosts GitLab components with resource allocation optimized for production workloads.

```yaml
gitlab:
  edition: "ce"
  version: "16.9.0"
  
  components:
    webservice:
      replicas: 3
      resources:
        requests:
          cpu: "1000m"
          memory: "2Gi"
        limits:
          cpu: "2000m"
          memory: "4Gi"
      readiness_probe:
        path: "/health"
        initial_delay: 30s
    
    gitaly:
      storage:
        size: "100Gi"
        class: "fast-ssd"
        backup_enabled: true
      replication_factor: 3
      
    sidekiq:
      queues:
        - "default"
        - "mailers"
        - "pipeline_processing"
      concurrency: 10
      memory_killer:
        max_memory_mb: 1000
    
    postgresql:
      version: "14"
      high_availability:
        enabled: true
        replicas: 3
        synchronous_standby_names: "ANY 1 (*)"
      resources:
        requests:
          cpu: "500m"
          memory: "1Gi"
        limits:
          cpu: "2000m"
          memory: "4Gi"
```

### Service Dependencies

- **Database Layer**: PostgreSQL cluster with synchronous replication
- **Storage Layer**: Gitaly cluster for Git repository management
- **Processing Layer**: Sidekiq workers for background job execution
- **Web Layer**: Unicorn/Puma application servers for HTTP requests

## Dynamic Runner Infrastructure

### Runner Pool Configuration

The runner tier provides elastic compute capacity for CI/CD pipeline execution.

```yaml
runner_pools:
  docker:
    executor: "docker"
    profiles:
      small:
        cpu: "500m"
        memory: "512Mi"
        concurrent_jobs: 2
        timeout: 3600s
      
      medium:
        cpu: "2000m"
        memory: "4Gi"
        concurrent_jobs: 4
        timeout: 7200s
      
      large:
        cpu: "4000m"
        memory: "8Gi"
        concurrent_jobs: 8
        timeout: 14400s
    
    cache:
      type: "s3"
      shared: true
      path: "runner-cache/"
    
  kubernetes:
    executor: "kubernetes"
    namespace: "gitlab-runners"
    service_account: "gitlab-runner"
    
    pod_annotations:
      cluster-autoscaler.kubernetes.io/safe-to-evict: "true"
      
    node_selector:
      node-type: "runner"
      
    tolerations:
      - key: "dedicated"
        operator: "Equal"
        value: "runner"
        effect: "NoSchedule"
```

### Scaling Behavior

- **Demand-Based Scaling**: Automatic scaling based on job queue depth
- **Resource Optimization**: Multiple profile sizes to match workload requirements
- **Ephemeral Execution**: Containers destroyed after job completion
- **Cache Management**: Shared cache storage to accelerate build processes

## Horizontal Pod Autoscaling

### Scaling Specifications

```yaml
horizontal_scaling:
  runner_pool:
    minReplicas: 0
    maxReplicas: 50
    
    metrics:
      - type: External
        external:
          metric:
            name: gitlab_job_queue_depth
          target:
            type: Value
            value: "5"
      
      - type: Resource
        resource:
          name: cpu
          target:
            type: Utilization
            averageUtilization: 70
    
    behavior:
      scaleUp:
        stabilizationWindowSeconds: 30
        policies:
          - type: Percent
            value: 200
            periodSeconds: 60
          - type: Pods
            value: 10
            periodSeconds: 60
        selectPolicy: Max
      
      scaleDown:
        stabilizationWindowSeconds: 300
        policies:
          - type: Percent
            value: 10
            periodSeconds: 60
        selectPolicy: Min
```

## Vertical Pod Autoscaling

### Resource Optimization

```yaml
vertical_scaling:
  updatePolicy:
    updateMode: "Auto"
    
  resourcePolicy:
    containerPolicies:
      - containerName: runner
        minAllowed:
          cpu: 100m
          memory: 128Mi
        maxAllowed:
          cpu: 8
          memory: 16Gi
        controlledResources: ["cpu", "memory"]
        controlledValues: RequestsAndLimits
```

## Configuration Management Structure

### GitOps Repository Layout

```
infrastructure/
├── environments/
│   ├── production/
│   │   ├── kustomization.yaml
│   │   ├── values/
│   │   │   ├── gitlab-values.yaml
│   │   │   ├── runner-values.yaml
│   │   │   └── load-balancer-values.yaml
│   │   └── patches/
│   └── staging/
│       ├── kustomization.yaml
│       └── values/
├── base/
│   ├── gitlab/
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   └── configmap.yaml
│   ├── runners/
│   │   ├── controller.yaml
│   │   ├── rbac.yaml
│   │   └── hpa.yaml
│   └── load-balancer/
│       ├── haproxy.yaml
│       └── keepalived.yaml
└── scripts/
    ├── install.sh
    ├── upgrade.sh
    └── validate.sh
```

## Validation and Testing

### Component Health Checks

```yaml
health_checks:
  gitlab_web:
    endpoint: "/health/readiness"
    expected_status: 200
    timeout: 5s
    
  runner_controller:
    endpoint: "/metrics"
    expected_metrics:
      - "gitlab_runner_jobs_total"
      - "gitlab_runner_concurrent_limit"
    
  load_balancer:
    endpoint: "/stats"
    authentication: "basic"
    expected_backends: ["gitlab_web", "runner_registration"]
```

### Performance Baselines

- **Request Latency**: P95 latency under 500ms for web requests
- **Throughput**: Support for 1000 concurrent users
- **Runner Capacity**: Scale to 100 concurrent build jobs
- **Failover Time**: Service restoration within 30 seconds

## Dependencies and Integration Points

### External Dependencies

- **DNS Resolution**: Requires valid DNS entries for service discovery
- **TLS Certificates**: Automated certificate management via Let's Encrypt
- **Container Registry**: Integration with external or internal registries
- **Backup Storage**: External storage for automated backup procedures

### Internal Dependencies

- **Kubernetes Platform**: Requires functional Kubernetes cluster
- **Storage Provisioner**: Dynamic volume provisioning capability
- **Network Policies**: Container network interface with policy support
- **Secret Management**: HashiCorp Vault or Kubernetes secrets integration

This document establishes the foundational architecture patterns and core component specifications required for GitLab infrastructure deployment. Subsequent documents will detail security configurations, supporting services, and operational procedures.