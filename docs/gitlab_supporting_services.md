# GitLab Supporting Infrastructure Services v3.0

## Service Architecture Overview

This document specifies the supporting infrastructure services required for GitLab platform operation. These services provide data persistence, caching, message queuing, and secret management capabilities that enable scalable and resilient GitLab deployments.

## Object Storage Infrastructure

### MinIO Distributed Configuration

MinIO provides S3-compatible object storage for GitLab artifacts, container registry, and backup storage requirements.

```yaml
minio:
  deployment:
    mode: "distributed"
    replicas: 4
    volumes_per_server: 2
    
  storage:
    total_capacity: "1TB"
    erasure_coding:
      data_blocks: 4
      parity_blocks: 2
    
  buckets:
    gitlab_artifacts:
      name: "gitlab-artifacts"
      versioning: false
      policy: "none"
      lifecycle:
        - id: "expire-old-artifacts"
          expiration_days: 30
          noncurrent_version_expiration_days: 7
          
    gitlab_registry:
      name: "gitlab-registry"
      versioning: true
      policy: "download"
      lifecycle:
        - id: "expire-old-layers"
          expiration_days: 90
          
    runner_cache:
      name: "runner-cache"
      versioning: false
      policy: "download"
      lifecycle:
        - id: "expire-cache"
          expiration_days: 7
          abort_incomplete_multipart_upload_days: 1
          
    gitlab_backups:
      name: "gitlab-backups"
      versioning: true
      policy: "none"
      lifecycle:
        - id: "transition-to-ia"
          transition_days: 30
          storage_class: "STANDARD_IA"
        - id: "expire-old-backups"
          expiration_days: 2555  # 7 years

  security:
    access_key: "${vault:secret/minio#access_key}"
    secret_key: "${vault:secret/minio#secret_key}"
    tls:
      enabled: true
      certificate_path: "/etc/ssl/minio"
      
  monitoring:
    prometheus:
      enabled: true
      port: 9000
      path: "/minio/prometheus/metrics"
```

### Storage Performance Optimization

```yaml
storage_optimization:
  read_quorum: 2
  write_quorum: 3
  
  caching:
    enabled: true
    memory_limit: "2Gi"
    exclude_patterns:
      - "*.tmp"
      - "*.log"
      
  compression:
    enabled: true
    types: ["application/json", "text/plain", "application/xml"]
    
  healing:
    enabled: true
    scan_mode: "deep"
    max_sleep: "250ms"
```

## Distributed Cache Layer

### Redis Cluster Configuration

Redis provides high-performance caching and session storage for GitLab applications.

```yaml
redis:
  topology: "cluster"
  nodes:
    masters: 3
    replicas_per_master: 1
    
  resources:
    requests:
      cpu: "100m"
      memory: "256Mi"
    limits:
      cpu: "500m"
      memory: "1Gi"
      
  persistence:
    aof:
      enabled: true
      fsync: "everysec"
      rewrite_incremental_fsync: true
      
    rdb:
      enabled: true
      save_periods:
        - "900 1"      # 900 seconds if at least 1 key changed
        - "300 10"     # 300 seconds if at least 10 keys changed
        - "60 10000"   # 60 seconds if at least 10000 keys changed
        
  cluster_configuration:
    cluster_require_full_coverage: false
    cluster_node_timeout: 15000
    cluster_migration_barrier: 1
    
  security:
    auth:
      enabled: true
      password: "${vault:secret/redis#password}"
    tls:
      enabled: true
      cert_file: "/tls/tls.crt"
      key_file: "/tls/tls.key"
      ca_file: "/tls/ca.crt"
      
  monitoring:
    exporter:
      enabled: true
      image: "oliver006/redis_exporter:latest"
      port: 9121
```

### Cache Optimization

```yaml
cache_policies:
  session_cache:
    ttl: 3600  # 1 hour
    max_memory_policy: "allkeys-lru"
    
  application_cache:
    ttl: 1800  # 30 minutes
    max_memory_policy: "volatile-lru"
    
  rate_limiting:
    ttl: 60
    max_memory_policy: "volatile-ttl"
```

## Message Queue Infrastructure

### NATS JetStream Configuration

NATS provides reliable message queuing for asynchronous processing and event-driven communication.

```yaml
nats:
  cluster:
    name: "gitlab-nats"
    replicas: 3
    
  jetstream:
    enabled: true
    memory_storage: "1Gi"
    file_storage: "10Gi"
    max_file_store: "100Gi"
    
  streams:
    job_events:
      name: "JOB_EVENTS"
      subjects: ["jobs.>"]
      retention: "limits"
      max_msgs: 100000
      max_msgs_per_subject: 1000
      max_bytes: "1GB"
      max_age: "24h"
      storage: "file"
      replicas: 3
      
    runner_lifecycle:
      name: "RUNNER_LIFECYCLE"
      subjects: ["runners.>"]
      retention: "interest"
      max_msgs: 10000
      max_bytes: "100MB"
      max_age: "1h"
      storage: "memory"
      replicas: 3
      
    audit_events:
      name: "AUDIT_EVENTS"
      subjects: ["audit.>"]
      retention: "limits"
      max_msgs: 1000000
      max_bytes: "10GB"
      max_age: "2555d"  # 7 years
      storage: "file"
      replicas: 3
      
  consumers:
    job_processor:
      stream: "JOB_EVENTS"
      durable: "job-processor"
      deliver_policy: "all"
      ack_policy: "explicit"
      ack_wait: "30s"
      max_deliver: 3
      
    audit_archiver:
      stream: "AUDIT_EVENTS"
      durable: "audit-archiver"
      deliver_policy: "all"
      ack_policy: "explicit"
      ack_wait: "60s"
      replay_policy: "instant"

  security:
    tls:
      enabled: true
      cert_file: "/etc/nats-certs/server.pem"
      key_file: "/etc/nats-certs/server-key.pem"
      ca_file: "/etc/nats-certs/ca.pem"
      verify: true
      
    authorization:
      users:
        - user: "gitlab"
          password: "${vault:secret/nats#gitlab_password}"
          permissions:
            publish: ["jobs.>", "runners.>"]
            subscribe: ["jobs.>", "runners.>"]
            
        - user: "audit"
          password: "${vault:secret/nats#audit_password}"
          permissions:
            publish: ["audit.>"]
            subscribe: ["audit.>"]
```

## Secret Management System

### HashiCorp Vault Deployment

Vault provides centralized secret management with dynamic secret generation and rotation capabilities.

```yaml
vault:
  deployment:
    mode: "high_availability"
    replicas: 3
    
  storage:
    backend: "integrated"
    raft:
      node_id: "vault-${POD_ORDINAL}"
      path: "/vault/data"
      
  listener:
    tcp:
      address: "0.0.0.0:8200"
      tls_cert_file: "/vault/tls/server.crt"
      tls_key_file: "/vault/tls/server.key"
      tls_min_version: "tls13"
      
  seal:
    type: "kubernetes"
    
  ui:
    enabled: true
    
  auth_methods:
    kubernetes:
      path: "kubernetes"
      config:
        kubernetes_host: "https://kubernetes.default.svc"
        kubernetes_ca_cert: "@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
        token_reviewer_jwt: "@/var/run/secrets/kubernetes.io/serviceaccount/token"
        
    userpass:
      path: "userpass"
      
  secret_engines:
    kv_v2:
      path: "gitlab/"
      config:
        max_versions: 5
        cas_required: false
        delete_version_after: "0s"
        
    pki:
      path: "pki/"
      config:
        max_lease_ttl: "87600h"  # 10 years
        default_lease_ttl: "8760h"  # 1 year
        
    database:
      path: "database/"
      
    transit:
      path: "transit/"
      
  policies:
    gitlab_app:
      name: "gitlab-app"
      policy: |
        path "gitlab/data/database/*" {
          capabilities = ["read"]
        }
        path "gitlab/data/oauth/*" {
          capabilities = ["read"]
        }
        path "pki/issue/gitlab-server" {
          capabilities = ["update"]
        }
        path "transit/encrypt/gitlab" {
          capabilities = ["update"]
        }
        path "transit/decrypt/gitlab" {
          capabilities = ["update"]
        }
        
    runner_controller:
      name: "runner-controller"
      policy: |
        path "gitlab/data/runner/*" {
          capabilities = ["read"]
        }
        path "pki/issue/gitlab-runner" {
          capabilities = ["update"]
        }
```

### Secret Rotation Strategy

```yaml
secret_rotation:
  automatic:
    database_passwords:
      frequency: "quarterly"
      notification: true
      
    api_tokens:
      frequency: "monthly"
      notification: true
      
    encryption_keys:
      frequency: "annually"
      notification: true
      
  manual:
    root_tokens:
      procedure: "break_glass"
      approvers: 2
      
    certificate_authorities:
      procedure: "scheduled_maintenance"
      notification_period: "30d"
```

## Database Infrastructure

### PostgreSQL High Availability

PostgreSQL provides the primary data store for GitLab application data.

```yaml
postgresql:
  version: "14.10"
  architecture: "streaming_replication"
  
  primary:
    resources:
      requests:
        cpu: "500m"
        memory: "1Gi"
      limits:
        cpu: "2000m"
        memory: "4Gi"
        
  standby:
    replicas: 2
    sync_mode: "synchronous"
    synchronous_standby_names: "ANY 1 (*)"
    
  configuration:
    shared_preload_libraries: "pg_stat_statements"
    max_connections: 200
    shared_buffers: "256MB"
    effective_cache_size: "1GB"
    maintenance_work_mem: "64MB"
    checkpoint_completion_target: 0.9
    wal_buffers: "16MB"
    default_statistics_target: 100
    random_page_cost: 1.1
    effective_io_concurrency: 200
    work_mem: "4MB"
    min_wal_size: "1GB"
    max_wal_size: "4GB"
    
  security:
    authentication:
      method: "scram-sha-256"
      password: "${vault:secret/postgresql#password}"
      
    encryption:
      ssl: true
      ssl_cert_file: "/etc/ssl/certs/server.crt"
      ssl_key_file: "/etc/ssl/private/server.key"
      ssl_ca_file: "/etc/ssl/certs/ca.crt"
      
  backup:
    method: "pg_basebackup"
    schedule: "0 2 * * *"  # Daily at 2 AM
    retention: "30d"
    compression: true
    
  monitoring:
    exporter:
      enabled: true
      image: "quay.io/prometheuscommunity/postgres-exporter:latest"
      queries:
        - "pg_stat_database"
        - "pg_stat_user_tables"
        - "pg_stat_statements"
```

## Service Discovery and Configuration

### Consul Integration

Consul provides service discovery and distributed configuration management.

```yaml
consul:
  datacenter: "gitlab-dc1"
  
  server:
    replicas: 3
    bootstrap_expect: 3
    
  client:
    enabled: true
    
  connect:
    enabled: true
    
  ui:
    enabled: true
    
  acl:
    enabled: true
    default_policy: "deny"
    
  services:
    gitlab_web:
      name: "gitlab-web"
      port: 8080
      tags: ["web", "gitlab"]
      checks:
        - name: "HTTP Health Check"
          http: "http://localhost:8080/health"
          interval: "10s"
          
    postgresql:
      name: "postgresql"
      port: 5432
      tags: ["database", "postgresql"]
      checks:
        - name: "TCP Health Check"
          tcp: "localhost:5432"
          interval: "10s"
          
    redis:
      name: "redis"
      port: 6379
      tags: ["cache", "redis"]
      checks:
        - name: "TCP Health Check"
          tcp: "localhost:6379"
          interval: "10s"
```

## Backup and Recovery Services

### Automated Backup Pipeline

```yaml
backup_services:
  velero:
    provider: "aws"
    bucket: "gitlab-backups"
    schedule:
      full_backup: "0 2 * * 0"  # Weekly on Sunday
      incremental_backup: "0 2 * * 1-6"  # Daily Monday-Saturday
      
    retention:
      daily: "7d"
      weekly: "4w"
      monthly: "12m"
      yearly: "7y"
      
    exclude_resources:
      - "secrets"
      - "events"
      
  database_backup:
    method: "pg_dump"
    schedule: "0 1 * * *"  # Daily at 1 AM
    compression: "gzip"
    encryption: true
    
  object_storage_backup:
    method: "mc_mirror"
    schedule: "0 3 * * *"  # Daily at 3 AM
    destination: "s3://gitlab-backups/minio"
    
  configuration_backup:
    method: "git_push"
    schedule: "*/15 * * * *"  # Every 15 minutes
    repository: "git@backup-server:config-backup.git"
```

## Service Health Monitoring

### Health Check Configuration

```yaml
health_checks:
  endpoints:
    minio:
      url: "https://minio.gitlab.svc.cluster.local:9000/minio/health/live"
      timeout: 5s
      interval: 30s
      
    redis:
      command: ["redis-cli", "ping"]
      timeout: 3s
      interval: 10s
      
    postgresql:
      command: ["pg_isready", "-h", "localhost", "-p", "5432"]
      timeout: 5s
      interval: 10s
      
    vault:
      url: "https://vault.gitlab.svc.cluster.local:8200/v1/sys/health"
      timeout: 5s
      interval: 30s
      
    nats:
      command: ["nats", "server", "check", "jetstream"]
      timeout: 3s
      interval: 15s
      
  alerting:
    channels:
      - type: "slack"
        webhook: "${vault:secret/alerting#slack_webhook}"
      - type: "email"
        smtp_server: "smtp.company.com"
        recipients: ["platform-team@company.com"]
        
    thresholds:
      critical: "service_down > 0"
      warning: "response_time > 5s"
      
  dependencies:
    postgresql:
      dependencies: []
      critical: true
      
    redis:
      dependencies: []
      critical: false
      
    minio:
      dependencies: []
      critical: true
      
    vault:
      dependencies: []
      critical: true
      
    nats:
      dependencies: ["postgresql"]
      critical: false
```

This supporting infrastructure specification establishes the foundation services required for GitLab platform operation. These services integrate with observability systems and operational procedures to provide comprehensive platform capabilities.