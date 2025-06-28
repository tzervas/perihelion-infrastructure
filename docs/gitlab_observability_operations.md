# GitLab Observability and Operations v3.0

## Observability Architecture

This document establishes comprehensive monitoring, logging, and operational procedures for GitLab infrastructure. The observability framework implements the three pillars of observability: metrics, logs, and traces, providing complete system visibility and operational intelligence.

## Metrics Collection Infrastructure

### Prometheus Configuration

Prometheus serves as the primary metrics collection and storage system with long-term retention capabilities.

```yaml
prometheus:
  global:
    scrape_interval: 30s
    scrape_timeout: 10s
    evaluation_interval: 30s
    external_labels:
      cluster: "gitlab-production"
      
  storage:
    retention:
      time: 15d
      size: 50GB
    tsdb:
      min_block_duration: 2h
      max_block_duration: 24h
      
  remote_write:
    - url: "http://thanos-receive:19291/api/v1/receive"
      queue_config:
        capacity: 10000
        max_shards: 5
        max_samples_per_send: 1000
        batch_send_deadline: 5s
        
  scrape_configs:
    - job_name: "kubernetes-nodes"
      scheme: https
      tls_config:
        ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        insecure_skip_verify: true
      bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
      kubernetes_sd_configs:
        - role: node
      relabel_configs:
        - source_labels: [__address__]
          regex: '(.*):10250'
          replacement: '${1}:9100'
          target_label: __address__
          
    - job_name: "gitlab-webservice"
      static_configs:
        - targets: ["gitlab-webservice:8080"]
      metrics_path: "/metrics"
      scrape_interval: 15s
      
    - job_name: "gitlab-sidekiq"
      static_configs:
        - targets: ["gitlab-sidekiq:3807"]
      metrics_path: "/metrics"
      
    - job_name: "postgresql"
      static_configs:
        - targets: ["postgresql-exporter:9187"]
        
    - job_name: "redis"
      static_configs:
        - targets: ["redis-exporter:9121"]
        
    - job_name: "minio"
      static_configs:
        - targets: ["minio:9000"]
      metrics_path: "/minio/prometheus/metrics"
```

### Custom Metrics Definition

```yaml
custom_metrics:
  gitlab_runner_metrics:
    - name: "gitlab_runner_jobs_total"
      description: "Total number of jobs processed by runners"
      type: "counter"
      labels: ["runner_id", "project", "status"]
      
    - name: "gitlab_runner_job_duration_seconds"
      description: "Duration of job execution in seconds"
      type: "histogram"
      labels: ["runner_id", "project"]
      buckets: [30, 60, 300, 600, 1800, 3600, 7200]
      
    - name: "gitlab_runner_concurrent_limit"
      description: "Maximum concurrent jobs for runner"
      type: "gauge"
      labels: ["runner_id"]
      
  application_metrics:
    - name: "gitlab_web_requests_total"
      description: "Total HTTP requests to GitLab web interface"
      type: "counter"
      labels: ["method", "status", "endpoint"]
      
    - name: "gitlab_web_request_duration_seconds"
      description: "HTTP request duration in seconds"
      type: "histogram"
      labels: ["method", "endpoint"]
      buckets: [0.1, 0.25, 0.5, 1, 2.5, 5, 10]
      
    - name: "gitlab_database_connections_active"
      description: "Number of active database connections"
      type: "gauge"
      labels: ["database"]
```

### Thanos Long-term Storage

```yaml
thanos:
  sidecar:
    enabled: true
    object_store_config:
      type: S3
      config:
        bucket: "thanos-metrics"
        endpoint: "minio:9000"
        access_key: "${vault:secret/thanos#access_key}"
        secret_key: "${vault:secret/thanos#secret_key}"
        insecure: false
        
  store:
    replicas: 2
    retention: "2555d"  # 7 years
    
  compactor:
    enabled: true
    retention:
      raw: "30d"
      5m: "90d"
      1h: "365d"
      
  query:
    replicas: 2
    stores:
      - "thanos-sidecar:10901"
      - "thanos-store:10901"
```

## Visualization and Dashboards

### Grafana Configuration

```yaml
grafana:
  admin:
    user: "admin"
    password: "${vault:secret/grafana#admin_password}"
    
  datasources:
    prometheus:
      name: "Prometheus"
      type: "prometheus"
      url: "http://prometheus:9090"
      access: "proxy"
      is_default: true
      
    thanos:
      name: "Thanos"
      type: "prometheus"
      url: "http://thanos-query:9090"
      access: "proxy"
      
  dashboards:
    gitlab_overview:
      title: "GitLab Overview"
      panels:
        - title: "Web Request Rate"
          type: "graph"
          targets:
            - expr: "rate(gitlab_web_requests_total[5m])"
            
        - title: "Job Queue Depth"
          type: "stat"
          targets:
            - expr: "gitlab_runner_jobs_queued"
            
        - title: "Database Connections"
          type: "graph"
          targets:
            - expr: "pg_stat_database_numbackends"
            
    runner_performance:
      title: "Runner Performance"
      panels:
        - title: "Job Success Rate"
          type: "stat"
          targets:
            - expr: "rate(gitlab_runner_jobs_total{status=\"success\"}[5m]) / rate(gitlab_runner_jobs_total[5m])"
            
        - title: "Average Job Duration"
          type: "graph"
          targets:
            - expr: "rate(gitlab_runner_job_duration_seconds_sum[5m]) / rate(gitlab_runner_job_duration_seconds_count[5m])"
            
        - title: "Active Runners"
          type: "stat"
          targets:
            - expr: "count(up{job=\"gitlab-runner\"} == 1)"
            
    security_monitoring:
      title: "Security Events"
      panels:
        - title: "Failed Authentication Attempts"
          type: "graph"
          targets:
            - expr: "rate(gitlab_auth_failures_total[5m])"
            
        - title: "Privileged Container Starts"
          type: "stat"
          targets:
            - expr: "increase(falco_events{rule_name=\"Privileged container started\"}[1h])"
```

## Distributed Tracing

### Jaeger Implementation

```yaml
jaeger:
  collector:
    replicas: 3
    resources:
      requests:
        cpu: "100m"
        memory: "128Mi"
      limits:
        cpu: "1000m"
        memory: "1Gi"
        
  storage:
    type: "elasticsearch"
    options:
      es:
        server_urls: "http://elasticsearch:9200"
        index_prefix: "jaeger"
        username: "${vault:secret/elasticsearch#username}"
        password: "${vault:secret/elasticsearch#password}"
        
  sampling:
    strategies:
      default_strategy:
        type: "adaptive"
        max_traces_per_second: 100
        
      per_service_strategies:
        - service: "gitlab-webservice"
          type: "probabilistic"
          param: 0.1
          
        - service: "gitlab-runner"
          type: "ratelimiting"
          param: 10
          
  query:
    replicas: 2
    base_path: "/jaeger"
```

### Application Instrumentation

```yaml
tracing_configuration:
  gitlab:
    enabled: true
    sampler_type: "probabilistic"
    sampler_param: 0.1
    
  spans:
    database_queries:
      enabled: true
      include_parameters: false
      
    http_requests:
      enabled: true
      include_headers: ["User-Agent", "X-Request-ID"]
      
    background_jobs:
      enabled: true
      include_arguments: false
```

## Log Aggregation Pipeline

### Fluent Bit Configuration

```yaml
fluent_bit:
  config:
    service:
      flush: 1
      daemon: false
      log_level: info
      parsers_file: parsers.conf
      
    inputs:
      - name: tail
        path: "/var/log/containers/*.log"
        parser: "docker"
        tag: "kube.*"
        refresh_interval: 5
        
      - name: systemd
        tag: "host.*"
        systemd_filter: "_SYSTEMD_UNIT=docker.service"
        
    filters:
      - name: kubernetes
        match: "kube.*"
        kube_url: "https://kubernetes.default.svc:443"
        kube_ca_file: "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
        kube_token_file: "/var/run/secrets/kubernetes.io/serviceaccount/token"
        merge_log: true
        keep_log: false
        k8s_logging_parser: true
        k8s_logging_exclude: false
        
      - name: grep
        match: "kube.*"
        exclude: "log level"
        
    outputs:
      - name: elasticsearch
        match: "*"
        host: "elasticsearch"
        port: 9200
        index: "gitlab"
        type: "_doc"
        logstash_format: true
        logstash_prefix: "gitlab"
        logstash_date_format: "%Y.%m.%d"
        time_key: "@timestamp"
        include_tag_key: true
        tag_key: "tag"
```

### Log Processing Rules

```yaml
log_processing:
  parsers:
    gitlab_production:
      format: "json"
      time_key: "time"
      time_format: "%Y-%m-%dT%H:%M:%S.%L%z"
      
    nginx_access:
      format: "regex"
      regex: "^(?<remote>[^ ]*) (?<host>[^ ]*) (?<user>[^ ]*) \\[(?<time>[^\\]]*)\\] \"(?<method>\\S+)(?: +(?<path>[^\\\"]*?)(?: +\\S*)?)?\" (?<code>[^ ]*) (?<size>[^ ]*)(?: \"(?<referer>[^\\\"]*)\" \"(?<agent>[^\\\"]*)\")"
      time_key: "time"
      time_format: "%d/%b/%Y:%H:%M:%S %z"
      
  retention_policies:
    application_logs:
      hot_tier: "7d"
      warm_tier: "30d"
      cold_tier: "90d"
      delete_after: "365d"
      
    audit_logs:
      hot_tier: "30d"
      warm_tier: "90d"
      cold_tier: "365d"
      delete_after: "2555d"  # 7 years
      
    debug_logs:
      hot_tier: "1d"
      warm_tier: "7d"
      delete_after: "30d"
```

## Alerting Framework

### Alert Rules Configuration

```yaml
alert_rules:
  groups:
    - name: "gitlab.rules"
      rules:
        - alert: "GitLabDown"
          expr: "up{job=\"gitlab-webservice\"} == 0"
          for: "1m"
          labels:
            severity: "critical"
          annotations:
            summary: "GitLab service is down"
            description: "GitLab webservice has been down for more than 1 minute"
            
        - alert: "HighErrorRate"
          expr: "rate(gitlab_web_requests_total{status=~\"5..\"}[5m]) / rate(gitlab_web_requests_total[5m]) > 0.1"
          for: "5m"
          labels:
            severity: "warning"
          annotations:
            summary: "High HTTP error rate detected"
            description: "Error rate is {{ $value | humanizePercentage }} for the last 5 minutes"
            
        - alert: "DatabaseConnectionsHigh"
          expr: "pg_stat_database_numbackends / pg_settings_max_connections > 0.8"
          for: "5m"
          labels:
            severity: "warning"
          annotations:
            summary: "Database connection usage is high"
            description: "Database connections are at {{ $value | humanizePercentage }} of maximum"
            
    - name: "infrastructure.rules"
      rules:
        - alert: "NodeExporterDown"
          expr: "up{job=\"node-exporter\"} == 0"
          for: "5m"
          labels:
            severity: "warning"
          annotations:
            summary: "Node exporter is down"
            
        - alert: "DiskSpaceRunningLow"
          expr: "(node_filesystem_avail_bytes / node_filesystem_size_bytes) < 0.1"
          for: "5m"
          labels:
            severity: "warning"
          annotations:
            summary: "Disk space is running low"
            description: "Filesystem {{ $labels.mountpoint }} has only {{ $value | humanizePercentage }} space left"
            
        - alert: "MemoryUsageHigh"
          expr: "(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) > 0.9"
          for: "10m"
          labels:
            severity: "warning"
          annotations:
            summary: "High memory usage detected"
            description: "Memory usage is above 90% for the last 10 minutes"
```

### Notification Channels

```yaml
alertmanager:
  global:
    smtp_smarthost: "smtp.company.com:587"
    smtp_from: "alerts@company.com"
    
  route:
    group_by: ["alertname", "cluster"]
    group_wait: "10s"
    group_interval: "10s"
    repeat_interval: "1h"
    receiver: "default"
    routes:
      - match:
          severity: "critical"
        receiver: "critical-alerts"
        
      - match:
          severity: "warning"
        receiver: "warning-alerts"
        
  receivers:
    - name: "default"
      email_configs:
        - to: "platform-team@company.com"
          subject: "GitLab Alert: {{ .GroupLabels.alertname }}"
          body: |
            {{ range .Alerts }}
            Alert: {{ .Annotations.summary }}
            Description: {{ .Annotations.description }}
            {{ end }}
            
    - name: "critical-alerts"
      slack_configs:
        - api_url: "${vault:secret/alerting#slack_webhook}"
          channel: "#critical-alerts"
          title: "Critical Alert: {{ .GroupLabels.alertname }}"
          text: "{{ range .Alerts }}{{ .Annotations.description }}{{ end }}"
          
      pagerduty_configs:
        - service_key: "${vault:secret/alerting#pagerduty_key}"
          description: "{{ .GroupLabels.alertname }}: {{ .GroupLabels.instance }}"
          
    - name: "warning-alerts"
      slack_configs:
        - api_url: "${vault:secret/alerting#slack_webhook}"
          channel: "#platform-alerts"
          title: "Warning: {{ .GroupLabels.alertname }}"
```

## Operational Procedures

### Backup and Recovery Operations

```yaml
backup_operations:
  database_backup:
    schedule: "0 2 * * *"  # Daily at 2 AM
    method: "pg_basebackup"
    retention:
      daily: "7d"
      weekly: "4w"
      monthly: "12m"
      
    validation:
      restore_test: "weekly"
      checksum_verification: true
      
  application_backup:
    schedule: "0 3 * * *"  # Daily at 3 AM
    components:
      - "repositories"
      - "uploads"
      - "artifacts"
      - "registry"
      
    encryption:
      enabled: true
      key_source: "vault"
      
  configuration_backup:
    schedule: "*/15 * * * *"  # Every 15 minutes
    method: "git_commit"
    repository: "config-backup"
    
  recovery_procedures:
    rto: "4h"  # Recovery Time Objective
    rpo: "1h"  # Recovery Point Objective
    
    procedures:
      - name: "database_recovery"
        steps:
          - "stop_application_services"
          - "restore_database_backup"
          - "verify_data_integrity"
          - "start_application_services"
        estimated_time: "2h"
        
      - name: "full_system_recovery"
        steps:
          - "provision_infrastructure"
          - "restore_configurations"
          - "restore_database"
          - "restore_repositories"
          - "validate_services"
        estimated_time: "4h"
```

### Incident Response Procedures

```yaml
incident_response:
  severity_levels:
    p0_critical:
      description: "Complete service outage"
      response_time: "15m"
      escalation_time: "30m"
      
    p1_high:
      description: "Major functionality impaired"
      response_time: "1h"
      escalation_time: "2h"
      
    p2_medium:
      description: "Minor functionality impaired"
      response_time: "4h"
      escalation_time: "8h"
      
    p3_low:
      description: "Cosmetic or documentation issues"
      response_time: "24h"
      escalation_time: "72h"
      
  response_team:
    primary:
      - "platform_engineer"
      - "sre_engineer"
      
    secondary:
      - "security_engineer"
      - "network_engineer"
      
  communication:
    status_page: "https://status.company.com"
    slack_channel: "#incident-response"
    email_list: "platform-team@company.com"
    
  escalation_matrix:
    - level: 1
      contacts: ["platform_team"]
      timeout: "30m"
      
    - level: 2
      contacts: ["engineering_manager"]
      timeout: "1h"
      
    - level: 3
      contacts: ["cto"]
      timeout: "2h"
```

### Maintenance Procedures

```yaml
maintenance_operations:
  scheduled_maintenance:
    window: "Sunday 02:00-04:00 UTC"
    notification_period: "7d"
    
    procedures:
      - name: "security_updates"
        frequency: "monthly"
        duration: "1h"
        
      - name: "certificate_renewal"
        frequency: "quarterly"
        duration: "30m"
        
      - name: "backup_validation"
        frequency: "weekly"
        duration: "2h"
        
  emergency_maintenance:
    approval_required: true
    approvers: ["platform_lead", "engineering_manager"]
    documentation_required: true
    
  rollback_procedures:
    database_schema:
      method: "migration_rollback"
      verification: "data_integrity_check"
      
    application_deployment:
      method: "helm_rollback"
      verification: "health_check"
      
    infrastructure_changes:
      method: "terraform_state_restore"
      verification: "service_availability"
```

This observability and operations framework provides comprehensive monitoring, alerting, and operational procedures for GitLab infrastructure management. Implementation ensures proactive issue detection, rapid incident response, and systematic maintenance processes.