# GitLab Security and Network Configuration v3.0

## Security Architecture Overview

This document establishes comprehensive security controls and network isolation policies for GitLab infrastructure deployment. The security model implements defense-in-depth principles through multiple layers of protection, access controls, and monitoring capabilities.

## Network Security Framework

### Security Zone Architecture

The network topology segregates components into distinct security zones with controlled communication pathways.

```yaml
network_zones:
  dmz:
    subnet: "10.0.1.0/24"
    components: ["load_balancers", "reverse_proxies"]
    access_policy: "restricted_ingress"
    
  application:
    subnet: "10.0.2.0/24"
    components: ["gitlab_services", "web_interfaces"]
    access_policy: "application_tier"
    
  runner:
    subnet: "10.0.3.0/24"
    components: ["dynamic_runners", "build_agents"]
    access_policy: "ephemeral_compute"
    
  data:
    subnet: "10.0.4.0/24"
    components: ["databases", "object_storage", "vault"]
    access_policy: "data_protection"
    
  management:
    subnet: "10.0.5.0/24"
    components: ["monitoring", "logging", "backup"]
    access_policy: "administrative"
```

### Network Policy Implementation

Kubernetes network policies enforce microsegmentation at the pod level.

```yaml
network_policies:
  default_deny:
    metadata:
      name: default-deny-all
    spec:
      podSelector: {}
      policyTypes: ["Ingress", "Egress"]
  
  gitlab_web_ingress:
    metadata:
      name: gitlab-web-ingress
    spec:
      podSelector:
        matchLabels:
          app: gitlab-webservice
      policyTypes: ["Ingress"]
      ingress:
        - from:
          - namespaceSelector:
              matchLabels:
                name: ingress-nginx
          - podSelector:
              matchLabels:
                app: gitlab-workhorse
          ports:
            - protocol: TCP
              port: 8080
  
  gitlab_database_access:
    metadata:
      name: gitlab-database-access
    spec:
      podSelector:
        matchLabels:
          app: postgresql
      policyTypes: ["Ingress"]
      ingress:
        - from:
          - podSelector:
              matchLabels:
                app: gitlab-webservice
          - podSelector:
              matchLabels:
                app: gitlab-sidekiq
          ports:
            - protocol: TCP
              port: 5432
  
  runner_egress:
    metadata:
      name: runner-egress
    spec:
      podSelector:
        matchLabels:
          app: gitlab-runner
      policyTypes: ["Egress"]
      egress:
        - to:
          - podSelector:
              matchLabels:
                app: gitlab-webservice
          ports:
            - protocol: TCP
              port: 443
        - to: []
          ports:
            - protocol: TCP
              port: 443
            - protocol: TCP
              port: 80
```

## Transport Layer Security

### SSL/TLS Configuration

Comprehensive TLS implementation ensures encrypted communication across all service endpoints.

```yaml
tls_configuration:
  global_settings:
    minimum_version: "TLSv1.3"
    cipher_suites:
      - "TLS_AES_256_GCM_SHA384"
      - "TLS_CHACHA20_POLY1305_SHA256"
      - "TLS_AES_128_GCM_SHA256"
    ecdh_curves:
      - "X25519"
      - "secp384r1"
      - "secp256r1"
  
  certificate_management:
    provider: "cert-manager"
    issuer: "letsencrypt-prod"
    renewal_threshold: 720h  # 30 days
    
  security_headers:
    strict_transport_security:
      enabled: true
      max_age: 31536000
      include_subdomains: true
      preload: true
    
    content_security_policy:
      default_src: "'self'"
      script_src: "'self' 'unsafe-inline'"
      style_src: "'self' 'unsafe-inline'"
      img_src: "'self' data: https:"
      
    x_frame_options: "DENY"
    x_content_type_options: "nosniff"
    referrer_policy: "strict-origin-when-cross-origin"
```

### Certificate Authority Integration

```yaml
certificate_authority:
  internal_ca:
    enabled: true
    root_ca:
      subject: "CN=GitLab Internal CA,O=Organization,C=US"
      validity: "87600h"  # 10 years
    
    intermediate_ca:
      subject: "CN=GitLab Services CA,O=Organization,C=US"
      validity: "43800h"  # 5 years
  
  certificate_profiles:
    server_auth:
      key_usage: ["digital_signature", "key_encipherment"]
      extended_key_usage: ["server_auth"]
      san_types: ["dns", "ip"]
    
    client_auth:
      key_usage: ["digital_signature"]
      extended_key_usage: ["client_auth"]
```

## Authentication and Authorization

### Role-Based Access Control

RBAC implementation provides granular permission management across system components.

```yaml
rbac_configuration:
  cluster_roles:
    gitlab_admin:
      rules:
        - apiGroups: [""]
          resources: ["*"]
          verbs: ["*"]
        - apiGroups: ["apps", "extensions"]
          resources: ["*"]
          verbs: ["*"]
    
    runner_controller:
      rules:
        - apiGroups: [""]
          resources: ["pods", "services", "configmaps"]
          verbs: ["create", "delete", "get", "list", "patch", "update", "watch"]
        - apiGroups: ["batch"]
          resources: ["jobs"]
          verbs: ["create", "delete", "get", "list", "patch", "update", "watch"]
        - apiGroups: ["autoscaling"]
          resources: ["horizontalpodautoscalers"]
          verbs: ["get", "list", "watch"]
    
    monitoring_reader:
      rules:
        - apiGroups: [""]
          resources: ["pods", "services", "endpoints", "nodes", "namespaces"]
          verbs: ["get", "list", "watch"]
        - apiGroups: ["apps"]
          resources: ["deployments", "replicasets", "daemonsets", "statefulsets"]
          verbs: ["get", "list", "watch"]
  
  service_accounts:
    gitlab_runner:
      namespace: "gitlab-runners"
      automount_token: true
      
    monitoring_agent:
      namespace: "monitoring"
      automount_token: true
      
    backup_operator:
      namespace: "gitlab-system"
      automount_token: false
```

### Multi-Factor Authentication

```yaml
authentication_methods:
  primary:
    type: "ldap"
    server: "ldaps://ldap.company.com:636"
    base_dn: "dc=company,dc=com"
    user_filter: "(objectClass=person)"
    
  secondary:
    type: "oauth2"
    providers:
      - name: "github"
        client_id: "${vault:secret/oauth/github#client_id}"
        client_secret: "${vault:secret/oauth/github#client_secret}"
      
      - name: "google"
        client_id: "${vault:secret/oauth/google#client_id}"
        client_secret: "${vault:secret/oauth/google#client_secret}"
  
  mfa_enforcement:
    enabled: true
    methods: ["totp", "webauthn"]
    grace_period: 168h  # 7 days
    bypass_roles: []
```

## Container Security

### Pod Security Standards

Implementation of Pod Security Standards ensures container-level security controls.

```yaml
pod_security:
  standards:
    baseline:
      namespaces: ["gitlab-system", "monitoring"]
      controls:
        - "disallow_privileged"
        - "disallow_privilege_escalation"
        - "require_non_root_user"
        - "restrict_seccomp"
    
    restricted:
      namespaces: ["gitlab-runners"]
      controls:
        - "disallow_privileged"
        - "disallow_privilege_escalation"
        - "require_non_root_user"
        - "restrict_seccomp"
        - "restrict_capabilities"
        - "require_run_as_non_root"
        - "restrict_volumes"
  
  security_contexts:
    default:
      runAsNonRoot: true
      runAsUser: 1000
      runAsGroup: 1000
      fsGroup: 1000
      seccompProfile:
        type: "RuntimeDefault"
      
    restricted:
      runAsNonRoot: true
      runAsUser: 1000
      runAsGroup: 1000
      fsGroup: 1000
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: "RuntimeDefault"
```

### Container Image Security

```yaml
image_security:
  registries:
    allowed:
      - "registry.gitlab.com"
      - "docker.io"
      - "gcr.io"
      - "quay.io"
    
  scanning:
    enabled: true
    vulnerability_database: "trivy"
    severity_threshold: "HIGH"
    
  signing:
    enabled: true
    cosign:
      public_key: "${vault:secret/cosign#public_key}"
      verify_attestations: true
  
  policies:
    - name: "base_image_policy"
      rule: "disallow_latest_tag"
      exceptions: ["development"]
    
    - name: "vulnerability_policy"
      rule: "block_critical_vulnerabilities"
      grace_period: "72h"
```

## Secret Management Integration

### Vault Configuration

HashiCorp Vault provides centralized secret management with dynamic secret generation.

```yaml
vault_integration:
  authentication:
    kubernetes:
      path: "kubernetes"
      role: "gitlab-secrets"
      service_account: "gitlab-vault-auth"
  
  secret_engines:
    kv_v2:
      path: "gitlab/"
      secrets:
        - "database/postgresql"
        - "oauth/providers"
        - "tls/certificates"
        - "runner/tokens"
    
    pki:
      path: "pki/"
      roles:
        - name: "gitlab-server"
          allowed_domains: ["gitlab.company.com", "*.gitlab.company.com"]
          allow_subdomains: true
          max_ttl: "8760h"
    
    database:
      path: "database/"
      connections:
        - name: "postgresql"
          plugin_name: "postgresql-database-plugin"
          connection_url: "postgresql://{{username}}:{{password}}@postgresql:5432/gitlab"
          allowed_roles: ["gitlab-app", "gitlab-readonly"]
  
  policies:
    gitlab_app:
      path:
        "gitlab/data/database/*": ["read"]
        "gitlab/data/oauth/*": ["read"]
        "pki/issue/gitlab-server": ["update"]
```

## Network Segmentation

### Firewall Rules

```yaml
firewall_configuration:
  ingress_rules:
    web_traffic:
      ports: [80, 443]
      sources: ["0.0.0.0/0"]
      protocol: "tcp"
      action: "allow"
    
    ssh_access:
      ports: [22]
      sources: ["10.0.0.0/8", "192.168.0.0/16"]
      protocol: "tcp"
      action: "allow"
      
    monitoring:
      ports: [9090, 3000]
      sources: ["10.0.5.0/24"]
      protocol: "tcp"
      action: "allow"
  
  egress_rules:
    internet_access:
      destinations: ["0.0.0.0/0"]
      ports: [80, 443]
      protocol: "tcp"
      action: "allow"
      
    dns_resolution:
      destinations: ["8.8.8.8", "8.8.4.4"]
      ports: [53]
      protocol: "udp"
      action: "allow"
```

## Security Monitoring

### Audit Logging

```yaml
audit_configuration:
  kubernetes:
    enabled: true
    policy: |
      apiVersion: audit.k8s.io/v1
      kind: Policy
      rules:
        - level: Metadata
          namespaces: ["gitlab-system", "gitlab-runners"]
          verbs: ["create", "update", "patch", "delete"]
          
        - level: Metadata
          resources:
            - group: ""
              resources: ["secrets", "configmaps"]
          verbs: ["get", "list", "watch"]
  
  application:
    gitlab:
      events: ["user_login", "project_create", "runner_register"]
      retention: "365d"
      
    vault:
      events: ["secret_read", "secret_write", "auth_failure"]
      retention: "2555d"  # 7 years
```

### Intrusion Detection

```yaml
intrusion_detection:
  falco:
    enabled: true
    rules:
      - name: "Detect privileged container"
        condition: "container and container.privileged=true"
        output: "Privileged container started"
        priority: "WARNING"
      
      - name: "Detect sensitive file access"
        condition: "open_read and fd.filename in (/etc/passwd, /etc/shadow)"
        output: "Sensitive file opened for reading"
        priority: "WARNING"
        
      - name: "Detect network tool execution"
        condition: "spawned_process and proc.name in (nc, ncat, netcat, nmap, dig, nslookup)"
        output: "Network tool executed"
        priority: "NOTICE"
```

## Compliance Framework

### Security Controls

```yaml
compliance_controls:
  encryption:
    data_at_rest:
      enabled: true
      algorithm: "AES-256-GCM"
      key_rotation: "quarterly"
      
    data_in_transit:
      enabled: true
      minimum_tls: "1.3"
      certificate_validation: true
  
  access_controls:
    principle_of_least_privilege: true
    regular_access_review: "monthly"
    privileged_access_monitoring: true
    
  data_protection:
    backup_encryption: true
    backup_retention: "2555d"  # 7 years
    data_classification: true
    
  incident_response:
    automated_alerting: true
    response_playbooks: true
    forensic_logging: true
```

### Vulnerability Management

```yaml
vulnerability_management:
  scanning:
    container_images:
      frequency: "daily"
      tools: ["trivy", "clair"]
      
    infrastructure:
      frequency: "weekly"
      tools: ["nessus", "openvas"]
      
    application:
      frequency: "monthly"
      tools: ["owasp-zap", "burp"]
  
  remediation:
    critical: "24h"
    high: "72h"
    medium: "30d"
    low: "90d"
    
  reporting:
    frequency: "weekly"
    stakeholders: ["security_team", "platform_team"]
    format: ["pdf", "json"]
```

This security and network configuration establishes comprehensive protection mechanisms for GitLab infrastructure deployment. Implementation requires coordination with supporting infrastructure services and operational procedures detailed in subsequent documents.