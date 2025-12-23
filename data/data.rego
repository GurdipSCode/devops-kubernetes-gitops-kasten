# =============================================================================
# OPA Data Configuration for Kasten K10 Policies
# Customize these values for your environment
# =============================================================================

# Cluster information
cluster:
  name: "production-cluster"
  region: "us-east-1"
  environment: "production"

# Retention requirements (in number of backups to keep)
retention:
  minimum:
    hourly: 24      # Keep at least 24 hourly backups
    daily: 7        # Keep at least 7 daily backups
    weekly: 4       # Keep at least 4 weekly backups
    monthly: 12     # Keep at least 12 monthly backups
    yearly: 3       # Keep at least 3 yearly backups

# Backup frequency requirements
backup_frequency:
  production:
    minimum: "hourly"     # Production must have at least hourly backups
  staging:
    minimum: "daily"      # Staging must have at least daily backups
  development:
    minimum: "weekly"     # Development must have at least weekly backups

# Critical namespaces that MUST have backup policies
critical_namespaces:
  - production
  - staging
  - databases
  - monitoring
  - logging
  - security

# Namespaces that should be excluded from backup requirements
excluded_namespaces:
  - kube-system
  - kube-public
  - kube-node-lease
  - kasten-io
  - kasten-io-mc

# Approved backup locations (bucket names or prefixes)
approved_locations:
  s3:
    - "company-backups-*"
    - "k10-dr-*"
  azure:
    - "companybackups"
  gcs:
    - "company-k10-backups"

# Approved regions for backup storage
approved_regions:
  primary:
    - "us-east-1"
    - "us-west-2"
  dr:
    - "eu-west-1"
    - "ap-southeast-1"

# Security requirements
security:
  encryption:
    required: true
    minimum_key_length: 256
  tls:
    required: true
    minimum_version: "1.2"
  authentication:
    required: true
    allowed_methods:
      - "oidc"
      - "ldap"
      - "token"

# Compliance requirements
compliance:
  required_labels:
    - "app.kubernetes.io/managed-by"
    - "environment"
    - "owner"
    - "cost-center"
  required_annotations:
    - "kasten.io/description"
    - "kasten.io/contact"

# Resource limits
resource_limits:
  max_concurrent_backups: 5
  max_concurrent_restores: 3
  max_concurrent_exports: 2

# Restore controls
restore:
  production_requires_approval: true
  cross_cluster_requires_approval: true
  same_namespace_requires_confirmation: true

# Blueprint restrictions
blueprints:
  allow_privileged: false
  allow_host_network: false
  allow_host_pid: false
  allow_root_user: false
  approved_images:
    - "ghcr.io/kanisterio/*"
    - "gcr.io/kasten-images/*"
    - "docker.io/kanisterio/*"

# Alert thresholds
alerts:
  backup_age_warning_hours: 26      # Warn if last backup > 26 hours old
  backup_age_critical_hours: 50     # Critical if last backup > 50 hours old
  storage_usage_warning_percent: 80
  storage_usage_critical_percent: 95
