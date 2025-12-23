# =============================================================================
# OPA Policies for Kasten K10
# Kubernetes Backup and Disaster Recovery Governance
# =============================================================================

package kasten

import future.keywords.in
import future.keywords.contains
import future.keywords.if
import future.keywords.every

# =============================================================================
# POLICY: Backup Policy Requirements
# =============================================================================

# Deny policies without a backup action
deny_policy_missing_backup contains msg if {
    input.apiVersion == "config.kio.kasten.io/v1alpha1"
    input.kind == "Policy"
    actions := input.spec.actions
    not has_backup_action(actions)
    msg := sprintf("Policy '%s' must include a backup action", [input.metadata.name])
}

has_backup_action(actions) if {
    some action in actions
    action.action == "backup"
}

# Deny policies without export action (for 3-2-1 backup rule)
warn_policy_missing_export contains msg if {
    input.apiVersion == "config.kio.kasten.io/v1alpha1"
    input.kind == "Policy"
    actions := input.spec.actions
    has_backup_action(actions)
    not has_export_action(actions)
    msg := sprintf("Policy '%s' should include an export action for off-cluster backup (3-2-1 rule)", [input.metadata.name])
}

has_export_action(actions) if {
    some action in actions
    action.action == "export"
}

# Deny policies with frequency less than daily for production namespaces
deny_insufficient_backup_frequency contains msg if {
    input.apiVersion == "config.kio.kasten.io/v1alpha1"
    input.kind == "Policy"
    
    # Check if targeting production namespace
    selector := input.spec.selector
    is_production_namespace(selector)
    
    # Check frequency
    frequency := input.spec.frequency
    not is_sufficient_frequency(frequency)
    
    msg := sprintf("Policy '%s' targets production namespace but has insufficient backup frequency. Minimum daily backups required.", [input.metadata.name])
}

is_production_namespace(selector) if {
    selector.matchExpressions[_].key == "environment"
    selector.matchExpressions[_].values[_] == "production"
}

is_production_namespace(selector) if {
    contains(selector.matchLabels.environment, "prod")
}

is_production_namespace(selector) if {
    endswith(selector.matchLabels["kubernetes.io/metadata.name"], "-prod")
}

is_sufficient_frequency(frequency) if {
    frequency == "@hourly"
}

is_sufficient_frequency(frequency) if {
    frequency == "@daily"
}

is_sufficient_frequency(frequency) if {
    # Cron expression - check if at least daily
    # This is a simplified check
    startswith(frequency, "0 ")
}

# =============================================================================
# POLICY: Retention Requirements
# =============================================================================

# Minimum retention periods
min_hourly_retention := 24
min_daily_retention := 7
min_weekly_retention := 4
min_monthly_retention := 12

# Deny policies with insufficient retention
deny_insufficient_retention contains msg if {
    input.apiVersion == "config.kio.kasten.io/v1alpha1"
    input.kind == "Policy"
    
    some action in input.spec.actions
    action.action == "backup"
    retention := action.retention
    
    # Check hourly retention
    retention.hourly.retention < min_hourly_retention
    
    msg := sprintf("Policy '%s' has insufficient hourly retention (%d). Minimum required: %d", 
        [input.metadata.name, retention.hourly.retention, min_hourly_retention])
}

deny_insufficient_retention contains msg if {
    input.apiVersion == "config.kio.kasten.io/v1alpha1"
    input.kind == "Policy"
    
    some action in input.spec.actions
    action.action == "backup"
    retention := action.retention
    
    # Check daily retention
    retention.daily.retention < min_daily_retention
    
    msg := sprintf("Policy '%s' has insufficient daily retention (%d). Minimum required: %d", 
        [input.metadata.name, retention.daily.retention, min_daily_retention])
}

deny_insufficient_retention contains msg if {
    input.apiVersion == "config.kio.kasten.io/v1alpha1"
    input.kind == "Policy"
    
    some action in input.spec.actions
    action.action == "backup"
    retention := action.retention
    
    # Check weekly retention
    retention.weekly.retention < min_weekly_retention
    
    msg := sprintf("Policy '%s' has insufficient weekly retention (%d). Minimum required: %d", 
        [input.metadata.name, retention.weekly.retention, min_weekly_retention])
}

deny_insufficient_retention contains msg if {
    input.apiVersion == "config.kio.kasten.io/v1alpha1"
    input.kind == "Policy"
    
    some action in input.spec.actions
    action.action == "backup"
    retention := action.retention
    
    # Check monthly retention
    retention.monthly.retention < min_monthly_retention
    
    msg := sprintf("Policy '%s' has insufficient monthly retention (%d). Minimum required: %d", 
        [input.metadata.name, retention.monthly.retention, min_monthly_retention])
}

# =============================================================================
# POLICY: Location Profile Security
# =============================================================================

# Deny location profiles without encryption
deny_unencrypted_location_profile contains msg if {
    input.apiVersion == "config.kio.kasten.io/v1alpha1"
    input.kind == "Profile"
    input.spec.type == "Location"
    
    # Check if encryption is disabled or missing
    not input.spec.locationSpec.credential.secretType == "kopia"
    not location_has_encryption(input.spec.locationSpec)
    
    msg := sprintf("Location Profile '%s' must have encryption enabled for data at rest", [input.metadata.name])
}

location_has_encryption(locationSpec) if {
    locationSpec.objectStore.encryption.enabled == true
}

location_has_encryption(locationSpec) if {
    locationSpec.objectStore.serverSideEncryption != ""
}

# Deny S3 location profiles without HTTPS
deny_insecure_s3_endpoint contains msg if {
    input.apiVersion == "config.kio.kasten.io/v1alpha1"
    input.kind == "Profile"
    input.spec.type == "Location"
    input.spec.locationSpec.objectStore.objectStoreType == "S3"
    
    endpoint := input.spec.locationSpec.objectStore.endpoint
    startswith(endpoint, "http://")
    
    msg := sprintf("Location Profile '%s' uses insecure HTTP endpoint. Use HTTPS instead.", [input.metadata.name])
}

# Deny location profiles with public bucket access
deny_public_bucket_access contains msg if {
    input.apiVersion == "config.kio.kasten.io/v1alpha1"
    input.kind == "Profile"
    input.spec.type == "Location"
    
    input.spec.locationSpec.objectStore.publicAccess == true
    
    msg := sprintf("Location Profile '%s' has public access enabled. Backup data must not be publicly accessible.", [input.metadata.name])
}

# Warn if using same region for backup location
warn_same_region_backup contains msg if {
    input.apiVersion == "config.kio.kasten.io/v1alpha1"
    input.kind == "Profile"
    input.spec.type == "Location"
    
    # This would need cluster region context in real implementation
    input.spec.locationSpec.objectStore.region == data.cluster.region
    
    msg := sprintf("Location Profile '%s' is in the same region as the cluster. Consider cross-region backups for disaster recovery.", [input.metadata.name])
}

# =============================================================================
# POLICY: Blueprint Security
# =============================================================================

# Deny blueprints with privileged containers
deny_privileged_blueprint_containers contains msg if {
    input.apiVersion == "cr.kanister.io/v1alpha1"
    input.kind == "Blueprint"
    
    some action_name, action in input.spec.actions
    some phase in action.phases
    phase.func == "KubeTask"
    phase.args.podOverride.containers[_].securityContext.privileged == true
    
    msg := sprintf("Blueprint '%s' action '%s' uses privileged containers. This is a security risk.", 
        [input.metadata.name, action_name])
}

# Deny blueprints running as root
deny_root_blueprint_containers contains msg if {
    input.apiVersion == "cr.kanister.io/v1alpha1"
    input.kind == "Blueprint"
    
    some action_name, action in input.spec.actions
    some phase in action.phases
    phase.func == "KubeTask"
    phase.args.podOverride.containers[_].securityContext.runAsUser == 0
    
    msg := sprintf("Blueprint '%s' action '%s' runs as root. Use non-root user instead.", 
        [input.metadata.name, action_name])
}

# Deny blueprints with host network access
deny_host_network_blueprint contains msg if {
    input.apiVersion == "cr.kanister.io/v1alpha1"
    input.kind == "Blueprint"
    
    some action_name, action in input.spec.actions
    some phase in action.phases
    phase.func == "KubeTask"
    phase.args.podOverride.hostNetwork == true
    
    msg := sprintf("Blueprint '%s' action '%s' uses host network. This is a security risk.", 
        [input.metadata.name, action_name])
}

# Warn on blueprints using shell commands (potential injection risk)
warn_blueprint_shell_injection contains msg if {
    input.apiVersion == "cr.kanister.io/v1alpha1"
    input.kind == "Blueprint"
    
    some action_name, action in input.spec.actions
    some phase in action.phases
    
    # Check for shell command patterns
    command := phase.args.command[_]
    contains(command, "eval ")
    
    msg := sprintf("Blueprint '%s' action '%s' uses 'eval' which may be vulnerable to command injection.", 
        [input.metadata.name, action_name])
}

warn_blueprint_shell_injection contains msg if {
    input.apiVersion == "cr.kanister.io/v1alpha1"
    input.kind == "Blueprint"
    
    some action_name, action in input.spec.actions
    some phase in action.phases
    
    command := phase.args.command[_]
    contains(command, "${{")
    
    msg := sprintf("Blueprint '%s' action '%s' uses template variables in shell commands. Ensure proper escaping.", 
        [input.metadata.name, action_name])
}

# =============================================================================
# POLICY: Restore Policy Controls
# =============================================================================

# Require approval for production restores
deny_prod_restore_without_approval contains msg if {
    input.apiVersion == "actions.kio.kasten.io/v1alpha1"
    input.kind == "RestoreAction"
    
    # Check if restoring to production namespace
    target_namespace := input.spec.targetNamespace
    is_production_target(target_namespace)
    
    # Check for approval annotation
    not has_restore_approval(input.metadata.annotations)
    
    msg := sprintf("RestoreAction to production namespace '%s' requires approval annotation 'kasten.io/approved-by'", 
        [target_namespace])
}

is_production_target(namespace) if {
    contains(namespace, "prod")
}

is_production_target(namespace) if {
    namespace == "production"
}

has_restore_approval(annotations) if {
    annotations["kasten.io/approved-by"] != ""
}

# Deny cross-cluster restores without explicit flag
deny_cross_cluster_restore_unintended contains msg if {
    input.apiVersion == "actions.kio.kasten.io/v1alpha1"
    input.kind == "RestoreAction"
    
    input.spec.targetCluster != ""
    input.spec.targetCluster != data.cluster.name
    
    not input.metadata.annotations["kasten.io/cross-cluster-restore"] == "true"
    
    msg := sprintf("Cross-cluster restore to '%s' requires explicit annotation 'kasten.io/cross-cluster-restore: true'", 
        [input.spec.targetCluster])
}

# Warn on restore to same namespace (potential data loss)
warn_restore_same_namespace contains msg if {
    input.apiVersion == "actions.kio.kasten.io/v1alpha1"
    input.kind == "RestoreAction"
    
    input.spec.targetNamespace == input.spec.sourceNamespace
    not input.metadata.annotations["kasten.io/in-place-restore"] == "true"
    
    msg := sprintf("RestoreAction to same namespace '%s' may overwrite existing data. Add annotation 'kasten.io/in-place-restore: true' to confirm.", 
        [input.spec.targetNamespace])
}

# =============================================================================
# POLICY: Namespace Protection
# =============================================================================

# List of namespaces that must have backup policies
required_backup_namespaces := [
    "production",
    "staging",
    "databases",
    "monitoring"
]

# Check that critical namespaces have backup policies
deny_unprotected_critical_namespace contains msg if {
    input.apiVersion == "v1"
    input.kind == "Namespace"
    input.metadata.name in required_backup_namespaces
    
    not namespace_has_backup_policy(input.metadata.name)
    
    msg := sprintf("Critical namespace '%s' must have a Kasten backup policy", [input.metadata.name])
}

# This would check against existing policies in the cluster
namespace_has_backup_policy(namespace) if {
    some policy in data.kasten.policies
    policy_covers_namespace(policy, namespace)
}

policy_covers_namespace(policy, namespace) if {
    policy.spec.selector.matchLabels["kubernetes.io/metadata.name"] == namespace
}

policy_covers_namespace(policy, namespace) if {
    some expr in policy.spec.selector.matchExpressions
    expr.key == "kubernetes.io/metadata.name"
    expr.operator == "In"
    namespace in expr.values
}

# =============================================================================
# POLICY: TransformSet Security
# =============================================================================

# Deny transforms that expose secrets
deny_transform_exposes_secrets contains msg if {
    input.apiVersion == "config.kio.kasten.io/v1alpha1"
    input.kind == "TransformSet"
    
    some transform in input.spec.transforms
    transform.subject.resource == "secrets"
    
    # Check for transforms that might log or expose secret data
    some op in transform.json6902
    op.op == "add"
    contains(op.path, "/data")
    
    msg := sprintf("TransformSet '%s' modifies secret data. Ensure sensitive data is not exposed.", 
        [input.metadata.name])
}

# Warn on transforms that change resource limits
warn_transform_changes_resources contains msg if {
    input.apiVersion == "config.kio.kasten.io/v1alpha1"
    input.kind == "TransformSet"
    
    some transform in input.spec.transforms
    some op in transform.json6902
    
    contains(op.path, "/spec/resources")
    
    msg := sprintf("TransformSet '%s' modifies resource limits. Verify this is intentional for the target environment.", 
        [input.metadata.name])
}

# =============================================================================
# POLICY: K10 Installation Security
# =============================================================================

# Deny K10 installation without authentication
deny_k10_no_auth contains msg if {
    input.apiVersion == "helm.toolkit.fluxcd.io/v2beta1"
    input.kind == "HelmRelease"
    input.metadata.name == "k10"
    
    values := input.spec.values
    values.auth.basicAuth.enabled == false
    values.auth.oidcAuth.enabled == false
    values.auth.tokenAuth.enabled == false
    values.auth.ldap.enabled == false
    
    msg := "K10 installation must have at least one authentication method enabled"
}

# Deny K10 without HTTPS/TLS
deny_k10_no_tls contains msg if {
    input.apiVersion == "helm.toolkit.fluxcd.io/v2beta1"
    input.kind == "HelmRelease"
    input.metadata.name == "k10"
    
    values := input.spec.values
    not values.ingress.tls
    values.externalGateway.create == true
    
    msg := "K10 external gateway must use TLS encryption"
}

# Warn on K10 with default service account
warn_k10_default_sa contains msg if {
    input.apiVersion == "helm.toolkit.fluxcd.io/v2beta1"
    input.kind == "HelmRelease"
    input.metadata.name == "k10"
    
    values := input.spec.values
    not values.serviceAccount.name
    
    msg := "K10 should use a dedicated service account instead of default"
}

# Deny K10 with cluster-wide permissions when not needed
deny_k10_excessive_permissions contains msg if {
    input.apiVersion == "helm.toolkit.fluxcd.io/v2beta1"
    input.kind == "HelmRelease"
    input.metadata.name == "k10"
    
    values := input.spec.values
    values.clusterScope == true
    not values.clusterScopeRequired
    
    msg := "K10 has cluster-wide permissions but clusterScopeRequired is not set. Use namespace-scoped installation if possible."
}

# =============================================================================
# POLICY: Compliance and Audit
# =============================================================================

# Require labels for all Kasten resources
deny_missing_required_labels contains msg if {
    is_kasten_resource(input)
    
    required_labels := ["app.kubernetes.io/managed-by", "environment", "owner"]
    missing := [label | 
        label := required_labels[_]
        not input.metadata.labels[label]
    ]
    
    count(missing) > 0
    
    msg := sprintf("%s '%s' is missing required labels: %v", 
        [input.kind, input.metadata.name, missing])
}

is_kasten_resource(resource) if {
    startswith(resource.apiVersion, "config.kio.kasten.io")
}

is_kasten_resource(resource) if {
    startswith(resource.apiVersion, "actions.kio.kasten.io")
}

is_kasten_resource(resource) if {
    resource.apiVersion == "cr.kanister.io/v1alpha1"
}

# Require description annotation for policies
deny_policy_no_description contains msg if {
    input.apiVersion == "config.kio.kasten.io/v1alpha1"
    input.kind == "Policy"
    
    not input.metadata.annotations["kasten.io/description"]
    
    msg := sprintf("Policy '%s' must have a description annotation 'kasten.io/description'", 
        [input.metadata.name])
}

# =============================================================================
# POLICY: Resource Limits
# =============================================================================

# Maximum number of concurrent backups
max_concurrent_backups := 5

deny_excessive_concurrent_backups contains msg if {
    input.apiVersion == "config.kio.kasten.io/v1alpha1"
    input.kind == "Policy"
    
    input.spec.concurrencyLimit > max_concurrent_backups
    
    msg := sprintf("Policy '%s' exceeds maximum concurrent backups (%d). Limit: %d", 
        [input.metadata.name, input.spec.concurrencyLimit, max_concurrent_backups])
}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

# Check if a value is in a list
value_in_list(value, list) if {
    list[_] == value
}

# Check if string contains sensitive patterns
contains_sensitive_data(str) if {
    sensitive_patterns := ["password", "secret", "token", "key", "credential"]
    some pattern in sensitive_patterns
    contains(lower(str), pattern)
}

# =============================================================================
# POLICY METADATA
# =============================================================================

# Policy documentation
policy_metadata := {
    "name": "Kasten K10 Governance Policies",
    "version": "1.0.0",
    "description": "OPA policies for Kasten K10 backup and disaster recovery governance",
    "categories": [
        "backup-requirements",
        "retention",
        "security",
        "location-profiles",
        "blueprints",
        "restore-controls",
        "compliance"
    ]
}
