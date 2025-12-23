# =============================================================================
# OPA Policy Tests for Kasten K10
# Run with: opa test kasten-policies.rego kasten-policies_test.rego -v
# =============================================================================

package kasten

import future.keywords.in

# =============================================================================
# Test: Backup Policy Requirements
# =============================================================================

# Test: Policy without backup action should be denied
test_deny_policy_missing_backup if {
    result := deny_policy_missing_backup with input as {
        "apiVersion": "config.kio.kasten.io/v1alpha1",
        "kind": "Policy",
        "metadata": {"name": "test-policy"},
        "spec": {
            "actions": [
                {"action": "export"}
            ]
        }
    }
    count(result) > 0
}

# Test: Policy with backup action should be allowed
test_allow_policy_with_backup if {
    result := deny_policy_missing_backup with input as {
        "apiVersion": "config.kio.kasten.io/v1alpha1",
        "kind": "Policy",
        "metadata": {"name": "test-policy"},
        "spec": {
            "actions": [
                {"action": "backup"}
            ]
        }
    }
    count(result) == 0
}

# Test: Policy without export should warn
test_warn_policy_missing_export if {
    result := warn_policy_missing_export with input as {
        "apiVersion": "config.kio.kasten.io/v1alpha1",
        "kind": "Policy",
        "metadata": {"name": "test-policy"},
        "spec": {
            "actions": [
                {"action": "backup"}
            ]
        }
    }
    count(result) > 0
}

# Test: Policy with both backup and export should not warn
test_no_warn_policy_with_export if {
    result := warn_policy_missing_export with input as {
        "apiVersion": "config.kio.kasten.io/v1alpha1",
        "kind": "Policy",
        "metadata": {"name": "test-policy"},
        "spec": {
            "actions": [
                {"action": "backup"},
                {"action": "export"}
            ]
        }
    }
    count(result) == 0
}

# =============================================================================
# Test: Location Profile Security
# =============================================================================

# Test: S3 location with HTTP endpoint should be denied
test_deny_insecure_s3_endpoint if {
    result := deny_insecure_s3_endpoint with input as {
        "apiVersion": "config.kio.kasten.io/v1alpha1",
        "kind": "Profile",
        "metadata": {"name": "insecure-profile"},
        "spec": {
            "type": "Location",
            "locationSpec": {
                "objectStore": {
                    "objectStoreType": "S3",
                    "endpoint": "http://minio.example.com"
                }
            }
        }
    }
    count(result) > 0
}

# Test: S3 location with HTTPS endpoint should be allowed
test_allow_secure_s3_endpoint if {
    result := deny_insecure_s3_endpoint with input as {
        "apiVersion": "config.kio.kasten.io/v1alpha1",
        "kind": "Profile",
        "metadata": {"name": "secure-profile"},
        "spec": {
            "type": "Location",
            "locationSpec": {
                "objectStore": {
                    "objectStoreType": "S3",
                    "endpoint": "https://s3.amazonaws.com"
                }
            }
        }
    }
    count(result) == 0
}

# Test: Location profile with public access should be denied
test_deny_public_bucket_access if {
    result := deny_public_bucket_access with input as {
        "apiVersion": "config.kio.kasten.io/v1alpha1",
        "kind": "Profile",
        "metadata": {"name": "public-profile"},
        "spec": {
            "type": "Location",
            "locationSpec": {
                "objectStore": {
                    "publicAccess": true
                }
            }
        }
    }
    count(result) > 0
}

# =============================================================================
# Test: Blueprint Security
# =============================================================================

# Test: Blueprint with privileged container should be denied
test_deny_privileged_blueprint if {
    result := deny_privileged_blueprint_containers with input as {
        "apiVersion": "cr.kanister.io/v1alpha1",
        "kind": "Blueprint",
        "metadata": {"name": "privileged-bp"},
        "spec": {
            "actions": {
                "backup": {
                    "phases": [
                        {
                            "func": "KubeTask",
                            "args": {
                                "podOverride": {
                                    "containers": [
                                        {
                                            "name": "backup",
                                            "securityContext": {
                                                "privileged": true
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    ]
                }
            }
        }
    }
    count(result) > 0
}

# Test: Blueprint running as root should be denied
test_deny_root_blueprint if {
    result := deny_root_blueprint_containers with input as {
        "apiVersion": "cr.kanister.io/v1alpha1",
        "kind": "Blueprint",
        "metadata": {"name": "root-bp"},
        "spec": {
            "actions": {
                "backup": {
                    "phases": [
                        {
                            "func": "KubeTask",
                            "args": {
                                "podOverride": {
                                    "containers": [
                                        {
                                            "name": "backup",
                                            "securityContext": {
                                                "runAsUser": 0
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    ]
                }
            }
        }
    }
    count(result) > 0
}

# Test: Blueprint with host network should be denied
test_deny_host_network_blueprint if {
    result := deny_host_network_blueprint with input as {
        "apiVersion": "cr.kanister.io/v1alpha1",
        "kind": "Blueprint",
        "metadata": {"name": "hostnet-bp"},
        "spec": {
            "actions": {
                "backup": {
                    "phases": [
                        {
                            "func": "KubeTask",
                            "args": {
                                "podOverride": {
                                    "hostNetwork": true
                                }
                            }
                        }
                    ]
                }
            }
        }
    }
    count(result) > 0
}

# =============================================================================
# Test: Restore Policy Controls
# =============================================================================

# Test: Restore to production without approval should be denied
test_deny_prod_restore_without_approval if {
    result := deny_prod_restore_without_approval with input as {
        "apiVersion": "actions.kio.kasten.io/v1alpha1",
        "kind": "RestoreAction",
        "metadata": {
            "name": "test-restore",
            "annotations": {}
        },
        "spec": {
            "targetNamespace": "production"
        }
    }
    count(result) > 0
}

# Test: Restore to production with approval should be allowed
test_allow_prod_restore_with_approval if {
    result := deny_prod_restore_without_approval with input as {
        "apiVersion": "actions.kio.kasten.io/v1alpha1",
        "kind": "RestoreAction",
        "metadata": {
            "name": "test-restore",
            "annotations": {
                "kasten.io/approved-by": "admin@company.com"
            }
        },
        "spec": {
            "targetNamespace": "production"
        }
    }
    count(result) == 0
}

# =============================================================================
# Test: Retention Requirements
# =============================================================================

# Test: Policy with insufficient daily retention should be denied
test_deny_insufficient_daily_retention if {
    result := deny_insufficient_retention with input as {
        "apiVersion": "config.kio.kasten.io/v1alpha1",
        "kind": "Policy",
        "metadata": {"name": "low-retention-policy"},
        "spec": {
            "actions": [
                {
                    "action": "backup",
                    "retention": {
                        "daily": {
                            "retention": 3
                        }
                    }
                }
            ]
        }
    }
    count(result) > 0
}

# =============================================================================
# Test: Compliance and Labels
# =============================================================================

# Test: Kasten resource without required labels should be denied
test_deny_missing_labels if {
    result := deny_missing_required_labels with input as {
        "apiVersion": "config.kio.kasten.io/v1alpha1",
        "kind": "Policy",
        "metadata": {
            "name": "unlabeled-policy",
            "labels": {}
        }
    }
    count(result) > 0
}

# Test: Policy without description should be denied
test_deny_policy_no_description if {
    result := deny_policy_no_description with input as {
        "apiVersion": "config.kio.kasten.io/v1alpha1",
        "kind": "Policy",
        "metadata": {
            "name": "undocumented-policy",
            "annotations": {}
        }
    }
    count(result) > 0
}

# Test: Policy with description should be allowed
test_allow_policy_with_description if {
    result := deny_policy_no_description with input as {
        "apiVersion": "config.kio.kasten.io/v1alpha1",
        "kind": "Policy",
        "metadata": {
            "name": "documented-policy",
            "annotations": {
                "kasten.io/description": "Daily backup policy for production databases"
            }
        }
    }
    count(result) == 0
}

# =============================================================================
# Test: K10 Installation Security
# =============================================================================

# Test: K10 without any auth should be denied
test_deny_k10_no_auth if {
    result := deny_k10_no_auth with input as {
        "apiVersion": "helm.toolkit.fluxcd.io/v2beta1",
        "kind": "HelmRelease",
        "metadata": {"name": "k10"},
        "spec": {
            "values": {
                "auth": {
                    "basicAuth": {"enabled": false},
                    "oidcAuth": {"enabled": false},
                    "tokenAuth": {"enabled": false},
                    "ldap": {"enabled": false}
                }
            }
        }
    }
    count(result) > 0
}

# Test: K10 with OIDC auth should be allowed
test_allow_k10_with_oidc if {
    result := deny_k10_no_auth with input as {
        "apiVersion": "helm.toolkit.fluxcd.io/v2beta1",
        "kind": "HelmRelease",
        "metadata": {"name": "k10"},
        "spec": {
            "values": {
                "auth": {
                    "basicAuth": {"enabled": false},
                    "oidcAuth": {"enabled": true},
                    "tokenAuth": {"enabled": false},
                    "ldap": {"enabled": false}
                }
            }
        }
    }
    count(result) == 0
}
