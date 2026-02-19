# OPA Policy: Multi-Tenancy Isolation for PAM
# Prevent cross-tenant access in shared environments
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.multi_tenancy_isolation

default allow = false

# Allow only if user tenant matches resource tenant
allow {
    input.user.tenant_id == input.resource.tenant_id
}

# Deny message
deny[msg] {
    not allow
    msg := sprintf("Access denied: cross-tenant access not allowed (user tenant: %s, resource tenant: %s)", 
                   [input.user.tenant_id, input.resource.tenant_id])
}

# Demo test cases
test_allow_same_tenant {
    allow with input as {
        "user": {"tenant_id": "tenant-123"},
        "resource": {"tenant_id": "tenant-123"}
    }
}

test_deny_cross_tenant {
    not allow with input as {
        "user": {"tenant_id": "tenant-123"},
        "resource": {"tenant_id": "tenant-456"}
    }
}

test_deny_missing_tenant {
    not allow with input as {
        "user": {"tenant_id": "tenant-123"},
        "resource": {}
    }
}
