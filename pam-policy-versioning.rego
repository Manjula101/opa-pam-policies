# OPA Policy: Policy Versioning & Rollback for PAM
# Manage policy versions and support safe rollbacks
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.policy_versioning

default allow = false

# Active policy version (configurable)
active_version := "v2.1"

# Allow if the requested policy version matches the active version
allow {
    input.policy_version == active_version
}

# Allow rollback to previous stable version under specific conditions
allow {
    input.action == "rollback"
    input.requested_version == "v2.0"
    input.approval.status == "approved"
}

# Deny message
deny[msg] {
    not allow
    msg := sprintf("Policy version denied: requested %s, active is %s", [input.policy_version, active_version])
}

# Demo test cases
test_allow_current_version {
    allow with input as {"policy_version": "v2.1"}
}

test_deny_old_version {
    not allow with input as {"policy_version": "v1.0"}
}

test_allow_approved_rollback {
    allow with input as {
        "action": "rollback",
        "requested_version": "v2.0",
        "approval": {"status": "approved"}
    }
}

test_deny_unapproved_rollback {
    not allow with input as {
        "action": "rollback",
        "requested_version": "v2.0",
        "approval": {"status": "pending"}
    }
}
