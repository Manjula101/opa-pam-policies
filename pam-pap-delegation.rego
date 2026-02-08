# OPA Policy: Policy Administration Point (PAP) Delegation for PAM
# Allow delegated policy management (e.g., team admins add policies)
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.pap_delegation

default allow = false

# Delegated roles (example)
delegated_roles := {"team_admin", "policy_manager"}

# Allow delegation if user has delegated role
allow {
    input.user.role in delegated_roles
}

# Allow specific actions for delegated users
allow {
    input.user.role in delegated_roles
    input.action in {"add_policy", "edit_policy", "delete_policy"}
}

# Deny message
deny[msg] {
    not allow
    msg := sprintf("Delegation denied: user %s not authorized for %s", [input.user.role, input.action])
}

# Demo test cases
test_allow_delegated_role {
    allow with input as {"user": {"role": "team_admin"}, "action": "add_policy"}
}

test_deny_non_delegated_role {
    not allow with input as {"user": {"role": "user"}, "action": "add_policy"}
}

test_allow_edit_policy {
    allow with input as {"user": {"role": "policy_manager"}, "action": "edit_policy"}
}
