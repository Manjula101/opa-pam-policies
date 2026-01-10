# OPA Policy: Role-Based Escalation Limits for PAM
# Deny privilege escalation without explicit approval
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.role_escalation

default allow = false

# Allowed escalation paths (user → role)
allowed_escalations := {
    {"user": "operator", "target_role": "admin", "requires_approval": true},
    {"user": "engineer", "target_role": "admin", "requires_approval": true},
    {"user": "analyst", "target_role": "engineer", "requires_approval": false},
}

# Allow if escalation is permitted and approved (if required)
allow {
    some path
    path.user == input.user
    path.target_role == input.target_role
    path.requires_approval == false
}

allow {
    some path
    path.user == input.user
    path.target_role == input.target_role
    path.requires_approval == true
    input.approval.status == "approved"
}

# Deny message
deny[msg] {
    not allow
    msg := sprintf("Escalation denied: %s → %s requires approval", [input.user, input.target_role])
}

# Demo test cases
test_allow_no_approval_needed {
    allow with input as {"user": "analyst", "target_role": "engineer"}
}

test_deny_unapproved_escalation {
    not allow with input as {"user": "operator", "target_role": "admin", "approval": {"status": "pending"}}
}

test_allow_approved_escalation {
    allow with input as {"user": "engineer", "target_role": "admin", "approval": {"status": "approved"}}
}
