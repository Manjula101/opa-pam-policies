# OPA Policy: Enforce MFA for privileged access
package pam.mfa

default allow = false

allow {
    input.mfa_verified == true
}

deny[msg] {
    not allow
    msg := "Access denied: MFA verification required"
}

# Test cases
test_allow_with_mfa {
    allow with input as {"mfa_verified": true}
}

test_deny_without_mfa {
    not allow with input as {"mfa_verified": false}
}
