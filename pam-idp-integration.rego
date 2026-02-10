# OPA Policy: Identity Provider (IdP) Integration for PAM
# Enforce access based on SAML/OIDC claims (e.g., group membership, risk signals)
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.idp_integration

default allow = false

# Required IdP claims (example)
required_claims := {
    "group_membership": "pam-admin-group",
    "risk_level": "low"
}

# Allow if all IdP claims meet criteria
allow {
    input.idp_claims.group_membership == required_claims.group_membership
    input.idp_claims.risk_level == required_claims.risk_level
}

# Deny message
deny[msg] {
    not allow
    msg := "Access denied: IdP claims not satisfied (check group membership and risk level)"
}

# Demo test cases
test_allow_valid_claims {
    allow with input as {
        "idp_claims": {
            "group_membership": "pam-admin-group",
            "risk_level": "low"
        }
    }
}

test_deny_wrong_group {
    not allow with input as {
        "idp_claims": {
            "group_membership": "user-group",
            "risk_level": "low"
        }
    }
}

test_deny_high_risk {
    not allow with input as {
        "idp_claims": {
            "group_membership": "pam-admin-group",
            "risk_level": "high"
        }
    }
}
