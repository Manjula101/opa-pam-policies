# OPA Policy: Zero-Trust Verification for PAM
# Enforce access by verifying identity, device posture, and network trust
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.zero_trust_verification

default allow = false

# Required Zero-Trust criteria
required_zt_criteria := {
    "identity_verified": true,
    "device_compliant": true,
    "network_trusted": true
}

# Allow if all Zero-Trust criteria met
allow {
    input.identity_verified == required_zt_criteria.identity_verified
    input.device_compliant == required_zt_criteria.device_compliant
    input.network_trusted == required_zt_criteria.network_trusted
}

# Deny message
deny[msg] {
    not allow
    msg := "Access denied: Zero-Trust verification failed (check identity, device, network)"
}

# Demo test cases
test_allow_full_zt {
    allow with input as {
        "identity_verified": true,
        "device_compliant": true,
        "network_trusted": true
    }
}

test_deny_no_identity {
    not allow with input as {
        "identity_verified": false,
        "device_compliant": true,
        "network_trusted": true
    }
}

test_deny_non_compliant_device {
    not allow with input as {
        "identity_verified": true,
        "device_compliant": false,
        "network_trusted": true
    }
}

test_deny_untrusted_network {
    not allow with input as {
        "identity_verified": true,
        "device_compliant": true,
        "network_trusted": false
    }
}
