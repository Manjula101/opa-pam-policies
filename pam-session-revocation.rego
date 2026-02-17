# OPA Policy: Session Revocation for PAM
# Automatically revoke sessions on logout, timeout, or detected anomaly
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.session_revocation

default allow = false

# Session revocation triggers
revoke {
    input.session.status == "logout"
}

revoke {
    input.session.timeout_exceeded == true
}

revoke {
    input.anomaly_detected == true
}

# Allow only if session is not revoked
allow {
    not revoke
}

# Deny message
deny[msg] {
    revoke
    msg := "Session revoked: logout, timeout, or anomaly detected"
}

# Demo test cases
test_allow_active_session {
    allow with input as {
        "session": {"status": "active"},
        "timeout_exceeded": false,
        "anomaly_detected": false
    }
}

test_revoke_on_logout {
    revoke with input as {
        "session": {"status": "logout"}
    }
}

test_revoke_on_timeout {
    revoke with input as {
        "session": {"status": "active"},
        "timeout_exceeded": true
    }
}

test_revoke_on_anomaly {
    revoke with input as {
        "session": {"status": "active"},
        "timeout_exceeded": false,
        "anomaly_detected": true
    }
}
