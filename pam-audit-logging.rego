# OPA Policy: Enforce Audit Logging for Privileged Access
# Require logging for all privileged actions
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.audit_logging

default allow = false

# Must have audit logging enabled
allow {
    input.audit_logging.enabled == true
}

# Must have log destination configured
allow {
    input.audit_logging.destination != null
    input.audit_logging.destination != ""
}

# Deny message
deny[msg] {
    not allow
    msg := "Access denied: audit logging not enabled or destination not configured"
}

# Demo test cases
test_allow_logging_enabled {
    allow with input as {
        "audit_logging": {
            "enabled": true,
            "destination": "syslog"
        }
    }
}

test_deny_logging_disabled {
    not allow with input as {
        "audit_logging": {
            "enabled": false,
            "destination": "syslog"
        }
    }
}

test_deny_no_destination {
    not allow with input as {
        "audit_logging": {
            "enabled": true,
            "destination": null
        }
    }
}
