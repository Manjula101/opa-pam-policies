# OPA Policy: Least Privilege Dynamic Enforcement for PAM
# Reduce privileges on anomaly detection
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.least_privilege_dynamic

default privileges = "denied"

# Baseline privileges (customizable)
baseline_privileges := ["read", "write", "execute"]

# Reduced privileges on anomaly
reduced_privileges := ["read"]

# Return baseline if no anomaly
privileges = baseline_privileges {
    not anomaly_detected
}

# Return reduced on anomaly
privileges = reduced_privileges {
    anomaly_detected
}

# Anomaly detection example (customize with input)
anomaly_detected {
    input.anomaly.risk_score > 0.5
}

# Deny message if denied
deny[msg] {
    privileges == "denied"
    msg := "Access denied: no privileges assigned"
}

# Demo test cases
test_baseline_privileges {
    privileges = baseline_privileges with input as {
        "anomaly": {"risk_score": 0.3}
    }
}

test_reduced_privileges {
    privileges = reduced_privileges with input as {
        "anomaly": {"risk_score": 0.6}
    }
}

test_deny_no_privileges {
    privileges == "denied" with input as {
        "anomaly": {"risk_score": 0.6}
    }
}
