# OPA Policy: Endpoint Security Posture Check for PAM
# Deny access from vulnerable or non-compliant endpoints
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.endpoint_posture

default allow = false

# Required endpoint posture criteria
required_posture := {
    "antivirus_installed": true,
    "patches_up_to_date": true,
    "os_version": "current"  # Or specific version check
}

# Allow if all criteria met
allow {
    input.endpoint.antivirus_installed == required_posture.antivirus_installed
    input.endpoint.patches_up_to_date == required_posture.patches_up_to_date
    input.endpoint.os_version == required_posture.os_version
}

# Deny message
deny[msg] {
    not allow
    msg := "Access denied: endpoint security posture non-compliant (check antivirus, patches, OS version)"
}

# Demo test cases
test_allow_compliant_endpoint {
    allow with input as {
        "endpoint": {
            "antivirus_installed": true,
            "patches_up_to_date": true,
            "os_version": "current"
        }
    }
}

test_deny_no_antivirus {
    not allow with input as {
        "endpoint": {
            "antivirus_installed": false,
            "patches_up_to_date": true,
            "os_version": "current"
        }
    }
}

test_deny_outdated_patches {
    not allow with input as {
        "endpoint": {
            "antivirus_installed": true,
            "patches_up_to_date": false,
            "os_version": "current"
        }
    }
}
