# OPA Policy: Device Compliance Check for PAM
# Deny access from non-compliant devices (e.g., no antivirus, outdated OS)
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.device_compliance

default allow = false

# Required compliance criteria
required_criteria := {
    "antivirus_installed": true,
    "os_version": "latest"  # Or specific version check
}

# Allow if all criteria met
allow {
    input.device.antivirus_installed == required_criteria.antivirus_installed
    input.device.os_version == required_criteria.os_version
}

# Deny message
deny[msg] {
    not allow
    msg := "Access denied: device not compliant (check antivirus and OS version)"
}

# Demo test cases
test_allow_compliant_device {
    allow with input as {
        "device": {
            "antivirus_installed": true,
            "os_version": "latest"
        }
    }
}

test_deny_no_antivirus {
    not allow with input as {
        "device": {
            "antivirus_installed": false,
            "os_version": "latest"
        }
    }
}

test_deny_outdated_os {
    not allow with input as {
        "device": {
            "antivirus_installed": true,
            "os_version": "old"
        }
    }
}
