# OPA Policy: Encryption Requirement for PAM Sessions
# Deny access if session is not encrypted
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.encryption

default allow = false

# Allow only encrypted sessions (TLS 1.3+)
allow {
    input.session.encryption.enabled == true
    input.session.encryption.protocol == "TLS1.3"
}

# Deny message
deny[msg] {
    not allow
    msg := "Access denied: session must be encrypted with TLS 1.3+"
}

# Demo test cases
test_allow_encrypted_session {
    allow with input as {
        "session": {
            "encryption": {
                "enabled": true,
                "protocol": "TLS1.3"
            }
        }
    }
}

test_deny_unencrypted_session {
    not allow with input as {
        "session": {
            "encryption": {
                "enabled": false,
                "protocol": "none"
            }
        }
    }
}

test_deny_old_protocol {
    not allow with input as {
        "session": {
            "encryption": {
                "enabled": true,
                "protocol": "TLS1.2"
            }
        }
    }
}
