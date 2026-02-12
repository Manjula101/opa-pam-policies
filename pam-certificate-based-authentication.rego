# OPA Policy: Certificate-Based Authentication for PAM
# Enforce access using valid client certificates
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.certificate_auth

default allow = false

# Required certificate attributes
required_cert := {
    "issuer": "Trusted CA",
    "valid": true,
    "not_revoked": true
}

# Allow if certificate meets all criteria
allow {
    input.cert.issuer == required_cert.issuer
    input.cert.valid == required_cert.valid
    input.cert.not_revoked == required_cert.not_revoked
}

# Deny message
deny[msg] {
    not allow
    msg := "Access denied: invalid or untrusted certificate (check issuer, validity, revocation)"
}

# Demo test cases
test_allow_valid_cert {
    allow with input as {
        "cert": {
            "issuer": "Trusted CA",
            "valid": true,
            "not_revoked": true
        }
    }
}

test_deny_wrong_issuer {
    not allow with input as {
        "cert": {
            "issuer": "Untrusted CA",
            "valid": true,
            "not_revoked": true
        }
    }
}

test_deny_expired_cert {
    not allow with input as {
        "cert": {
            "issuer": "Trusted CA",
            "valid": false,
            "not_revoked": true
        }
    }
}

test_deny_revoked_cert {
    not allow with input as {
        "cert": {
            "issuer": "Trusted CA",
            "valid": true,
            "not_revoked": false
        }
    }
}
