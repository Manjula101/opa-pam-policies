# OPA Policy: Data Loss Prevention (DLP) for PAM
# Deny sharing or transfer of sensitive data (PII, credentials, etc.)
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.data_loss_prevention

default allow = false

# Sensitive data patterns (regex examples)
sensitive_patterns := {
    `(?i)password|pwd|pass`,  # Passwords
    `(?i)credit\s?card|ccnum`,  # Credit cards
    `(?i)ssn|social\s?security`,  # SSNs
    `(?i)api_key|token|secret`,  # API keys
}

# Allow if no sensitive data detected
allow {
    not contains_sensitive_data
}

contains_sensitive_data {
    some pattern
    regex.match(pattern, input.data)
}

# Deny message
deny[msg] {
    contains_sensitive_data
    msg := "Access denied: potential data loss detected (sensitive data in input)"
}

# Demo test cases
test_allow_safe_data {
    allow with input as {"data": "Hello world"}
}

test_deny_password {
    not allow with input as {"data": "My password is secret123"}
}

test_deny_credit_card {
    not allow with input as {"data": "Credit card: 4111111111111111"}
}

test_deny_api_key {
    not allow with input as {"data": "API_KEY=abc123xyz"}
}
