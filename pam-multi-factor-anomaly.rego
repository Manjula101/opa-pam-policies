# OPA Policy: Multi-Factor Anomaly Detection for PAM
# Deny if unusual MFA method or location
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.multi_factor_anomaly

default allow = false

# Usual MFA methods (e.g., app, SMS, hardware key)
usual_mfa_methods := {"app", "hardware_key"}

# Usual MFA locations (country codes)
usual_mfa_locations := {"LK", "US", "GB"}

# Allow if no anomalies
allow {
    not unusual_mfa_method
    not unusual_mfa_location
}

unusual_mfa_method {
    input.mfa.method
    not usual_mfa_methods[input.mfa.method]
}

unusual_mfa_location {
    input.mfa.location.country_code
    not usual_mfa_locations[input.mfa.location.country_code]
}

# Deny message
deny[msg] {
    not allow
    msg := "Access denied: multi-factor anomaly detected (unusual method or location)"
}

# Demo test cases
test_allow_usual_mfa {
    allow with input as {"mfa": {"method": "app", "location": {"country_code": "LK"}}}
}

test_deny_unusual_mfa_method {
    not allow with input as {"mfa": {"method": "email", "location": {"country_code": "LK"}}}
}

test_deny_unusual_mfa_location {
    not allow with input as {"mfa": {"method": "app", "location": {"country_code": "RU"}}}
}
