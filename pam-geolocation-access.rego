# OPA Policy: Geolocation-based Access Control for PAM
# Deny privileged access from high-risk countries
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.geolocation

default allow = false

# High-risk countries (ISO 3166-1 alpha-2 codes) – example list
high_risk_countries := {
    "RU",  # Russia
    "CN",  # China
    "KP",  # North Korea
    "IR",  # Iran
    "SY",  # Syria
}

# Allow if user country not in high-risk list
allow {
    input.geo.country_code
    not high_risk_countries[input.geo.country_code]
}

# Deny message
deny[msg] {
    not allow
    msg := sprintf("Access denied: privileged access not permitted from country %s", [input.geo.country_code])
}

# Demo test cases
test_allow_safe_country {
    allow with input as {"geo": {"country_code": "US"}}
}

test_allow_approved_country {
    allow with input as {"geo": {"country_code": "LK"}}  # Sri Lanka
}

test_deny_high_risk_country {
    not allow with input as {"geo": {"country_code": "RU"}}
}
