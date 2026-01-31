# OPA Policy: Attribute-Based Access Control (ABAC) for PAM
# Enforce access based on contextual attributes (role + device trust + time + location + risk score)
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.abac_contextual

default allow = false

# Thresholds for approval
max_risk_score := 0.5  # Risk score must be ≤ 0.5
min_device_trust := 0.8  # Device trust must be ≥ 0.8
business_hour_start := 9
business_hour_end := 18
approved_countries := {"LK", "US", "GB"}

# Allow if all attributes meet criteria
allow {
    input.user.role == "approved_role"  # e.g., "admin", "engineer"
    input.device.trust_score >= min_device_trust
    hour := time.hour(time.now_ns())
    hour >= business_hour_start
    hour < business_hour_end
    approved_countries[input.geo.country_code]
    input.risk.score <= max_risk_score
}

# Deny message
deny[msg] {
    not allow
    msg := "Access denied: ABAC contextual attributes not met (check role, device trust, time, location, risk score)"
}

# Demo test cases
test_allow_all_criteria_met {
    allow with input as {
        "user": {"role": "admin"},
        "device": {"trust_score": 0.9},
        "geo": {"country_code": "LK"},
        "risk": {"score": 0.4}
    }
}

test_deny_high_risk_score {
    not allow with input as {
        "user": {"role": "admin"},
        "device": {"trust_score": 0.9},
        "geo": {"country_code": "LK"},
        "risk": {"score": 0.6}
    }
}

test_deny_low_device_trust {
    not allow with input as {
        "user": {"role": "admin"},
        "device": {"trust_score": 0.7},
        "geo": {"country_code": "LK"},
        "risk": {"score": 0.4}
    }
}

test_deny_outside_business_hours {
    not allow with input as {
        "user": {"role": "admin"},
        "device": {"trust_score": 0.9},
        "geo": {"country_code": "LK"},
        "risk": {"score": 0.4}
    }
}
