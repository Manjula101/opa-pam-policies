# OPA Policy: Time-based Access Control for PAM
# Allow privileged access only during business hours
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.time_based

default allow = false

# Business hours: 9:00–18:00 UTC (Monday–Friday)
business_hours := {
    "start_hour": 9,
    "end_hour": 18,
    "days": {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"}
}

# Allow if current time is within business hours
allow {
    now := time.now_ns()
    hour := time.hour(now)
    weekday := time.weekday(now)  # 0 = Sunday, 1 = Monday, ..., 6 = Saturday
    weekday >= 1
    weekday <= 5
    hour >= business_hours.start_hour
    hour < business_hours.end_hour
}

# Deny message
deny[msg] {
    not allow
    msg := "Access denied: privileged access only allowed during business hours (09:00–18:00 UTC, Mon–Fri)"
}

# Demo test cases
test_allow_business_hours {
    allow with input as {}  # Assume now is business time
}

test_deny_outside_hours {
    not allow with input as {}  # Assume now is outside business hours
}

test_deny_weekend {
    not allow with input as {}  # Assume now is weekend
}
