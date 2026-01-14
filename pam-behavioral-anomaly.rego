# OPA Policy: Behavioral Anomaly Detection for PAM
# Deny access if unusual patterns (e.g., odd hours or location)
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.behavioral_anomaly

default allow = false

# Usual business hours (9AM - 6PM UTC)
usual_hours_start := 9
usual_hours_end := 18

# Usual locations (country codes)
usual_countries := {"LK", "US", "GB"}

# Allow if no anomalies
allow {
    not unusual_time
    not unusual_location
}

unusual_time {
    hour := time.hour(time.now_ns())
    hour < usual_hours_start
}

unusual_time {
    hour := time.hour(time.now_ns())
    hour >= usual_hours_end
}

unusual_location {
    input.geo.country_code
    not usual_countries[input.geo.country_code]
}

# Deny message
deny[msg] {
    not allow
    msg := "Access denied: behavioral anomaly detected (unusual time or location)"
}

# Demo test cases
test_allow_usual_time_and_location {
    allow with input as {"geo": {"country_code": "LK"}}
}

test_deny_unusual_time {
    not allow with input as {"geo": {"country_code": "LK"}}
}

test_deny_unusual_location {
    not allow with input as {"geo": {"country_code": "RU"}}
}
