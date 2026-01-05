# OPA Policy: Limit privileged session duration
# Zero-Trust Privileged Access Management
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.session_duration

default allow = false

# Max session duration: 8 hours (in nanoseconds)
max_duration_ns := 28800000000000  # 8 hours

# Allow if session has not exceeded max duration
allow {
    session_start := input.session.start_time_ns
    now := time.now_ns()
    duration := now - session_start
    duration <= max_duration_ns
}

# Deny with message if exceeded
deny[msg] {
    not allow
    duration_hours := (time.now_ns() - input.session.start_time_ns) / 3600000000000
    msg := sprintf("Session exceeded maximum duration of 8 hours (current: %.1f hours)", [duration_hours])
}

# Demo test cases
test_allow_within_limit {
    allow with input as {
        "session": {"start_time_ns": time.now_ns() - 3600000000000}  # 1 hour ago
    }
}

test_deny_over_limit {
    not allow with input as {
        "session": {"start_time_ns": time.now_ns() - 36000000000000}  # 10 hours ago
    }
}
