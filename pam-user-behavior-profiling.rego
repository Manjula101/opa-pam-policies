# OPA Policy: User Behavior Profiling for PAM
# Deny access if deviation from baseline behavior
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.user_behavior

default allow = false

# Baseline behavior thresholds (example)
baseline := {
    "avg_access_per_day": 5,
    "usual_access_window": [9, 18],  # 9AM-6PM
}

# Allow if no deviations
allow {
    not unusual_frequency
    not outside_access_window
}

unusual_frequency {
    input.access_count_today > baseline.avg_access_per_day * 2  # More than 2x average
}

outside_access_window {
    hour := time.hour(time.now_ns())
    hour < baseline.usual_access_window[0]
}

outside_access_window {
    hour := time.hour(time.now_ns())
    hour > baseline.usual_access_window[1]
}

# Deny message
deny[msg] {
    not allow
    msg := "Access denied: user behavior deviation from baseline detected"
}

# Demo test cases
test_allow_normal_behavior {
    allow with input as {"access_count_today": 3}
}

test_deny_unusual_frequency {
    not allow with input as {"access_count_today": 11}
}

test_deny_outside_window {
    not allow with input as {"access_count_today": 3}
}
