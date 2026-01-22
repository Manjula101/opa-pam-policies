# OPA Policy: Insider Threat Detection for PAM
# Deny access if suspicious behavior (e.g., rapid actions or unusual patterns)
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.insider_threat

default allow = false

# Thresholds for anomalies
max_actions_per_minute := 5
usual_action_pattern := "login -> view -> logout"  # Example pattern

# Allow if no anomalies
allow {
    not rapid_actions
    not unusual_pattern
}

rapid_actions {
    action_count := count(input.recent_actions)
    action_count > max_actions_per_minute
}

unusual_pattern {
    input.action_pattern != usual_action_pattern
}

# Deny message
deny[msg] {
    not allow
    msg := "Access denied: insider threat anomaly detected (rapid actions or unusual pattern)"
}

# Demo test cases
test_allow_normal_behavior {
    allow with input as {
        "recent_actions": ["login", "view"],
        "action_pattern": "login -> view -> logout"
    }
}

test_deny_rapid_actions {
    not allow with input as {
        "recent_actions": ["action1", "action2", "action3", "action4", "action5", "action6"],
        "action_pattern": "login -> view -> logout"
    }
}

test_deny_unusual_pattern {
    not allow with input as {
        "recent_actions": ["login", "view"],
        "action_pattern": "login -> delete -> logout"
    }
}
