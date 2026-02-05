# OPA Policy: Continuous Session Monitoring for PAM
# Monitor ongoing sessions for anomalies and revoke access mid-session
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.continuous_session_monitoring

default allow = true

# Anomaly thresholds
max_actions_per_minute := 10
high_risk_commands := {"rm -rf", "nc", "wget", "curl http", "chmod 777"}

# Revoke if anomaly detected
revoke[msg] {
    action_count := count(input.recent_actions)
    action_count > max_actions_per_minute
    msg := sprintf("Session revoked: rapid actions detected (%d actions in 1 minute)", [action_count])
}

revoke[msg] {
    some command
    high_risk_commands[command]
    contains(lower(input.current_command), command)
    msg := sprintf("Session revoked: high-risk command detected (%s)", [command])
}

# Allow if no revocation triggered
allow {
    not revoke[_]
}

# Deny message (for initial access)
deny[msg] {
    revoke[msg]
}

# Demo test cases
test_allow_normal_session {
    allow with input as {
        "recent_actions": ["login", "view", "logout"],
        "current_command": "ls"
    }
}

test_revoke_rapid_actions {
    revoke[msg] with input as {
        "recent_actions": ["action1", "action2", "action3", "action4", "action5", "action6", "action7", "action8", "action9", "action10", "action11"],
        "current_command": "ls"
    }
}

test_revoke_high_risk_command {
    revoke[msg] with input as {
        "recent_actions": ["login"],
        "current_command": "rm -rf /"
    }
}
