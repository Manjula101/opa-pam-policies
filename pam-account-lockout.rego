# OPA Policy: Enforce Account Lockout after Failed Authentication Attempts
# Prevent brute force attacks with progressive lockout mechanisms
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.account_lockout

default allow = false

# Account lockout thresholds and durations
lockout_config := {
    "failed_attempts_threshold": 5,
    "lockout_duration_minutes": 30,
    "progressive_lockout": true,
    "max_lockout_duration_hours": 24,
    "reset_counter_hours": 1,
}

# Tier-based lockout durations for progressive enforcement
progressive_lockout_tiers := [
    {"attempts": 5, "lockout_minutes": 15},
    {"attempts": 10, "lockout_minutes": 60},
    {"attempts": 15, "lockout_minutes": 240},
]

# Allow access if account is not locked
allow {
    input.account_status != "locked"
    input.failed_attempts < lockout_config["failed_attempts_threshold"]
}

# Allow if account was locked but lockout period has expired
allow {
    input.account_status == "locked"
    input.last_failed_attempt != null
    time_since_last_attempt := input.current_timestamp - input.last_failed_attempt
    time_since_last_attempt > (lockout_config["lockout_duration_minutes"] * 60)
}

# Deny access if account is locked and lockout period is active
deny[msg] {
    input.account_status == "locked"
    input.last_failed_attempt != null
    time_since_last_attempt := input.current_timestamp - input.last_failed_attempt
    time_since_last_attempt <= (lockout_config["lockout_duration_minutes"] * 60)
    remaining_minutes := (lockout_config["lockout_duration_minutes"] * 60 - time_since_last_attempt) / 60
    msg := sprintf("Account locked: %s. Failed attempts: %d. Remaining lockout time: %.0f minutes", 
                   [input.username, input.failed_attempts, remaining_minutes])
}

# Deny access if failed attempts exceed threshold
deny[msg] {
    not allow
    input.failed_attempts >= lockout_config["failed_attempts_threshold"]
    msg := sprintf("Account will be locked: %s. Failed attempts: %d/%d. Attempts remaining: %d",
                   [input.username, input.failed_attempts, lockout_config["failed_attempts_threshold"],
                    lockout_config["failed_attempts_threshold"] - input.failed_attempts])
}

# Calculate progressive lockout duration based on failed attempts
lockout_duration_minutes[duration] {
    some tier
    tier := progressive_lockout_tiers[_]
    input.failed_attempts >= tier.attempts
    duration := tier.lockout_minutes
}

# Get recommended lockout duration for current failed attempt count
recommended_lockout[duration] {
    some tier_idx
    tier_idx := count(progressive_lockout_tiers) - 1
    input.failed_attempts >= progressive_lockout_tiers[tier_idx].attempts
    duration := progressive_lockout_tiers[tier_idx].lockout_minutes
}

# Recommendation to administrators on account status
recommendations[rec] {
    input.failed_attempts > 0
    input.failed_attempts < lockout_config["failed_attempts_threshold"]
    remaining := lockout_config["failed_attempts_threshold"] - input.failed_attempts
    rec := sprintf("Warning: Account %s has %d failed attempts. %d more attempts before lockout.",
                   [input.username, input.failed_attempts, remaining])
}

recommendations[rec] {
    input.account_status == "locked"
    rec := sprintf("Account %s is locked. Consider administrative unlock if this is a legitimate user.",
                   [input.username])
}

# Audit rule for all authentication attempts
audit[entry] {
    entry := {
        "event": "authentication_attempt",
        "username": input.username,
        "timestamp": input.current_timestamp,
        "status": input.account_status,
        "failed_attempts": input.failed_attempts,
        "ip_address": input.ip_address,
        "result": "access_denied" if not allow else "access_allowed"
    }
}

# Test cases
test_allow_valid_account {
    allow with input as {
        "username": "john.doe",
        "account_status": "active",
        "failed_attempts": 0,
        "current_timestamp": 1625000000,
        "last_failed_attempt": null,
        "ip_address": "192.168.1.100"
    }
}

test_allow_few_failed_attempts {
    allow with input as {
        "username": "jane.smith",
        "account_status": "active",
        "failed_attempts": 3,
        "current_timestamp": 1625000000,
        "last_failed_attempt": null,
        "ip_address": "192.168.1.101"
    }
}

test_deny_account_locked {
    not allow with input as {
        "username": "hacker",
        "account_status": "locked",
        "failed_attempts": 5,
        "current_timestamp": 1625000060,
        "last_failed_attempt": 1625000000,
        "ip_address": "203.0.113.45"
    }
}

test_deny_threshold_exceeded {
    not allow with input as {
        "username": "suspicious.user",
        "account_status": "active",
        "failed_attempts": 5,
        "current_timestamp": 1625000000,
        "last_failed_attempt": 1624999800,
        "ip_address": "198.51.100.50"
    }
}

test_allow_lockout_expired {
    allow with input as {
        "username": "john.doe",
        "account_status": "locked",
        "failed_attempts": 5,
        "current_timestamp": 1625003000,
        "last_failed_attempt": 1625000000,
        "ip_address": "192.168.1.100"
    }
}

test_recommendations_warning {
    count(recommendations) > 0 with input as {
        "username": "cautious.user",
        "account_status": "active",
        "failed_attempts": 3,
        "current_timestamp": 1625000000,
        "last_failed_attempt": 1624999500,
        "ip_address": "192.168.1.102"
    }
}
