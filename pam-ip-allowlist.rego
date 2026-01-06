# OPA Policy: IP Allowlist for Privileged Access
# Zero-Trust Network Enforcement
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.ip_allowlist

default allow = false

# Approved corporate IP ranges (example CIDR)
approved_ips = {
    "192.168.1.0/24",
    "10.0.0.0/8",
    "203.0.113.0/24",  # Example office IP
}

# Allow if source IP is in approved list
allow {
    some approved
    net.cidr_contains(approved, input.source_ip)
}

# Deny message
deny[msg] {
    not allow
    msg := sprintf("Access denied: source IP %s not in approved allowlist", [input.source_ip])
}

# Demo test cases
test_allow_approved_ip {
    allow with input as {"source_ip": "192.168.1.100"}
}

test_deny_unapproved_ip {
    not allow with input as {"source_ip": "8.8.8.8"}
}

test_allow_cidr_match {
    allow with input as {"source_ip": "10.10.50.25"}
}
