# OPA Policy: Data Exfiltration Prevention for PAM
# Deny file transfers to unapproved destinations
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.data_exfiltration

default allow = false

# Approved destinations (domains, IPs, etc.)
approved_destinations := {
    "internal.domain.com",
    "approved.cloud.storage",
    "192.168.1.0/24",
}

# Allow if destination is approved
allow {
    some approved
    input.destination
    contains(lower(input.destination), approved)
}

# Deny message
deny[msg] {
    not allow
    msg := sprintf("Data exfiltration denied: file transfer to %s not approved", [input.destination])
}

# Demo test cases
test_allow_approved_destination {
    allow with input as {"destination": "internal.domain.com"}
}

test_deny_unapproved_destination {
    not allow with input as {"destination": "external.unapproved.com"}
}

test_allow_ip_approved {
    allow with input as {"destination": "192.168.1.100"}
}
