# OPA Policy: Compliance Mapping & Evidence Collection for PAM
# Map policies to frameworks (SOC 2, ISO 27001) and generate audit evidence
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.compliance_mapping

default compliant = false

# Compliance mappings (example frameworks)
compliance_map := {
    "SOC2": {
        "controls": {
            "CC6.1": "mfa_enforcement",  # MFA for access control
            "CC6.3": "role_escalation",  # Role-based access
            "CC7.1": "audit_logging"     # Logging and monitoring
        }
    },
    "ISO27001": {
        "controls": {
            "A.9.2.3": "mfa_enforcement",  # MFA for user access
            "A.9.4.1": "ip_allowlist",  # Network access control
            "A.12.6.1": "risk_commands"  # Technical vulnerability management
        }
    }
}

# Compliant if all required controls are satisfied
compliant {
    framework := input.framework
    controls := compliance_map[framework].controls
    count(controls) == count({control | some key; controls[key] == input.policy_status[key]; input.policy_status[key] == "satisfied"})
}

# Generate evidence report
evidence_report[report] {
    framework := input.framework
    controls := compliance_map[framework].controls
    report := {
        "framework": framework,
        "compliance_status": compliant,
        "details": {key: {"control": key, "policy": controls[key], "status": input.policy_status[controls[key]]} | some key in keys(controls)}
    }
}

# Deny message
deny[msg] {
    not compliant
    msg := sprintf("Compliance failure for %s: check required controls", [input.framework])
}

# Demo test cases
test_compliant_soc2 {
    compliant with input as {
        "framework": "SOC2",
        "policy_status": {
            "mfa_enforcement": "satisfied",
            "role_escalation": "satisfied",
            "audit_logging": "satisfied"
        }
    }
}

test_non_compliant_iso27001 {
    not compliant with input as {
        "framework": "ISO27001",
        "policy_status": {
            "mfa_enforcement": "satisfied",
            "ip_allowlist": "failed",
            "risk_commands": "satisfied"
        }
    }
}
