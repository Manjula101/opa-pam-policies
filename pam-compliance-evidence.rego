# OPA Policy: Compliance Evidence Generation for PAM
# Maps policies to compliance frameworks and generates audit evidence
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.compliance_evidence

# Compliance frameworks mapping
compliance_map := {
    "SOC2": {
        "CC6.1": "mfa_enforcement",
        "CC6.3": "role_escalation",
        "CC7.1": "audit_logging"
    },
    "ISO27001": {
        "A.9.2.3": "mfa_enforcement",
        "A.9.4.1": "ip_allowlist",
        "A.12.6.1": "risk_commands"
    }
}

# Generate evidence report
evidence_report[report] {
    framework := input.framework
    controls := compliance_map[framework]
    report := {
        "framework": framework,
        "timestamp": time.now_ns(),
        "controls": { 
            control: {
                "policy": controls[control],
                "status": input.policy_status[controls[control]],
                "evidence": input.evidence[controls[control]]
            } | some control in keys(controls)
        }
    }
}

# Default evidence if no framework specified
default evidence_report = {"status": "no_framework_provided"}

# Demo test cases
test_soc2_evidence {
    evidence_report[report] with input as {
        "framework": "SOC2",
        "policy_status": {
            "mfa_enforcement": "satisfied",
            "role_escalation": "satisfied",
            "audit_logging": "satisfied"
        },
        "evidence": {
            "mfa_enforcement": "MFA enforced on all sessions",
            "role_escalation": "Escalation requires approval",
            "audit_logging": "All actions logged to SIEM"
        }
    }
}

test_iso27001_evidence {
    evidence_report[report] with input as {
        "framework": "ISO27001",
        "policy_status": {
            "mfa_enforcement": "satisfied",
            "ip_allowlist": "failed"
        }
    }
}
