# OPA Policy: Session Termination on Anomaly for PAM
# Automatically terminate sessions if anomalies are detected mid-session
# Enterprise Security Lab | Manjula Wickramasuriya

package pam.session_termination

default terminate = false

# Anomaly thresholds (example)
max_anomaly_score := 0.7

# Terminate if anomaly score exceeds threshold
terminate[msg] {
    input.anomaly_score > max_anomaly_score
    msg := sprintf("Session terminated: anomaly score exceeded (%f > %f)", [input.anomaly_score, max_anomaly_score])
}

# Demo test cases
test_no_termination_low_score {
    not terminate[_] with input as {"anomaly_score": 0.5}
}

test_termination_high_score {
    terminate[msg] with input as {"anomaly_score": 0.8}
}

test_termination_message {
    terminate[msg] with input as {"anomaly_score": 0.8}
    msg == "Session terminated: anomaly score exceeded (0.800000 > 0.700000)"
}
