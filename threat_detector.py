from datetime import datetime
import joblib
import re

# Load ML model and vectorizer
model = joblib.load("threat_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")


def detect_threat(log_text):

    # ML severity prediction
    X = vectorizer.transform([log_text])
    ml_prediction = model.predict(X)[0]

    probabilities = model.predict_proba(X)[0]
    confidence_score = round(max(probabilities) * 100, 2)

    threat_level = ml_prediction
    threat_type = "Normal"
    failed_attempts = 0
    suspicious_ip = "None"

    ai_explanation = "The log appears to show normal system activity."
    ai_recommendation = "Continue monitoring system and network activity."

    lines = log_text.split("\n")

    for line in lines:

        lower_line = line.lower()

        if "failed password" in lower_line:

            threat_type = "Brute Force Attack"
            failed_attempts += 1

            ip_match = re.search(
                r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
                line
            )

            if ip_match:
                suspicious_ip = ip_match.group()

            ai_explanation = (
                f"Failed login activity was detected. "
                f"This may indicate a brute-force attack from IP {suspicious_ip}."
            )

            ai_recommendation = (
                "Block the suspicious IP, review authentication logs, "
                "and enable Multi-Factor Authentication."
            )

        elif "trojan" in lower_line or "malware" in lower_line or "virus" in lower_line:

            threat_type = "Malware Detected"

            ai_explanation = (
                "Malware-related indicators were detected in the log. "
                "This may indicate a compromised device or malicious file activity."
            )

            ai_recommendation = (
                "Isolate the affected system, run antivirus scans, "
                "remove malicious files, and investigate the source of infection."
            )

        elif "unauthorized access" in lower_line or "privilege escalation" in lower_line:

            threat_type = "Unauthorized Access"

            ai_explanation = (
                "Unauthorized access activity was detected. "
                "This may indicate account compromise or privilege misuse."
            )

            ai_recommendation = (
                "Review user permissions, reset affected credentials, "
                "and investigate recent account activity."
            )

    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "threat_level": threat_level,
        "threat_type": threat_type,
        "failed_attempts": failed_attempts,
        "suspicious_ip": suspicious_ip,
        "confidence_score": confidence_score,
        "ai_explanation": ai_explanation,
        "ai_recommendation": ai_recommendation,
        "log_text": log_text
    }
