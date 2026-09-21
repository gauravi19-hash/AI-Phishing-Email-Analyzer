import re


def analyze_email_content(subject="", text_body="", html_body=""):
    """
    Analyze email subject and body for common
    phishing/social-engineering indicators.

    This is rule-based analysis. It does not prove
    that an email is malicious.
    """

    findings = []

    combined_text = " ".join([
        subject or "",
        text_body or "",
        html_body or ""
    ]).lower()

    # --------------------------------------------------
    # 1. Urgency indicators
    # --------------------------------------------------

    urgency_patterns = [
        "urgent",
        "immediately",
        "act now",
        "action required",
        "as soon as possible",
        "within 24 hours",
        "final warning",
        "important notice",
        "expires today"
    ]

    matched_urgency = [
        phrase
        for phrase in urgency_patterns
        if phrase in combined_text
    ]

    if matched_urgency:
        findings.append({
            "type": "Urgency Language",
            "severity": "Medium",
            "evidence": ", ".join(matched_urgency),
            "description": (
                "The email uses urgency-related language "
                "that may pressure the recipient to act quickly."
            )
        })

    # --------------------------------------------------
    # 2. Account verification indicators
    # --------------------------------------------------

    account_patterns = [
        "verify your account",
        "account verification",
        "verify account",
        "confirm your account",
        "account has been suspended",
        "account will be suspended",
        "account will be locked",
        "account security",
        "unusual activity"
    ]

    matched_account = [
        phrase
        for phrase in account_patterns
        if phrase in combined_text
    ]

    if matched_account:
        findings.append({
            "type": "Account Verification Language",
            "severity": "Medium",
            "evidence": ", ".join(matched_account),
            "description": (
                "The email contains account-related verification "
                "or security language commonly observed in phishing."
            )
        })

    # --------------------------------------------------
    # 3. Credential-related indicators
    # --------------------------------------------------

    credential_patterns = [
        "password",
        "username",
        "user name",
        "login credentials",
        "credentials",
        "sign in",
        "signin",
        "log in",
        "login"
    ]

    matched_credentials = [
        phrase
        for phrase in credential_patterns
        if phrase in combined_text
    ]

    if matched_credentials:
        findings.append({
            "type": "Credential-Related Language",
            "severity": "Medium",
            "evidence": ", ".join(matched_credentials),
            "description": (
                "The email contains terminology associated "
                "with account access or credentials."
            )
        })

    # --------------------------------------------------
    # 4. Threat / consequence indicators
    # --------------------------------------------------

    threat_patterns = [
        "suspended",
        "locked",
        "disabled",
        "terminated",
        "unauthorized activity",
        "security breach",
        "will be closed",
        "will be deleted"
    ]

    matched_threats = [
        phrase
        for phrase in threat_patterns
        if phrase in combined_text
    ]

    if matched_threats:
        findings.append({
            "type": "Threat or Consequence Language",
            "severity": "Medium",
            "evidence": ", ".join(matched_threats),
            "description": (
                "The email contains language describing possible "
                "negative consequences if the recipient does not act."
            )
        })

    # --------------------------------------------------
    # 5. Call-to-action indicators
    # --------------------------------------------------

    action_patterns = [
        "click here",
        "click the link",
        "click below",
        "verify now",
        "confirm now",
        "update now",
        "sign in now",
        "login now"
    ]

    matched_actions = [
        phrase
        for phrase in action_patterns
        if phrase in combined_text
    ]

    if matched_actions:
        findings.append({
            "type": "Call-to-Action Language",
            "severity": "Low",
            "evidence": ", ".join(matched_actions),
            "description": (
                "The email contains language encouraging "
                "the recipient to take an immediate action."
            )
        })

    return findings