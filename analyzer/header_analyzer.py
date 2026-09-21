def analyze_headers(message):
    """
    Analyze email headers for suspicious indicators.
    """

    findings = []

    from_header = message.get("From", "")
    reply_to = message.get("Reply-To", "")
    return_path = message.get("Return-Path", "")
    authentication_results = message.get("Authentication-Results", "")

    # 1. Reply-To mismatch
    if from_header and reply_to:
        from_domain = extract_domain(from_header)
        reply_domain = extract_domain(reply_to)

        if from_domain and reply_domain and from_domain.lower() != reply_domain.lower():
            findings.append({
                "type": "Reply-To Mismatch",
                "severity": "High",
                "evidence": f"From: {from_header} | Reply-To: {reply_to}",
                "description": (
                    "The Reply-To domain differs from the sender domain. "
                    "This can indicate phishing or an attempt to redirect replies."
                )
            })

    # 2. Return-Path mismatch
    if from_header and return_path:
        from_domain = extract_domain(from_header)
        return_domain = extract_domain(return_path)

        if from_domain and return_domain and from_domain.lower() != return_domain.lower():
            findings.append({
                "type": "Return-Path Mismatch",
                "severity": "Medium",
                "evidence": f"From: {from_header} | Return-Path: {return_path}",
                "description": (
                    "The Return-Path domain differs from the visible sender domain."
                )
            })

    # 3. Authentication results
    auth_lower = authentication_results.lower()

    if "spf=fail" in auth_lower:
        findings.append({
            "type": "SPF Failure",
            "severity": "High",
            "evidence": authentication_results,
            "description": (
                "SPF authentication failed for the message."
            )
        })

    if "dkim=fail" in auth_lower:
        findings.append({
            "type": "DKIM Failure",
            "severity": "High",
            "evidence": authentication_results,
            "description": (
                "DKIM authentication failed for the message."
            )
        })

    if "dkim=none" in auth_lower:
        findings.append({
            "type": "DKIM Missing",
            "severity": "Medium",
            "evidence": authentication_results,
            "description": (
                "No DKIM signature was detected."
            )
        })

    if "dmarc=fail" in auth_lower:
        findings.append({
            "type": "DMARC Failure",
            "severity": "High",
            "evidence": authentication_results,
            "description": (
                "DMARC authentication failed."
            )
        })

    # 4. Received headers
    received_headers = message.get_all("Received", [])

    if received_headers:
        findings.append({
            "type": "Received Headers Found",
            "severity": "Info",
            "evidence": f"{len(received_headers)} Received header(s)",
            "description": (
                "Received headers were found and can be used to trace "
                "the email's delivery path."
            )
        })

    return findings


def extract_domain(email_value):
    """
    Extract domain from an email address or header value.
    """

    if not email_value:
        return None

    if "<" in email_value and ">" in email_value:
        email_value = email_value.split("<", 1)[1].split(">", 1)[0]

    if "@" not in email_value:
        return None

    return email_value.split("@", 1)[1].strip()