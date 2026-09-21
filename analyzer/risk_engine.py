SEVERITY_POINTS = {
    "Info": 0,
    "Low": 5,
    "Medium": 10,
    "High": 20,
    "Critical": 30
}


def calculate_risk_score(
    header_findings,
    content_findings,
    url_findings,
    vt_url_results,
    attachment_findings,
    vt_hash_results
):
    
    """
    Calculate an illustrative phishing risk score
    based on observed evidence.

    This score is a prioritization aid, not a probability
    that an email is malicious.
    """

    score = 0
    evidence = []

    # -----------------------------------------
    # Header findings
    # -----------------------------------------

    for finding in content_findings:
        severity = finding.get("severity", "Info")
        points = SEVERITY_POINTS.get(severity, 0)
        score += points

        if points > 0:
            evidence.append({
                "source": "Content Analysis",
                "type": finding["type"],
                "points": points,
                "evidence": finding["evidence"]
            })

    # -----------------------------------------
    # URL findings
    # -----------------------------------------

    for finding in url_findings:

        severity = finding.get("severity", "Info")

        points = SEVERITY_POINTS.get(severity, 0)

        score += points

        if points > 0:
            evidence.append({
                "source": "URL Analysis",
                "type": finding["type"],
                "points": points,
                "evidence": finding["evidence"]
            })

    # -----------------------------------------
    # VirusTotal URL results
    # -----------------------------------------

    for result in vt_url_results:

        if result.get("status") != "success":
            continue

        malicious = result.get("malicious", 0)
        suspicious = result.get("suspicious", 0)

        if malicious > 0:

            points = 30

            score += points

            evidence.append({
                "source": "VirusTotal",
                "type": "Malicious URL Detection",
                "points": points,
                "evidence": (
                    f"{malicious} security vendor(s) "
                    f"flagged the URL as malicious."
                )
            })

        elif suspicious > 0:

            points = 15

            score += points

            evidence.append({
                "source": "VirusTotal",
                "type": "Suspicious URL Detection",
                "points": points,
                "evidence": (
                    f"{suspicious} security vendor(s) "
                    f"flagged the URL as suspicious."
                )
            })

    # -----------------------------------------
    # Attachments
    # -----------------------------------------

    if attachment_findings:

        for attachment in attachment_findings:

            evidence.append({
                "source": "Attachment Analysis",
                "type": "Attachment Present",
                "points": 0,
                "evidence": (
                    f"{attachment['filename']} "
                    f"({attachment['size']} bytes)"
                )
            })

    # -----------------------------------------
    # VirusTotal file hash results
    # -----------------------------------------

    for result in vt_hash_results:

        if result.get("status") != "success":
            continue

        malicious = result.get("malicious", 0)
        suspicious = result.get("suspicious", 0)

        if malicious > 0:

            points = 40

            score += points

            evidence.append({
                "source": "VirusTotal",
                "type": "Malicious File Hash",
                "points": points,
                "evidence": (
                    f"{malicious} security vendor(s) "
                    f"flagged the file as malicious."
                )
            })

        elif suspicious > 0:

            points = 20

            score += points

            evidence.append({
                "source": "VirusTotal",
                "type": "Suspicious File Hash",
                "points": points,
                "evidence": (
                    f"{suspicious} security vendor(s) "
                    f"flagged the file as suspicious."
                )
            })

    # -----------------------------------------
    # Cap score
    # -----------------------------------------

    score = min(score, 100)

    # -----------------------------------------
    # Determine risk level
    # -----------------------------------------

    if score >= 75:
        risk_level = "Critical"

    elif score >= 50:
        risk_level = "High"

    elif score >= 25:
        risk_level = "Suspicious"

    else:
        risk_level = "Low"

    return {
        "score": score,
        "risk_level": risk_level,
        "evidence": evidence
    }