def map_findings_to_mitre(header_findings, url_findings, attachment_findings):
    """
    Map observed phishing evidence to MITRE ATT&CK techniques.

    Mappings are based on observed evidence and should not be
    treated as proof of attacker intent.
    """

    techniques = []

    # --------------------------------------------------
    # Spearphishing Link
    # --------------------------------------------------

    if url_findings:

        techniques.append({
            "technique_id": "T1566.002",
            "technique": "Phishing: Spearphishing Link",
            "evidence": "Email contains one or more URLs.",
            "confidence": "Medium"
        })

    # --------------------------------------------------
    # Spearphishing Attachment
    # --------------------------------------------------

    if attachment_findings:

        techniques.append({
            "technique_id": "T1566.001",
            "technique": "Phishing: Spearphishing Attachment",
            "evidence": "Email contains an attachment.",
            "confidence": "Medium"
        })

    # --------------------------------------------------
    # Additional phishing indicators
    # --------------------------------------------------

    suspicious_header_types = {
        "SPF Failure",
        "DKIM Failure",
        "DMARC Failure",
        "Reply-To Mismatch",
        "Return-Path Mismatch"
    }

    header_evidence = [
        finding["type"]
        for finding in header_findings
    ]

    matching_headers = [
        finding
        for finding in header_evidence
        if finding in suspicious_header_types
    ]

    if matching_headers:

        techniques.append({
            "technique_id": "T1566",
            "technique": "Phishing",
            "evidence": (
                "Suspicious email authentication or routing indicators: "
                + ", ".join(matching_headers)
            ),
            "confidence": "Medium"
        })

    return techniques