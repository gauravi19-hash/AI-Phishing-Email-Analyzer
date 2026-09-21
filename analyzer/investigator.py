from analyzer.email_parser import parse_email, extract_body
from analyzer.header_analyzer import analyze_headers
from analyzer.content_analyzer import analyze_email_content
from analyzer.url_analyzer import extract_urls, analyze_url
from analyzer.attachment_analyzer import extract_attachments
from analyzer.virustotal import (
    check_url_reputation,
    check_file_hash_reputation
)
from analyzer.mitre_mapper import map_findings_to_mitre
from analyzer.risk_engine import calculate_risk_score


def investigate_email(file_path):
    """
    Run the complete phishing email investigation pipeline.
    """

    # --------------------------------------------------
    # 1. Load email
    # --------------------------------------------------

    with open(file_path, "rb") as file:
        email_bytes = file.read()

    result = parse_email(email_bytes)

    message = result["message"]
    headers = result["headers"]


    # --------------------------------------------------
    # 2. Header analysis
    # --------------------------------------------------

    header_findings = analyze_headers(message)


    # --------------------------------------------------
    # 3. Extract email body
    # --------------------------------------------------

    text_body, html_body = extract_body(message)

    content_findings = analyze_email_content(
    subject=headers.get("subject", ""),
    text_body=text_body,
    html_body=html_body
)


    # --------------------------------------------------
    # 4. URL analysis
    # --------------------------------------------------

    urls = extract_urls(
        text_body,
        html_body
    )

    url_findings = []
    vt_url_results = []

    for url in urls:

        analysis = analyze_url(url)

        url_findings.extend(
            analysis["findings"]
        )

        vt_result = check_url_reputation(url)

        vt_url_results.append({
            "url": url,
            "result": vt_result
        })


    # --------------------------------------------------
    # 5. Attachment analysis
    # --------------------------------------------------

    attachments = extract_attachments(message)

    vt_hash_results = []

    for attachment in attachments:

        file_hash = attachment["sha256"]

        vt_result = check_file_hash_reputation(
            file_hash
        )

        vt_hash_results.append({
            "filename": attachment["filename"],
            "sha256": file_hash,
            "result": vt_result
        })


    # --------------------------------------------------
    # 6. MITRE ATT&CK mapping
    # --------------------------------------------------

    mitre_techniques = map_findings_to_mitre(
        header_findings,
        url_findings,
        attachments
    )


    # --------------------------------------------------
    # 7. Risk calculation
    # --------------------------------------------------

    # Extract only the actual VT result dictionaries
    # for the risk engine.

    vt_url_for_risk = [
        item["result"]
        for item in vt_url_results
    ]

    vt_hash_for_risk = [
        item["result"]
        for item in vt_hash_results
    ]

    risk_result = calculate_risk_score(
    header_findings,
    content_findings,
    url_findings,
    vt_url_for_risk,
    attachments,
    vt_hash_for_risk
)


    # --------------------------------------------------
    # 8. Build final investigation result
    # --------------------------------------------------

    investigation = {

        "email": {
            "from": headers.get("from"),
            "to": headers.get("to"),
            "subject": headers.get("subject"),
            "date": headers.get("date"),
            "reply_to": headers.get("reply_to"),
            "return_path": headers.get("return_path"),
            "message_id": headers.get("message_id")
        },

        "header_findings": header_findings,

"content_findings": content_findings,

"urls": {
            "extracted": urls,
            "findings": url_findings,
            "virustotal": vt_url_results
        },

        "attachments": {
            "files": attachments,
            "virustotal": vt_hash_results
        },

        "mitre_attack": mitre_techniques,

        "risk_assessment": risk_result
    }


    return investigation