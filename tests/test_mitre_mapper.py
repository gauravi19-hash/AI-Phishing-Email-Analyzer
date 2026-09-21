from analyzer.email_parser import parse_email, extract_body
from analyzer.header_analyzer import analyze_headers
from analyzer.url_analyzer import extract_urls, analyze_url
from analyzer.attachment_analyzer import extract_attachments
from analyzer.mitre_mapper import map_findings_to_mitre


with open("samples/phishing/test_phishing.eml", "rb") as file:
    email_bytes = file.read()


# Parse email
result = parse_email(email_bytes)

message = result["message"]


# Header analysis
header_findings = analyze_headers(message)


# URL analysis
text_body, html_body = extract_body(message)

urls = extract_urls(text_body, html_body)

url_findings = []

for url in urls:

    analysis = analyze_url(url)

    if analysis["findings"]:
        url_findings.extend(analysis["findings"])


# Attachment analysis
attachment_findings = extract_attachments(message)


# MITRE mapping
techniques = map_findings_to_mitre(
    header_findings,
    url_findings,
    attachment_findings
)


print("\n===== MITRE ATT&CK MAPPING =====\n")


if not techniques:

    print("No MITRE ATT&CK techniques mapped.")

else:

    for technique in techniques:

        print(f"Technique ID: {technique['technique_id']}")
        print(f"Technique: {technique['technique']}")
        print(f"Evidence: {technique['evidence']}")
        print(f"Confidence: {technique['confidence']}")
        print("-" * 60)