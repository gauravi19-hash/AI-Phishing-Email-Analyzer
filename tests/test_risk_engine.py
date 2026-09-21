from analyzer.email_parser import parse_email, extract_body
from analyzer.header_analyzer import analyze_headers
from analyzer.url_analyzer import extract_urls, analyze_url
from analyzer.attachment_analyzer import extract_attachments
from analyzer.virustotal import check_url_reputation
from analyzer.risk_engine import calculate_risk_score


# -----------------------------------------
# Load email
# -----------------------------------------

with open("samples/phishing/test_phishing.eml", "rb") as file:
    email_bytes = file.read()


result = parse_email(email_bytes)

message = result["message"]


# -----------------------------------------
# Header analysis
# -----------------------------------------

header_findings = analyze_headers(message)


# -----------------------------------------
# URL analysis
# -----------------------------------------

text_body, html_body = extract_body(message)

urls = extract_urls(text_body, html_body)

url_findings = []

vt_url_results = []


for url in urls:

    analysis = analyze_url(url)

    url_findings.extend(
        analysis["findings"]
    )

    vt_result = check_url_reputation(url)

    vt_url_results.append(vt_result)


# -----------------------------------------
# Attachment analysis
# -----------------------------------------

attachment_findings = extract_attachments(message)


# No file hash lookups for this particular
# phishing sample because it has no attachment.

vt_hash_results = []


# -----------------------------------------
# Risk calculation
# -----------------------------------------

risk_result = calculate_risk_score(
    header_findings,
    url_findings,
    vt_url_results,
    attachment_findings,
    vt_hash_results
)


# -----------------------------------------
# Display result
# -----------------------------------------

print("\n===== PHISHING RISK ASSESSMENT =====\n")

print(f"Risk Score: {risk_result['score']}/100")
print(f"Risk Level: {risk_result['risk_level']}")

print("\n===== EVIDENCE =====\n")


if not risk_result["evidence"]:

    print("No significant evidence detected.")

else:

    for item in risk_result["evidence"]:

        print(f"Source: {item['source']}")
        print(f"Finding: {item['type']}")
        print(f"Points: {item['points']}")
        print(f"Evidence: {item['evidence']}")
        print("-" * 60)