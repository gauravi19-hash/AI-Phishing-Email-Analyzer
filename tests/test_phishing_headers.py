from analyzer.email_parser import parse_email
from analyzer.header_analyzer import analyze_headers


with open("samples/phishing/test_phishing.eml", "rb") as file:
    email_bytes = file.read()


result = parse_email(email_bytes)

findings = analyze_headers(result["message"])


print("\n===== PHISHING HEADER ANALYSIS =====\n")

for finding in findings:
    print(f"Type: {finding['type']}")
    print(f"Severity: {finding['severity']}")
    print(f"Evidence: {finding['evidence']}")
    print(f"Description: {finding['description']}")
    print("-" * 60)