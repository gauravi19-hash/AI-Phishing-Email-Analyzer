from analyzer.email_parser import parse_email
from analyzer.header_analyzer import analyze_headers


with open("samples/test_email.eml", "rb") as file:
    email_bytes = file.read()


result = parse_email(email_bytes)

findings = analyze_headers(result["message"])


print("\n===== HEADER ANALYSIS =====\n")

if not findings:
    print("No suspicious header findings detected.")

else:
    for finding in findings:
        print(f"Type: {finding['type']}")
        print(f"Severity: {finding['severity']}")
        print(f"Evidence: {finding['evidence']}")
        print(f"Description: {finding['description']}")
        print("-" * 60)