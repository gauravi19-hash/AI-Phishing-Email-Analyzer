from analyzer.email_parser import parse_email, extract_body
from analyzer.content_analyzer import analyze_email_content


EMAIL_PATH = "samples/phishing/test_phishing.eml"


with open(EMAIL_PATH, "rb") as file:
    email_bytes = file.read()


result = parse_email(email_bytes)

message = result["message"]

text_body, html_body = extract_body(message)

subject = result["headers"].get("subject", "")


findings = analyze_email_content(
    subject=subject,
    text_body=text_body,
    html_body=html_body
)


print("\n")
print("=" * 70)
print("             EMAIL CONTENT ANALYSIS")
print("=" * 70)


if not findings:

    print("\nNo content-based indicators detected.")

else:

    for finding in findings:

        print("\nType:", finding["type"])
        print("Severity:", finding["severity"])
        print("Evidence:", finding["evidence"])
        print("Description:", finding["description"])

        print("-" * 70)