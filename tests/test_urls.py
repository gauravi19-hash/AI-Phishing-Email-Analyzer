from analyzer.email_parser import parse_email, extract_body
from analyzer.url_analyzer import extract_urls, analyze_url


with open("samples/phishing/test_phishing.eml", "rb") as file:
    email_bytes = file.read()


result = parse_email(email_bytes)

text_body, html_body = extract_body(result["message"])

urls = extract_urls(text_body, html_body)


print("\n===== URL EXTRACTION =====\n")

if not urls:
    print("No URLs found.")

else:
    for url in urls:

        print(f"URL: {url}")

        analysis = analyze_url(url)

        print(f"Domain: {analysis['domain']}")

        if analysis["findings"]:

            for finding in analysis["findings"]:
                print(f"Type: {finding['type']}")
                print(f"Severity: {finding['severity']}")
                print(f"Evidence: {finding['evidence']}")
                print(f"Description: {finding['description']}")

        else:
            print("No suspicious URL indicators detected.")

        print("-" * 60)