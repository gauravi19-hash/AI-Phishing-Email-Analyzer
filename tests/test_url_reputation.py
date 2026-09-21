from analyzer.email_parser import parse_email, extract_body
from analyzer.url_analyzer import extract_urls, analyze_url
from analyzer.virustotal import check_url_reputation


# Load phishing email
with open("samples/phishing/test_phishing.eml", "rb") as file:
    email_bytes = file.read()


# Parse email
result = parse_email(email_bytes)

text_body, html_body = extract_body(result["message"])


# Extract URLs
urls = extract_urls(text_body, html_body)


print("\n===== URL REPUTATION ANALYSIS =====\n")


if not urls:
    print("No URLs found.")

else:

    for url in urls:

        print(f"URL: {url}")
        print("-" * 60)

        # --------------------------------
        # Local URL analysis
        # --------------------------------

        local_analysis = analyze_url(url)

        print("\n[LOCAL ANALYSIS]")

        print(f"Domain: {local_analysis['domain']}")

        if local_analysis["findings"]:

            for finding in local_analysis["findings"]:

                print(f"Type: {finding['type']}")
                print(f"Severity: {finding['severity']}")
                print(f"Evidence: {finding['evidence']}")
                print(f"Description: {finding['description']}")

        else:
            print("No suspicious URL indicators detected.")


        # --------------------------------
        # VirusTotal analysis
        # --------------------------------

        print("\n[VIRUSTOTAL ANALYSIS]")

        vt_result = check_url_reputation(url)

        if vt_result["status"] == "success":

            print(f"Malicious: {vt_result['malicious']}")
            print(f"Suspicious: {vt_result['suspicious']}")
            print(f"Harmless: {vt_result['harmless']}")
            print(f"Undetected: {vt_result['undetected']}")

        elif vt_result["status"] == "not_found":

            print("URL not found in VirusTotal.")
            print("This does NOT mean the URL is benign.")

        else:

            print(f"VirusTotal error: {vt_result['message']}")

        print("\n" + "=" * 60)