from analyzer.investigator import investigate_email
from analyzer.save_report import save_investigation_result

EMAIL_PATH = "samples/phishing/test_phishing.eml"


result = investigate_email(EMAIL_PATH)

save_investigation_result(
    result,
    "investigation_result.json"
)

print("\nInvestigation JSON saved to investigation_result.json")


print("\n")
print("=" * 70)
print("             SOC PHISHING EMAIL INVESTIGATION")
print("=" * 70)


# --------------------------------------------------
# EMAIL INFORMATION
# --------------------------------------------------

email = result["email"]

print("\n[EMAIL INFORMATION]\n")

print(f"From: {email['from']}")
print(f"To: {email['to']}")
print(f"Subject: {email['subject']}")
print(f"Date: {email['date']}")
print(f"Reply-To: {email['reply_to']}")
print(f"Return-Path: {email['return_path']}")
print(f"Message-ID: {email['message_id']}")


# --------------------------------------------------
# HEADER FINDINGS
# --------------------------------------------------

print("\n")
print("=" * 70)
print("HEADER FINDINGS")
print("=" * 70)

header_findings = result["header_findings"]

if not header_findings:

    print("\nNo suspicious header findings.")

else:

    for finding in header_findings:

        print(f"\nType: {finding['type']}")
        print(f"Severity: {finding['severity']}")
        print(f"Evidence: {finding['evidence']}")
        print(f"Description: {finding['description']}")


# --------------------------------------------------
# URL FINDINGS
# --------------------------------------------------

print("\n")
print("=" * 70)
print("URL ANALYSIS")
print("=" * 70)

urls = result["urls"]

print(f"\nURLs extracted: {len(urls['extracted'])}")

for url in urls["extracted"]:

    print(f"\nURL: {url}")


print("\nLocal URL findings:")

if not urls["findings"]:

    print("No suspicious URL findings.")

else:

    for finding in urls["findings"]:

        print(f"\nType: {finding['type']}")
        print(f"Severity: {finding['severity']}")
        print(f"Evidence: {finding['evidence']}")


print("\nVirusTotal URL results:")

for item in urls["virustotal"]:

    print(f"\nURL: {item['url']}")

    vt = item["result"]

    if vt["status"] == "success":

        print(f"Malicious: {vt['malicious']}")
        print(f"Suspicious: {vt['suspicious']}")
        print(f"Harmless: {vt['harmless']}")
        print(f"Undetected: {vt['undetected']}")

    else:

        print(f"Status: {vt['status']}")
        print(f"Message: {vt.get('message')}")


# --------------------------------------------------
# ATTACHMENTS
# --------------------------------------------------

print("\n")
print("=" * 70)
print("ATTACHMENT ANALYSIS")
print("=" * 70)

attachments = result["attachments"]

print(f"\nAttachments found: {len(attachments['files'])}")

for attachment in attachments["files"]:

    print(f"\nFilename: {attachment['filename']}")
    print(f"Content Type: {attachment['content_type']}")
    print(f"Size: {attachment['size']} bytes")
    print(f"SHA-256: {attachment['sha256']}")


# --------------------------------------------------
# MITRE ATT&CK
# --------------------------------------------------

print("\n")
print("=" * 70)
print("MITRE ATT&CK MAPPING")
print("=" * 70)

techniques = result["mitre_attack"]

if not techniques:

    print("\nNo techniques mapped.")

else:

    for technique in techniques:

        print(f"\nTechnique ID: {technique['technique_id']}")
        print(f"Technique: {technique['technique']}")
        print(f"Evidence: {technique['evidence']}")
        print(f"Confidence: {technique['confidence']}")


# --------------------------------------------------
# RISK ASSESSMENT
# --------------------------------------------------

print("\n")
print("=" * 70)
print("RISK ASSESSMENT")
print("=" * 70)

risk = result["risk_assessment"]

print(f"\nRisk Score: {risk['score']}/100")
print(f"Risk Level: {risk['risk_level']}")


print("\nRisk Evidence:")

for item in risk["evidence"]:

    print(f"\nSource: {item['source']}")
    print(f"Finding: {item['type']}")
    print(f"Points: {item['points']}")
    print(f"Evidence: {item['evidence']}")


print("\n")
print("=" * 70)
print("             INVESTIGATION COMPLETE")
print("=" * 70)