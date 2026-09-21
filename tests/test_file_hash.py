from analyzer.email_parser import parse_email
from analyzer.attachment_analyzer import extract_attachments
from analyzer.virustotal import check_file_hash_reputation


with open("samples/phishing/test_attachment.eml", "rb") as file:
    email_bytes = file.read()


result = parse_email(email_bytes)

attachments = extract_attachments(result["message"])


print("\n===== FILE HASH REPUTATION =====\n")


if not attachments:

    print("No attachments found.")

else:

    for attachment in attachments:

        filename = attachment["filename"]
        file_hash = attachment["sha256"]

        print(f"Filename: {filename}")
        print(f"SHA-256: {file_hash}")

        vt_result = check_file_hash_reputation(file_hash)

        print("\n[VIRUSTOTAL]")

        if vt_result["status"] == "success":

            print(f"Malicious: {vt_result['malicious']}")
            print(f"Suspicious: {vt_result['suspicious']}")
            print(f"Harmless: {vt_result['harmless']}")
            print(f"Undetected: {vt_result['undetected']}")

            if vt_result.get("filename"):
                print(f"VirusTotal filename: {vt_result['filename']}")

        elif vt_result["status"] == "not_found":

            print("File hash not found in VirusTotal.")
            print("This does NOT mean the file is benign.")

        else:

            print(f"VirusTotal error: {vt_result['message']}")

        print("\n" + "=" * 60)