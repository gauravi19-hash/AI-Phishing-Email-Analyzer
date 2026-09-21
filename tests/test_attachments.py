from analyzer.email_parser import parse_email
from analyzer.attachment_analyzer import extract_attachments


with open("samples/phishing/test_attachment.eml", "rb") as file:
    email_bytes = file.read()


result = parse_email(email_bytes)

attachments = extract_attachments(result["message"])


print("\n===== ATTACHMENT ANALYSIS =====\n")


if not attachments:

    print("No attachments found.")

else:

    for attachment in attachments:

        print(f"Filename: {attachment['filename']}")
        print(f"Content Type: {attachment['content_type']}")
        print(f"Size: {attachment['size']} bytes")
        print(f"SHA-256: {attachment['sha256']}")
        print("-" * 60)